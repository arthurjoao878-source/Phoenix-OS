"""Native TLS context lifecycle and bounded listener for the Phoenix control plane."""

from __future__ import annotations

import asyncio
import hashlib
import os
import ssl
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from phoenix_os.control_plane.errors import (
    ControlPlaneTlsContextStateError,
    ControlPlaneTlsListenerStateError,
    ControlPlaneTlsMaterialError,
    ControlPlaneTlsReloadError,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneNetworkPolicy,
    ControlPlaneTlsMinimumVersion,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
)

DEFAULT_CONTROL_PLANE_TLS_HANDSHAKE_TIMEOUT = 5.0
MAX_CONTROL_PLANE_TLS_HANDSHAKE_TIMEOUT = 60.0
DEFAULT_CONTROL_PLANE_TLS_SHUTDOWN_TIMEOUT = 5.0
MAX_CONTROL_PLANE_TLS_SHUTDOWN_TIMEOUT = 60.0
DEFAULT_CONTROL_PLANE_TLS_EXPIRY_WARNING = timedelta(days=30)
MAX_CONTROL_PLANE_TLS_MATERIAL_BYTES = 4 * 1024 * 1024
MAX_CONTROL_PLANE_TLS_LISTENER_CONNECTIONS = 4096
MAX_CONTROL_PLANE_TLS_STREAM_BYTES = 1024 * 1024


class ControlPlaneTlsClock(Protocol):
    """Clock boundary used for deterministic certificate health and reload tests."""

    def now(self) -> datetime: ...


class _SystemTlsClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class ControlPlaneTlsCertificateHealth(StrEnum):
    """Safe validity state derived from the leaf server certificate."""

    VALID = "valid"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    NOT_YET_VALID = "not-yet-valid"


class ControlPlaneTlsContextState(StrEnum):
    """One-shot TLS context lifecycle."""

    CREATED = "created"
    READY = "ready"
    CLOSED = "closed"


class ControlPlaneTlsListenerState(StrEnum):
    """One-shot bounded TLS listener lifecycle."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneTlsCertificateMetadata:
    """Allowlisted certificate metadata with no file path or private-key material."""

    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    subject_common_name: str | None
    issuer_common_name: str | None

    def __post_init__(self) -> None:
        fingerprint = self.sha256_fingerprint.strip().lower()
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError("TLS certificate fingerprint must be a SHA-256 hexadecimal digest")
        _require_aware(self.not_before, "certificate not_before")
        _require_aware(self.not_after, "certificate not_after")
        if self.not_after <= self.not_before:
            raise ValueError("TLS certificate validity interval is invalid")
        subject = _normalize_optional_name(self.subject_common_name)
        issuer = _normalize_optional_name(self.issuer_common_name)
        object.__setattr__(self, "sha256_fingerprint", fingerprint)
        object.__setattr__(self, "subject_common_name", subject)
        object.__setattr__(self, "issuer_common_name", issuer)

    def health_at(
        self,
        now: datetime,
        *,
        warning_window: timedelta = DEFAULT_CONTROL_PLANE_TLS_EXPIRY_WARNING,
    ) -> ControlPlaneTlsCertificateHealth:
        _require_aware(now, "certificate health time")
        if warning_window < timedelta(0):
            raise ValueError("TLS certificate warning window cannot be negative")
        if now < self.not_before:
            return ControlPlaneTlsCertificateHealth.NOT_YET_VALID
        if now >= self.not_after:
            return ControlPlaneTlsCertificateHealth.EXPIRED
        if self.not_after - now <= warning_window:
            return ControlPlaneTlsCertificateHealth.EXPIRING
        return ControlPlaneTlsCertificateHealth.VALID


@dataclass(frozen=True, slots=True)
class ControlPlaneTlsContextSnapshot:
    """Non-sensitive TLS context and certificate health snapshot."""

    state: ControlPlaneTlsContextState
    generation: int
    loaded_at: datetime | None
    certificate: ControlPlaneTlsCertificateMetadata | None
    certificate_health: ControlPlaneTlsCertificateHealth | None
    mutual_tls: bool
    successful_reloads: int
    failed_reloads: int
    last_error: str | None = None

    def __post_init__(self) -> None:
        state = ControlPlaneTlsContextState(self.state)
        health = (
            None
            if self.certificate_health is None
            else ControlPlaneTlsCertificateHealth(self.certificate_health)
        )
        if self.generation < 0 or self.successful_reloads < 0 or self.failed_reloads < 0:
            raise ValueError("TLS context counters cannot be negative")
        if self.loaded_at is not None:
            _require_aware(self.loaded_at, "TLS context loaded_at")
        if state is ControlPlaneTlsContextState.READY:
            if (
                self.generation <= 0
                or self.loaded_at is None
                or self.certificate is None
                or health is None
            ):
                raise ValueError("ready TLS context snapshot requires loaded certificate metadata")
        elif (
            self.generation != 0
            or self.loaded_at is not None
            or self.certificate is not None
            or health is not None
        ):
            raise ValueError("inactive TLS context snapshot must not contain loaded metadata")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "certificate_health", health)
        object.__setattr__(self, "last_error", error)


@dataclass(frozen=True, slots=True)
class ControlPlaneTlsListenerConfig:
    """Bounded TLS handshake, stream, and shutdown limits."""

    handshake_timeout: float = DEFAULT_CONTROL_PLANE_TLS_HANDSHAKE_TIMEOUT
    shutdown_timeout: float = DEFAULT_CONTROL_PLANE_TLS_SHUTDOWN_TIMEOUT
    max_connections: int = 64
    stream_limit: int = 64 * 1024
    backlog: int = 100

    def __post_init__(self) -> None:
        if not 0 < self.handshake_timeout <= MAX_CONTROL_PLANE_TLS_HANDSHAKE_TIMEOUT:
            raise ValueError("TLS handshake timeout is outside supported bounds")
        if not 0 < self.shutdown_timeout <= MAX_CONTROL_PLANE_TLS_SHUTDOWN_TIMEOUT:
            raise ValueError("TLS shutdown timeout is outside supported bounds")
        if not 1 <= self.max_connections <= MAX_CONTROL_PLANE_TLS_LISTENER_CONNECTIONS:
            raise ValueError("TLS listener max_connections is outside supported bounds")
        if not 1024 <= self.stream_limit <= MAX_CONTROL_PLANE_TLS_STREAM_BYTES:
            raise ValueError("TLS listener stream_limit is outside supported bounds")
        if not 1 <= self.backlog <= 65535:
            raise ValueError("TLS listener backlog is outside supported bounds")


@dataclass(frozen=True, slots=True)
class ControlPlaneTlsListenerSnapshot:
    """Safe listener counters plus current TLS certificate state."""

    state: ControlPlaneTlsListenerState
    host: str
    port: int | None
    accepted_connections: int
    completed_connections: int
    rejected_connections: int
    active_connections: int
    tls: ControlPlaneTlsContextSnapshot
    last_error: str | None = None

    def __post_init__(self) -> None:
        state = ControlPlaneTlsListenerState(self.state)
        if not self.host.strip():
            raise ValueError("TLS listener snapshot host must not be blank")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("TLS listener snapshot port is invalid")
        counters = (
            self.accepted_connections,
            self.completed_connections,
            self.rejected_connections,
            self.active_connections,
        )
        if any(value < 0 for value in counters):
            raise ValueError("TLS listener counters cannot be negative")
        if self.completed_connections > self.accepted_connections:
            raise ValueError("completed TLS connections cannot exceed accepted connections")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "host", self.host.strip())
        object.__setattr__(self, "last_error", error)


@dataclass(frozen=True, slots=True)
class _TlsBundle:
    context: ssl.SSLContext
    certificate: ControlPlaneTlsCertificateMetadata


class ControlPlaneTlsContextManager:
    """Build, retain, and atomically reload native server TLS contexts."""

    def __init__(
        self,
        policy: ControlPlaneTlsPolicy,
        *,
        clock: ControlPlaneTlsClock | None = None,
        expiry_warning: timedelta = DEFAULT_CONTROL_PLANE_TLS_EXPIRY_WARNING,
    ) -> None:
        if not policy.enabled:
            raise ValueError("TLS context manager requires an enabled TLS policy")
        if expiry_warning < timedelta(0):
            raise ValueError("TLS expiry warning window cannot be negative")
        self._policy = policy
        self._clock = clock or _SystemTlsClock()
        self._expiry_warning = expiry_warning
        self._state = ControlPlaneTlsContextState.CREATED
        self._listener_context: ssl.SSLContext | None = None
        self._active_context: ssl.SSLContext | None = None
        self._certificate: ControlPlaneTlsCertificateMetadata | None = None
        self._generation = 0
        self._loaded_at: datetime | None = None
        self._successful_reloads = 0
        self._failed_reloads = 0
        self._last_error: str | None = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneTlsContextState:
        return self._state

    @property
    def listener_context(self) -> ssl.SSLContext:
        context = self._listener_context
        if self._state is not ControlPlaneTlsContextState.READY or context is None:
            raise ControlPlaneTlsContextStateError("TLS context is not ready")
        return context

    async def start(self, context: object = None) -> None:
        del context
        async with self._lock:
            if self._state is not ControlPlaneTlsContextState.CREATED:
                raise ControlPlaneTlsContextStateError(
                    f"cannot start TLS context from state {self._state.value}"
                )
        try:
            bundle = await asyncio.to_thread(_build_tls_bundle, self._policy, self._clock.now())
        except ControlPlaneTlsMaterialError:
            raise
        async with self._lock:
            if self._state is not ControlPlaneTlsContextState.CREATED:
                raise ControlPlaneTlsContextStateError("TLS context state changed during start")
            bundle.context.set_servername_callback(self._select_active_context)
            self._listener_context = bundle.context
            self._active_context = bundle.context
            self._certificate = bundle.certificate
            self._generation = 1
            self._loaded_at = self._clock.now()
            self._last_error = None
            self._state = ControlPlaneTlsContextState.READY

    async def reload(self) -> ControlPlaneTlsContextSnapshot:
        async with self._lock:
            if self._state is not ControlPlaneTlsContextState.READY:
                raise ControlPlaneTlsContextStateError("TLS context must be ready before reload")
        try:
            bundle = await asyncio.to_thread(_build_tls_bundle, self._policy, self._clock.now())
        except ControlPlaneTlsMaterialError as exception:
            async with self._lock:
                self._failed_reloads += 1
                self._last_error = type(exception).__name__
            raise ControlPlaneTlsReloadError("control-plane TLS reload failed") from exception
        async with self._lock:
            if self._state is not ControlPlaneTlsContextState.READY:
                raise ControlPlaneTlsContextStateError("TLS context state changed during reload")
            self._active_context = bundle.context
            self._certificate = bundle.certificate
            self._generation += 1
            self._successful_reloads += 1
            self._loaded_at = self._clock.now()
            self._last_error = None
            return self._snapshot_unlocked()

    async def snapshot(self) -> ControlPlaneTlsContextSnapshot:
        async with self._lock:
            return self._snapshot_unlocked()

    async def close(self, context: object = None) -> None:
        del context
        async with self._lock:
            if self._state is ControlPlaneTlsContextState.CLOSED:
                return
            self._listener_context = None
            self._active_context = None
            self._certificate = None
            self._generation = 0
            self._loaded_at = None
            self._state = ControlPlaneTlsContextState.CLOSED

    def _select_active_context(
        self,
        ssl_object: ssl.SSLObject | ssl.SSLSocket,
        server_name: str | None,
        initial_context: ssl.SSLSocket,
    ) -> int | None:
        del server_name, initial_context
        active = self._active_context
        if active is not None:
            ssl_object.context = active
        return None

    def _snapshot_unlocked(self) -> ControlPlaneTlsContextSnapshot:
        certificate = self._certificate
        health = (
            None
            if certificate is None
            else certificate.health_at(self._clock.now(), warning_window=self._expiry_warning)
        )
        return ControlPlaneTlsContextSnapshot(
            state=self._state,
            generation=self._generation,
            loaded_at=self._loaded_at,
            certificate=certificate,
            certificate_health=health,
            mutual_tls=self._policy.mutual_tls,
            successful_reloads=self._successful_reloads,
            failed_reloads=self._failed_reloads,
            last_error=self._last_error,
        )


ControlPlaneTlsConnectionHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter],
    Awaitable[None],
]


class ControlPlaneTlsListener:
    """Bind one native TLS socket with bounded post-handshake connection handling."""

    def __init__(
        self,
        network_policy: ControlPlaneNetworkPolicy,
        handler: ControlPlaneTlsConnectionHandler,
        *,
        config: ControlPlaneTlsListenerConfig | None = None,
        contexts: ControlPlaneTlsContextManager | None = None,
    ) -> None:
        if not network_policy.tls.enabled:
            raise ValueError("TLS listener requires an enabled network TLS policy")
        self._network_policy = network_policy
        self._handler = handler
        self._config = config or ControlPlaneTlsListenerConfig()
        self._contexts = contexts or ControlPlaneTlsContextManager(network_policy.tls)
        self._owns_contexts = contexts is None
        self._state = ControlPlaneTlsListenerState.CREATED
        self._server: asyncio.Server | None = None
        self._port: int | None = None
        self._accepted = 0
        self._completed = 0
        self._rejected = 0
        self._active = 0
        self._last_error: str | None = None
        self._state_lock = asyncio.Lock()
        self._counter_lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneTlsListenerState:
        return self._state

    @property
    def host(self) -> str:
        return self._network_policy.bind_host

    @property
    def port(self) -> int | None:
        return self._port

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not ControlPlaneTlsListenerState.CREATED:
                raise ControlPlaneTlsListenerStateError(
                    f"cannot start TLS listener from state {self._state.value}"
                )
        if self._contexts.state is ControlPlaneTlsContextState.CREATED:
            await self._contexts.start()
        elif self._contexts.state is not ControlPlaneTlsContextState.READY:
            raise ControlPlaneTlsListenerStateError("TLS context manager is not available")
        try:
            server = await asyncio.start_server(
                self._handle_connection,
                host=self._network_policy.bind_host,
                port=self._network_policy.port,
                ssl=self._contexts.listener_context,
                ssl_handshake_timeout=self._config.handshake_timeout,
                ssl_shutdown_timeout=self._config.shutdown_timeout,
                limit=self._config.stream_limit,
                backlog=self._config.backlog,
            )
        except Exception:
            if self._owns_contexts:
                await self._contexts.close()
            raise
        sockets = server.sockets or ()
        if len(sockets) != 1:
            server.close()
            await server.wait_closed()
            if self._owns_contexts:
                await self._contexts.close()
            raise RuntimeError("control-plane TLS listener requires exactly one bound socket")
        async with self._state_lock:
            if self._state is not ControlPlaneTlsListenerState.CREATED:
                server.close()
                await server.wait_closed()
                raise ControlPlaneTlsListenerStateError("TLS listener state changed during start")
            self._server = server
            self._port = int(sockets[0].getsockname()[1])
            self._state = ControlPlaneTlsListenerState.RUNNING

    async def reload(self) -> ControlPlaneTlsContextSnapshot:
        if self._state is not ControlPlaneTlsListenerState.RUNNING:
            raise ControlPlaneTlsListenerStateError("TLS listener must be running before reload")
        return await self._contexts.reload()

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is ControlPlaneTlsListenerState.STOPPED:
                return
            if self._state is ControlPlaneTlsListenerState.CREATED:
                self._state = ControlPlaneTlsListenerState.STOPPED
                if self._owns_contexts:
                    await self._contexts.close()
                return
            if self._state is not ControlPlaneTlsListenerState.RUNNING:
                raise ControlPlaneTlsListenerStateError(
                    f"cannot stop TLS listener from state {self._state.value}"
                )
            self._state = ControlPlaneTlsListenerState.STOPPING
            server = self._server
            self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        if self._owns_contexts:
            await self._contexts.close()
        async with self._state_lock:
            self._state = ControlPlaneTlsListenerState.STOPPED

    async def snapshot(self) -> ControlPlaneTlsListenerSnapshot:
        async with self._counter_lock:
            return ControlPlaneTlsListenerSnapshot(
                state=self._state,
                host=self.host,
                port=self._port,
                accepted_connections=self._accepted,
                completed_connections=self._completed,
                rejected_connections=self._rejected,
                active_connections=self._active,
                tls=await self._contexts.snapshot(),
                last_error=self._last_error,
            )

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._counter_lock:
            if self._active >= self._config.max_connections:
                self._rejected += 1
                self._last_error = "ConnectionCapacityExceeded"
                reject = True
            else:
                self._accepted += 1
                self._active += 1
                reject = False
        if reject:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, RuntimeError):
                pass
            return
        try:
            await self._handler(reader, writer)
        except Exception as exception:
            async with self._counter_lock:
                self._last_error = type(exception).__name__
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, RuntimeError):
                pass
            async with self._counter_lock:
                self._active -= 1
                self._completed += 1


def _build_tls_bundle(policy: ControlPlaneTlsPolicy, now: datetime) -> _TlsBundle:
    certificate_file = _require_material_file(policy.certificate_file, "certificate")
    private_key_file = _require_material_file(policy.private_key_file, "private key", secret=True)
    if certificate_file.resolve() == private_key_file.resolve():
        raise ControlPlaneTlsMaterialError(
            "TLS certificate and private key must be different files"
        )
    client_ca_file = None
    if policy.client_ca_file is not None:
        client_ca_file = _require_material_file(policy.client_ca_file, "client CA")
    metadata = _decode_certificate_metadata(certificate_file)
    health = metadata.health_at(now, warning_window=timedelta(0))
    if health is ControlPlaneTlsCertificateHealth.NOT_YET_VALID:
        raise ControlPlaneTlsMaterialError("TLS certificate is not yet valid")
    if health is ControlPlaneTlsCertificateHealth.EXPIRED:
        raise ControlPlaneTlsMaterialError("TLS certificate has expired")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = _minimum_tls_version(policy.minimum_version)
    context.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_CIPHER_SERVER_PREFERENCE"):
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        context.options |= ssl.OP_NO_RENEGOTIATION
    if hasattr(context, "num_tickets"):
        context.num_tickets = 0
    context.set_alpn_protocols(["http/1.1"])
    try:
        context.load_cert_chain(
            certfile=str(certificate_file),
            keyfile=str(private_key_file),
        )
        if policy.mode is ControlPlaneTlsMode.MUTUAL:
            if client_ca_file is None:  # pragma: no cover - protected by policy
                raise AssertionError("mutual TLS policy lost its client CA")
            context.load_verify_locations(cafile=str(client_ca_file))
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_NONE
    except (OSError, ssl.SSLError) as exception:
        raise ControlPlaneTlsMaterialError(
            "unable to load control-plane TLS material"
        ) from exception
    context.check_hostname = False
    return _TlsBundle(context=context, certificate=metadata)


def _minimum_tls_version(value: ControlPlaneTlsMinimumVersion) -> ssl.TLSVersion:
    if value is ControlPlaneTlsMinimumVersion.TLS_1_3:
        return ssl.TLSVersion.TLSv1_3
    return ssl.TLSVersion.TLSv1_2


def _require_material_file(value: str | None, label: str, *, secret: bool = False) -> Path:
    if value is None:
        raise ControlPlaneTlsMaterialError(f"TLS {label} file is not configured")
    path = Path(value)
    try:
        info = path.lstat()
    except OSError as exception:
        raise ControlPlaneTlsMaterialError(f"TLS {label} file is not accessible") from exception
    if stat.S_ISLNK(info.st_mode):
        raise ControlPlaneTlsMaterialError(f"TLS {label} file must not be a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise ControlPlaneTlsMaterialError(f"TLS {label} path must reference a regular file")
    if info.st_size <= 0 or info.st_size > MAX_CONTROL_PLANE_TLS_MATERIAL_BYTES:
        raise ControlPlaneTlsMaterialError(f"TLS {label} file size is outside supported bounds")
    if secret and os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ControlPlaneTlsMaterialError(
            "TLS private key permissions must deny group and other access"
        )
    return path


def _decode_certificate_metadata(path: Path) -> ControlPlaneTlsCertificateMetadata:
    try:
        pem = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exception:
        raise ControlPlaneTlsMaterialError("TLS certificate cannot be read as PEM") from exception
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    start = pem.find(begin)
    finish = pem.find(end, start + len(begin))
    if start < 0 or finish < 0:
        raise ControlPlaneTlsMaterialError("TLS certificate PEM block is missing")
    leaf_pem = pem[start : finish + len(end)]
    try:
        der = ssl.PEM_cert_to_DER_cert(leaf_pem)
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if decoder is None:
            raise ControlPlaneTlsMaterialError("TLS certificate decoder is unavailable")
        decoded = decoder(str(path))
        not_before = _certificate_time(decoded, "notBefore")
        not_after = _certificate_time(decoded, "notAfter")
    except ControlPlaneTlsMaterialError:
        raise
    except (OSError, ssl.SSLError, ValueError) as exception:
        raise ControlPlaneTlsMaterialError("TLS certificate metadata is invalid") from exception
    return ControlPlaneTlsCertificateMetadata(
        sha256_fingerprint=hashlib.sha256(der).hexdigest(),
        not_before=not_before,
        not_after=not_after,
        subject_common_name=_certificate_common_name(decoded.get("subject")),
        issuer_common_name=_certificate_common_name(decoded.get("issuer")),
    )


def _certificate_time(decoded: dict[str, Any], field: str) -> datetime:
    raw = decoded.get(field)
    if not isinstance(raw, str):
        raise ControlPlaneTlsMaterialError(f"TLS certificate {field} is missing")
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), UTC)
    except ValueError as exception:
        raise ControlPlaneTlsMaterialError(f"TLS certificate {field} is invalid") from exception


def _certificate_common_name(value: object) -> str | None:
    if not isinstance(value, tuple):
        return None
    for relative_name in value:
        if not isinstance(relative_name, tuple):
            continue
        for attribute in relative_name:
            if (
                isinstance(attribute, tuple)
                and len(attribute) == 2
                and attribute[0] == "commonName"
                and isinstance(attribute[1], str)
            ):
                return attribute[1]
    return None


def _normalize_optional_name(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > 255:
        raise ValueError("TLS certificate common name is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("TLS certificate common name contains control characters")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
