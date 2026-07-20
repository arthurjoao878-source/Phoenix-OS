"""Safe remote authentication admission, address protection, and audit events."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import math
import re
import time
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionHttpBoundary,
    ControlPlaneDurableSessionHttpLogin,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneRemoteLoginRejectedError,
    ControlPlaneRemoteLoginThrottleClosedError,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentity,
    ControlPlaneClientIdentitySource,
)
from phoenix_os.control_plane.network_guard import (
    ControlPlaneNetworkRejectionReason,
    ControlPlaneNetworkRequestContext,
)
from phoenix_os.events import BusClosedError, EventBus

DEFAULT_REMOTE_LOGIN_CLIENT_ATTEMPTS = 10
DEFAULT_REMOTE_LOGIN_OPERATOR_ATTEMPTS = 20
DEFAULT_REMOTE_LOGIN_WINDOW = 60.0
DEFAULT_REMOTE_LOGIN_CLIENT_CAPACITY = 4096
DEFAULT_REMOTE_LOGIN_OPERATOR_CAPACITY = 4096
MAX_REMOTE_LOGIN_ATTEMPTS = 100_000
MAX_REMOTE_LOGIN_WINDOW = 3600.0
MAX_REMOTE_LOGIN_CAPACITY = 100_000

_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class ControlPlaneRemoteAddressFamily(StrEnum):
    """Allowlisted address-family facts safe for audit payloads."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class ControlPlaneRemoteAddressScope(StrEnum):
    """Allowlisted coarse address scope without retaining an address literal."""

    UNSPECIFIED = "unspecified"
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link-local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    GLOBAL = "global"
    OTHER = "other"


class ControlPlaneRemoteLoginBlockReason(StrEnum):
    """Allowlisted login admission reason with no credential or address content."""

    CLIENT = "client"
    OPERATOR = "operator"
    CAPACITY = "capacity"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class ControlPlaneRemoteLoginBlockedError(ControlPlaneRemoteLoginRejectedError):
    """Raised with an allowlisted dimension after remote login admission blocks."""

    reason: ControlPlaneRemoteLoginBlockReason

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reason",
            ControlPlaneRemoteLoginBlockReason(self.reason),
        )

    def __str__(self) -> str:
        return "remote operator login rejected"


class ControlPlaneRemoteAuditEvent(StrEnum):
    """Fixed remote-security event names accepted by the audit emitter."""

    CONNECTION_ACCEPTED = "control-plane.remote.connection.accepted"
    CONNECTION_CLOSED = "control-plane.remote.connection.closed"
    NETWORK_REJECTED = "control-plane.remote.network.rejected"
    AUTHENTICATION_SUCCEEDED = "control-plane.remote.authentication.succeeded"
    AUTHENTICATION_REJECTED = "control-plane.remote.authentication.rejected"
    LOGIN_BLOCKED = "control-plane.remote.login.blocked"


class ControlPlaneRemoteClock(Protocol):
    """Monotonic clock used by remote login admission windows."""

    def now(self) -> float: ...


class _SystemRemoteClock:
    def now(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class ControlPlaneSafeRemoteAddress:
    """HMAC-protected remote address facts safe for logs and Event Bus payloads."""

    fingerprint: str
    family: ControlPlaneRemoteAddressFamily
    scope: ControlPlaneRemoteAddressScope
    source: ControlPlaneClientIdentitySource
    trusted_proxy: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        if _FINGERPRINT_PATTERN.fullmatch(self.fingerprint) is None:
            raise ValueError("remote address fingerprint must be a SHA-256 hex digest")
        object.__setattr__(self, "family", ControlPlaneRemoteAddressFamily(self.family))
        object.__setattr__(self, "scope", ControlPlaneRemoteAddressScope(self.scope))
        object.__setattr__(self, "source", ControlPlaneClientIdentitySource(self.source))
        if self.schema_version != 1:
            raise ValueError("unsupported safe remote address schema version")

    def payload(self) -> dict[str, object]:
        """Return a strict allowlist of non-sensitive address facts."""

        return {
            "client_fingerprint": self.fingerprint,
            "address_family": self.family.value,
            "address_scope": self.scope.value,
            "identity_source": self.source.value,
            "trusted_proxy": self.trusted_proxy,
        }


class ControlPlaneRemoteAddressProtector:
    """Convert canonical client identities to non-reversible HMAC references."""

    def __init__(self, secret: bytes | bytearray | memoryview) -> None:
        key = bytes(secret)
        if len(key) < 32 or len(key) > 128:
            raise ValueError("remote address protection secret must contain 32 to 128 bytes")
        self._secret = key

    def protect(self, identity: ControlPlaneClientIdentity) -> ControlPlaneSafeRemoteAddress:
        address = ipaddress.ip_address(identity.address)
        material = f"phoenix-remote-address:v1:{address.compressed}".encode("ascii")
        fingerprint = hmac.new(self._secret, material, hashlib.sha256).hexdigest()
        return ControlPlaneSafeRemoteAddress(
            fingerprint=fingerprint,
            family=(
                ControlPlaneRemoteAddressFamily.IPV4
                if address.version == 4
                else ControlPlaneRemoteAddressFamily.IPV6
            ),
            scope=_address_scope(address),
            source=identity.source,
            trusted_proxy=identity.trusted_proxy,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneRemoteLoginThrottlePolicy:
    """Bounded monotonic login limits keyed independently by client and operator."""

    client_attempts: int = DEFAULT_REMOTE_LOGIN_CLIENT_ATTEMPTS
    operator_attempts: int = DEFAULT_REMOTE_LOGIN_OPERATOR_ATTEMPTS
    window: float = DEFAULT_REMOTE_LOGIN_WINDOW
    client_capacity: int = DEFAULT_REMOTE_LOGIN_CLIENT_CAPACITY
    operator_capacity: int = DEFAULT_REMOTE_LOGIN_OPERATOR_CAPACITY

    def __post_init__(self) -> None:
        if not 1 <= self.client_attempts <= MAX_REMOTE_LOGIN_ATTEMPTS:
            raise ValueError("remote client login limit is outside supported bounds")
        if not 1 <= self.operator_attempts <= MAX_REMOTE_LOGIN_ATTEMPTS:
            raise ValueError("remote operator login limit is outside supported bounds")
        if not math.isfinite(self.window) or not 0 < self.window <= MAX_REMOTE_LOGIN_WINDOW:
            raise ValueError("remote login window is outside supported bounds")
        if not 1 <= self.client_capacity <= MAX_REMOTE_LOGIN_CAPACITY:
            raise ValueError("remote client tracking capacity is outside supported bounds")
        if not 1 <= self.operator_capacity <= MAX_REMOTE_LOGIN_CAPACITY:
            raise ValueError("remote operator tracking capacity is outside supported bounds")


@dataclass(frozen=True, slots=True)
class ControlPlaneRemoteLoginThrottleSnapshot:
    """Counter-only remote login throttle state."""

    closed: bool
    client_attempts: int
    operator_attempts: int
    client_blocks: int
    operator_blocks: int
    capacity_blocks: int
    tracked_clients: int
    tracked_operators: int
    client_capacity: int
    operator_capacity: int
    last_block: ControlPlaneRemoteLoginBlockReason | None = None

    def __post_init__(self) -> None:
        counters = (
            self.client_attempts,
            self.operator_attempts,
            self.client_blocks,
            self.operator_blocks,
            self.capacity_blocks,
            self.tracked_clients,
            self.tracked_operators,
        )
        if any(value < 0 for value in counters):
            raise ValueError("remote login throttle counters cannot be negative")
        if self.tracked_clients > self.client_capacity:
            raise ValueError("tracked remote clients exceed configured capacity")
        if self.tracked_operators > self.operator_capacity:
            raise ValueError("tracked remote operators exceed configured capacity")
        block = (
            None if self.last_block is None else ControlPlaneRemoteLoginBlockReason(self.last_block)
        )
        object.__setattr__(self, "last_block", block)


class ControlPlaneRemoteLoginThrottle:
    """Fail-closed sliding-window admission for remote login endpoints."""

    def __init__(
        self,
        policy: ControlPlaneRemoteLoginThrottlePolicy | None = None,
        *,
        clock: ControlPlaneRemoteClock | None = None,
    ) -> None:
        self._policy = policy or ControlPlaneRemoteLoginThrottlePolicy()
        self._clock = clock or _SystemRemoteClock()
        self._client_buckets: dict[str, deque[float]] = {}
        self._operator_buckets: dict[str, deque[float]] = {}
        self._closed = False
        self._client_attempts = 0
        self._operator_attempts = 0
        self._client_blocks = 0
        self._operator_blocks = 0
        self._capacity_blocks = 0
        self._last_block: ControlPlaneRemoteLoginBlockReason | None = None
        self._lock = asyncio.Lock()

    @property
    def policy(self) -> ControlPlaneRemoteLoginThrottlePolicy:
        return self._policy

    @property
    def closed(self) -> bool:
        return self._closed

    async def consume_client(self, identity: ControlPlaneClientIdentity) -> None:
        """Consume one attempt for a canonical resolved client address."""

        await self._consume(
            buckets=self._client_buckets,
            key=identity.address,
            limit=self._policy.client_attempts,
            capacity=self._policy.client_capacity,
            dimension=ControlPlaneRemoteLoginBlockReason.CLIENT,
        )

    async def consume_operator(self, operator_id: UUID) -> None:
        """Consume one attempt for an authenticated stable operator id."""

        await self._consume(
            buckets=self._operator_buckets,
            key=str(operator_id),
            limit=self._policy.operator_attempts,
            capacity=self._policy.operator_capacity,
            dimension=ControlPlaneRemoteLoginBlockReason.OPERATOR,
        )

    async def snapshot(self) -> ControlPlaneRemoteLoginThrottleSnapshot:
        now = self._validated_now()
        async with self._lock:
            self._purge(self._client_buckets, now)
            self._purge(self._operator_buckets, now)
            return ControlPlaneRemoteLoginThrottleSnapshot(
                closed=self._closed,
                client_attempts=self._client_attempts,
                operator_attempts=self._operator_attempts,
                client_blocks=self._client_blocks,
                operator_blocks=self._operator_blocks,
                capacity_blocks=self._capacity_blocks,
                tracked_clients=len(self._client_buckets),
                tracked_operators=len(self._operator_buckets),
                client_capacity=self._policy.client_capacity,
                operator_capacity=self._policy.operator_capacity,
                last_block=self._last_block,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._client_buckets.clear()
            self._operator_buckets.clear()

    async def _consume(
        self,
        *,
        buckets: dict[str, deque[float]],
        key: str,
        limit: int,
        capacity: int,
        dimension: ControlPlaneRemoteLoginBlockReason,
    ) -> None:
        now = self._validated_now()
        async with self._lock:
            if self._closed:
                self._last_block = ControlPlaneRemoteLoginBlockReason.CLOSED
                raise ControlPlaneRemoteLoginThrottleClosedError("remote login throttle is closed")
            self._purge(self._client_buckets, now)
            self._purge(self._operator_buckets, now)
            if dimension is ControlPlaneRemoteLoginBlockReason.CLIENT:
                self._client_attempts += 1
            else:
                self._operator_attempts += 1
            bucket = buckets.get(key)
            if bucket is None:
                if len(buckets) >= capacity:
                    self._capacity_blocks += 1
                    self._last_block = ControlPlaneRemoteLoginBlockReason.CAPACITY
                    raise ControlPlaneRemoteLoginBlockedError(
                        ControlPlaneRemoteLoginBlockReason.CAPACITY
                    )
                bucket = deque()
                buckets[key] = bucket
            cutoff = now - self._policy.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                if dimension is ControlPlaneRemoteLoginBlockReason.CLIENT:
                    self._client_blocks += 1
                else:
                    self._operator_blocks += 1
                self._last_block = dimension
                raise ControlPlaneRemoteLoginBlockedError(dimension)
            bucket.append(now)

    def _purge(self, buckets: dict[str, deque[float]], now: float) -> None:
        cutoff = now - self._policy.window
        empty: list[str] = []
        for key, bucket in buckets.items():
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                empty.append(key)
        for key in empty:
            del buckets[key]

    def _validated_now(self) -> float:
        now = self._clock.now()
        if not math.isfinite(now):
            raise RuntimeError("remote login clock returned a non-finite value")
        return now


@dataclass(frozen=True, slots=True)
class ControlPlaneRemoteAuditSnapshot:
    """Counter-only state for remote security event emission."""

    emitted: int
    dropped: int
    last_event: ControlPlaneRemoteAuditEvent | None = None

    def __post_init__(self) -> None:
        if self.emitted < 0 or self.dropped < 0:
            raise ValueError("remote audit counters cannot be negative")
        event = None if self.last_event is None else ControlPlaneRemoteAuditEvent(self.last_event)
        object.__setattr__(self, "last_event", event)


class ControlPlaneRemoteAudit:
    """Emit fixed remote-security events containing only protected address facts."""

    def __init__(
        self,
        events: EventBus | None,
        protector: ControlPlaneRemoteAddressProtector,
    ) -> None:
        self._events = events
        self._protector = protector
        self._emitted = 0
        self._dropped = 0
        self._last_event: ControlPlaneRemoteAuditEvent | None = None
        self._lock = asyncio.Lock()

    async def connection_accepted(self, identity: ControlPlaneClientIdentity) -> None:
        await self._emit(
            ControlPlaneRemoteAuditEvent.CONNECTION_ACCEPTED,
            identity=identity,
            result="accepted",
        )

    async def connection_closed(self, identity: ControlPlaneClientIdentity) -> None:
        await self._emit(
            ControlPlaneRemoteAuditEvent.CONNECTION_CLOSED,
            identity=identity,
            result="closed",
        )

    async def network_rejected(
        self,
        reason: ControlPlaneNetworkRejectionReason,
        *,
        identity: ControlPlaneClientIdentity | None = None,
    ) -> None:
        await self._emit(
            ControlPlaneRemoteAuditEvent.NETWORK_REJECTED,
            identity=identity,
            result=ControlPlaneNetworkRejectionReason(reason).value,
        )

    async def authentication_succeeded(
        self,
        identity: ControlPlaneClientIdentity,
        operator_id: UUID,
    ) -> None:
        await self._emit(
            ControlPlaneRemoteAuditEvent.AUTHENTICATION_SUCCEEDED,
            identity=identity,
            result="accepted",
            operator_id=operator_id,
        )

    async def authentication_rejected(self, identity: ControlPlaneClientIdentity) -> None:
        await self._emit(
            ControlPlaneRemoteAuditEvent.AUTHENTICATION_REJECTED,
            identity=identity,
            result="rejected",
        )

    async def login_blocked(
        self,
        identity: ControlPlaneClientIdentity,
        reason: ControlPlaneRemoteLoginBlockReason,
        *,
        operator_id: UUID | None = None,
    ) -> None:
        await self._emit(
            ControlPlaneRemoteAuditEvent.LOGIN_BLOCKED,
            identity=identity,
            result=ControlPlaneRemoteLoginBlockReason(reason).value,
            operator_id=operator_id,
        )

    async def snapshot(self) -> ControlPlaneRemoteAuditSnapshot:
        async with self._lock:
            return ControlPlaneRemoteAuditSnapshot(
                emitted=self._emitted,
                dropped=self._dropped,
                last_event=self._last_event,
            )

    async def _emit(
        self,
        event: ControlPlaneRemoteAuditEvent,
        *,
        identity: ControlPlaneClientIdentity | None,
        result: str,
        operator_id: UUID | None = None,
    ) -> None:
        event_parts = event.value.split(".")
        payload: dict[str, object] = {
            "action": event_parts[-2],
            "outcome": event_parts[-1],
            "result": result,
        }
        if identity is not None:
            payload.update(self._protector.protect(identity).payload())
        if operator_id is not None:
            payload["operator_id"] = str(operator_id)
        emitted = False
        if self._events is not None:
            try:
                await self._events.emit(
                    event.value,
                    source="control-plane.remote-security",
                    payload=payload,
                )
                emitted = True
            except (BusClosedError, RuntimeError):
                emitted = False
        async with self._lock:
            if emitted:
                self._emitted += 1
            else:
                self._dropped += 1
            self._last_event = event


class ControlPlaneRemoteAuthenticationService:
    """Authenticate remote operators only after bounded client and operator admission."""

    def __init__(
        self,
        *,
        sessions: ControlPlaneDurableSessionHttpBoundary,
        throttle: ControlPlaneRemoteLoginThrottle,
        audit: ControlPlaneRemoteAudit,
    ) -> None:
        origin = sessions.public_origin
        if (
            origin is None
            or not origin.secure
            or origin.loopback
            or not sessions.cookie_policy.secure
        ):
            raise ValueError(
                "remote authentication requires an HTTPS public origin and Secure cookies"
            )
        self._sessions = sessions
        self._throttle = throttle
        self._audit = audit
        self._origin = origin

    @property
    def public_origin(self) -> str:
        return self._origin.value

    async def login(
        self,
        authorization: str | None,
        context: ControlPlaneNetworkRequestContext,
    ) -> ControlPlaneDurableSessionHttpLogin:
        """Issue a session after exact-origin, client, credential, and operator admission."""

        identity = context.identity
        if context.origin != self._origin.value:
            await self._audit.authentication_rejected(identity)
            raise ControlPlaneRemoteLoginRejectedError("remote operator login rejected")
        try:
            await self._throttle.consume_client(identity)
        except ControlPlaneRemoteLoginBlockedError as exception:
            await self._audit.login_blocked(identity, exception.reason)
            raise ControlPlaneRemoteLoginRejectedError("remote operator login rejected") from None
        except ControlPlaneRemoteLoginThrottleClosedError:
            await self._audit.login_blocked(
                identity,
                ControlPlaneRemoteLoginBlockReason.CLOSED,
            )
            raise ControlPlaneRemoteLoginRejectedError("remote operator login rejected") from None

        evidence = await self._sessions.authenticate_operator(authorization)
        if evidence is None:
            await self._audit.authentication_rejected(identity)
            raise ControlPlaneRemoteLoginRejectedError("remote operator login rejected")
        try:
            await self._throttle.consume_operator(evidence.operator_id)
        except ControlPlaneRemoteLoginBlockedError as exception:
            await self._audit.login_blocked(
                identity,
                exception.reason,
                operator_id=evidence.operator_id,
            )
            raise ControlPlaneRemoteLoginRejectedError("remote operator login rejected") from None
        except ControlPlaneRemoteLoginThrottleClosedError:
            await self._audit.login_blocked(
                identity,
                ControlPlaneRemoteLoginBlockReason.CLOSED,
                operator_id=evidence.operator_id,
            )
            raise ControlPlaneRemoteLoginRejectedError("remote operator login rejected") from None

        try:
            login = await self._sessions.issue_login(evidence, origin=self._origin)
        except Exception as exception:
            await self._audit.authentication_rejected(identity)
            raise ControlPlaneRemoteLoginRejectedError(
                "remote operator login rejected"
            ) from exception
        await self._audit.authentication_succeeded(identity, evidence.operator_id)
        return login


def _address_scope(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ControlPlaneRemoteAddressScope:
    if address.is_unspecified:
        return ControlPlaneRemoteAddressScope.UNSPECIFIED
    if address.is_loopback:
        return ControlPlaneRemoteAddressScope.LOOPBACK
    if address.is_link_local:
        return ControlPlaneRemoteAddressScope.LINK_LOCAL
    if address.is_multicast:
        return ControlPlaneRemoteAddressScope.MULTICAST
    if address.is_reserved:
        return ControlPlaneRemoteAddressScope.RESERVED
    if address.is_private:
        return ControlPlaneRemoteAddressScope.PRIVATE
    if address.is_global:
        return ControlPlaneRemoteAddressScope.GLOBAL
    return ControlPlaneRemoteAddressScope.OTHER
