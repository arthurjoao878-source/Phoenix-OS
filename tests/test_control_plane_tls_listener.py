from __future__ import annotations

import asyncio
import os
import ssl
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests_support.tls_test_material import write_test_tls_material

from phoenix_os.control_plane.errors import (
    ControlPlaneTlsContextStateError,
    ControlPlaneTlsListenerStateError,
    ControlPlaneTlsMaterialError,
    ControlPlaneTlsReloadError,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneNetworkPolicy,
    ControlPlanePublicOrigin,
    ControlPlaneTlsMinimumVersion,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
)
from phoenix_os.control_plane.tls_listener import (
    DEFAULT_CONTROL_PLANE_TLS_EXPIRY_WARNING,
    MAX_CONTROL_PLANE_TLS_HANDSHAKE_TIMEOUT,
    MAX_CONTROL_PLANE_TLS_LISTENER_CONNECTIONS,
    MAX_CONTROL_PLANE_TLS_MATERIAL_BYTES,
    MAX_CONTROL_PLANE_TLS_SHUTDOWN_TIMEOUT,
    ControlPlaneTlsCertificateHealth,
    ControlPlaneTlsCertificateMetadata,
    ControlPlaneTlsContextManager,
    ControlPlaneTlsContextState,
    ControlPlaneTlsListener,
    ControlPlaneTlsListenerConfig,
    ControlPlaneTlsListenerState,
)

_NOW = datetime(2030, 1, 1, tzinfo=UTC)


@dataclass
class _Clock:
    value: datetime = _NOW

    def now(self) -> datetime:
        return self.value


def _material(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    paths = write_test_tls_material(tmp_path)
    if os.name != "nt":
        paths[1].chmod(0o600)
        paths[4].chmod(0o600)
    return paths


def _tls_policy(tmp_path: Path, *, mutual: bool = False) -> ControlPlaneTlsPolicy:
    certificate, private_key, ca, _, _ = _material(tmp_path)
    return ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.MUTUAL if mutual else ControlPlaneTlsMode.SERVER,
        certificate_file=str(certificate.resolve()),
        private_key_file=str(private_key.resolve()),
        client_ca_file=str(ca.resolve()) if mutual else None,
    )


def _network_policy(tmp_path: Path, *, mutual: bool = False) -> ControlPlaneNetworkPolicy:
    return ControlPlaneNetworkPolicy(
        bind_host="127.0.0.1",
        public_origin=ControlPlanePublicOrigin("https://127.0.0.1"),
        tls=_tls_policy(tmp_path, mutual=mutual),
        secure_cookies=True,
    )


def _client_context(*, ca: Path | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca is None:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.load_verify_locations(cafile=str(ca))
        context.check_hostname = False
    return context


def test_tls_listener_constants_are_bounded() -> None:
    assert DEFAULT_CONTROL_PLANE_TLS_EXPIRY_WARNING == timedelta(days=30)
    assert MAX_CONTROL_PLANE_TLS_HANDSHAKE_TIMEOUT == 60.0
    assert MAX_CONTROL_PLANE_TLS_SHUTDOWN_TIMEOUT == 60.0
    assert MAX_CONTROL_PLANE_TLS_LISTENER_CONNECTIONS == 4096
    assert MAX_CONTROL_PLANE_TLS_MATERIAL_BYTES == 4 * 1024 * 1024


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"handshake_timeout": 0}, "handshake"),
        ({"handshake_timeout": 61}, "handshake"),
        ({"shutdown_timeout": 0}, "shutdown"),
        ({"max_connections": 0}, "max_connections"),
        ({"stream_limit": 100}, "stream_limit"),
        ({"backlog": 0}, "backlog"),
    ],
)
def test_listener_config_rejects_invalid_bounds(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneTlsListenerConfig(**kwargs)  # type: ignore[arg-type]


def test_certificate_metadata_health_states() -> None:
    metadata = ControlPlaneTlsCertificateMetadata(
        sha256_fingerprint="a" * 64,
        not_before=_NOW,
        not_after=_NOW + timedelta(days=60),
        subject_common_name="phoenix.example",
        issuer_common_name="Phoenix CA",
    )
    assert (
        metadata.health_at(_NOW - timedelta(seconds=1))
        is ControlPlaneTlsCertificateHealth.NOT_YET_VALID
    )
    assert metadata.health_at(_NOW) is ControlPlaneTlsCertificateHealth.VALID
    assert (
        metadata.health_at(_NOW + timedelta(days=31)) is ControlPlaneTlsCertificateHealth.EXPIRING
    )
    assert metadata.health_at(_NOW + timedelta(days=60)) is ControlPlaneTlsCertificateHealth.EXPIRED


def test_certificate_metadata_rejects_secrets_and_invalid_values() -> None:
    with pytest.raises(ValueError, match="fingerprint"):
        ControlPlaneTlsCertificateMetadata(
            sha256_fingerprint="not-a-digest",
            not_before=_NOW,
            not_after=_NOW + timedelta(days=1),
            subject_common_name=None,
            issuer_common_name=None,
        )
    with pytest.raises(ValueError, match="interval"):
        ControlPlaneTlsCertificateMetadata(
            sha256_fingerprint="b" * 64,
            not_before=_NOW,
            not_after=_NOW,
            subject_common_name=None,
            issuer_common_name=None,
        )


def test_context_manager_requires_enabled_policy() -> None:
    with pytest.raises(ValueError, match="enabled TLS policy"):
        ControlPlaneTlsContextManager(ControlPlaneTlsPolicy())


@pytest.mark.asyncio
async def test_context_manager_loads_server_certificate_without_path_exposure(
    tmp_path: Path,
) -> None:
    manager = ControlPlaneTlsContextManager(_tls_policy(tmp_path), clock=_Clock())
    await manager.start()
    snapshot = await manager.snapshot()

    assert snapshot.state is ControlPlaneTlsContextState.READY
    assert snapshot.generation == 1
    assert snapshot.certificate is not None
    assert snapshot.certificate.sha256_fingerprint
    assert snapshot.certificate_health is ControlPlaneTlsCertificateHealth.VALID
    assert snapshot.mutual_tls is False
    rendered = repr(snapshot)
    assert "server.key" not in rendered
    assert str(tmp_path) not in rendered
    assert manager.listener_context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert manager.listener_context.verify_mode is ssl.CERT_NONE


@pytest.mark.asyncio
async def test_context_manager_enforces_tls_1_3_minimum(tmp_path: Path) -> None:
    policy = _tls_policy(tmp_path)
    policy = ControlPlaneTlsPolicy(
        mode=policy.mode,
        certificate_file=policy.certificate_file,
        private_key_file=policy.private_key_file,
        minimum_version=ControlPlaneTlsMinimumVersion.TLS_1_3,
    )
    manager = ControlPlaneTlsContextManager(policy, clock=_Clock())
    await manager.start()
    assert manager.listener_context.minimum_version is ssl.TLSVersion.TLSv1_3


@pytest.mark.asyncio
async def test_context_manager_configures_mutual_tls(tmp_path: Path) -> None:
    manager = ControlPlaneTlsContextManager(_tls_policy(tmp_path, mutual=True), clock=_Clock())
    await manager.start()
    snapshot = await manager.snapshot()
    assert snapshot.mutual_tls is True
    assert manager.listener_context.verify_mode is ssl.CERT_REQUIRED


@pytest.mark.asyncio
async def test_context_manager_reload_swaps_new_connections_without_rebinding(
    tmp_path: Path,
) -> None:
    manager = ControlPlaneTlsContextManager(_tls_policy(tmp_path), clock=_Clock())
    await manager.start()
    listener_context = manager.listener_context
    snapshot = await manager.reload()
    assert manager.listener_context is listener_context
    assert snapshot.generation == 2
    assert snapshot.successful_reloads == 1
    assert snapshot.failed_reloads == 0


@pytest.mark.asyncio
async def test_failed_reload_preserves_active_context_and_records_generic_error(
    tmp_path: Path,
) -> None:
    policy = _tls_policy(tmp_path)
    manager = ControlPlaneTlsContextManager(policy, clock=_Clock())
    await manager.start()
    listener_context = manager.listener_context
    assert policy.private_key_file is not None
    await asyncio.to_thread(Path(policy.private_key_file).write_text, "broken", encoding="ascii")

    with pytest.raises(ControlPlaneTlsReloadError, match="reload failed"):
        await manager.reload()

    snapshot = await manager.snapshot()
    assert manager.listener_context is listener_context
    assert snapshot.state is ControlPlaneTlsContextState.READY
    assert snapshot.generation == 1
    assert snapshot.failed_reloads == 1
    assert snapshot.last_error == "ControlPlaneTlsMaterialError"
    assert "broken" not in repr(snapshot)


@pytest.mark.asyncio
async def test_context_manager_rejects_insecure_private_key_permissions(tmp_path: Path) -> None:
    policy = _tls_policy(tmp_path)
    if os.name == "nt":
        pytest.skip("POSIX permission enforcement is not available on Windows")
    assert policy.private_key_file is not None
    private_key_info = await asyncio.to_thread(Path(policy.private_key_file).stat)
    assert stat.S_IMODE(private_key_info.st_mode) == 0o600
    await asyncio.to_thread(Path(policy.private_key_file).chmod, 0o644)
    manager = ControlPlaneTlsContextManager(policy, clock=_Clock())
    with pytest.raises(ControlPlaneTlsMaterialError, match="permissions"):
        await manager.start()


@pytest.mark.asyncio
async def test_context_manager_rejects_symlink_material(tmp_path: Path) -> None:
    policy = _tls_policy(tmp_path)
    certificate = tmp_path / "certificate-link.pem"
    try:
        certificate.symlink_to(Path(policy.certificate_file or ""))
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable")
    linked = ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.SERVER,
        certificate_file=str(certificate.absolute()),
        private_key_file=policy.private_key_file,
    )
    manager = ControlPlaneTlsContextManager(linked, clock=_Clock())
    with pytest.raises(ControlPlaneTlsMaterialError, match="symbolic link"):
        await manager.start()


@pytest.mark.asyncio
async def test_context_manager_lifecycle_is_one_shot(tmp_path: Path) -> None:
    manager = ControlPlaneTlsContextManager(_tls_policy(tmp_path), clock=_Clock())
    with pytest.raises(ControlPlaneTlsContextStateError, match="not ready"):
        _ = manager.listener_context
    await manager.start()
    with pytest.raises(ControlPlaneTlsContextStateError, match="cannot start"):
        await manager.start()
    await manager.close()
    await manager.close()
    assert (await manager.snapshot()).state is ControlPlaneTlsContextState.CLOSED
    with pytest.raises(ControlPlaneTlsContextStateError, match="ready before reload"):
        await manager.reload()


@pytest.mark.asyncio
async def test_tls_listener_accepts_encrypted_connection_and_accounts_it(tmp_path: Path) -> None:
    received = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert await reader.readexactly(4) == b"ping"
        writer.write(b"pong")
        await writer.drain()
        received.set()

    listener = ControlPlaneTlsListener(_network_policy(tmp_path), handler)
    await listener.start()
    assert listener.port is not None
    reader, writer = await asyncio.open_connection(
        listener.host,
        listener.port,
        ssl=_client_context(),
        server_hostname=None,
    )
    writer.write(b"ping")
    await writer.drain()
    assert await reader.readexactly(4) == b"pong"
    writer.close()
    await writer.wait_closed()
    await asyncio.wait_for(received.wait(), timeout=1)
    for _ in range(20):
        snapshot = await listener.snapshot()
        if snapshot.completed_connections == 1:
            break
        await asyncio.sleep(0.01)

    snapshot = await listener.snapshot()
    assert snapshot.state is ControlPlaneTlsListenerState.RUNNING
    assert snapshot.accepted_connections == 1
    assert snapshot.completed_connections == 1
    assert snapshot.active_connections == 0
    assert snapshot.tls.generation == 1
    await listener.stop()
    assert (await listener.snapshot()).state is ControlPlaneTlsListenerState.STOPPED


@pytest.mark.asyncio
async def test_tls_listener_requires_client_certificate_in_mutual_mode(tmp_path: Path) -> None:
    _, _, ca, client_cert, client_key = _material(tmp_path / "client-material")
    called = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer
        called.set()

    listener = ControlPlaneTlsListener(
        _network_policy(tmp_path / "server-material", mutual=True), handler
    )
    await listener.start()
    assert listener.port is not None

    with pytest.raises((ConnectionError, ssl.SSLError, asyncio.IncompleteReadError)):
        reader, writer = await asyncio.open_connection(
            listener.host,
            listener.port,
            ssl=_client_context(ca=ca),
            server_hostname=None,
        )
        await reader.readexactly(1)
        writer.close()
        await writer.wait_closed()
    assert not called.is_set()

    context = _client_context(ca=ca)
    context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    _, writer = await asyncio.open_connection(
        listener.host,
        listener.port,
        ssl=context,
        server_hostname=None,
    )
    await asyncio.wait_for(called.wait(), timeout=1)
    writer.close()
    await writer.wait_closed()
    await listener.stop()


@pytest.mark.asyncio
async def test_tls_listener_enforces_post_handshake_connection_capacity(tmp_path: Path) -> None:
    release = asyncio.Event()
    entered = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer
        entered.set()
        await release.wait()

    listener = ControlPlaneTlsListener(
        _network_policy(tmp_path),
        handler,
        config=ControlPlaneTlsListenerConfig(max_connections=1),
    )
    await listener.start()
    assert listener.port is not None
    _, first_writer = await asyncio.open_connection(
        listener.host, listener.port, ssl=_client_context(), server_hostname=None
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    second_reader, second_writer = await asyncio.open_connection(
        listener.host, listener.port, ssl=_client_context(), server_hostname=None
    )
    assert await asyncio.wait_for(second_reader.read(), timeout=1) == b""
    snapshot = await listener.snapshot()
    assert snapshot.active_connections == 1
    assert snapshot.rejected_connections == 1
    release.set()
    first_writer.close()
    second_writer.close()
    await first_writer.wait_closed()
    await second_writer.wait_closed()
    await listener.stop()


@pytest.mark.asyncio
async def test_tls_listener_reload_keeps_bound_port(tmp_path: Path) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer

    listener = ControlPlaneTlsListener(_network_policy(tmp_path), handler)
    await listener.start()
    port = listener.port
    snapshot = await listener.reload()
    assert listener.port == port
    assert snapshot.generation == 2
    await listener.stop()


@pytest.mark.asyncio
async def test_tls_listener_lifecycle_is_one_shot(tmp_path: Path) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer

    listener = ControlPlaneTlsListener(_network_policy(tmp_path), handler)
    with pytest.raises(ControlPlaneTlsListenerStateError, match="running before reload"):
        await listener.reload()
    await listener.start()
    with pytest.raises(ControlPlaneTlsListenerStateError, match="cannot start"):
        await listener.start()
    await listener.stop()
    await listener.stop()


@pytest.mark.asyncio
async def test_tls_listener_rejects_disabled_tls_policy() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer

    with pytest.raises(ValueError, match="enabled network TLS policy"):
        ControlPlaneTlsListener(ControlPlaneNetworkPolicy(), handler)


@pytest.mark.asyncio
async def test_tls_listener_applies_handshake_timeout(tmp_path: Path) -> None:
    called = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer
        called.set()

    listener = ControlPlaneTlsListener(
        _network_policy(tmp_path),
        handler,
        config=ControlPlaneTlsListenerConfig(handshake_timeout=0.1),
    )
    await listener.start()
    assert listener.port is not None
    reader, writer = await asyncio.open_connection(listener.host, listener.port)
    assert await asyncio.wait_for(reader.read(), timeout=1) == b""
    assert not called.is_set()
    writer.close()
    await writer.wait_closed()
    await listener.stop()
