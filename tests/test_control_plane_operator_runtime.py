from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from phoenix_os import (
    AdminTokenAuthenticator,
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    ControlPlaneHttpServer,
    ControlPlaneOperatorAccessService,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
    EventBus,
    InMemoryControlPlaneOperatorRegistry,
    Kernel,
    MappingConfigSource,
    MemoryStateStore,
    PhoenixRuntime,
    Router,
    RuntimeAssembler,
    StateControlPlaneOperatorRegistry,
)

_BOOTSTRAP = ControlPlaneOperatorToken("runtime-bootstrap-operator-0123456789abcdef")
_EXISTING = ControlPlaneOperatorToken("runtime-existing-operator-0123456789abcdef")


async def _runtime(
    *,
    state: MemoryStateStore | None = None,
    registry: InMemoryControlPlaneOperatorRegistry | None = None,
    bootstrap: ControlPlaneOperatorToken | None = _BOOTSTRAP,
) -> PhoenixRuntime:
    events = EventBus()
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    return await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        configuration=configuration,
        state=state,
        control_plane_operator_registry=registry,
        control_plane_operator_token=bootstrap,
        control_plane_operator_username="local-maintainer",
        control_plane_operator_display_name="Local Maintainer",
        control_plane_command_recovery_poll_interval=3600,
        control_plane_command_retention_poll_interval=3600,
    ).assemble()


async def _request(
    server: ControlPlaneHttpServer,
    method: str,
    path: str,
    *,
    authorization: str | None = None,
    body: bytes = b"",
) -> tuple[int, dict[str, str], dict[str, Any]]:
    assert server.port is not None
    reader, writer = await asyncio.open_connection(server.host, server.port)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {server.host}"]
    if authorization is not None:
        lines.append(f"Authorization: {authorization}")
    if body:
        lines.extend(
            (
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
            )
        )
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, raw_body = response.split(b"\r\n\r\n", 1)
    head_lines = head.decode("iso-8859-1").split("\r\n")
    status = int(head_lines[0].split(" ", 2)[1])
    headers = {
        name.lower(): value.strip()
        for name, value in (line.split(":", 1) for line in head_lines[1:])
    }
    return status, headers, json.loads(raw_body)


@pytest.mark.asyncio
async def test_runtime_uses_bounded_memory_operator_registry_without_state_store() -> None:
    runtime = await _runtime()

    registry = runtime.service("control_plane.operator-registry")
    assert isinstance(registry, InMemoryControlPlaneOperatorRegistry)
    assert isinstance(
        runtime.service("control_plane.operator-access"),
        ControlPlaneOperatorAccessService,
    )
    assert runtime.service("control_plane.operators") is not None


@pytest.mark.asyncio
async def test_runtime_uses_state_operator_registry_with_default_state_store() -> None:
    runtime = await _runtime(state=MemoryStateStore())

    assert isinstance(
        runtime.service("control_plane.operator-registry"),
        StateControlPlaneOperatorRegistry,
    )


@pytest.mark.asyncio
async def test_runtime_bootstraps_maintainer_only_when_started() -> None:
    runtime = await _runtime()
    registry = runtime.service("control_plane.operator-registry")
    assert isinstance(registry, InMemoryControlPlaneOperatorRegistry)
    assert await registry.get_by_username("local-maintainer") is None

    await runtime.start()
    record = await registry.get_by_username("local-maintainer")

    assert record is not None
    assert record.display_name == "Local Maintainer"
    assert record.role is ControlPlaneOperatorRole.MAINTAINER
    assert record.token_digest == _BOOTSTRAP.digest
    await runtime.stop()
    assert registry.closed


@pytest.mark.asyncio
async def test_runtime_does_not_overwrite_existing_bootstrap_username() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    created_at = datetime(2026, 7, 19, 22, tzinfo=UTC)
    existing = ControlPlaneOperatorRecord(
        id=uuid4(),
        username="local-maintainer",
        display_name="Existing Maintainer",
        role=ControlPlaneOperatorRole.MAINTAINER,
        token_digest=_EXISTING.digest,
        created_at=created_at,
        updated_at=created_at,
    )
    await registry.add(existing)
    runtime = await _runtime(registry=registry)

    await runtime.start()
    current = await registry.get_by_username("local-maintainer")

    assert current == existing
    assert current.token_digest != _BOOTSTRAP.digest
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_exchanges_bootstrap_credential_for_temporary_session() -> None:
    runtime = await _runtime()
    server = runtime.service("control_plane.http")
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()
    try:
        status, headers, login = await _request(
            server,
            "POST",
            "/v1/control-plane/operator/login",
            authorization=f"Bearer {_BOOTSTRAP.value}",
        )
        session_token = login["session_token"]
        assert isinstance(session_token, str)
        me_status, _, me = await _request(
            server,
            "GET",
            "/v1/control-plane/operator/me",
            authorization=f"Bearer {session_token}",
        )
        list_status, _, operators = await _request(
            server,
            "GET",
            "/v1/control-plane/operators?limit=20",
            authorization=f"Bearer {session_token}",
        )
    finally:
        await runtime.stop()

    assert status == 200
    assert headers["cache-control"] == "no-store"
    assert session_token != _BOOTSTRAP.value
    assert me_status == 200
    assert me["username"] == "local-maintainer"
    assert list_status == 200
    assert operators["page"]["total"] == 1
    assert operators["items"][0]["username"] == "local-maintainer"
    assert "token_digest" not in repr(operators)


@pytest.mark.asyncio
async def test_runtime_rejects_long_lived_credential_on_authenticated_routes() -> None:
    runtime = await _runtime()
    server = runtime.service("control_plane.http")
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()
    try:
        status, _, payload = await _request(
            server,
            "GET",
            "/v1/control-plane/operator/me",
            authorization=f"Bearer {_BOOTSTRAP.value}",
        )
    finally:
        await runtime.stop()

    assert status == 401
    assert payload == {"error": "unauthorized"}


@pytest.mark.asyncio
async def test_runtime_closes_operator_access_before_registry_owner() -> None:
    runtime = await _runtime()
    access = runtime.service("control_plane.operator-access")
    registry = runtime.service("control_plane.operator-registry")
    assert isinstance(access, ControlPlaneOperatorAccessService)
    assert isinstance(registry, InMemoryControlPlaneOperatorRegistry)

    await runtime.start()
    await runtime.stop()

    assert (await access.snapshot()).closed
    assert registry.closed


@pytest.mark.asyncio
async def test_runtime_supports_explicit_registry_without_bootstrap_credential() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    runtime = await _runtime(registry=registry, bootstrap=None)

    await runtime.start()

    assert (await registry.snapshot()).operators == 0
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_rejects_legacy_and_operator_authentication_together() -> None:
    events = EventBus()
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()

    with pytest.raises(ValueError, match="exclusive"):
        RuntimeAssembler(
            kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=configuration,
            control_plane_authenticator=AdminTokenAuthenticator(
                "legacy-runtime-token-0123456789abcdef"
            ),
            control_plane_operator_token=_BOOTSTRAP,
        )


@pytest.mark.asyncio
async def test_runtime_rejects_invalid_operator_capacity() -> None:
    events = EventBus()
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()

    with pytest.raises(ValueError, match="capacity"):
        RuntimeAssembler(
            kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=configuration,
            control_plane_operator_token=_BOOTSTRAP,
            control_plane_operator_capacity=0,
        )
