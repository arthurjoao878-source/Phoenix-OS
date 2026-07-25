from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from http import HTTPStatus
from uuid import UUID

import pytest

from phoenix_os.events import EventBus
from phoenix_os.inbound_events import (
    INBOUND_SOURCES_DISABLE_PERMISSION,
    INBOUND_SOURCES_ENABLE_PERMISSION,
    INBOUND_SOURCES_UPDATE_PERMISSION,
    InboundEventSchema,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundManagerConfig,
    InboundRuntimeBundle,
    InboundRuntimeState,
    InboundSchemaRegistrationError,
    InboundServiceAccountSecurityBridge,
    create_in_memory_inbound_repositories,
    create_inbound_runtime,
    inbound_http_path,
)
from phoenix_os.policy import (
    PolicyEngine,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.secrets import SecretRef, SecretsManager

_NOW = datetime(2026, 7, 26, 18, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000003501")


class _Normalizer:
    schema = InboundEventSchema(
        event_type="release.completed",
        event_schema_version=1,
        internal_event_type="external.release.completed",
        required_fields=frozenset({"release", "status"}),
    )

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        return dict(payload)


def _source(
    *,
    name: str = "release.events",
    status: InboundEventSourceStatus = (InboundEventSourceStatus.ACTIVE),
    revision: int = 1,
) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name=name,
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        status=status,
        disabled_at=(_NOW if status is InboundEventSourceStatus.DISABLED else None),
        revoked_at=(_NOW if status is InboundEventSourceStatus.REVOKED else None),
        revision=revision,
    )


def _context(permission: str) -> SecurityContext:
    return SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({permission}),
    )


async def _bundle(
    *,
    source: InboundEventSource | None = None,
    normalizers: tuple[_Normalizer, ...] = (_Normalizer(),),
) -> InboundRuntimeBundle:
    repositories = create_in_memory_inbound_repositories()
    if source is not None:
        await repositories.sources.add(source)
    return create_inbound_runtime(
        event_bus=EventBus(),
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        secrets=SecretsManager(),
        normalizers=normalizers,
        policy_engine=PolicyEngine(),
        manager_config=InboundManagerConfig(machine_administration_enabled=True),
        publisher_poll_interval=60.0,
        recovery_poll_interval=60.0,
    )


@pytest.mark.asyncio
async def test_empty_runtime_starts_without_exposing_ingress() -> None:
    bundle = await _bundle()

    await bundle.owner.start()
    snapshot = await bundle.owner.snapshot()

    assert snapshot.state is InboundRuntimeState.RUNNING
    assert snapshot.registered_schemas == 1
    assert snapshot.loaded_sources == 0
    assert snapshot.active_routes == 0
    assert snapshot.recovery_batches == 1
    assert not bundle.ingress.handles("/v1/control-plane/inbound/release.events")

    await bundle.owner.stop()


@pytest.mark.asyncio
async def test_start_loads_only_active_exact_source_routes() -> None:
    source = _source()
    bundle = await _bundle(source=source)

    await bundle.owner.start()
    path = inbound_http_path(source)

    assert bundle.ingress.handles(path)
    assert bundle.ingress.body_limit(path) == source.max_body_bytes
    status, payload, headers = await bundle.ingress.dispatch(
        method="GET",
        path=path,
        query={},
        headers={},
        body=b"",
        transport_context=None,
    )
    assert status is HTTPStatus.METHOD_NOT_ALLOWED
    assert payload == {"error": "method_not_allowed"}
    assert headers["Cache-Control"] == "no-store"

    await bundle.owner.stop()


@pytest.mark.asyncio
async def test_disabled_source_is_not_exposed_until_enabled() -> None:
    source = _source(status=InboundEventSourceStatus.DISABLED)
    bundle = await _bundle(source=source)
    await bundle.owner.start()
    path = inbound_http_path(source)

    assert not bundle.ingress.handles(path)

    enabled = await bundle.manager.enable_source(
        source.id,
        _context(INBOUND_SOURCES_ENABLE_PERMISSION),
        expected_revision=1,
    )
    assert enabled.status is InboundEventSourceStatus.ACTIVE
    assert bundle.ingress.handles(path)

    await bundle.owner.stop()


@pytest.mark.asyncio
async def test_active_rename_and_disable_update_exact_routes() -> None:
    source = _source()
    bundle = await _bundle(source=source)
    await bundle.owner.start()
    old_path = inbound_http_path(source)

    updated = await bundle.manager.update_source(
        source.id,
        _context(INBOUND_SOURCES_UPDATE_PERMISSION),
        expected_revision=1,
        name="release.notifications",
    )
    new_path = "/v1/control-plane/inbound/release.notifications"
    assert not bundle.ingress.handles(old_path)
    assert bundle.ingress.handles(new_path)
    assert updated.name == "release.notifications"

    disabled = await bundle.manager.disable_source(
        source.id,
        _context(INBOUND_SOURCES_DISABLE_PERMISSION),
        expected_revision=2,
    )
    assert disabled.status is InboundEventSourceStatus.DISABLED
    assert not bundle.ingress.handles(new_path)

    await bundle.owner.stop()


@pytest.mark.asyncio
async def test_shutdown_closes_owned_runtime_resources() -> None:
    bundle = await _bundle(source=_source())

    await bundle.owner.start()
    await bundle.owner.stop()

    snapshot = await bundle.owner.snapshot()
    source_snapshot = await bundle.sources.snapshot()
    event_snapshot = await bundle.events.snapshot()
    replay_snapshot = await bundle.replay.snapshot()

    assert snapshot.state is InboundRuntimeState.STOPPED
    assert bundle.ingress.closed
    assert bundle.limiter.closed
    assert bundle.publisher.closed
    assert bundle.manager.closed
    assert bundle.recovery.closed
    assert source_snapshot.closed
    assert event_snapshot.closed
    assert replay_snapshot.closed


@pytest.mark.asyncio
async def test_duplicate_schema_failure_closes_partial_runtime() -> None:
    bundle = await _bundle(
        normalizers=(
            _Normalizer(),
            _Normalizer(),
        )
    )

    with pytest.raises(InboundSchemaRegistrationError):
        await bundle.owner.start()

    snapshot = await bundle.owner.snapshot()
    assert snapshot.state is InboundRuntimeState.FAILED
    assert bundle.ingress.closed
    assert bundle.publisher.closed
    assert bundle.manager.closed
    assert bundle.recovery.closed


@pytest.mark.asyncio
async def test_unbound_service_account_bridge_fails_closed() -> None:
    bridge = InboundServiceAccountSecurityBridge()

    assert not bridge.bound
    assert (
        await bridge.authenticate(
            "Bearer hidden",
            context=None,
        )
        is None
    )

    with pytest.raises(
        RuntimeError,
        match="replay is not bound",
    ):
        await bridge.admit(
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_unknown_runtime_route_returns_no_store_not_found() -> None:
    bundle = await _bundle()
    await bundle.owner.start()

    status, payload, headers = await bundle.ingress.dispatch(
        method="POST",
        path="/v1/control-plane/inbound/unknown",
        query={},
        headers={},
        body=b"{}",
        transport_context=None,
    )

    assert status is HTTPStatus.NOT_FOUND
    assert payload == {"error": "not_found"}
    assert headers == {"Cache-Control": "no-store"}

    await bundle.owner.stop()
