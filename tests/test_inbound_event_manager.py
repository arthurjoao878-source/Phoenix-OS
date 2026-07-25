from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery
from phoenix_os.events import Event, EventBus
from phoenix_os.inbound_events import (
    INBOUND_EVENTS_READ_PERMISSION,
    INBOUND_HEALTH_READ_PERMISSION,
    INBOUND_RECEIPTS_READ_PERMISSION,
    INBOUND_REDRIVE_PERMISSION,
    INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
    INBOUND_SOURCES_CREATE_PERMISSION,
    INBOUND_SOURCES_DISABLE_PERMISSION,
    INBOUND_SOURCES_ENABLE_PERMISSION,
    INBOUND_SOURCES_READ_PERMISSION,
    INBOUND_SOURCES_REVOKE_PERMISSION,
    INBOUND_SOURCES_ROTATE_PERMISSION,
    INBOUND_SOURCES_UPDATE_PERMISSION,
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundAuthenticationMode,
    InboundEventPublisher,
    InboundEventReceipt,
    InboundEventSchema,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundManager,
    InboundManagerAccessDeniedError,
    InboundManagerConfig,
    InboundPublicationDisposition,
    InboundPublicationRecovery,
    InboundPublicationRetryPolicy,
    InboundRedriveNotEligibleError,
    InboundReplayKind,
    InboundReplayReservation,
    InboundSchemaRegistrationError,
    InboundSchemaRegistry,
    InboundServiceAccountPolicy,
    InboundSourceConflictError,
    InMemoryInboundRepositories,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
    inbound_evidence_digest,
)
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000026")
_RECEIPT_ID = UUID("00000000-0000-4000-8000-000000000027")
_PERMISSIONS = frozenset(
    {
        INBOUND_SOURCES_READ_PERMISSION,
        INBOUND_SOURCES_CREATE_PERMISSION,
        INBOUND_SOURCES_UPDATE_PERMISSION,
        INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
        INBOUND_SOURCES_DISABLE_PERMISSION,
        INBOUND_SOURCES_ENABLE_PERMISSION,
        INBOUND_SOURCES_REVOKE_PERMISSION,
        INBOUND_SOURCES_ROTATE_PERMISSION,
        INBOUND_EVENTS_READ_PERMISSION,
        INBOUND_RECEIPTS_READ_PERMISSION,
        INBOUND_REDRIVE_PERMISSION,
        INBOUND_HEALTH_READ_PERMISSION,
    }
)


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


def _human(
    permissions: frozenset[str] = _PERMISSIONS,
) -> SecurityContext:
    return SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=permissions,
        correlation_id="admin-correlation",
    )


def _machine(
    permission: str,
    resource: str,
) -> SecurityContext:
    return SecurityContext(
        principal="service-account:automation",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({permission}),
        scopes=frozenset({permission}),
        attributes={"resource": resource},
        correlation_id="machine-correlation",
    )


def _source(
    *,
    source_id: UUID = _SOURCE_ID,
    status: InboundEventSourceStatus = InboundEventSourceStatus.ACTIVE,
    authentication: InboundHmacPolicy | InboundServiceAccountPolicy | None = None,
    revision: int = 1,
    updated_at: datetime = _NOW,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    retry: InboundPublicationRetryPolicy | None = None,
) -> InboundEventSource:
    if status is InboundEventSourceStatus.DISABLED and disabled_at is None:
        disabled_at = updated_at
    if status is InboundEventSourceStatus.REVOKED and revoked_at is None:
        revoked_at = updated_at
    return InboundEventSource(
        id=source_id,
        name="release.events",
        display_name="Release Events",
        authentication=authentication
        or InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=updated_at,
        created_by="maintainer:test",
        retry=retry or InboundPublicationRetryPolicy(),
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
    )


def _acceptance(source: InboundEventSource) -> InboundAcceptance:
    payload = {
        "release": "0.25.0",
        "status": "completed",
        "private": "must-not-leak",
    }
    digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    event = InboundAcceptedEvent(
        id=_EVENT_ID,
        receipt_id=_RECEIPT_ID,
        source_id=source.id,
        source_event_id="external-release-000001",
        external_event_type="release.completed",
        external_schema_version=1,
        internal_event_type="external.release.completed",
        occurred_at=_NOW,
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=payload,
        normalized_payload_sha256=digest,
        correlation_id="inbound-correlation",
        next_attempt_at=_NOW,
    )
    receipt = InboundEventReceipt(
        id=_RECEIPT_ID,
        accepted_event_id=event.id,
        source_id=source.id,
        source_event_id=event.source_event_id,
        external_event_type=event.external_event_type,
        external_schema_version=event.external_schema_version,
        accepted_at=event.accepted_at,
        correlation_id=event.correlation_id,
    )
    reservations = tuple(
        InboundReplayReservation(
            source_id=source.id,
            kind=kind,
            evidence_digest=inbound_evidence_digest(
                source.id,
                kind,
                value,
            ),
            accepted_event_id=event.id,
            created_at=_NOW,
            expires_at=_NOW + timedelta(days=1),
            normalized_payload_sha256=(
                digest if kind is InboundReplayKind.SOURCE_EVENT_ID else None
            ),
        )
        for kind, value in (
            (InboundReplayKind.REQUEST_ID, "request-000001"),
            (InboundReplayKind.NONCE, "nonce-000001"),
            (
                InboundReplayKind.SOURCE_EVENT_ID,
                event.source_event_id,
            ),
        )
    )
    return InboundAcceptance(event, receipt, reservations)


async def _manager(
    *,
    machine: bool = False,
    with_source: bool = True,
    with_event: bool = False,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> tuple[
    InboundManager,
    InMemoryInboundRepositories,
    InboundSchemaRegistry,
]:
    repositories = create_in_memory_inbound_repositories()
    schemas = InboundSchemaRegistry()
    schemas.register(_Normalizer())
    source = _source()
    if with_source:
        await repositories.sources.add(source)
    if with_event:
        if not with_source:
            await repositories.sources.add(source)
        await repositories.events.accept(_acceptance(source))
    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        audit=audit,
        observability=observability,
        clock=lambda: _NOW + timedelta(seconds=10),
    )
    manager = InboundManager(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        recovery=recovery,
        schemas=schemas,
        config=InboundManagerConfig(machine_administration_enabled=machine),
        audit=audit,
        observability=observability,
        clock=lambda: _NOW + timedelta(seconds=10),
        source_id_factory=lambda: _SOURCE_ID,
    )
    return manager, repositories, schemas


@pytest.mark.asyncio
async def test_create_source_is_disabled_and_view_hides_secret_reference() -> None:
    manager, repositories, _ = await _manager(with_source=False)

    view = await manager.create_source(
        _human(),
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("highly-sensitive-secret-name", "private", 7)),
        event_types=frozenset({"release.completed"}),
    )

    assert view.status is InboundEventSourceStatus.DISABLED
    assert view.disabled_at == _NOW + timedelta(seconds=10)
    assert view.authentication.mode is InboundAuthenticationMode.HMAC_SHA256
    assert view.authentication.key_version == 7
    rendered = repr(view)
    assert "highly-sensitive-secret-name" not in rendered
    assert "private" not in rendered
    stored = await repositories.sources.get(view.id)
    assert stored is not None
    assert stored.status is InboundEventSourceStatus.DISABLED


@pytest.mark.asyncio
async def test_create_requires_exact_human_permission() -> None:
    manager, _, _ = await _manager(with_source=False)

    with pytest.raises(InboundManagerAccessDeniedError):
        await manager.create_source(
            _human(frozenset({"*"})),
            name="release.events",
            display_name="Release Events",
            authentication=InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
            event_types=frozenset({"release.completed"}),
        )


@pytest.mark.asyncio
async def test_schema_registry_blocks_unreviewed_source_types() -> None:
    manager, _, _ = await _manager(with_source=False)

    with pytest.raises(InboundSchemaRegistrationError):
        await manager.create_source(
            _human(),
            name="unknown.events",
            display_name="Unknown Events",
            authentication=InboundHmacPolicy(SecretRef("unknown-inbound", "integrations", 1)),
            event_types=frozenset({"unknown.completed"}),
        )


@pytest.mark.asyncio
async def test_source_lifecycle_and_revision_conflicts_are_protected() -> None:
    manager, _, _ = await _manager()
    current = await manager.get_source(_SOURCE_ID, _human())

    disabled = await manager.disable_source(
        _SOURCE_ID,
        _human(),
        expected_revision=current.revision,
    )
    assert disabled.status is InboundEventSourceStatus.DISABLED

    with pytest.raises(InboundSourceConflictError, match="revision conflict"):
        await manager.enable_source(
            _SOURCE_ID,
            _human(),
            expected_revision=current.revision,
        )

    enabled = await manager.enable_source(
        _SOURCE_ID,
        _human(),
        expected_revision=disabled.revision,
    )
    assert enabled.status is InboundEventSourceStatus.ACTIVE

    revoked = await manager.revoke_source(
        _SOURCE_ID,
        _human(),
        expected_revision=enabled.revision,
    )
    assert revoked.status is InboundEventSourceStatus.REVOKED

    with pytest.raises(InboundSourceConflictError, match="only active"):
        await manager.disable_source(
            _SOURCE_ID,
            _human(),
            expected_revision=revoked.revision,
        )


@pytest.mark.asyncio
async def test_authentication_change_requires_disabled_source() -> None:
    manager, _, _ = await _manager()

    with pytest.raises(InboundSourceConflictError, match="disabled source"):
        await manager.update_authentication(
            _SOURCE_ID,
            _human(),
            expected_revision=1,
            authentication=InboundServiceAccountPolicy(resource="inbound-source:release.events"),
        )

    disabled = await manager.disable_source(
        _SOURCE_ID,
        _human(),
        expected_revision=1,
    )
    updated = await manager.update_authentication(
        _SOURCE_ID,
        _human(),
        expected_revision=disabled.revision,
        authentication=InboundServiceAccountPolicy(resource="inbound-source:release.events"),
    )
    assert updated.authentication.mode is InboundAuthenticationMode.SERVICE_ACCOUNT
    assert updated.authentication.service_account_resource == "inbound-source:release.events"


@pytest.mark.asyncio
async def test_active_hmac_rotation_requires_bounded_predecessor() -> None:
    manager, _, _ = await _manager()

    with pytest.raises(ValueError, match="predecessor validity"):
        await manager.rotate_hmac_key(
            _SOURCE_ID,
            _human(),
            expected_revision=1,
            secret_ref=SecretRef(
                "release-inbound",
                "integrations",
                2,
            ),
        )

    rotated = await manager.rotate_hmac_key(
        _SOURCE_ID,
        _human(),
        expected_revision=1,
        secret_ref=SecretRef(
            "release-inbound",
            "integrations",
            2,
        ),
        predecessor_valid_until=_NOW + timedelta(minutes=10),
    )
    assert rotated.authentication.key_version == 2
    assert rotated.authentication.predecessor_key_version == 1
    assert "release-inbound" not in repr(rotated)


@pytest.mark.asyncio
async def test_event_and_receipt_views_do_not_expose_payload_or_digest() -> None:
    manager, repositories, _ = await _manager(with_event=True)

    event_view = await manager.get_event(_EVENT_ID, _human())
    receipt_view = await manager.get_receipt(_RECEIPT_ID, _human())

    event_fields = {item.name for item in fields(event_view)}
    assert "normalized_payload" not in event_fields
    assert "normalized_payload_sha256" not in event_fields
    assert "source_event_id" not in event_fields
    rendered = repr(event_view)
    accepted = await repositories.events.get(_EVENT_ID)
    assert accepted is not None
    assert "must-not-leak" not in rendered
    assert accepted.normalized_payload_sha256 not in rendered
    assert receipt_view.source_event_id == accepted.source_event_id


@pytest.mark.asyncio
async def test_machine_administration_is_opt_in_exact_and_resource_bound() -> None:
    manager, _, _ = await _manager(machine=False)
    resource = f"inbound-source:{_SOURCE_ID}"
    context = _machine(INBOUND_SOURCES_READ_PERMISSION, resource)

    with pytest.raises(InboundManagerAccessDeniedError):
        await manager.get_source(_SOURCE_ID, context)

    enabled_manager, _, _ = await _manager(machine=True)
    view = await enabled_manager.get_source(_SOURCE_ID, context)
    assert view.id == _SOURCE_ID

    wrong_resource = _machine(
        INBOUND_SOURCES_READ_PERMISSION,
        "inbound-source:00000000-0000-4000-8000-000000000999",
    )
    with pytest.raises(InboundManagerAccessDeniedError):
        await enabled_manager.get_source(_SOURCE_ID, wrong_resource)

    with pytest.raises(InboundManagerAccessDeniedError):
        await enabled_manager.list_sources(context)


@pytest.mark.asyncio
async def test_redrive_uses_exact_event_resource_and_preserves_identity() -> None:
    source = _source(retry=InboundPublicationRetryPolicy(max_attempts=1))
    repositories = create_in_memory_inbound_repositories()
    await repositories.sources.add(source)
    acceptance = _acceptance(source)
    await repositories.events.accept(acceptance)
    bus = EventBus()

    async def fail(event: Event) -> None:
        del event
        raise RuntimeError("private")

    await bus.subscribe("external.release.completed", fail)
    publisher = InboundEventPublisher(
        sources=repositories.sources,
        events=repositories.events,
        event_bus=bus,
        clock=lambda: _NOW,
    )
    result = await publisher.publish(_EVENT_ID)
    assert result.disposition is InboundPublicationDisposition.DEAD_LETTER

    schemas = InboundSchemaRegistry()
    schemas.register(_Normalizer())
    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: _NOW + timedelta(seconds=1),
    )
    manager = InboundManager(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        recovery=recovery,
        schemas=schemas,
        config=InboundManagerConfig(machine_administration_enabled=True),
        clock=lambda: _NOW + timedelta(seconds=1),
    )
    context = _machine(
        INBOUND_REDRIVE_PERMISSION,
        f"inbound-event:{_EVENT_ID}",
    )
    redriven = await manager.redrive_event(_EVENT_ID, context)
    assert redriven.accepted_event_id == _EVENT_ID

    with pytest.raises(InboundRedriveNotEligibleError):
        await manager.redrive_event(_EVENT_ID, context)


@pytest.mark.asyncio
async def test_snapshot_and_safe_signals_include_no_credentials() -> None:
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    audit = AuditLedger(clock=lambda: _NOW + timedelta(seconds=10))
    manager, _, _ = await _manager(
        with_source=False,
        audit=audit,
        observability=observability,
    )
    await manager.create_source(
        _human(),
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("audit-secret-name", "private-namespace", 3)),
        event_types=frozenset({"release.completed"}),
    )
    snapshot = await manager.snapshot(_human())
    assert snapshot.sources.sources == 1
    assert snapshot.sources.disabled == 1
    assert snapshot.events.events == 0
    assert snapshot.schemas.registrations == 1

    records = await audit.read(
        AuditQuery(sources=frozenset({"phoenix.inbound"})),
        SecurityContext(
            principal="auditor:test",
            principal_type=PrincipalType.USER,
            authenticated=True,
            permissions=frozenset({"audit.read"}),
        ),
    )
    assert len(records) == 1
    rendered = json.dumps(dict(records[0].event.details), sort_keys=True)
    assert "audit-secret-name" not in rendered
    assert "private-namespace" not in rendered

    observations = (await sink.snapshot()).records
    assert len(observations) == 2
    observation_rendered = repr(observations)
    assert "audit-secret-name" not in observation_rendered
    assert "private-namespace" not in observation_rendered
