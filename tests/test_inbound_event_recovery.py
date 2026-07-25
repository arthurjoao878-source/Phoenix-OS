from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery
from phoenix_os.events import Event, EventBus
from phoenix_os.inbound_events import (
    INBOUND_REDRIVE_PERMISSION,
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventPublisher,
    InboundEventReceipt,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundPublicationDisposition,
    InboundPublicationOutcome,
    InboundPublicationRecovery,
    InboundPublicationRetryPolicy,
    InboundPublicationStatus,
    InboundRecoveryDisposition,
    InboundRecoveryRuntimeState,
    InboundRecoveryWorker,
    InboundRedriveAccessDeniedError,
    InboundRedriveNotEligibleError,
    InboundReplayKind,
    InboundReplayReservation,
    StateInboundEventRepository,
    StateInboundReplayRepository,
    StateInboundSourceRepository,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
    inbound_evidence_digest,
)
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000026")
_RECEIPT_ID = UUID("00000000-0000-4000-8000-000000000027")


def _source(
    *,
    retry: InboundPublicationRetryPolicy | None = None,
) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        retry=retry or InboundPublicationRetryPolicy(),
    )


def _acceptance(
    source: InboundEventSource,
    *,
    expires_at: datetime | None = None,
) -> InboundAcceptance:
    payload = {"release": "0.25.0", "status": "completed"}
    payload_digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    event = InboundAcceptedEvent(
        id=_EVENT_ID,
        receipt_id=_RECEIPT_ID,
        source_id=source.id,
        source_event_id="release-000000000001",
        external_event_type="release.completed",
        external_schema_version=1,
        internal_event_type="external.release.completed",
        occurred_at=_NOW - timedelta(seconds=1),
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=payload,
        normalized_payload_sha256=payload_digest,
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
    expiry = expires_at or _NOW + timedelta(days=1)
    evidence = (
        (InboundReplayKind.REQUEST_ID, "request-000000000001"),
        (InboundReplayKind.NONCE, "nonce-000000000001"),
        (InboundReplayKind.SOURCE_EVENT_ID, event.source_event_id),
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
            expires_at=expiry,
            normalized_payload_sha256=(
                payload_digest if kind is InboundReplayKind.SOURCE_EVENT_ID else None
            ),
        )
        for kind, value in evidence
    )
    return InboundAcceptance(event, receipt, reservations)


def _claim(
    event: InboundAcceptedEvent,
    *,
    at: datetime,
) -> InboundAcceptedEvent:
    return replace(
        event,
        status=InboundPublicationStatus.PUBLISHING,
        updated_at=at,
        current_attempt=event.completed_attempts + 1,
        publishing_at=at,
        next_attempt_at=None,
        terminal_at=None,
        revision=event.revision + 1,
    )


def _redrive_context(*, allowed: bool = True) -> SecurityContext:
    return SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=(frozenset({INBOUND_REDRIVE_PERMISSION}) if allowed else frozenset()),
        correlation_id="redrive-correlation",
    )


@pytest.mark.asyncio
async def test_interrupted_publication_recovers_to_retrying() -> None:
    source = _source()
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(source)
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)
    claimed = _claim(
        acceptance.event,
        at=_NOW + timedelta(seconds=1),
    )
    await repositories.events.replace(claimed, expected_revision=1)

    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: _NOW + timedelta(seconds=2),
    )
    batch = await recovery.recover_publishing()

    assert batch.considered == 1
    result = batch.results[0]
    assert result.disposition is InboundRecoveryDisposition.RETRYING
    assert result.attempt == 1
    stored = await repositories.events.get(acceptance.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.RETRYING
    assert stored.attempts[0].error_category == "runtime_recovery"
    assert stored.attempts[0].outcome is InboundPublicationOutcome.RETRYABLE_FAILURE


@pytest.mark.asyncio
async def test_interrupted_last_attempt_recovers_to_dead_letter() -> None:
    source = _source(retry=InboundPublicationRetryPolicy(max_attempts=1))
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(source)
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)
    claimed = _claim(
        acceptance.event,
        at=_NOW + timedelta(seconds=1),
    )
    await repositories.events.replace(claimed, expected_revision=1)

    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: _NOW + timedelta(seconds=2),
    )
    result = (await recovery.recover_publishing()).results[0]

    assert result.disposition is InboundRecoveryDisposition.DEAD_LETTER
    stored = await repositories.events.get(acceptance.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.DEAD_LETTER
    assert stored.terminal_at == _NOW + timedelta(seconds=2)


@pytest.mark.asyncio
async def test_interrupted_event_from_inactive_source_is_discarded() -> None:
    source = _source()
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(source)
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)
    disabled_at = _NOW + timedelta(seconds=1)
    await repositories.sources.replace(
        replace(
            source,
            status=InboundEventSourceStatus.DISABLED,
            updated_at=disabled_at,
            disabled_at=disabled_at,
            revision=2,
        ),
        expected_revision=1,
    )
    claimed = _claim(acceptance.event, at=disabled_at)
    await repositories.events.replace(claimed, expected_revision=1)

    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: _NOW + timedelta(seconds=2),
    )
    result = (await recovery.recover_publishing()).results[0]

    assert result.disposition is InboundRecoveryDisposition.DISCARDED
    assert result.error_category == "source_inactive"
    stored = await repositories.events.get(acceptance.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.DISCARDED
    assert stored.completed_attempts == 0


@pytest.mark.asyncio
async def test_redrive_requires_permission_and_eligible_dead_letter() -> None:
    source = _source(retry=InboundPublicationRetryPolicy(max_attempts=1))
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(source)
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)
    bus = EventBus()

    async def fail(event: Event) -> None:
        del event
        raise RuntimeError("private failure")

    await bus.subscribe("external.release.completed", fail)
    publisher = InboundEventPublisher(
        sources=repositories.sources,
        events=repositories.events,
        event_bus=bus,
        clock=lambda: _NOW,
    )
    dead_letter = await publisher.publish(acceptance.event.id)
    assert dead_letter.disposition is InboundPublicationDisposition.DEAD_LETTER

    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: _NOW + timedelta(seconds=1),
    )
    with pytest.raises(InboundRedriveAccessDeniedError):
        await recovery.redrive(
            acceptance.event.id,
            _redrive_context(allowed=False),
        )

    redriven = await recovery.redrive(
        acceptance.event.id,
        _redrive_context(),
    )
    assert redriven.status is InboundPublicationStatus.RETRYING
    assert redriven.completed_attempts == 1

    with pytest.raises(InboundRedriveNotEligibleError):
        await recovery.redrive(
            acceptance.event.id,
            _redrive_context(),
        )


@pytest.mark.asyncio
async def test_state_restart_recovery_preserves_at_least_once_identity() -> None:
    store = MemoryStateStore()
    source = _source()
    acceptance = _acceptance(source)
    first_sources = StateInboundSourceRepository(store)
    first_events = StateInboundEventRepository(store)
    first_replay = StateInboundReplayRepository(store)
    await first_sources.add(source)
    await first_events.accept(acceptance)
    claimed = _claim(
        acceptance.event,
        at=_NOW + timedelta(seconds=1),
    )
    await first_events.replace(claimed, expected_revision=1)
    await first_sources.close()
    await first_events.close()
    await first_replay.close()

    restarted_sources = StateInboundSourceRepository(store)
    restarted_events = StateInboundEventRepository(store)
    restarted_replay = StateInboundReplayRepository(store)
    now = [_NOW + timedelta(seconds=2)]
    recovery = InboundPublicationRecovery(
        sources=restarted_sources,
        events=restarted_events,
        replay=restarted_replay,
        clock=lambda: now[0],
    )
    recovered = (await recovery.recover_publishing()).results[0]
    assert recovered.disposition is InboundRecoveryDisposition.RETRYING
    assert recovered.next_attempt_at is not None

    now[0] = recovered.next_attempt_at
    bus = EventBus()
    identities: list[UUID] = []

    async def receive(event: Event) -> None:
        identities.append(event.id)

    await bus.subscribe("external.release.completed", receive)
    publisher = InboundEventPublisher(
        sources=restarted_sources,
        events=restarted_events,
        event_bus=bus,
        clock=lambda: now[0],
    )
    published = await publisher.publish(acceptance.event.id)

    assert published.disposition is InboundPublicationDisposition.PUBLISHED
    assert identities == [acceptance.event.id]
    stored = await restarted_events.get(acceptance.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.PUBLISHED
    assert [attempt.number for attempt in stored.attempts] == [1, 2]
    assert stored.attempts[0].error_category == "runtime_recovery"


@pytest.mark.asyncio
async def test_maintenance_worker_prunes_expired_replay() -> None:
    now = [_NOW + timedelta(seconds=2)]
    source = _source()
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(
        source,
        expires_at=_NOW + timedelta(seconds=1),
    )
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)
    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: now[0],
    )
    worker = InboundRecoveryWorker(recovery, poll_interval=0.01)

    await worker.start()
    for _ in range(100):
        if (await repositories.replay.snapshot()).reservations == 0:
            break
        await asyncio.sleep(0.01)
    await worker.stop()

    assert (await repositories.replay.snapshot()).reservations == 0
    snapshot = await worker.snapshot()
    assert snapshot.state is InboundRecoveryRuntimeState.STOPPED
    assert snapshot.ticks >= 1
    assert snapshot.replay_pruned == 3
    assert snapshot.failures == 0


@pytest.mark.asyncio
async def test_recovery_audit_and_observability_exclude_sensitive_data() -> None:
    source = _source(retry=InboundPublicationRetryPolicy(max_attempts=1))
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(source)
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)
    claimed = _claim(
        acceptance.event,
        at=_NOW + timedelta(seconds=1),
    )
    await repositories.events.replace(claimed, expected_revision=1)

    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    audit = AuditLedger(clock=lambda: _NOW + timedelta(seconds=2))
    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        audit=audit,
        observability=observability,
        clock=lambda: _NOW + timedelta(seconds=2),
    )
    await recovery.recover_publishing()

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
    assert "normalized_payload" not in rendered
    assert acceptance.event.normalized_payload_sha256 not in rendered
    assert acceptance.event.source_event_id not in rendered
    assert "private" not in rendered

    observations = (await sink.snapshot()).records
    assert len(observations) == 2
    recovery_snapshot = await recovery.snapshot()
    assert recovery_snapshot.audit_failures == 0
    assert recovery_snapshot.observation_failures == 0
