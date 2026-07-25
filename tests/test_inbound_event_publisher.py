from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery
from phoenix_os.events import Event, EventBus
from phoenix_os.inbound_events import (
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventPublisher,
    InboundEventReceipt,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundPublicationDisposition,
    InboundPublicationOutcome,
    InboundPublicationRetryPolicy,
    InboundPublicationStatus,
    InboundPublisherClosedError,
    InboundPublisherConfig,
    InboundPublisherRuntimeState,
    InboundPublisherWorker,
    InboundReplayKind,
    InboundReplayReservation,
    InMemoryInboundRepositories,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
)
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000026")
_RECEIPT_ID = UUID("00000000-0000-4000-8000-000000000027")


@dataclass
class _Fixture:
    source: InboundEventSource
    event: InboundAcceptedEvent
    repositories: InMemoryInboundRepositories
    publisher: InboundEventPublisher
    bus: EventBus


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
    event_id: UUID = _EVENT_ID,
    receipt_id: UUID = _RECEIPT_ID,
) -> InboundAcceptance:
    payload = {"release": "0.25.0", "status": "completed"}
    payload_digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    event = InboundAcceptedEvent(
        id=event_id,
        receipt_id=receipt_id,
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
        id=receipt_id,
        accepted_event_id=event_id,
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
            evidence_digest=hashlib.sha256(f"{event_id}:{kind.value}".encode()).hexdigest(),
            accepted_event_id=event_id,
            created_at=_NOW,
            expires_at=_NOW + timedelta(days=1),
            normalized_payload_sha256=(
                payload_digest if kind is InboundReplayKind.SOURCE_EVENT_ID else None
            ),
        )
        for kind in InboundReplayKind
    )
    return InboundAcceptance(event, receipt, reservations)


async def _fixture(
    *,
    retry: InboundPublicationRetryPolicy | None = None,
    clock: list[datetime] | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> _Fixture:
    source = _source(retry=retry)
    repositories = create_in_memory_inbound_repositories()
    await repositories.sources.add(source)
    acceptance = _acceptance(source)
    await repositories.events.accept(acceptance)
    bus = EventBus()
    resolved_clock = [_NOW] if clock is None else clock
    publisher = InboundEventPublisher(
        sources=repositories.sources,
        events=repositories.events,
        event_bus=bus,
        audit=audit,
        observability=observability,
        clock=lambda: resolved_clock[0],
    )
    return _Fixture(
        source=source,
        event=acceptance.event,
        repositories=repositories,
        publisher=publisher,
        bus=bus,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"batch_size": 0},
        {"batch_size": 201},
        {"global_concurrency": 0},
        {"global_concurrency": 1_025},
    ],
)
def test_publisher_config_rejects_unbounded_values(
    kwargs: dict[str, int],
) -> None:
    with pytest.raises(ValueError):
        InboundPublisherConfig(**kwargs)


@pytest.mark.asyncio
async def test_publisher_emits_reviewed_payload_with_stable_identity() -> None:
    fixture = await _fixture()
    seen: list[Event] = []

    async def handler(event: Event) -> None:
        seen.append(event)

    await fixture.bus.subscribe("external.release.completed", handler)
    batch = await fixture.publisher.publish_due()

    assert batch.considered == 1
    result = batch.results[0]
    assert result.disposition is InboundPublicationDisposition.PUBLISHED
    assert result.status is InboundPublicationStatus.PUBLISHED
    assert result.attempt == 1
    assert len(seen) == 1
    published = seen[0]
    assert published.id == fixture.event.id
    assert published.name == fixture.event.internal_event_type
    assert dict(published.payload) == dict(fixture.event.normalized_payload)
    assert published.metadata["accepted_event_id"] == str(fixture.event.id)
    assert published.metadata["publication_attempt"] == "1"
    assert published.correlation_id == fixture.event.correlation_id

    stored = await fixture.repositories.events.get(fixture.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.PUBLISHED
    assert stored.completed_attempts == 1
    assert stored.attempts[0].outcome is InboundPublicationOutcome.SUCCEEDED


@pytest.mark.asyncio
async def test_publisher_treats_zero_handlers_as_successful_bus_acceptance() -> None:
    fixture = await _fixture()

    result = await fixture.publisher.publish(fixture.event.id)

    assert result.disposition is InboundPublicationDisposition.PUBLISHED
    stored = await fixture.repositories.events.get(fixture.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.PUBLISHED


@pytest.mark.asyncio
async def test_publisher_retries_then_dead_letters_with_same_event_identity() -> None:
    now = [_NOW]
    retry = InboundPublicationRetryPolicy(
        max_attempts=2,
        initial_delay=timedelta(seconds=1),
        max_delay=timedelta(seconds=1),
    )
    fixture = await _fixture(retry=retry, clock=now)
    identities: list[UUID] = []

    async def failing_handler(event: Event) -> None:
        identities.append(event.id)
        raise RuntimeError("private handler failure")

    await fixture.bus.subscribe("external.release.completed", failing_handler)

    first = await fixture.publisher.publish(fixture.event.id)
    assert first.disposition is InboundPublicationDisposition.RETRYING
    assert first.error_category == "handler_failed"
    assert first.next_attempt_at == _NOW + timedelta(seconds=1)

    now[0] += timedelta(seconds=1)
    second = await fixture.publisher.publish(fixture.event.id)
    assert second.disposition is InboundPublicationDisposition.DEAD_LETTER
    assert second.error_category == "handler_failed"
    assert identities == [fixture.event.id, fixture.event.id]

    stored = await fixture.repositories.events.get(fixture.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.DEAD_LETTER
    assert [attempt.number for attempt in stored.attempts] == [1, 2]
    assert all(
        attempt.outcome is InboundPublicationOutcome.RETRYABLE_FAILURE
        for attempt in stored.attempts
    )
    assert all(attempt.error_category == "handler_failed" for attempt in stored.attempts)


@pytest.mark.asyncio
async def test_concurrent_publication_claims_event_only_once() -> None:
    fixture = await _fixture()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocking_handler(event: Event) -> None:
        del event
        entered.set()
        await release.wait()

    await fixture.bus.subscribe("external.release.completed", blocking_handler)
    first_task = asyncio.create_task(fixture.publisher.publish(fixture.event.id))
    await asyncio.wait_for(entered.wait(), timeout=1)
    second = await fixture.publisher.publish(fixture.event.id)
    release.set()
    first = await asyncio.wait_for(first_task, timeout=1)

    assert first.disposition is InboundPublicationDisposition.PUBLISHED
    assert second.disposition is InboundPublicationDisposition.SKIPPED
    stored = await fixture.repositories.events.get(fixture.event.id)
    assert stored is not None
    assert stored.completed_attempts == 1


@pytest.mark.asyncio
async def test_missing_source_is_safely_discarded() -> None:
    source = _source()
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(source)
    await repositories.events.accept(acceptance)
    publisher = InboundEventPublisher(
        sources=repositories.sources,
        events=repositories.events,
        event_bus=EventBus(),
        clock=lambda: _NOW,
    )

    result = await publisher.publish(acceptance.event.id)

    assert result.disposition is InboundPublicationDisposition.DISCARDED
    assert result.error_category == "source_missing"
    stored = await repositories.events.get(acceptance.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.DISCARDED
    assert stored.completed_attempts == 0
    snapshot = await publisher.snapshot()
    assert snapshot.source_missing == 1
    assert snapshot.discarded == 1


@pytest.mark.asyncio
async def test_runtime_worker_publishes_and_stops_cleanly() -> None:
    fixture = await _fixture()
    delivered = asyncio.Event()

    async def handler(event: Event) -> None:
        del event
        delivered.set()

    await fixture.bus.subscribe("external.release.completed", handler)
    worker = InboundPublisherWorker(
        fixture.publisher,
        poll_interval=0.01,
    )

    await worker.start()
    await asyncio.wait_for(delivered.wait(), timeout=1)
    await worker.stop()

    snapshot = await worker.snapshot()
    assert snapshot.state is InboundPublisherRuntimeState.STOPPED
    assert snapshot.ticks >= 1
    assert snapshot.considered >= 1
    assert snapshot.failures == 0
    stored = await fixture.repositories.events.get(fixture.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.PUBLISHED


@pytest.mark.asyncio
async def test_closed_publisher_rejects_new_work() -> None:
    fixture = await _fixture()
    await fixture.publisher.close()

    with pytest.raises(InboundPublisherClosedError, match="closed"):
        await fixture.publisher.publish_due()


@pytest.mark.asyncio
async def test_inactive_source_is_discarded_before_event_bus_publication() -> None:
    fixture = await _fixture()
    disabled_at = _NOW + timedelta(seconds=1)
    await fixture.repositories.sources.replace(
        replace(
            fixture.source,
            status=InboundEventSourceStatus.DISABLED,
            updated_at=disabled_at,
            disabled_at=disabled_at,
            revision=2,
        ),
        expected_revision=1,
    )
    seen: list[Event] = []

    async def handler(event: Event) -> None:
        seen.append(event)

    await fixture.bus.subscribe("external.release.completed", handler)
    result = await fixture.publisher.publish(fixture.event.id)

    assert result.disposition is InboundPublicationDisposition.DISCARDED
    assert result.error_category == "source_inactive"
    assert seen == []
    stored = await fixture.repositories.events.get(fixture.event.id)
    assert stored is not None
    assert stored.status is InboundPublicationStatus.DISCARDED


@pytest.mark.asyncio
async def test_publisher_audit_and_observability_are_safe() -> None:
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    audit = AuditLedger(clock=lambda: _NOW)
    fixture = await _fixture(
        audit=audit,
        observability=observability,
    )

    await fixture.publisher.publish(fixture.event.id)

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
    assert fixture.event.normalized_payload_sha256 not in rendered
    assert fixture.event.source_event_id not in rendered

    observations = (await sink.snapshot()).records
    assert len(observations) == 3
    snapshot = await fixture.publisher.snapshot()
    assert snapshot.audit_failures == 0
    assert snapshot.observation_failures == 0
