from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.inbound_events import (
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundCorruptionError,
    InboundEventAlreadyExistsError,
    InboundEventConflictError,
    InboundEventReceipt,
    InboundEventRepositoryClosedError,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundPublicationStatus,
    InboundReplayCapacityError,
    InboundReplayKind,
    InboundReplayReservation,
    InboundSourceAlreadyExistsError,
    InboundSourceConflictError,
    InboundSourceRepositoryClosedError,
    StateInboundEventRepository,
    StateInboundReplayRepository,
    StateInboundSourceRepository,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
    inbound_evidence_digest,
)
from phoenix_os.secrets import SecretRef
from phoenix_os.state import MemoryStateStore, StateKey

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)


def _source(
    name: str = "release.events",
    *,
    source_id: UUID | None = None,
    status: InboundEventSourceStatus = InboundEventSourceStatus.ACTIVE,
    updated_at: datetime = _NOW,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    revision: int = 1,
) -> InboundEventSource:
    return InboundEventSource(
        id=source_id or uuid4(),
        name=name,
        display_name=name.replace(".", " ").title(),
        authentication=InboundHmacPolicy(SecretRef("inbound-key", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=updated_at,
        created_by="maintainer:arthur",
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
    )


def _acceptance(
    source_id: UUID,
    *,
    event_id: UUID | None = None,
    receipt_id: UUID | None = None,
    source_event_id: str = "release-1",
    request_id: str = "request-1",
    nonce: str = "nonce-1",
    expires_at: datetime | None = None,
) -> InboundAcceptance:
    accepted_event_id = event_id or uuid4()
    stable_receipt_id = receipt_id or uuid4()
    payload = {"release_id": source_event_id, "status": "completed"}
    payload_digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    event = InboundAcceptedEvent(
        id=accepted_event_id,
        receipt_id=stable_receipt_id,
        source_id=source_id,
        source_event_id=source_event_id,
        external_event_type="release.completed",
        external_schema_version=1,
        internal_event_type="external.release.completed",
        occurred_at=_NOW,
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=payload,
        normalized_payload_sha256=payload_digest,
        next_attempt_at=_NOW,
    )
    receipt = InboundEventReceipt(
        id=stable_receipt_id,
        accepted_event_id=accepted_event_id,
        source_id=source_id,
        source_event_id=source_event_id,
        external_event_type="release.completed",
        external_schema_version=1,
        accepted_at=_NOW,
    )
    expiry = expires_at or _NOW + timedelta(hours=1)
    evidence = (
        (InboundReplayKind.REQUEST_ID, request_id),
        (InboundReplayKind.NONCE, nonce),
        (InboundReplayKind.SOURCE_EVENT_ID, source_event_id),
    )
    reservations = tuple(
        InboundReplayReservation(
            source_id=source_id,
            kind=kind,
            evidence_digest=inbound_evidence_digest(source_id, kind, value),
            accepted_event_id=accepted_event_id,
            created_at=_NOW,
            expires_at=expiry,
            normalized_payload_sha256=(
                payload_digest if kind is InboundReplayKind.SOURCE_EVENT_ID else None
            ),
        )
        for kind, value in evidence
    )
    return InboundAcceptance(event, receipt, reservations)


def _source_event_reservation(
    acceptance: InboundAcceptance,
) -> InboundReplayReservation:
    return next(
        item
        for item in acceptance.replay_reservations
        if item.kind is InboundReplayKind.SOURCE_EVENT_ID
    )


@pytest.mark.asyncio
async def test_state_source_repository_survives_recreation() -> None:
    store = MemoryStateStore()
    first = StateInboundSourceRepository(store)
    source = _source()
    await first.add(source)
    await first.close()

    second = StateInboundSourceRepository(store)

    assert await second.get(source.id) == source
    assert await second.get_by_name(" RELEASE.EVENTS ") == source
    assert (await second.snapshot()).sources == 1
    assert store.closed is False


@pytest.mark.asyncio
async def test_state_source_repository_rejects_duplicates_and_stale_revision() -> None:
    repository = StateInboundSourceRepository(MemoryStateStore())
    source = _source()
    await repository.add(source)

    with pytest.raises(InboundSourceAlreadyExistsError, match="name"):
        await repository.add(_source("RELEASE.EVENTS"))

    replacement = replace(
        source,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    with pytest.raises(InboundSourceConflictError, match="revision conflict"):
        await repository.replace(replacement, expected_revision=2)


@pytest.mark.asyncio
async def test_state_source_repository_replaces_name_and_index_atomically() -> None:
    store = MemoryStateStore()
    repository = StateInboundSourceRepository(store)
    source = _source()
    await repository.add(source)
    replacement = replace(
        source,
        name="deploy.events",
        display_name="Deploy Events",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    assert await repository.replace(replacement, expected_revision=1) == replacement
    assert await repository.get_by_name("release.events") is None
    assert await repository.get_by_name("deploy.events") == replacement

    restarted = StateInboundSourceRepository(store)
    assert await restarted.get(replacement.id) == replacement


@pytest.mark.asyncio
async def test_state_source_repository_detects_corrupt_record() -> None:
    store = MemoryStateStore()
    repository = StateInboundSourceRepository(store)
    source = _source()
    await repository.add(source)
    key = StateKey(
        "inbound-sources",
        f"source_record_{source.id.hex}",
        dict,
    )
    stored = await store.get(key)
    assert stored is not None
    await store.put(
        key,
        {"schema_version": 999},
        expected_version=stored.version,
    )

    with pytest.raises(InboundCorruptionError):
        await repository.get(source.id)


@pytest.mark.asyncio
async def test_state_source_repository_detects_missing_name_index() -> None:
    store = MemoryStateStore()
    repository = StateInboundSourceRepository(store)
    source = _source()
    await repository.add(source)
    index_key = StateKey(
        "inbound-sources",
        f"source_name_{source.name}",
        dict,
    )
    assert await store.delete(index_key)

    with pytest.raises(InboundCorruptionError, match="incomplete"):
        await repository.list()


@pytest.mark.asyncio
async def test_state_acceptance_is_atomic_and_survives_recreation() -> None:
    store = MemoryStateStore()
    events = StateInboundEventRepository(store)
    replay = StateInboundReplayRepository(store)
    acceptance = _acceptance(uuid4())

    await events.accept(acceptance)
    await events.close()
    await replay.close()

    restarted_events = StateInboundEventRepository(store)
    restarted_replay = StateInboundReplayRepository(store)
    assert await restarted_events.get(acceptance.event.id) == acceptance.event
    assert await restarted_events.get_receipt(acceptance.receipt.id) == acceptance.receipt
    source_reservation = _source_event_reservation(acceptance)
    assert (
        await restarted_events.get_by_source_event_digest(
            acceptance.event.source_id,
            source_reservation.evidence_digest,
        )
        == acceptance.event
    )
    assert (await restarted_replay.snapshot()).reservations == 3


@pytest.mark.asyncio
async def test_state_acceptance_rolls_back_when_replay_capacity_is_exhausted() -> None:
    store = MemoryStateStore()
    events = StateInboundEventRepository(store, replay_capacity=2)
    acceptance = _acceptance(uuid4())

    with pytest.raises(InboundReplayCapacityError):
        await events.accept(acceptance)

    records = await store.list(namespace="inbound-events")
    assert records == ()


@pytest.mark.asyncio
async def test_state_acceptance_rolls_back_on_duplicate_identity() -> None:
    store = MemoryStateStore()
    events = StateInboundEventRepository(store)
    first = _acceptance(uuid4())
    await events.accept(first)
    duplicate = _acceptance(
        first.event.source_id,
        source_event_id=first.event.source_event_id,
        request_id="request-2",
        nonce="nonce-2",
    )

    with pytest.raises(InboundEventAlreadyExistsError):
        await events.accept(duplicate)

    assert await events.get(duplicate.event.id) is None
    assert len(await store.list(namespace="inbound-events")) == 6


@pytest.mark.asyncio
async def test_state_event_repository_replaces_and_recovers_lifecycle() -> None:
    store = MemoryStateStore()
    repository = StateInboundEventRepository(store)
    acceptance = _acceptance(uuid4())
    await repository.accept(acceptance)
    publishing_at = _NOW + timedelta(seconds=1)
    publishing = replace(
        acceptance.event,
        status=InboundPublicationStatus.PUBLISHING,
        updated_at=publishing_at,
        current_attempt=1,
        publishing_at=publishing_at,
        next_attempt_at=None,
        revision=2,
    )

    assert await repository.replace(publishing, expected_revision=1) == publishing
    restarted = StateInboundEventRepository(store)
    assert await restarted.get(publishing.id) == publishing
    snapshot = await restarted.snapshot()
    assert snapshot.events == 1
    assert snapshot.publishing == 1


@pytest.mark.asyncio
async def test_state_event_repository_rejects_stale_revision() -> None:
    repository = StateInboundEventRepository(MemoryStateStore())
    acceptance = _acceptance(uuid4())
    await repository.accept(acceptance)
    discarded_at = _NOW + timedelta(seconds=1)
    discarded = replace(
        acceptance.event,
        status=InboundPublicationStatus.DISCARDED,
        updated_at=discarded_at,
        next_attempt_at=None,
        terminal_at=discarded_at,
        revision=2,
    )

    with pytest.raises(InboundEventConflictError, match="revision conflict"):
        await repository.replace(discarded, expected_revision=2)


@pytest.mark.asyncio
async def test_state_event_repository_detects_missing_receipt() -> None:
    store = MemoryStateStore()
    repository = StateInboundEventRepository(store)
    acceptance = _acceptance(uuid4())
    await repository.accept(acceptance)
    receipt_key = StateKey(
        "inbound-events",
        f"receipt_record_{acceptance.receipt.id.hex}",
        dict,
    )
    assert await store.delete(receipt_key)

    with pytest.raises(InboundCorruptionError, match="receipt is missing"):
        await repository.get(acceptance.event.id)


@pytest.mark.asyncio
async def test_state_event_repository_detects_corrupt_source_event_index() -> None:
    store = MemoryStateStore()
    repository = StateInboundEventRepository(store)
    acceptance = _acceptance(uuid4())
    await repository.accept(acceptance)
    reservation = _source_event_reservation(acceptance)
    index_key = StateKey(
        "inbound-events",
        (f"source_event_{acceptance.event.source_id.hex}_{reservation.evidence_digest}"),
        dict,
    )
    stored = await store.get(index_key)
    assert stored is not None
    document = dict(stored.value)
    document["event_record_digest"] = "0" * 64
    await store.put(index_key, document, expected_version=stored.version)

    with pytest.raises(InboundCorruptionError, match="event digest"):
        await repository.get(acceptance.event.id)


@pytest.mark.asyncio
async def test_state_replay_repository_prunes_expired_without_deleting_event() -> None:
    store = MemoryStateStore()
    events = StateInboundEventRepository(store)
    replay = StateInboundReplayRepository(store)
    acceptance = _acceptance(
        uuid4(),
        expires_at=_NOW + timedelta(seconds=1),
    )
    await events.accept(acceptance)

    assert await replay.prune_expired(now=_NOW) == 0
    assert await replay.prune_expired(now=_NOW + timedelta(seconds=1)) == 3
    assert (await replay.snapshot()).reservations == 0
    assert await events.get(acceptance.event.id) == acceptance.event


@pytest.mark.asyncio
async def test_state_repositories_close_without_closing_borrowed_store() -> None:
    store = MemoryStateStore()
    source_repository = StateInboundSourceRepository(store)
    event_repository = StateInboundEventRepository(store)
    replay_repository = StateInboundReplayRepository(store)
    source = _source()
    acceptance = _acceptance(source.id)
    await source_repository.add(source)
    await event_repository.accept(acceptance)

    await source_repository.close()
    await event_repository.close()
    await replay_repository.close()

    assert (await source_repository.snapshot()).closed is True
    assert (await event_repository.snapshot()).closed is True
    assert (await replay_repository.snapshot()).closed is True
    assert store.closed is False
    with pytest.raises(InboundSourceRepositoryClosedError):
        await source_repository.get(source.id)
    with pytest.raises(InboundEventRepositoryClosedError):
        await event_repository.get(acceptance.event.id)


@pytest.mark.asyncio
async def test_memory_and_state_repositories_have_equivalent_safe_results() -> None:
    source = _source()
    acceptance = _acceptance(source.id)
    memory = create_in_memory_inbound_repositories()
    store = MemoryStateStore()
    state_sources = StateInboundSourceRepository(store)
    state_events = StateInboundEventRepository(store)
    state_replay = StateInboundReplayRepository(store)

    await memory.sources.add(source)
    await memory.events.accept(acceptance)
    await state_sources.add(source)
    await state_events.accept(acceptance)

    assert await memory.sources.list() == await state_sources.list()
    assert await memory.events.list() == await state_events.list()
    assert await memory.replay.list() == await state_replay.list()
    assert await memory.sources.snapshot() == await state_sources.snapshot()
    assert await memory.events.snapshot() == await state_events.snapshot()
    assert await memory.replay.snapshot() == await state_replay.snapshot()
