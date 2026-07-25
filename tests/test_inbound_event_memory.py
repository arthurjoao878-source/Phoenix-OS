from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.inbound_events import (
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventAlreadyExistsError,
    InboundEventCapacityError,
    InboundEventConflictError,
    InboundEventReceipt,
    InboundEventRepositoryClosedError,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundPublicationStatus,
    InboundReplayAlreadyExistsError,
    InboundReplayCapacityError,
    InboundReplayKind,
    InboundReplayRepositoryClosedError,
    InboundReplayReservation,
    InboundSourceAlreadyExistsError,
    InboundSourceCapacityError,
    InboundSourceConflictError,
    InboundSourceRepositoryClosedError,
    InMemoryInboundEventRepository,
    InMemoryInboundReplayRepository,
    InMemoryInboundSourceRepository,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
    inbound_evidence_digest,
)
from phoenix_os.secrets import SecretRef

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


@pytest.mark.asyncio
async def test_source_repository_adds_reads_lists_and_snapshots() -> None:
    repository = InMemoryInboundSourceRepository(capacity=4)
    release = _source("release.events")
    backup = _source("backup.events")

    await repository.add(release)
    await repository.add(backup)

    assert await repository.get(release.id) == release
    assert await repository.get_by_name(" RELEASE.EVENTS ") == release
    page = await repository.list()
    assert tuple(item.name for item in page.items) == (
        "backup.events",
        "release.events",
    )
    snapshot = await repository.snapshot()
    assert snapshot.sources == 2
    assert snapshot.active == 2
    assert snapshot.capacity == 4


@pytest.mark.asyncio
async def test_source_repository_rejects_duplicate_identity_and_capacity() -> None:
    repository = InMemoryInboundSourceRepository(capacity=1)
    source_id = uuid4()
    await repository.add(_source("release.events", source_id=source_id))

    with pytest.raises(InboundSourceAlreadyExistsError, match="id"):
        await repository.add(_source("backup.events", source_id=source_id))

    with pytest.raises(InboundSourceAlreadyExistsError, match="name"):
        await repository.add(_source("RELEASE.EVENTS"))

    with pytest.raises(InboundSourceCapacityError):
        await repository.add(_source("backup.events"))


@pytest.mark.asyncio
async def test_source_repository_replaces_and_renames_atomically() -> None:
    repository = InMemoryInboundSourceRepository()
    source = _source()
    await repository.add(source)
    updated_at = _NOW + timedelta(seconds=1)
    replacement = replace(
        source,
        name="deploy.events",
        display_name="Deploy Events",
        updated_at=updated_at,
        revision=2,
    )

    assert await repository.replace(replacement, expected_revision=1) == replacement
    assert await repository.get_by_name("release.events") is None
    assert await repository.get_by_name("deploy.events") == replacement


@pytest.mark.asyncio
async def test_source_repository_rejects_stale_and_revoked_replacement() -> None:
    repository = InMemoryInboundSourceRepository()
    source = _source()
    await repository.add(source)
    replacement = replace(
        source,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(InboundSourceConflictError, match="revision conflict"):
        await repository.replace(replacement, expected_revision=2)

    revoked_at = _NOW + timedelta(seconds=1)
    revoked = replace(
        source,
        status=InboundEventSourceStatus.REVOKED,
        updated_at=revoked_at,
        revoked_at=revoked_at,
        revision=2,
    )
    assert await repository.replace(revoked, expected_revision=1) == revoked

    with pytest.raises(InboundSourceConflictError, match="terminal"):
        await repository.replace(
            replace(
                revoked,
                updated_at=revoked_at + timedelta(seconds=1),
                revision=3,
            ),
            expected_revision=2,
        )


@pytest.mark.asyncio
async def test_memory_acceptance_persists_event_receipt_and_three_reservations() -> None:
    repositories = create_in_memory_inbound_repositories()
    source = _source()
    acceptance = _acceptance(source.id)
    await repositories.sources.add(source)

    await repositories.events.accept(acceptance)

    assert await repositories.events.get(acceptance.event.id) == acceptance.event
    assert await repositories.events.get_receipt(acceptance.receipt.id) == acceptance.receipt
    source_reservation = next(
        item
        for item in acceptance.replay_reservations
        if item.kind is InboundReplayKind.SOURCE_EVENT_ID
    )
    assert (
        await repositories.events.get_by_source_event_digest(
            source.id,
            source_reservation.evidence_digest,
        )
        == acceptance.event
    )
    replay_snapshot = await repositories.replay.snapshot()
    assert replay_snapshot.reservations == 3
    assert replay_snapshot.request_ids == 1
    assert replay_snapshot.nonces == 1
    assert replay_snapshot.source_events == 1


@pytest.mark.asyncio
async def test_memory_acceptance_rolls_back_when_replay_capacity_is_exhausted() -> None:
    replay = InMemoryInboundReplayRepository(capacity=2)
    events = InMemoryInboundEventRepository(
        replay_repository=replay,
        replay_capacity=2,
    )
    acceptance = _acceptance(uuid4())

    with pytest.raises(InboundReplayCapacityError):
        await events.accept(acceptance)

    assert await events.get(acceptance.event.id) is None
    assert await events.get_receipt(acceptance.receipt.id) is None
    assert (await replay.snapshot()).reservations == 0


@pytest.mark.asyncio
async def test_memory_acceptance_rolls_back_on_duplicate_replay_evidence() -> None:
    repositories = create_in_memory_inbound_repositories()
    source_id = uuid4()
    first = _acceptance(source_id)
    await repositories.events.accept(first)
    second = _acceptance(
        source_id,
        source_event_id="release-2",
        request_id="request-1",
        nonce="nonce-2",
    )

    with pytest.raises(InboundReplayAlreadyExistsError, match="request_id"):
        await repositories.events.accept(second)

    assert await repositories.events.get(second.event.id) is None
    assert await repositories.events.get_receipt(second.receipt.id) is None
    assert (await repositories.events.snapshot()).events == 1


@pytest.mark.asyncio
async def test_memory_acceptance_rejects_duplicate_source_event_identity() -> None:
    repositories = create_in_memory_inbound_repositories()
    source_id = uuid4()
    first = _acceptance(source_id)
    await repositories.events.accept(first)
    duplicate = _acceptance(
        source_id,
        source_event_id=first.event.source_event_id,
        request_id="request-2",
        nonce="nonce-2",
    )

    with pytest.raises(InboundEventAlreadyExistsError, match="source-event"):
        await repositories.events.accept(duplicate)


@pytest.mark.asyncio
async def test_memory_event_repository_enforces_capacity_atomically() -> None:
    replay = InMemoryInboundReplayRepository(capacity=12)
    events = InMemoryInboundEventRepository(
        capacity=1,
        replay_capacity=12,
        replay_repository=replay,
    )
    first = _acceptance(uuid4())
    second = _acceptance(uuid4(), request_id="request-2", nonce="nonce-2")
    await events.accept(first)

    with pytest.raises(InboundEventCapacityError):
        await events.accept(second)

    assert await events.get(second.event.id) is None
    assert (await replay.snapshot()).reservations == 3


@pytest.mark.asyncio
async def test_memory_event_repository_replaces_valid_lifecycle_state() -> None:
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(uuid4())
    await repositories.events.accept(acceptance)
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

    assert await repositories.events.replace(publishing, expected_revision=1) == publishing
    snapshot = await repositories.events.snapshot()
    assert snapshot.events == 1
    assert snapshot.publishing == 1


@pytest.mark.asyncio
async def test_memory_event_repository_rejects_stale_or_illegal_transition() -> None:
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(uuid4())
    await repositories.events.accept(acceptance)
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
        await repositories.events.replace(discarded, expected_revision=2)

    with pytest.raises(ValueError, match="requires an attempt"):
        replace(
            acceptance.event,
            status=InboundPublicationStatus.PUBLISHED,
            updated_at=discarded_at,
            next_attempt_at=None,
            terminal_at=discarded_at,
            revision=2,
        )


@pytest.mark.asyncio
async def test_memory_replay_repository_prunes_expired_reservations() -> None:
    repositories = create_in_memory_inbound_repositories()
    acceptance = _acceptance(
        uuid4(),
        expires_at=_NOW + timedelta(seconds=1),
    )
    await repositories.events.accept(acceptance)

    assert await repositories.replay.prune_expired(now=_NOW) == 0
    assert await repositories.replay.prune_expired(now=_NOW + timedelta(seconds=1)) == 3
    assert (await repositories.replay.snapshot()).reservations == 0
    assert await repositories.events.get(acceptance.event.id) == acceptance.event


@pytest.mark.asyncio
async def test_memory_repositories_close_without_destroying_safe_snapshots() -> None:
    repositories = create_in_memory_inbound_repositories()
    source = _source()
    acceptance = _acceptance(source.id)
    await repositories.sources.add(source)
    await repositories.events.accept(acceptance)

    await repositories.close()
    await repositories.close()

    assert (await repositories.sources.snapshot()).closed is True
    assert (await repositories.events.snapshot()).closed is True
    assert (await repositories.replay.snapshot()).closed is True
    with pytest.raises(InboundSourceRepositoryClosedError):
        await repositories.sources.get(source.id)
    with pytest.raises(InboundEventRepositoryClosedError):
        await repositories.events.get(acceptance.event.id)
    with pytest.raises(InboundReplayRepositoryClosedError):
        await repositories.replay.list()
