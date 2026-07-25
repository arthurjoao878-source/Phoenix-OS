from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.inbound_events import (
    InboundAdmissionResult,
    InboundEventSource,
    InboundHmacPolicy,
    InboundIdempotencyConflictError,
    InboundReplayCapacityError,
    InboundReplayIdempotencyService,
    InboundReplayRejectedError,
    InboundRequestEvidence,
    StateInboundEventRepository,
    StateInboundReplayRepository,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
)
from phoenix_os.secrets import SecretRef
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")


def _source(*, replay_retention: timedelta = timedelta(hours=1)) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        replay_retention=replay_retention,
    )


def _payload(release: str = "0.25.0") -> dict[str, object]:
    return {"release": release, "status": "completed"}


def _evidence(
    *,
    request_id: str = "request-000000000001",
    nonce: str = "nonce-000000000001",
    source_event_id: str = "release-000000000001",
    timestamp: datetime = _NOW,
) -> InboundRequestEvidence:
    body = b'{"event":"release.completed"}'
    return InboundRequestEvidence(
        source_id=_SOURCE_ID,
        request_id=request_id,
        source_event_id=source_event_id,
        nonce=nonce,
        timestamp=timestamp,
        body_sha256=hashlib.sha256(body).hexdigest(),
        correlation_id="inbound-correlation",
    )


async def _admit(
    service: InboundReplayIdempotencyService,
    source: InboundEventSource,
    evidence: InboundRequestEvidence,
    *,
    payload: dict[str, object] | None = None,
) -> InboundAdmissionResult:
    return await service.admit(
        source,
        evidence,
        external_event_type="release.completed",
        external_schema_version=1,
        internal_event_type="external.release.completed",
        occurred_at=evidence.timestamp - timedelta(seconds=1),
        normalized_payload=_payload() if payload is None else payload,
    )


@pytest.mark.asyncio
async def test_first_use_creates_event_and_fresh_repeat_returns_stable_receipt() -> None:
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()

    first = await _admit(service, source, _evidence())
    repeat = await _admit(
        service,
        source,
        _evidence(
            request_id="request-000000000002",
            nonce="nonce-000000000002",
        ),
    )

    assert first.idempotent is False
    assert repeat.idempotent is True
    assert repeat.receipt == first.receipt
    assert repeat.accepted_event_id == first.accepted_event_id
    assert (await repositories.events.snapshot()).events == 1
    assert (await repositories.replay.snapshot()).reservations == 5


@pytest.mark.asyncio
async def test_reused_request_id_is_rejected_even_when_content_matches() -> None:
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()
    await _admit(service, source, _evidence())

    with pytest.raises(
        InboundReplayRejectedError,
        match="inbound request replay rejected",
    ):
        await _admit(
            service,
            source,
            _evidence(nonce="nonce-000000000002"),
        )


@pytest.mark.asyncio
async def test_reused_nonce_is_rejected_even_when_content_matches() -> None:
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()
    await _admit(service, source, _evidence())

    with pytest.raises(
        InboundReplayRejectedError,
        match="inbound request replay rejected",
    ):
        await _admit(
            service,
            source,
            _evidence(request_id="request-000000000002"),
        )


@pytest.mark.asyncio
async def test_source_event_digest_conflict_is_generic() -> None:
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()
    await _admit(service, source, _evidence())

    with pytest.raises(
        InboundIdempotencyConflictError,
        match="inbound source-event content conflicts",
    ):
        await _admit(
            service,
            source,
            _evidence(
                request_id="request-000000000002",
                nonce="nonce-000000000002",
            ),
            payload=_payload("0.25.1"),
        )


@pytest.mark.asyncio
async def test_state_replay_and_idempotent_receipt_survive_restart() -> None:
    store = MemoryStateStore()
    first_events = StateInboundEventRepository(store)
    first_replay = StateInboundReplayRepository(store)
    first_service = InboundReplayIdempotencyService(
        first_events,
        first_replay,
        clock=lambda: _NOW,
    )
    source = _source()
    first = await _admit(first_service, source, _evidence())
    await first_events.close()
    await first_replay.close()

    second_events = StateInboundEventRepository(store)
    second_replay = StateInboundReplayRepository(store)
    second_service = InboundReplayIdempotencyService(
        second_events,
        second_replay,
        clock=lambda: _NOW,
    )
    repeat_evidence = _evidence(
        request_id="request-000000000002",
        nonce="nonce-000000000002",
    )
    repeat = await _admit(second_service, source, repeat_evidence)
    assert repeat.idempotent is True
    assert repeat.receipt == first.receipt
    await second_events.close()
    await second_replay.close()

    third_service = InboundReplayIdempotencyService(
        StateInboundEventRepository(store),
        StateInboundReplayRepository(store),
        clock=lambda: _NOW,
    )
    with pytest.raises(InboundReplayRejectedError):
        await _admit(third_service, source, repeat_evidence)


@pytest.mark.asyncio
async def test_concurrent_source_event_admission_returns_one_stable_receipt() -> None:
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()
    requests = (
        _evidence(),
        _evidence(
            request_id="request-000000000002",
            nonce="nonce-000000000002",
        ),
    )

    results = await asyncio.gather(*(_admit(service, source, evidence) for evidence in requests))

    assert sorted(result.idempotent for result in results) == [False, True]
    assert results[0].receipt == results[1].receipt
    assert (await repositories.events.snapshot()).events == 1
    assert (await repositories.replay.snapshot()).reservations == 5


@pytest.mark.asyncio
async def test_idempotent_replay_reservation_is_atomic_at_capacity() -> None:
    repositories = create_in_memory_inbound_repositories(replay_capacity=3)
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()
    first = await _admit(service, source, _evidence())

    with pytest.raises(InboundReplayCapacityError):
        await _admit(
            service,
            source,
            _evidence(
                request_id="request-000000000002",
                nonce="nonce-000000000002",
            ),
        )

    assert (await repositories.replay.snapshot()).reservations == 3
    assert await repositories.events.get_receipt(first.receipt.id) == first.receipt


@pytest.mark.asyncio
async def test_expired_request_and_nonce_can_be_reused_with_stable_event() -> None:
    now = [_NOW]
    source = _source(replay_retention=timedelta(minutes=5))
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: now[0],
    )
    evidence = _evidence()
    first = await _admit(service, source, evidence)

    now[0] = _NOW + timedelta(minutes=6)
    repeat = await _admit(
        service,
        source,
        _evidence(timestamp=now[0]),
    )

    assert repeat.idempotent is True
    assert repeat.receipt == first.receipt
    assert (await repositories.replay.snapshot()).reservations == 2


@pytest.mark.asyncio
async def test_replay_and_conflict_failures_expose_only_generic_messages() -> None:
    repositories = create_in_memory_inbound_repositories()
    service = InboundReplayIdempotencyService(
        repositories.events,
        repositories.replay,
        clock=lambda: _NOW,
    )
    source = _source()
    await _admit(service, source, _evidence())

    messages: set[str] = set()
    with pytest.raises(InboundReplayRejectedError) as replay:
        await _admit(
            service,
            source,
            _evidence(nonce="nonce-000000000002"),
        )
    messages.add(str(replay.value))

    with pytest.raises(InboundIdempotencyConflictError) as conflict:
        await _admit(
            service,
            source,
            _evidence(
                request_id="request-000000000002",
                nonce="nonce-000000000002",
            ),
            payload=_payload("private-release-name"),
        )
    messages.add(str(conflict.value))

    assert messages == {
        "inbound request replay rejected",
        "inbound source-event content conflicts",
    }
    assert "request-000000000001" not in " ".join(messages)
    assert "nonce-000000000001" not in " ".join(messages)
    assert canonical_inbound_json_bytes(_payload()).decode() not in " ".join(messages)
