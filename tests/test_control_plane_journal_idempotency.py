from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane import (
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneCommandJournalStatus,
    ControlPlaneCommandStateError,
    ControlPlaneCommandStatus,
    ControlPlaneIdempotencyCapacityError,
    ControlPlaneIdempotencyConflictError,
    ControlPlaneIdempotencyStoreClosedError,
    IdempotencyKey,
    InMemoryControlPlaneCommandJournalRepository,
    JournalControlPlaneIdempotencyStore,
    StateControlPlaneCommandJournalRepository,
)
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 7, 19, 4, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(seconds=1)
_KEY = "journal-key-0001"


def _intent(
    *,
    key: str = _KEY,
    payload_digest: str = "a" * 64,
    command_id: UUID | None = None,
    action: ControlPlaneCommandAction = ControlPlaneCommandAction.CREATE_JOB,
    target: str = "capability:demo.echo",
) -> ControlPlaneCommandIntent:
    return ControlPlaneCommandIntent(
        id=uuid4() if command_id is None else command_id,
        action=action,
        target=target,
        idempotency_key=IdempotencyKey(key),
        payload_digest=payload_digest,
        requested_at=_NOW,
    )


@pytest.mark.parametrize(
    "principal, message",
    [
        ("", "must not be blank"),
        ("   ", "must not be blank"),
        ("x" * 129, "too long"),
        ("admin\nroot", "control characters"),
    ],
)
def test_journal_idempotency_rejects_invalid_principal(principal: str, message: str) -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()

    with pytest.raises(ValueError, match=message):
        JournalControlPlaneIdempotencyStore(repository, principal=principal)


@pytest.mark.asyncio
async def test_journal_idempotency_reserves_executing_record() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="phoenix.dashboard")
    intent = _intent()

    reservation = await store.reserve(intent)
    record = await repository.get(intent.id)

    assert reservation.replayed is False
    assert reservation.receipt.status is ControlPlaneCommandStatus.PENDING
    assert record is not None
    assert record.status is ControlPlaneCommandJournalStatus.EXECUTING
    assert record.principal == "phoenix.dashboard"
    assert record.idempotency_digest == intent.idempotency_key.digest.hex()
    assert record.fingerprint == intent.fingerprint


@pytest.mark.asyncio
async def test_journal_idempotency_replays_original_command_identity() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    original = _intent()
    replay = _intent()

    first = await store.reserve(original)
    second = await store.reserve(replay)

    assert first.replayed is False
    assert second.replayed is True
    assert second.receipt.command_id == original.id


@pytest.mark.asyncio
async def test_journal_idempotency_rejects_key_reuse_for_different_fingerprint() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    await store.reserve(_intent())

    with pytest.raises(ControlPlaneIdempotencyConflictError):
        await store.reserve(_intent(payload_digest="b" * 64))


@pytest.mark.asyncio
async def test_journal_idempotency_rejects_command_id_collision() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    command_id = uuid4()
    await store.reserve(_intent(command_id=command_id))

    with pytest.raises(ControlPlaneIdempotencyConflictError):
        await store.reserve(_intent(key="journal-key-0002", command_id=command_id))


@pytest.mark.asyncio
async def test_journal_idempotency_completes_durably() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await store.reserve(intent)

    receipt = await store.complete(intent, result_code="job.created", completed_at=_LATER)
    record = await repository.get(intent.id)

    assert receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert receipt.result_code == "job.created"
    assert record is not None
    assert record.status is ControlPlaneCommandJournalStatus.SUCCEEDED
    assert record.completed_at == _LATER


@pytest.mark.asyncio
async def test_journal_idempotency_replays_identical_completion() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await store.reserve(intent)
    first = await store.complete(intent, result_code="job.created", completed_at=_LATER)

    second = await store.complete(intent, result_code="job.created", completed_at=_LATER)

    assert second == first


@pytest.mark.asyncio
async def test_journal_idempotency_persists_failed_receipt() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await store.reserve(intent)

    receipt = await store.fail(intent, result_code="job.create-failed", completed_at=_LATER)
    record = await repository.get(intent.id)

    assert receipt.status is ControlPlaneCommandStatus.FAILED
    assert record is not None
    assert record.status is ControlPlaneCommandJournalStatus.FAILED


@pytest.mark.asyncio
async def test_journal_idempotency_persists_rejected_receipt() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await store.reserve(intent)

    receipt = await store.reject(intent, result_code="command.denied", completed_at=_LATER)
    record = await repository.get(intent.id)

    assert receipt.status is ControlPlaneCommandStatus.FAILED
    assert record is not None
    assert record.status is ControlPlaneCommandJournalStatus.REJECTED


@pytest.mark.asyncio
async def test_journal_idempotency_rejects_terminal_replacement() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await store.reserve(intent)
    await store.complete(intent, result_code="job.created", completed_at=_LATER)

    with pytest.raises(ControlPlaneCommandStateError, match="cannot be replaced"):
        await store.fail(intent, result_code="job.create-failed", completed_at=_LATER)


@pytest.mark.asyncio
async def test_journal_idempotency_requires_reservation_before_completion() -> None:
    store = JournalControlPlaneIdempotencyStore(
        InMemoryControlPlaneCommandJournalRepository(),
        principal="admin",
    )

    with pytest.raises(ControlPlaneCommandStateError, match="reserved"):
        await store.complete(_intent(), result_code="job.created", completed_at=_LATER)


@pytest.mark.asyncio
async def test_journal_idempotency_get_returns_persisted_receipt() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()

    assert await store.get(IdempotencyKey(_KEY)) is None
    await store.reserve(intent)
    receipt = await store.get(IdempotencyKey(_KEY))

    assert receipt is not None
    assert receipt.command_id == intent.id


@pytest.mark.asyncio
async def test_journal_idempotency_snapshot_maps_journal_states() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository(capacity=10)
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    succeeded = _intent(key="journal-key-1001")
    failed = _intent(key="journal-key-1002")
    rejected = _intent(key="journal-key-1003")
    pending = _intent(key="journal-key-1004")
    for intent in (succeeded, failed, rejected, pending):
        await store.reserve(intent)
    await store.complete(succeeded, result_code="job.created", completed_at=_LATER)
    await store.fail(failed, result_code="job.failed", completed_at=_LATER)
    await store.reject(rejected, result_code="command.denied", completed_at=_LATER)

    snapshot = await store.snapshot()

    assert snapshot.entries == 4
    assert snapshot.pending == 1
    assert snapshot.succeeded == 1
    assert snapshot.failed == 2
    assert snapshot.capacity == 10


@pytest.mark.asyncio
async def test_journal_idempotency_close_borrows_repository_lifecycle() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await store.reserve(intent)

    await store.close()

    assert store.closed is True
    assert repository.closed is False
    assert await repository.get(intent.id) is not None


@pytest.mark.asyncio
async def test_journal_idempotency_rejects_operations_after_close() -> None:
    store = JournalControlPlaneIdempotencyStore(
        InMemoryControlPlaneCommandJournalRepository(),
        principal="admin",
    )
    await store.close()

    with pytest.raises(ControlPlaneIdempotencyStoreClosedError):
        await store.reserve(_intent())
    with pytest.raises(ControlPlaneIdempotencyStoreClosedError):
        await store.get(IdempotencyKey(_KEY))


@pytest.mark.asyncio
async def test_journal_idempotency_maps_repository_capacity() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository(capacity=1)
    store = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    await store.reserve(_intent())

    with pytest.raises(ControlPlaneIdempotencyCapacityError):
        await store.reserve(_intent(key="journal-key-0002"))


@pytest.mark.asyncio
async def test_journal_idempotency_survives_adapter_restart() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    first = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    intent = _intent()
    await first.reserve(intent)
    await first.complete(intent, result_code="job.created", completed_at=_LATER)
    await first.close()

    restarted = JournalControlPlaneIdempotencyStore(repository, principal="admin")
    replay = await restarted.reserve(_intent())

    assert replay.replayed is True
    assert replay.receipt.command_id == intent.id
    assert replay.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert replay.receipt.result_code == "job.created"


@pytest.mark.asyncio
async def test_journal_idempotency_replays_from_state_store_after_restart() -> None:
    state = MemoryStateStore()
    first_repository = StateControlPlaneCommandJournalRepository(state)
    first = JournalControlPlaneIdempotencyStore(first_repository, principal="admin")
    intent = _intent()
    await first.reserve(intent)
    await first.complete(intent, result_code="job.created", completed_at=_LATER)
    await first.close()
    await first_repository.close()

    restarted_repository = StateControlPlaneCommandJournalRepository(state)
    restarted = JournalControlPlaneIdempotencyStore(restarted_repository, principal="admin")
    replay = await restarted.reserve(_intent())

    assert replay.replayed is True
    assert replay.receipt.command_id == intent.id
    assert replay.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert replay.receipt.result_code == "job.created"
