from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneCommandAction,
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandJournalNotFoundError,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalStatus,
    ControlPlaneCommandRetentionCandidate,
    ControlPlaneCommandRetentionPlan,
    ControlPlaneCommandRetentionPolicy,
    ControlPlaneCommandRetentionResult,
    ControlPlaneCommandRetentionService,
    InMemoryControlPlaneCommandJournalRepository,
    StateControlPlaneCommandJournalRepository,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 7, 19, 7, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _record(
    index: int,
    *,
    status: ControlPlaneCommandJournalStatus = ControlPlaneCommandJournalStatus.SUCCEEDED,
    age_days: int = 0,
    revision: int = 2,
) -> ControlPlaneCommandJournalRecord:
    requested_at = _NOW - timedelta(days=age_days, minutes=index)
    terminal = status.terminal
    updated_at = requested_at + timedelta(seconds=1)
    return ControlPlaneCommandJournalRecord(
        command_id=UUID(int=index),
        action=ControlPlaneCommandAction.CREATE_JOB,
        target=f"job:retention-{index}",
        principal="dashboard.operator",
        idempotency_digest=_digest(f"key-{index}"),
        fingerprint=_digest(f"fingerprint-{index}"),
        status=status,
        requested_at=requested_at,
        updated_at=updated_at,
        completed_at=updated_at if terminal else None,
        result_code="job.created" if terminal else None,
        revision=revision,
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_age": None, "max_terminal_entries": None}, "requires"),
        ({"max_age": timedelta(0)}, "max_age"),
        ({"max_age": timedelta(seconds=-1)}, "max_age"),
        ({"max_terminal_entries": -1}, "entries"),
        ({"batch_size": 0}, "batch_size"),
        ({"batch_size": 201}, "batch_size"),
        ({"max_scan": 0}, "max_scan"),
        ({"max_scan": 100_001}, "max_scan"),
    ],
)
def test_retention_policy_rejects_invalid_bounds(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneCommandRetentionPolicy(**kwargs)  # type: ignore[arg-type]


def test_retention_policy_accepts_age_only_and_count_only() -> None:
    assert ControlPlaneCommandRetentionPolicy(max_terminal_entries=None).max_age is not None
    assert ControlPlaneCommandRetentionPolicy(max_age=None, max_terminal_entries=0).max_age is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("expected_revision", 0, "revision"),
        ("completed_at", datetime(2026, 1, 1), "completed_at"),
        ("status", ControlPlaneCommandJournalStatus.PENDING, "terminal"),
    ],
)
def test_retention_candidate_rejects_invalid_values(
    field: str,
    value: object,
    message: str,
) -> None:
    candidate = ControlPlaneCommandRetentionCandidate(
        UUID(int=1),
        2,
        _NOW,
        ControlPlaneCommandJournalStatus.SUCCEEDED,
    )

    with pytest.raises(ValueError, match=message):
        replace(candidate, **{field: value})  # type: ignore[arg-type]


def test_retention_plan_rejects_duplicate_candidates_and_bad_counters() -> None:
    candidate = ControlPlaneCommandRetentionCandidate(
        UUID(int=1),
        2,
        _NOW,
        ControlPlaneCommandJournalStatus.SUCCEEDED,
    )
    with pytest.raises(ValueError, match="unique"):
        ControlPlaneCommandRetentionPlan(_NOW, 2, 2, (candidate, candidate))
    with pytest.raises(ValueError, match="counters"):
        ControlPlaneCommandRetentionPlan(_NOW, 1, 2, ())


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"planned": -1}, "negative"),
        ({"planned": 2, "deleted": 1}, "equal"),
        ({"completed_at": datetime(2026, 1, 1)}, "timezone"),
        ({"schema_version": 2}, "schema"),
    ],
)
def test_retention_result_validates_outcomes(kwargs: dict[str, object], message: str) -> None:
    values: dict[str, object] = {
        "planned": 1,
        "deleted": 1,
        "conflicts": 0,
        "failures": 0,
        "completed_at": _NOW,
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=message):
        ControlPlaneCommandRetentionResult(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_retention_plan_selects_expired_terminal_records_only() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record(1, age_days=40))
    await repository.add(_record(2, age_days=10))
    await repository.add(
        _record(3, status=ControlPlaneCommandJournalStatus.EXECUTING, age_days=50, revision=1)
    )
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)

    plan = await service.plan(
        ControlPlaneCommandRetentionPolicy(max_age=timedelta(days=30), max_terminal_entries=None)
    )

    assert plan.scanned == 3
    assert plan.terminal == 2
    assert tuple(item.command_id for item in plan.candidates) == (UUID(int=1),)


@pytest.mark.asyncio
async def test_retention_plan_enforces_terminal_count_oldest_first() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    for index in range(1, 6):
        await repository.add(_record(index, age_days=index))
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)

    plan = await service.plan(
        ControlPlaneCommandRetentionPolicy(
            max_age=None,
            max_terminal_entries=2,
            batch_size=10,
        )
    )

    assert tuple(item.command_id for item in plan.candidates) == (
        UUID(int=5),
        UUID(int=4),
        UUID(int=3),
    )


@pytest.mark.asyncio
async def test_retention_plan_unions_age_and_count_and_applies_batch_limit() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    for index in range(1, 7):
        await repository.add(_record(index, age_days=index * 10))
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)

    plan = await service.plan(
        ControlPlaneCommandRetentionPolicy(
            max_age=timedelta(days=25),
            max_terminal_entries=4,
            batch_size=2,
        )
    )

    assert len(plan.candidates) == 2
    assert tuple(item.command_id for item in plan.candidates) == (UUID(int=6), UUID(int=5))


@pytest.mark.asyncio
async def test_retention_scan_is_bounded() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    for index in range(1, 6):
        await repository.add(_record(index, age_days=60))
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)

    plan = await service.plan(
        ControlPlaneCommandRetentionPolicy(
            max_age=timedelta(days=30),
            max_terminal_entries=None,
            max_scan=3,
        )
    )

    assert plan.scanned == 3
    assert len(plan.candidates) == 3


@pytest.mark.asyncio
async def test_memory_repository_delete_terminal_removes_record_and_digest_index() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(1)
    await repository.add(record)

    await repository.delete_terminal(record.command_id, expected_revision=record.revision)

    assert await repository.get(record.command_id) is None
    assert await repository.get_by_idempotency_digest(record.idempotency_digest) is None
    assert (await repository.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_memory_repository_delete_terminal_rejects_nonterminal_stale_and_missing() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    pending = _record(1, status=ControlPlaneCommandJournalStatus.PENDING, revision=1)
    terminal = _record(2)
    await repository.add(pending)
    await repository.add(terminal)

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="non-terminal"):
        await repository.delete_terminal(pending.command_id, expected_revision=1)
    with pytest.raises(ControlPlaneCommandJournalConflictError, match="revision"):
        await repository.delete_terminal(terminal.command_id, expected_revision=1)
    with pytest.raises(ControlPlaneCommandJournalNotFoundError):
        await repository.delete_terminal(UUID(int=999), expected_revision=1)


@pytest.mark.asyncio
async def test_state_repository_delete_terminal_is_atomic_and_persists_removal() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record(1)
    await repository.add(record)

    await repository.delete_terminal(record.command_id, expected_revision=record.revision)
    reopened = StateControlPlaneCommandJournalRepository(store)

    assert await reopened.get(record.command_id) is None
    assert await reopened.get_by_idempotency_digest(record.idempotency_digest) is None
    assert (await reopened.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_state_repository_delete_terminal_rejects_nonterminal_without_partial_delete() -> (
    None
):
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    pending = _record(1, status=ControlPlaneCommandJournalStatus.PENDING, revision=1)
    await repository.add(pending)

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="non-terminal"):
        await repository.delete_terminal(pending.command_id, expected_revision=1)

    assert await repository.get(pending.command_id) == pending
    assert await repository.get_by_idempotency_digest(pending.idempotency_digest) == pending


@pytest.mark.asyncio
async def test_retention_apply_deletes_candidates_and_emits_safe_audit_fact() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    first = _record(1, age_days=40)
    second = _record(2, age_days=35)
    await repository.add(first)
    await repository.add(second)
    events = EventBus()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    service = ControlPlaneCommandRetentionService(repository, events=events, clock=lambda: _NOW)

    result = await service.run(
        ControlPlaneCommandRetentionPolicy(
            max_age=timedelta(days=30),
            max_terminal_entries=None,
        )
    )

    assert result == ControlPlaneCommandRetentionResult(2, 2, 0, 0, _NOW)
    assert (await repository.snapshot()).entries == 0
    event = captured[-1]
    assert event.name == "control-plane.command.journal.retention-completed"
    assert event.payload["deleted"] == 2
    assert "command_id" not in event.payload
    assert "digest" not in repr(event.payload)
    assert "fingerprint" not in repr(event.payload)


class _ConflictRepository(InMemoryControlPlaneCommandJournalRepository):
    async def delete_terminal(self, command_id: UUID, *, expected_revision: int) -> None:
        del command_id, expected_revision
        raise ControlPlaneCommandJournalConflictError("conflict")


@pytest.mark.asyncio
async def test_retention_apply_counts_concurrent_conflicts() -> None:
    repository = _ConflictRepository()
    record = _record(1)
    await repository.add(record)
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)
    plan = ControlPlaneCommandRetentionPlan(
        _NOW,
        1,
        1,
        (
            ControlPlaneCommandRetentionCandidate(
                record.command_id,
                record.revision,
                record.completed_at or record.updated_at,
                record.status,
            ),
        ),
    )

    result = await service.apply(plan)

    assert result == ControlPlaneCommandRetentionResult(1, 0, 1, 0, _NOW)


@pytest.mark.asyncio
async def test_retention_with_no_candidates_is_a_valid_noop() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record(1, age_days=1))
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)

    result = await service.run(
        ControlPlaneCommandRetentionPolicy(
            max_age=timedelta(days=30),
            max_terminal_entries=None,
        )
    )

    assert result == ControlPlaneCommandRetentionResult(0, 0, 0, 0, _NOW)
    assert (await repository.snapshot()).entries == 1
