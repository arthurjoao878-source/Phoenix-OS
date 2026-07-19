from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneCommandAction,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalStatus,
    ControlPlaneCommandRetentionPolicy,
    ControlPlaneCommandRetentionService,
    ControlPlaneCommandRetentionWorker,
    ControlPlaneCommandRetentionWorkerSnapshot,
    ControlPlaneCommandRetentionWorkerState,
    ControlPlaneCommandRetentionWorkerStateError,
    InMemoryControlPlaneCommandJournalRepository,
)

_NOW = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)


def _record(index: int, *, age_days: int = 40) -> ControlPlaneCommandJournalRecord:
    requested_at = _NOW - timedelta(days=age_days, minutes=index)
    completed_at = requested_at + timedelta(seconds=1)
    return ControlPlaneCommandJournalRecord(
        command_id=UUID(int=index),
        action=ControlPlaneCommandAction.CREATE_JOB,
        target=f"job:{index}",
        principal="dashboard.operator",
        idempotency_digest=hashlib.sha256(f"key-{index}".encode()).hexdigest(),
        fingerprint=hashlib.sha256(f"fingerprint-{index}".encode()).hexdigest(),
        status=ControlPlaneCommandJournalStatus.SUCCEEDED,
        requested_at=requested_at,
        updated_at=completed_at,
        completed_at=completed_at,
        result_code="job.created",
        revision=2,
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"poll_interval": 0.0}, "poll_interval"),
        ({"worker": " "}, "worker"),
        ({"clock": None}, "clock"),
    ],
)
def test_retention_worker_rejects_invalid_configuration(
    kwargs: dict[str, object],
    message: str,
) -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    service = ControlPlaneCommandRetentionService(repository)
    policy = ControlPlaneCommandRetentionPolicy()

    with pytest.raises((TypeError, ValueError), match=message):
        ControlPlaneCommandRetentionWorker(service, policy, **kwargs)  # type: ignore[arg-type]


def test_retention_worker_snapshot_validates_fields() -> None:
    with pytest.raises(ValueError, match="negative"):
        ControlPlaneCommandRetentionWorkerSnapshot(
            ControlPlaneCommandRetentionWorkerState.RUNNING,
            "worker",
            -1,
            0,
            0,
            0,
            0,
        )
    with pytest.raises(ValueError, match="timezone"):
        ControlPlaneCommandRetentionWorkerSnapshot(
            ControlPlaneCommandRetentionWorkerState.RUNNING,
            "worker",
            0,
            0,
            0,
            0,
            0,
            last_tick_at=datetime(2026, 1, 1),
        )


@pytest.mark.asyncio
async def test_retention_worker_run_once_applies_policy_and_updates_snapshot() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record(1))
    service = ControlPlaneCommandRetentionService(repository, clock=lambda: _NOW)
    worker = ControlPlaneCommandRetentionWorker(
        service,
        ControlPlaneCommandRetentionPolicy(
            max_age=timedelta(days=30),
            max_terminal_entries=None,
        ),
        poll_interval=3600,
        clock=lambda: _NOW,
    )
    await worker.start(object())

    result = await worker.run_once(now=_NOW)
    snapshot = await worker.snapshot()

    assert result.deleted == 1
    assert snapshot.state is ControlPlaneCommandRetentionWorkerState.RUNNING
    assert snapshot.ticks >= 1
    assert snapshot.deleted >= 1
    assert await repository.get(UUID(int=1)) is None
    await worker.stop(object())


@pytest.mark.asyncio
async def test_retention_worker_rejects_run_before_start() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    worker = ControlPlaneCommandRetentionWorker(
        ControlPlaneCommandRetentionService(repository),
        ControlPlaneCommandRetentionPolicy(),
    )

    with pytest.raises(ControlPlaneCommandRetentionWorkerStateError, match="created"):
        await worker.run_once(now=_NOW)


@pytest.mark.asyncio
async def test_retention_worker_rejects_second_start() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    worker = ControlPlaneCommandRetentionWorker(
        ControlPlaneCommandRetentionService(repository),
        ControlPlaneCommandRetentionPolicy(),
        poll_interval=3600,
    )
    await worker.start(object())

    with pytest.raises(ControlPlaneCommandRetentionWorkerStateError, match="running"):
        await worker.start(object())

    await worker.stop(object())


@pytest.mark.asyncio
async def test_retention_worker_can_stop_before_start() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    worker = ControlPlaneCommandRetentionWorker(
        ControlPlaneCommandRetentionService(repository),
        ControlPlaneCommandRetentionPolicy(),
    )

    await worker.stop(object())

    assert (await worker.snapshot()).state is ControlPlaneCommandRetentionWorkerState.STOPPED
