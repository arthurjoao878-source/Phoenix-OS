from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.durable_session_retention import (
    ControlPlaneDurableSessionRetentionPolicy,
    ControlPlaneDurableSessionRetentionService,
    ControlPlaneDurableSessionRetentionWorker,
    ControlPlaneDurableSessionRetentionWorkerState,
)
from phoenix_os.events import Event, EventBus

_BASE = datetime(2026, 7, 19, 12, tzinfo=UTC)
_POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=2),
    idle_ttl=timedelta(hours=1),
    rotation_interval=timedelta(minutes=30),
)


def _record(index: int) -> ControlPlaneDurableSessionRecord:
    return ControlPlaneDurableSessionRecord.issue(
        operator_id=uuid4(),
        username=f"operator-{index}",
        token=ControlPlaneDurableSessionToken(f"token-{index:026d}"),
        csrf_secret=ControlPlaneDurableCsrfSecret(f"csrf-{index:027d}"),
        operator_revision=1,
        operator_token_version=1,
        issued_at=_BASE + timedelta(minutes=index),
        policy=_POLICY,
    )


async def _terminal(
    repository: InMemoryControlPlaneDurableSessionRepository,
    index: int,
    *,
    terminated_at: datetime,
) -> ControlPlaneDurableSessionRecord:
    record = _record(index)
    await repository.add(record)
    return await repository.terminate(
        record.id,
        expected_revision=record.revision,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        terminated_at=terminated_at,
    )


def test_retention_policy_requires_at_least_one_bound() -> None:
    with pytest.raises(ValueError, match="requires"):
        ControlPlaneDurableSessionRetentionPolicy(max_age=None, max_terminal_entries=None)


@pytest.mark.asyncio
async def test_retention_never_selects_active_session() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    active = _record(1)
    await repository.add(active)
    service = ControlPlaneDurableSessionRetentionService(repository)

    plan = await service.plan(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(seconds=1),
            max_terminal_entries=0,
        ),
        now=_BASE + timedelta(days=30),
    )

    assert plan.scanned == 1
    assert plan.terminal == 0
    assert plan.candidates == ()
    assert await repository.get(active.id) == active


@pytest.mark.asyncio
async def test_retention_selects_old_terminal_records_oldest_first() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    first = await _terminal(repository, 1, terminated_at=_BASE + timedelta(hours=1))
    second = await _terminal(repository, 2, terminated_at=_BASE + timedelta(hours=2))
    await _terminal(repository, 3, terminated_at=_BASE + timedelta(days=9))
    service = ControlPlaneDurableSessionRetentionService(repository)

    plan = await service.plan(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(days=1),
            max_terminal_entries=None,
            batch_size=2,
        ),
        now=_BASE + timedelta(days=10),
    )

    assert [item.session_id for item in plan.candidates] == [first.id, second.id]


@pytest.mark.asyncio
async def test_retention_applies_revision_bound_deletion() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = await _terminal(repository, 1, terminated_at=_BASE + timedelta(hours=1))
    service = ControlPlaneDurableSessionRetentionService(repository)
    plan = await service.plan(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(days=1),
            max_terminal_entries=None,
        ),
        now=_BASE + timedelta(days=10),
    )

    result = await service.apply(plan, now=_BASE + timedelta(days=10))

    assert result.deleted == 1
    assert result.conflicts == 0
    assert await repository.get(record.id) is None


@pytest.mark.asyncio
async def test_retention_reports_stale_plan_as_conflict() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = await _terminal(repository, 1, terminated_at=_BASE + timedelta(hours=1))
    service = ControlPlaneDurableSessionRetentionService(repository)
    plan = await service.plan(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(days=1),
            max_terminal_entries=None,
        ),
        now=_BASE + timedelta(days=10),
    )
    await repository.delete_terminal(record.id, expected_revision=record.revision)

    result = await service.apply(plan, now=_BASE + timedelta(days=10))

    assert result.deleted == 0
    assert result.conflicts == 1


@pytest.mark.asyncio
async def test_retention_protects_rotation_lineage() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    predecessor = _record(1)
    await repository.add(predecessor)
    successor = ControlPlaneDurableSessionRecord.issue(
        operator_id=predecessor.operator_id,
        username=predecessor.username,
        token=ControlPlaneDurableSessionToken("successor-token-00000000000000001"),
        csrf_secret=ControlPlaneDurableCsrfSecret("successor-csrf-000000000000000002"),
        operator_revision=predecessor.operator_revision,
        operator_token_version=predecessor.operator_token_version,
        issued_at=_BASE + timedelta(minutes=40),
        policy=_POLICY,
        generation=2,
        predecessor_session_id=predecessor.id,
        absolute_expires_at=predecessor.absolute_expires_at,
    )
    rotation = await repository.rotate(
        predecessor.id,
        expected_revision=predecessor.revision,
        successor=successor,
        rotated_at=_BASE + timedelta(minutes=40),
    )
    service = ControlPlaneDurableSessionRetentionService(repository)

    plan = await service.plan(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(seconds=1),
            max_terminal_entries=0,
        ),
        now=_BASE + timedelta(days=10),
    )

    assert rotation.previous.status is ControlPlaneDurableSessionStatus.ROTATED
    assert plan.protected_lineage == 1
    assert plan.candidates == ()


@pytest.mark.asyncio
async def test_retention_count_bound_removes_oldest_overflow() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    records = [
        await _terminal(repository, index, terminated_at=_BASE + timedelta(hours=index))
        for index in range(1, 5)
    ]
    service = ControlPlaneDurableSessionRetentionService(repository)

    plan = await service.plan(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=None,
            max_terminal_entries=2,
            batch_size=10,
        ),
        now=_BASE + timedelta(days=1),
    )

    assert [item.session_id for item in plan.candidates] == [records[0].id, records[1].id]


@pytest.mark.asyncio
async def test_retention_emits_safe_event() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    await _terminal(repository, 1, terminated_at=_BASE + timedelta(hours=1))
    events = EventBus()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    service = ControlPlaneDurableSessionRetentionService(repository, events=events)

    await service.run(
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(days=1),
            max_terminal_entries=None,
        ),
        now=_BASE + timedelta(days=10),
    )

    event = captured[-1]
    assert event.name == "control-plane.operator.session.retention-completed"
    assert event.payload["deleted"] == 1
    assert "token" not in repr(event.payload).lower()
    assert "digest" not in repr(event.payload).lower()


@pytest.mark.asyncio
async def test_retention_worker_runs_once_and_stops() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    await _terminal(repository, 1, terminated_at=_BASE + timedelta(hours=1))
    worker = ControlPlaneDurableSessionRetentionWorker(
        ControlPlaneDurableSessionRetentionService(repository),
        ControlPlaneDurableSessionRetentionPolicy(
            max_age=timedelta(days=1),
            max_terminal_entries=None,
        ),
        poll_interval=3600,
        clock=lambda: _BASE + timedelta(days=10),
    )

    await worker.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await worker.stop()
    snapshot = await worker.snapshot()

    assert snapshot.ticks == 1
    assert snapshot.deleted == 1
    assert snapshot.state is ControlPlaneDurableSessionRetentionWorkerState.STOPPED
