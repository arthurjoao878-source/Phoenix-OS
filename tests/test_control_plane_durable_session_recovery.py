from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRecoveryBatch,
    ControlPlaneDurableSessionRecoveryService,
    ControlPlaneDurableSessionRecoveryWorker,
    ControlPlaneDurableSessionRecoveryWorkerState,
    ControlPlaneDurableSessionRecoveryWorkerStateError,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
    InMemoryControlPlaneDurableSessionRepository,
    InMemoryControlPlaneOperatorRegistry,
)

NOW = datetime(2026, 7, 19, 20, 0, tzinfo=UTC)
POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=2),
    idle_ttl=timedelta(minutes=20),
    rotation_interval=timedelta(minutes=10),
)


def _operator(
    value: int = 1,
    *,
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    token_version: int = 1,
    revision: int = 1,
) -> ControlPlaneOperatorRecord:
    updated = NOW + timedelta(seconds=max(0, revision - 1))
    return ControlPlaneOperatorRecord(
        id=UUID(int=value),
        username=f"operator.{value}",
        display_name=f"Operator {value}",
        role=ControlPlaneOperatorRole.OPERATOR,
        token_digest=ControlPlaneOperatorToken(f"operator-{value:039d}").digest,
        created_at=NOW,
        updated_at=updated,
        status=status,
        disabled_at=updated if status is ControlPlaneOperatorStatus.DISABLED else None,
        revoked_at=updated if status is ControlPlaneOperatorStatus.REVOKED else None,
        token_version=token_version,
        revision=revision,
    )


def _session(
    value: int,
    operator: ControlPlaneOperatorRecord,
    *,
    issued_at: datetime = NOW,
) -> ControlPlaneDurableSessionRecord:
    return ControlPlaneDurableSessionRecord.issue(
        session_id=UUID(int=10_000 + value),
        operator_id=operator.id,
        username=operator.username,
        token=ControlPlaneDurableSessionToken(f"session-{value:040d}"),
        csrf_secret=ControlPlaneDurableCsrfSecret(f"csrf-{value:043d}"),
        operator_revision=operator.revision,
        operator_token_version=operator.token_version,
        issued_at=issued_at,
        policy=POLICY,
    )


async def _setup(
    records: tuple[tuple[ControlPlaneOperatorRecord | None, ControlPlaneDurableSessionRecord], ...],
) -> tuple[
    InMemoryControlPlaneDurableSessionRepository,
    InMemoryControlPlaneOperatorRegistry,
    ControlPlaneDurableSessionRecoveryService,
]:
    repository = InMemoryControlPlaneDurableSessionRepository()
    registry = InMemoryControlPlaneOperatorRegistry()
    added: set[UUID] = set()
    for operator, record in records:
        if operator is not None and operator.id not in added:
            await registry.add(operator)
            added.add(operator.id)
        await repository.add(record)
    service = ControlPlaneDurableSessionRecoveryService(
        repository=repository,
        registry=registry,
        clock=lambda: NOW,
    )
    return repository, registry, service


def test_recovery_batch_rejects_inconsistent_counters() -> None:
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRecoveryBatch(1, 0, 0, 0, 0, 0)
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRecoveryBatch(-1, 0, 0, 0, 0, 0)


@pytest.mark.asyncio
async def test_recovery_empty_repository_is_safe() -> None:
    _, _, service = await _setup(())
    assert await service.recover() == ControlPlaneDurableSessionRecoveryBatch(0, 0, 0, 0, 0, 0)


@pytest.mark.asyncio
async def test_recovery_leaves_healthy_active_session_unchanged() -> None:
    operator = _operator()
    record = _session(1, operator)
    repository, _, service = await _setup(((operator, record),))

    batch = await service.recover(now=NOW + timedelta(minutes=5))

    assert batch.scanned == 1
    assert batch.healthy == 1
    assert batch.eligible == 0
    assert await repository.get(record.id) == record


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("elapsed", "reason"),
    [
        (POLICY.idle_ttl, ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT),
        (POLICY.absolute_ttl, ControlPlaneDurableSessionTerminationReason.ABSOLUTE_TIMEOUT),
    ],
)
async def test_recovery_expires_overdue_sessions(
    elapsed: timedelta,
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    operator = _operator()
    record = _session(1, operator)
    repository, _, service = await _setup(((operator, record),))

    batch = await service.recover(now=NOW + elapsed)

    assert batch.recovered == 1
    assert batch.records[0].status is ControlPlaneDurableSessionStatus.EXPIRED
    assert batch.records[0].termination_reason is reason
    persisted = await repository.get(record.id)
    assert persisted == batch.records[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operator", "reason"),
    [
        (None, ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE),
        (
            _operator(status=ControlPlaneOperatorStatus.DISABLED),
            ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE,
        ),
        (
            _operator(status=ControlPlaneOperatorStatus.REVOKED),
            ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE,
        ),
        (
            _operator(token_version=2, revision=2),
            ControlPlaneDurableSessionTerminationReason.CREDENTIAL_ROTATED,
        ),
        (
            _operator(revision=2),
            ControlPlaneDurableSessionTerminationReason.PERMISSIONS_CHANGED,
        ),
    ],
)
async def test_recovery_invalidates_stale_operator_bindings(
    operator: ControlPlaneOperatorRecord | None,
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    original = _operator()
    record = _session(1, original)
    repository, _, service = await _setup(((operator, record),))

    batch = await service.recover(now=NOW + timedelta(minutes=1))

    assert batch.recovered == 1
    recovered = batch.records[0]
    assert recovered.status is ControlPlaneDurableSessionStatus.REVOKED
    assert recovered.termination_reason is reason
    assert await repository.get(record.id) == recovered


@pytest.mark.asyncio
async def test_recovery_is_bounded_by_requested_page() -> None:
    records: list[tuple[ControlPlaneOperatorRecord, ControlPlaneDurableSessionRecord]] = []
    for value in range(1, 6):
        operator = _operator(value)
        records.append(
            (operator, _session(value, operator, issued_at=NOW + timedelta(seconds=value)))
        )
    repository, _, service = await _setup(tuple(records))

    batch = await service.recover(limit=2, now=NOW + POLICY.absolute_ttl + timedelta(minutes=1))

    assert batch.scanned == 2
    assert batch.recovered == 2
    snapshot = await repository.snapshot()
    assert snapshot.expired == 2
    assert snapshot.active == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, -1, 201])
async def test_recovery_rejects_invalid_limit(limit: int) -> None:
    _, _, service = await _setup(())
    with pytest.raises(ValueError):
        await service.recover(limit=limit)


@pytest.mark.asyncio
async def test_recovery_rejects_naive_time() -> None:
    _, _, service = await _setup(())
    with pytest.raises(ValueError):
        await service.recover(now=datetime(2026, 7, 19, 20, 0))


class _ConflictRepository(InMemoryControlPlaneDurableSessionRepository):
    async def terminate(self, *args: Any, **kwargs: Any) -> ControlPlaneDurableSessionRecord:
        raise ControlPlaneDurableSessionConflictError("conflict")


class _FailureRegistry(InMemoryControlPlaneOperatorRegistry):
    async def get(self, operator_id: UUID) -> ControlPlaneOperatorRecord | None:
        del operator_id
        raise RuntimeError("private registry failure")


@pytest.mark.asyncio
async def test_recovery_counts_conflicts_without_raising() -> None:
    operator = _operator()
    record = _session(1, operator)
    repository = _ConflictRepository()
    await repository.add(record)
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(operator)
    service = ControlPlaneDurableSessionRecoveryService(
        repository=repository,
        registry=registry,
    )

    batch = await service.recover(now=NOW + POLICY.absolute_ttl)

    assert batch.eligible == 1
    assert batch.conflicts == 1
    assert batch.failures == 0
    assert batch.records == ()


@pytest.mark.asyncio
async def test_recovery_counts_failures_without_exception_text() -> None:
    operator = _operator()
    record = _session(1, operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(record)
    service = ControlPlaneDurableSessionRecoveryService(
        repository=repository,
        registry=_FailureRegistry(),
    )

    batch = await service.recover(now=NOW + timedelta(minutes=1))

    assert batch.eligible == 1
    assert batch.failures == 1
    assert "private" not in repr(batch)


def test_recovery_worker_rejects_invalid_configuration() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    registry = InMemoryControlPlaneOperatorRegistry()
    service = ControlPlaneDurableSessionRecoveryService(
        repository=repository,
        registry=registry,
    )
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRecoveryWorker(service, poll_interval=0)
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRecoveryWorker(service, batch_size=0)
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRecoveryWorker(service, batch_size=201)
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRecoveryWorker(service, worker=" ")


@pytest.mark.asyncio
async def test_recovery_worker_runs_bounded_tick_and_reports_snapshot() -> None:
    operator = _operator()
    record = _session(1, operator)
    _, _, service = await _setup(((operator, record),))
    worker = ControlPlaneDurableSessionRecoveryWorker(
        service,
        poll_interval=60,
        batch_size=5,
        clock=lambda: NOW + POLICY.absolute_ttl,
    )
    await worker.start(object())

    batch = await worker.run_once(now=NOW + POLICY.absolute_ttl)
    snapshot = await worker.snapshot()
    await worker.stop(object())

    assert batch.recovered == 1
    assert snapshot.state is ControlPlaneDurableSessionRecoveryWorkerState.RUNNING
    assert snapshot.ticks >= 1
    assert snapshot.recovered >= 1
    stopped = await worker.snapshot()
    assert stopped.state is ControlPlaneDurableSessionRecoveryWorkerState.STOPPED


@pytest.mark.asyncio
async def test_recovery_worker_lifecycle_is_strict_and_stop_is_idempotent() -> None:
    _, _, service = await _setup(())
    worker = ControlPlaneDurableSessionRecoveryWorker(service, poll_interval=60)
    with pytest.raises(ControlPlaneDurableSessionRecoveryWorkerStateError):
        await worker.run_once()
    await worker.start(object())
    with pytest.raises(ControlPlaneDurableSessionRecoveryWorkerStateError):
        await worker.start(object())
    await worker.stop(object())
    await worker.stop(object())
    with pytest.raises(ControlPlaneDurableSessionRecoveryWorkerStateError):
        await worker.run_once()


@pytest.mark.asyncio
async def test_recovery_worker_records_typed_error_only() -> None:
    operator = _operator()
    record = _session(1, operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(record)
    service = ControlPlaneDurableSessionRecoveryService(
        repository=repository,
        registry=_FailureRegistry(),
    )
    worker = ControlPlaneDurableSessionRecoveryWorker(service, poll_interval=60)
    await worker.start(object())

    await worker.run_once(now=NOW + timedelta(minutes=1))
    snapshot = await worker.snapshot()
    await worker.stop(object())

    assert snapshot.failures >= 1
    assert snapshot.last_error is None
    assert "private registry failure" not in repr(snapshot)


@pytest.mark.asyncio
async def test_recovery_worker_handles_service_level_failure() -> None:
    class _BrokenService(ControlPlaneDurableSessionRecoveryService):
        async def recover(self, **kwargs: Any) -> ControlPlaneDurableSessionRecoveryBatch:
            del kwargs
            raise RuntimeError("sensitive failure")

    service = _BrokenService(
        repository=InMemoryControlPlaneDurableSessionRepository(),
        registry=InMemoryControlPlaneOperatorRegistry(),
    )
    worker = ControlPlaneDurableSessionRecoveryWorker(service, poll_interval=60)
    await worker.start(object())

    batch = await worker.run_once(now=NOW)
    snapshot = await worker.snapshot()
    await worker.stop(object())

    assert batch.scanned == 0
    assert snapshot.last_error == "RuntimeError"
    assert "sensitive failure" not in repr(snapshot)


@pytest.mark.asyncio
async def test_worker_background_loop_stops_cleanly() -> None:
    _, _, service = await _setup(())
    worker = ControlPlaneDurableSessionRecoveryWorker(service, poll_interval=0.01)
    await worker.start(object())
    await asyncio.sleep(0.03)
    await worker.stop(object())
    snapshot = await worker.snapshot()
    assert snapshot.state is ControlPlaneDurableSessionRecoveryWorkerState.STOPPED
    assert snapshot.ticks >= 1
