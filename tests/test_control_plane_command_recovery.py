from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane import (
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalStatus,
    ControlPlaneCommandRecoveryBatch,
    ControlPlaneCommandRecoveryDecision,
    ControlPlaneCommandRecoveryDisposition,
    ControlPlaneCommandRecoveryJobSource,
    ControlPlaneCommandRecoveryProbe,
    ControlPlaneCommandRecoveryService,
    ControlPlaneCommandRecoveryWorker,
    ControlPlaneCommandRecoveryWorkerSnapshot,
    ControlPlaneCommandRecoveryWorkerState,
    ControlPlaneCommandRecoveryWorkerStateError,
    ControlPlaneCommandRecoveryWorkflowSource,
    ControlPlaneCommandSideEffectProbe,
    IdempotencyKey,
    InMemoryControlPlaneCommandJournalRepository,
)
from phoenix_os.jobs import JobRecord, JobStatus
from phoenix_os.workflows import WorkflowRecord, WorkflowStatus

_NOW = datetime(2026, 7, 19, 5, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(seconds=1)


def _intent(
    action: ControlPlaneCommandAction,
    target: str,
    *,
    key: str,
    command_id: UUID | None = None,
) -> ControlPlaneCommandIntent:
    return ControlPlaneCommandIntent(
        id=uuid4() if command_id is None else command_id,
        action=action,
        target=target,
        idempotency_key=IdempotencyKey(key),
        payload_digest="a" * 64,
        requested_at=_NOW,
    )


def _record(
    action: ControlPlaneCommandAction,
    target: str,
    *,
    key: str = "recovery-key-0001",
    command_id: UUID | None = None,
    status: ControlPlaneCommandJournalStatus = ControlPlaneCommandJournalStatus.EXECUTING,
) -> ControlPlaneCommandJournalRecord:
    intent = _intent(action, target, key=key, command_id=command_id)
    return ControlPlaneCommandJournalRecord(
        command_id=intent.id,
        action=intent.action,
        target=intent.target,
        principal="admin",
        idempotency_digest=intent.idempotency_key.digest.hex(),
        fingerprint=intent.fingerprint,
        status=status,
        requested_at=_NOW,
        updated_at=_NOW,
        completed_at=_NOW if status.terminal else None,
        result_code="command.done" if status.terminal else None,
    )


@dataclass(frozen=True)
class _JobState:
    status: JobStatus


class _JobSource:
    def __init__(self, records: dict[UUID, JobStatus] | None = None, *, fail: bool = False) -> None:
        self.records = {} if records is None else records
        self.fail = fail

    async def get(self, job_id: UUID) -> JobRecord | None:
        if self.fail:
            raise RuntimeError("private source failure")
        status = self.records.get(job_id)
        return None if status is None else cast(JobRecord, _JobState(status))


@dataclass(frozen=True)
class _WorkflowState:
    status: WorkflowStatus


class _WorkflowSource:
    def __init__(
        self,
        records: dict[UUID, WorkflowStatus] | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self.records = {} if records is None else records
        self.fail = fail

    async def get(self, workflow_id: UUID) -> WorkflowRecord | None:
        if self.fail:
            raise RuntimeError("private source failure")
        status = self.records.get(workflow_id)
        return None if status is None else cast(WorkflowRecord, _WorkflowState(status))


class _StaticProbe:
    def __init__(self, decisions: dict[UUID, ControlPlaneCommandRecoveryDecision]) -> None:
        self.decisions = decisions

    async def probe(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandRecoveryDecision:
        return self.decisions[record.command_id]


class _FailingProbe:
    async def probe(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandRecoveryDecision:
        del record
        raise RuntimeError("private probe failure")


@pytest.mark.parametrize(
    "disposition, result_code, message",
    [
        (ControlPlaneCommandRecoveryDisposition.DEFERRED, "job.created", "cannot contain"),
        (ControlPlaneCommandRecoveryDisposition.SUCCEEDED, None, "requires"),
        (ControlPlaneCommandRecoveryDisposition.FAILED, None, "requires"),
        (ControlPlaneCommandRecoveryDisposition.SUCCEEDED, "Bad Code", "requires"),
    ],
)
def test_recovery_decision_rejects_invalid_state(
    disposition: ControlPlaneCommandRecoveryDisposition,
    result_code: str | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneCommandRecoveryDecision(disposition, result_code)


def test_recovery_decision_constructors_normalize_codes() -> None:
    assert ControlPlaneCommandRecoveryDecision.deferred().result_code is None
    assert (
        ControlPlaneCommandRecoveryDecision.succeeded(" Job.Created ").result_code == "job.created"
    )
    assert ControlPlaneCommandRecoveryDecision.failed("Job.Failed").result_code == "job.failed"


@pytest.mark.asyncio
async def test_side_effect_probe_recovers_created_job_by_command_id() -> None:
    command_id = uuid4()
    record = _record(
        ControlPlaneCommandAction.CREATE_JOB,
        "capability:demo.echo",
        command_id=command_id,
    )
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(
            ControlPlaneCommandRecoveryJobSource, _JobSource({command_id: JobStatus.SCHEDULED})
        )
    )

    decision = await probe.probe(record)

    assert decision == ControlPlaneCommandRecoveryDecision.succeeded("job.created")


@pytest.mark.asyncio
async def test_side_effect_probe_defers_missing_created_job() -> None:
    record = _record(ControlPlaneCommandAction.CREATE_JOB, "capability:demo.echo")
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(ControlPlaneCommandRecoveryJobSource, _JobSource())
    )

    assert await probe.probe(record) == ControlPlaneCommandRecoveryDecision.deferred()


@pytest.mark.asyncio
async def test_side_effect_probe_recovers_dead_letter_retry() -> None:
    command_id = uuid4()
    record = _record(
        ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB,
        f"job:{uuid4()}",
        command_id=command_id,
    )
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(
            ControlPlaneCommandRecoveryJobSource, _JobSource({command_id: JobStatus.SCHEDULED})
        )
    )

    assert await probe.probe(record) == ControlPlaneCommandRecoveryDecision.succeeded("job.retried")


@pytest.mark.parametrize(
    "status, expected",
    [
        (JobStatus.CANCELLED, ControlPlaneCommandRecoveryDecision.succeeded("job.cancelled")),
        (JobStatus.SUCCEEDED, ControlPlaneCommandRecoveryDecision.failed("job.not-cancellable")),
        (JobStatus.DEAD_LETTER, ControlPlaneCommandRecoveryDecision.failed("job.not-cancellable")),
        (JobStatus.SCHEDULED, ControlPlaneCommandRecoveryDecision.deferred()),
    ],
)
@pytest.mark.asyncio
async def test_side_effect_probe_reconciles_job_cancel_status(
    status: JobStatus,
    expected: ControlPlaneCommandRecoveryDecision,
) -> None:
    job_id = uuid4()
    record = _record(ControlPlaneCommandAction.CANCEL_JOB, f"job:{job_id}")
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(ControlPlaneCommandRecoveryJobSource, _JobSource({job_id: status}))
    )

    assert await probe.probe(record) == expected


@pytest.mark.asyncio
async def test_side_effect_probe_reports_missing_cancelled_job() -> None:
    record = _record(ControlPlaneCommandAction.CANCEL_JOB, f"job:{uuid4()}")
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(ControlPlaneCommandRecoveryJobSource, _JobSource())
    )

    assert await probe.probe(record) == ControlPlaneCommandRecoveryDecision.failed("job.not-found")


@pytest.mark.asyncio
async def test_side_effect_probe_rejects_invalid_job_target() -> None:
    record = _record(ControlPlaneCommandAction.CANCEL_JOB, "job:not-a-uuid")
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(ControlPlaneCommandRecoveryJobSource, _JobSource())
    )

    assert await probe.probe(record) == ControlPlaneCommandRecoveryDecision.failed(
        "command.recovery-invalid-target"
    )


@pytest.mark.asyncio
async def test_side_effect_probe_defers_private_source_failures() -> None:
    record = _record(ControlPlaneCommandAction.CANCEL_JOB, f"job:{uuid4()}")
    probe = ControlPlaneCommandSideEffectProbe(
        jobs=cast(ControlPlaneCommandRecoveryJobSource, _JobSource(fail=True))
    )

    assert await probe.probe(record) == ControlPlaneCommandRecoveryDecision.deferred()


@pytest.mark.parametrize(
    "status, expected",
    [
        (
            WorkflowStatus.CANCELLED,
            ControlPlaneCommandRecoveryDecision.succeeded("workflow.cancelled"),
        ),
        (
            WorkflowStatus.SUCCEEDED,
            ControlPlaneCommandRecoveryDecision.failed("workflow.not-cancellable"),
        ),
        (
            WorkflowStatus.FAILED,
            ControlPlaneCommandRecoveryDecision.failed("workflow.not-cancellable"),
        ),
        (WorkflowStatus.RUNNING, ControlPlaneCommandRecoveryDecision.deferred()),
    ],
)
@pytest.mark.asyncio
async def test_side_effect_probe_reconciles_workflow_cancel_status(
    status: WorkflowStatus,
    expected: ControlPlaneCommandRecoveryDecision,
) -> None:
    workflow_id = uuid4()
    record = _record(ControlPlaneCommandAction.CANCEL_WORKFLOW, f"workflow:{workflow_id}")
    probe = ControlPlaneCommandSideEffectProbe(
        workflows=cast(
            ControlPlaneCommandRecoveryWorkflowSource,
            _WorkflowSource({workflow_id: status}),
        )
    )

    assert await probe.probe(record) == expected


@pytest.mark.asyncio
async def test_side_effect_probe_reports_missing_workflow() -> None:
    record = _record(ControlPlaneCommandAction.CANCEL_WORKFLOW, f"workflow:{uuid4()}")
    probe = ControlPlaneCommandSideEffectProbe(
        workflows=cast(ControlPlaneCommandRecoveryWorkflowSource, _WorkflowSource())
    )

    assert await probe.probe(record) == ControlPlaneCommandRecoveryDecision.failed(
        "workflow.not-found"
    )


@pytest.mark.asyncio
async def test_side_effect_probe_rejects_terminal_record() -> None:
    record = _record(
        ControlPlaneCommandAction.CREATE_JOB,
        "capability:demo.echo",
        status=ControlPlaneCommandJournalStatus.SUCCEEDED,
    )

    with pytest.raises(ValueError, match="do not require"):
        await ControlPlaneCommandSideEffectProbe().probe(record)


@pytest.mark.asyncio
async def test_recovery_service_transitions_succeeded_decision() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(ControlPlaneCommandAction.CREATE_JOB, "capability:demo.echo")
    await repository.add(record)
    service = ControlPlaneCommandRecoveryService(
        repository,
        cast(
            ControlPlaneCommandRecoveryProbe,
            _StaticProbe(
                {record.command_id: ControlPlaneCommandRecoveryDecision.succeeded("job.created")}
            ),
        ),
    )

    batch = await service.recover(now=_LATER)

    assert batch.recovered == 1
    assert batch.records[0].status is ControlPlaneCommandJournalStatus.SUCCEEDED
    assert batch.records[0].result_code == "job.created"


@pytest.mark.asyncio
async def test_recovery_service_transitions_failed_decision() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(ControlPlaneCommandAction.CANCEL_JOB, f"job:{uuid4()}")
    await repository.add(record)
    service = ControlPlaneCommandRecoveryService(
        repository,
        cast(
            ControlPlaneCommandRecoveryProbe,
            _StaticProbe(
                {record.command_id: ControlPlaneCommandRecoveryDecision.failed("job.not-found")}
            ),
        ),
    )

    batch = await service.recover(now=_LATER)

    assert batch.recovered == 1
    assert batch.records[0].status is ControlPlaneCommandJournalStatus.FAILED


@pytest.mark.asyncio
async def test_recovery_service_keeps_deferred_record_non_terminal() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(ControlPlaneCommandAction.CREATE_JOB, "capability:demo.echo")
    await repository.add(record)
    service = ControlPlaneCommandRecoveryService(
        repository,
        cast(
            ControlPlaneCommandRecoveryProbe,
            _StaticProbe({record.command_id: ControlPlaneCommandRecoveryDecision.deferred()}),
        ),
    )

    batch = await service.recover(now=_LATER)

    assert batch.deferred == 1
    assert batch.recovered == 0
    assert await repository.get(record.command_id) == record


@pytest.mark.asyncio
async def test_recovery_service_skips_terminal_records() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(
        ControlPlaneCommandAction.CREATE_JOB,
        "capability:demo.echo",
        status=ControlPlaneCommandJournalStatus.SUCCEEDED,
    )
    await repository.add(record)
    service = ControlPlaneCommandRecoveryService(
        repository,
        cast(ControlPlaneCommandRecoveryProbe, _FailingProbe()),
    )

    batch = await service.recover(now=_LATER)

    assert batch.scanned == 1
    assert batch.eligible == 0
    assert batch.failures == 0


@pytest.mark.parametrize("limit", [0, -1, 201])
@pytest.mark.asyncio
async def test_recovery_service_rejects_invalid_limit(limit: int) -> None:
    service = ControlPlaneCommandRecoveryService(
        InMemoryControlPlaneCommandJournalRepository(),
        cast(ControlPlaneCommandRecoveryProbe, _FailingProbe()),
    )

    with pytest.raises(ValueError, match="between 1 and 200"):
        await service.recover(limit=limit)


@pytest.mark.asyncio
async def test_recovery_service_counts_probe_failures_without_leaking_text() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(ControlPlaneCommandAction.CREATE_JOB, "capability:demo.echo")
    await repository.add(record)
    service = ControlPlaneCommandRecoveryService(
        repository,
        cast(ControlPlaneCommandRecoveryProbe, _FailingProbe()),
    )

    batch = await service.recover(now=_LATER)

    assert batch.failures == 1
    assert batch.records == ()


@pytest.mark.parametrize(
    "batch",
    [
        ControlPlaneCommandRecoveryBatch(0, 0, 0, 0, 0, 0),
        ControlPlaneCommandRecoveryBatch(2, 1, 0, 1, 0, 0),
    ],
)
def test_recovery_batch_accepts_consistent_counters(
    batch: ControlPlaneCommandRecoveryBatch,
) -> None:
    assert batch.scanned >= batch.eligible


@pytest.mark.parametrize(
    "values, message",
    [
        ((-1, 0, 0, 0, 0, 0), "negative"),
        ((0, 1, 0, 1, 0, 0), "cannot exceed"),
        ((1, 1, 0, 0, 0, 0), "must equal"),
    ],
)
def test_recovery_batch_rejects_inconsistent_counters(
    values: tuple[int, int, int, int, int, int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneCommandRecoveryBatch(*values)


@pytest.mark.parametrize(
    "case, message",
    [
        ("poll", "positive"),
        ("zero-batch", "between"),
        ("large-batch", "between"),
        ("worker", "must not be blank"),
    ],
)
def test_recovery_worker_rejects_invalid_configuration(case: str, message: str) -> None:
    service = ControlPlaneCommandRecoveryService(
        InMemoryControlPlaneCommandJournalRepository(),
        cast(ControlPlaneCommandRecoveryProbe, _FailingProbe()),
    )

    with pytest.raises(ValueError, match=message):
        if case == "poll":
            ControlPlaneCommandRecoveryWorker(service, poll_interval=0.0)
        elif case == "zero-batch":
            ControlPlaneCommandRecoveryWorker(service, batch_size=0)
        elif case == "large-batch":
            ControlPlaneCommandRecoveryWorker(service, batch_size=201)
        else:
            ControlPlaneCommandRecoveryWorker(service, worker="   ")


@pytest.mark.asyncio
async def test_recovery_worker_rejects_tick_before_start() -> None:
    service = ControlPlaneCommandRecoveryService(
        InMemoryControlPlaneCommandJournalRepository(),
        cast(ControlPlaneCommandRecoveryProbe, _FailingProbe()),
    )
    worker = ControlPlaneCommandRecoveryWorker(service)

    with pytest.raises(ControlPlaneCommandRecoveryWorkerStateError):
        await worker.run_once(now=_LATER)


@pytest.mark.asyncio
async def test_recovery_worker_is_runtime_lifecycle_compatible() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record(ControlPlaneCommandAction.CREATE_JOB, "capability:demo.echo")
    await repository.add(record)
    service = ControlPlaneCommandRecoveryService(
        repository,
        cast(
            ControlPlaneCommandRecoveryProbe,
            _StaticProbe({record.command_id: ControlPlaneCommandRecoveryDecision.deferred()}),
        ),
    )
    worker = ControlPlaneCommandRecoveryWorker(service, poll_interval=60.0, batch_size=10)

    await worker.start(object())
    await asyncio.sleep(0)
    snapshot = await worker.snapshot()
    await worker.stop(object())
    stopped = await worker.snapshot()

    assert snapshot.state is ControlPlaneCommandRecoveryWorkerState.RUNNING
    assert snapshot.ticks >= 1
    assert snapshot.scanned >= 1
    assert stopped.state is ControlPlaneCommandRecoveryWorkerState.STOPPED
    assert repository.closed is False


def test_recovery_worker_snapshot_normalizes_fields() -> None:
    snapshot = ControlPlaneCommandRecoveryWorkerSnapshot(
        state=ControlPlaneCommandRecoveryWorkerState.RUNNING,
        worker=" worker ",
        ticks=1,
        scanned=2,
        recovered=1,
        deferred=1,
        conflicts=0,
        failures=0,
        last_tick_at=_NOW,
        last_error=" ",
    )

    assert snapshot.worker == "worker"
    assert snapshot.last_error is None
