from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.capabilities import CapabilityContext
from phoenix_os.control_plane import (
    ControlPlaneHealth,
    ControlPlaneService,
    ControlPlaneSnapshot,
    WorkflowSummary,
    snapshot_to_dict,
)
from phoenix_os.jobs import (
    JobSchedulerSnapshot,
    JobWorkerSnapshot,
    JobWorkerState,
    RetryPolicy,
)
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState
from phoenix_os.workflows import (
    WorkflowDefinition,
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepRecord,
    WorkflowStepStatus,
    WorkflowWorkerSnapshot,
    WorkflowWorkerState,
)

_NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
_RUNTIME_ID = UUID("10000000-0000-0000-0000-000000000001")


class _RuntimeSource:
    def __init__(self, state: RuntimeState = RuntimeState.RUNNING) -> None:
        self.state = state

    async def snapshot(self) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            runtime_id=_RUNTIME_ID,
            state=self.state,
            components=("jobs", "workflows"),
            active_components=("jobs", "workflows") if self.state is RuntimeState.RUNNING else (),
            in_flight_requests=0,
            created_at=_NOW,
            started_at=_NOW if self.state is RuntimeState.RUNNING else None,
            stopped_at=_NOW if self.state is RuntimeState.STOPPED else None,
        )


class _JobSource:
    def __init__(self, *, dead_letter: int = 0) -> None:
        self.dead_letter = dead_letter

    async def snapshot(self) -> JobSchedulerSnapshot:
        return JobSchedulerSnapshot(
            closed=False,
            jobs=self.dead_letter,
            scheduled=0,
            running=0,
            retrying=0,
            succeeded=0,
            cancelled=0,
            dead_letter=self.dead_letter,
            runs=self.dead_letter,
        )


class _WorkflowSource:
    def __init__(self, records: tuple[WorkflowRecord, ...] = ()) -> None:
        self.records = records

    async def list_all(self) -> tuple[WorkflowRecord, ...]:
        return self.records


class _JobWorkerSource:
    def __init__(self, failures: int = 0, last_error: str | None = None) -> None:
        self.failures = failures
        self.last_error = last_error

    async def snapshot(self) -> JobWorkerSnapshot:
        return JobWorkerSnapshot(
            state=JobWorkerState.RUNNING,
            worker="jobs",
            ticks=1,
            runs=1,
            failures=self.failures,
            last_tick_at=_NOW,
            last_error=self.last_error,
        )


class _WorkflowWorkerSource:
    async def snapshot(self) -> WorkflowWorkerSnapshot:
        return WorkflowWorkerSnapshot(
            state=WorkflowWorkerState.RUNNING,
            worker="workflows",
            ticks=1,
            workflows=1,
            failures=0,
            last_tick_at=_NOW,
        )


def _workflow(status: WorkflowStatus, *, secret_output: bool = False) -> WorkflowRecord:
    definition = WorkflowDefinition(
        name="release",
        steps=(
            WorkflowStep(
                id="publish",
                capability="release.publish",
                arguments={"token": "secret-value"},
                context=CapabilityContext(),
                retry=RetryPolicy(),
                metadata={"owner": "platform"},
            ),
        ),
    )
    if status is WorkflowStatus.PENDING:
        step = WorkflowStepRecord("publish", WorkflowStepStatus.READY)
        return WorkflowRecord(
            definition=definition,
            status=status,
            created_at=_NOW,
            updated_at=_NOW,
            steps={"publish": step},
        )
    if status is WorkflowStatus.RUNNING:
        step = WorkflowStepRecord(
            "publish",
            WorkflowStepStatus.RUNNING,
            job_id=UUID("20000000-0000-0000-0000-000000000001"),
            started_at=_NOW,
        )
        return WorkflowRecord(
            definition=definition,
            status=status,
            created_at=_NOW,
            updated_at=_NOW,
            steps={"publish": step},
        )
    if status is WorkflowStatus.SUCCEEDED:
        step = WorkflowStepRecord(
            "publish",
            WorkflowStepStatus.SUCCEEDED,
            job_id=UUID("20000000-0000-0000-0000-000000000001"),
            started_at=_NOW,
            finished_at=_NOW,
            output={"secret": "hidden"} if secret_output else {},
        )
        return WorkflowRecord(
            definition=definition,
            status=status,
            created_at=_NOW,
            updated_at=_NOW,
            steps={"publish": step},
            finished_at=_NOW,
        )
    if status is WorkflowStatus.FAILED:
        step = WorkflowStepRecord(
            "publish",
            WorkflowStepStatus.FAILED,
            job_id=UUID("20000000-0000-0000-0000-000000000001"),
            started_at=_NOW,
            finished_at=_NOW,
            error="ProviderError",
        )
        return WorkflowRecord(
            definition=definition,
            status=status,
            created_at=_NOW,
            updated_at=_NOW,
            steps={"publish": step},
            finished_at=_NOW,
            error="ProviderError",
        )
    step = WorkflowStepRecord(
        "publish",
        WorkflowStepStatus.CANCELLED,
        finished_at=_NOW,
    )
    return WorkflowRecord(
        definition=definition,
        status=WorkflowStatus.CANCELLED,
        created_at=_NOW,
        updated_at=_NOW,
        steps={"publish": step},
        finished_at=_NOW,
    )


def test_workflow_summary_rejects_negative_counts() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        WorkflowSummary(-1, 0, 0, 0, 0, 0)


def test_workflow_summary_requires_state_total() -> None:
    with pytest.raises(ValueError, match="must equal total"):
        WorkflowSummary(2, 1, 0, 0, 0, 0)


def test_control_plane_snapshot_requires_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ControlPlaneSnapshot(
            generated_at=datetime(2026, 7, 18, 12, 0),
            health=ControlPlaneHealth.HEALTHY,
            runtime=RuntimeSnapshot(
                runtime_id=_RUNTIME_ID,
                state=RuntimeState.RUNNING,
                components=(),
                active_components=(),
                in_flight_requests=0,
                created_at=_NOW,
                started_at=_NOW,
                stopped_at=None,
            ),
            jobs=JobSchedulerSnapshot(False, 0, 0, 0, 0, 0, 0, 0, 0),
            workflows=WorkflowSummary(0, 0, 0, 0, 0, 0),
        )


@pytest.mark.asyncio
async def test_service_returns_healthy_snapshot_for_clean_running_runtime() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(),
        job_worker=_JobWorkerSource(),
        workflow_worker=_WorkflowWorkerSource(),
        clock=lambda: _NOW,
    )

    snapshot = await service.snapshot()

    assert snapshot.health is ControlPlaneHealth.HEALTHY
    assert snapshot.generated_at == _NOW
    assert snapshot.workflows.total == 0


@pytest.mark.asyncio
async def test_service_aggregates_every_workflow_state() -> None:
    records = tuple(_workflow(status) for status in WorkflowStatus)
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(records),
        clock=lambda: _NOW,
    )

    summary = (await service.snapshot()).workflows

    assert summary == WorkflowSummary(5, 1, 1, 1, 1, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state, expected",
    [
        (RuntimeState.CREATED, ControlPlaneHealth.STOPPED),
        (RuntimeState.STOPPED, ControlPlaneHealth.STOPPED),
        (RuntimeState.STARTING, ControlPlaneHealth.DEGRADED),
        (RuntimeState.FAILED, ControlPlaneHealth.DEGRADED),
    ],
)
async def test_service_derives_health_from_runtime_state(
    state: RuntimeState,
    expected: ControlPlaneHealth,
) -> None:
    service = ControlPlaneService(
        _RuntimeSource(state),
        _JobSource(),
        _WorkflowSource(),
        clock=lambda: _NOW,
    )

    assert (await service.snapshot()).health is expected


@pytest.mark.asyncio
async def test_dead_letter_job_degrades_health() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(dead_letter=1),
        _WorkflowSource(),
        clock=lambda: _NOW,
    )

    assert (await service.snapshot()).health is ControlPlaneHealth.DEGRADED


@pytest.mark.asyncio
async def test_failed_workflow_degrades_health() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource((_workflow(WorkflowStatus.FAILED),)),
        clock=lambda: _NOW,
    )

    assert (await service.snapshot()).health is ControlPlaneHealth.DEGRADED


@pytest.mark.asyncio
async def test_worker_failure_degrades_health() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(),
        job_worker=_JobWorkerSource(failures=1, last_error="StateConflictError"),
        clock=lambda: _NOW,
    )

    assert (await service.snapshot()).health is ControlPlaneHealth.DEGRADED


@pytest.mark.asyncio
async def test_serializer_omits_workflow_arguments_outputs_and_metadata() -> None:
    record = _workflow(WorkflowStatus.SUCCEEDED, secret_output=True)
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource((record,)),
        clock=lambda: _NOW,
    )

    payload = snapshot_to_dict(await service.snapshot())
    rendered = repr(payload)

    assert payload["schema_version"] == 1
    assert "secret-value" not in rendered
    assert "hidden" not in rendered
    assert "platform" not in rendered
    assert "release.publish" not in rendered


@pytest.mark.asyncio
async def test_serializer_represents_optional_workers_as_null() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(),
        clock=lambda: _NOW,
    )

    payload = snapshot_to_dict(await service.snapshot())

    assert payload["job_worker"] is None
    assert payload["workflow_worker"] is None


@pytest.mark.asyncio
async def test_service_rejects_naive_clock_values() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(),
        clock=lambda: datetime(2026, 7, 18, 12, 0),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        await service.snapshot()
