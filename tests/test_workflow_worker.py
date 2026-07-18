from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.capabilities import CapabilityDescriptor, CapabilityInvocation, CapabilityRegistry
from phoenix_os.jobs import InMemoryJobRepository, JobScheduler
from phoenix_os.workflows import (
    InMemoryWorkflowRepository,
    WorkflowDefinition,
    WorkflowOrchestrator,
    WorkflowStatus,
    WorkflowStep,
    WorkflowWorker,
    WorkflowWorkerState,
    WorkflowWorkerStateError,
)

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


async def services() -> tuple[WorkflowOrchestrator, JobScheduler]:
    capabilities = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"step": invocation.capability}

    await capabilities.register(CapabilityDescriptor("workflow.echo"), provider)
    jobs = JobScheduler(InMemoryJobRepository(), capabilities)
    return WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs), jobs


def definition() -> WorkflowDefinition:
    return WorkflowDefinition("worker", (WorkflowStep("echo", "workflow.echo"),))


def test_workflow_worker_validates_configuration() -> None:
    class Placeholder:
        pass

    value = Placeholder()
    with pytest.raises(ValueError, match="worker must not be blank"):
        WorkflowWorker(value, worker=" ")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="poll_interval must be positive"):
        WorkflowWorker(value, poll_interval=0)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="clock must be callable"):
        WorkflowWorker(value, clock=None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_workflow_worker_reconciles_and_closes_orchestrator() -> None:
    coordinator, jobs = await services()
    workflow = await coordinator.start(definition(), now=NOW)
    worker = WorkflowWorker(
        coordinator,
        poll_interval=60,
        worker="test.workflow-worker",
        clock=lambda: NOW,
    )

    await worker.start(object())
    await jobs.run_due(now=NOW)
    records = await worker.run_once(now=NOW + timedelta(seconds=1))
    snapshot = await worker.snapshot()

    assert records[0].id == workflow.id
    assert records[0].status is WorkflowStatus.SUCCEEDED
    assert snapshot.state is WorkflowWorkerState.RUNNING
    assert snapshot.worker == "test.workflow-worker"
    assert snapshot.ticks >= 1
    assert snapshot.workflows >= 1
    assert snapshot.failures == 0

    await worker.stop(object())
    assert worker.state is WorkflowWorkerState.STOPPED
    assert coordinator.closed
    assert not jobs.closed


@pytest.mark.asyncio
async def test_workflow_worker_is_one_shot_and_requires_running_state() -> None:
    coordinator, _ = await services()
    worker = WorkflowWorker(coordinator, poll_interval=60)

    with pytest.raises(WorkflowWorkerStateError, match="cannot run workflow tick"):
        await worker.run_once(now=NOW)

    await worker.start(object())
    with pytest.raises(WorkflowWorkerStateError, match="cannot start workflow worker"):
        await worker.start(object())
    await worker.stop(object())
