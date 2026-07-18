from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from phoenix_os.capabilities import (
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
)
from phoenix_os.jobs import (
    InMemoryJobRepository,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
    JobWorker,
    JobWorkerState,
    JobWorkerStateError,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


async def registry() -> CapabilityRegistry:
    capabilities = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"value": invocation.arguments["value"]}

    await capabilities.register(CapabilityDescriptor("test.echo"), provider)
    return capabilities


@pytest.mark.asyncio
async def test_worker_executes_due_job_and_stops_scheduler() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    job = await scheduler.schedule(
        JobSpec(
            capability="test.echo",
            schedule=JobSchedule(NOW),
            arguments={"value": 42},
        ),
        now=NOW,
    )
    worker = JobWorker(scheduler, poll_interval=0.01, clock=lambda: NOW)

    await worker.start(object())
    for _ in range(100):
        loaded = await scheduler.get(job.id)
        if loaded is not None and loaded.status is JobStatus.SUCCEEDED:
            break
        await asyncio.sleep(0.005)
    else:
        pytest.fail("worker did not execute due job")

    running = await worker.snapshot()
    await worker.stop(object())
    stopped = await worker.snapshot()

    assert running.state is JobWorkerState.RUNNING
    assert running.ticks >= 1
    assert running.runs == 1
    assert stopped.state is JobWorkerState.STOPPED
    assert scheduler.closed


@pytest.mark.asyncio
async def test_worker_isolates_tick_infrastructure_failure() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    await scheduler.close()
    worker = JobWorker(scheduler, poll_interval=0.01, clock=lambda: NOW)

    await worker.start(object())
    await asyncio.sleep(0.025)
    snapshot = await worker.snapshot()
    await worker.stop(object())

    assert snapshot.ticks >= 1
    assert snapshot.failures >= 1
    assert snapshot.last_error == "JobSchedulerClosedError"


@pytest.mark.asyncio
async def test_worker_is_one_shot_and_validates_configuration() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    worker = JobWorker(scheduler, clock=lambda: NOW)
    await worker.start(object())

    with pytest.raises(JobWorkerStateError, match="cannot start"):
        await worker.start(object())

    await worker.stop(object())
    with pytest.raises(JobWorkerStateError, match="cannot start"):
        await worker.start(object())

    with pytest.raises(ValueError, match="poll_interval"):
        JobWorker(scheduler, poll_interval=0)
