from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.capabilities import (
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
)
from phoenix_os.jobs import (
    InMemoryJobRepository,
    JobLeaseLostError,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
    RetryPolicy,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def spec(*, attempts: int = 1, interval: timedelta | None = None) -> JobSpec:
    return JobSpec(
        capability="test.echo",
        schedule=JobSchedule(NOW, interval=interval),
        arguments={"value": 7},
        context=CapabilityContext(principal="tester"),
        retry=RetryPolicy(max_attempts=attempts, initial_delay=timedelta(seconds=5)),
    )


async def registry() -> CapabilityRegistry:
    result = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"value": invocation.arguments["value"]}

    await result.register(CapabilityDescriptor("test.echo"), provider)
    return result


@pytest.mark.asyncio
async def test_one_time_job_completes() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    job = await scheduler.schedule(spec(), now=NOW)

    runs = await scheduler.run_due(now=NOW)
    loaded = await scheduler.get(job.id)

    assert len(runs) == 1
    assert runs[0].status is JobStatus.SUCCEEDED
    assert loaded is not None
    assert loaded.status is JobStatus.SUCCEEDED
    assert loaded.output == {"value": 7}


@pytest.mark.asyncio
async def test_future_job_is_not_claimed() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    future = JobSpec(capability="test.echo", schedule=JobSchedule(NOW + timedelta(hours=1)))
    await scheduler.schedule(future, now=NOW)

    assert await scheduler.run_due(now=NOW) == ()


@pytest.mark.asyncio
async def test_retry_then_success() -> None:
    calls = 0
    capabilities = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        nonlocal calls
        del invocation
        calls += 1
        if calls == 1:
            raise RuntimeError("secret detail")
        return {"ok": True}

    await capabilities.register(CapabilityDescriptor("test.echo"), provider)
    scheduler = JobScheduler(InMemoryJobRepository(), capabilities)
    job = await scheduler.schedule(spec(attempts=2), now=NOW)

    first = await scheduler.run_due(now=NOW)
    waiting = await scheduler.get(job.id)
    second = await scheduler.run_due(now=NOW + timedelta(seconds=5))
    completed = await scheduler.get(job.id)

    assert first[0].status is JobStatus.RETRYING
    assert first[0].error == "CapabilityExecutionError"
    assert waiting is not None and waiting.next_run_at == NOW + timedelta(seconds=5)
    assert second[0].status is JobStatus.SUCCEEDED
    assert completed is not None and completed.attempts == 2


@pytest.mark.asyncio
async def test_permanent_failure_moves_to_dead_letter() -> None:
    capabilities = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        del invocation
        return {"value": 1 / 0}

    await capabilities.register(CapabilityDescriptor("test.echo"), provider)
    scheduler = JobScheduler(InMemoryJobRepository(), capabilities)
    job = await scheduler.schedule(spec(attempts=1), now=NOW)

    runs = await scheduler.run_due(now=NOW)
    loaded = await scheduler.get(job.id)

    assert runs[0].status is JobStatus.DEAD_LETTER
    assert loaded is not None and loaded.error == "CapabilityExecutionError"


@pytest.mark.asyncio
async def test_recurring_job_reschedules_at_fixed_rate() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    job = await scheduler.schedule(spec(interval=timedelta(minutes=1)), now=NOW)

    await scheduler.run_due(now=NOW + timedelta(minutes=3, seconds=10))
    loaded = await scheduler.get(job.id)

    assert loaded is not None
    assert loaded.status is JobStatus.SCHEDULED
    assert loaded.next_run_at == NOW + timedelta(minutes=4)
    assert loaded.attempts == 0


@pytest.mark.asyncio
async def test_two_workers_cannot_claim_same_job() -> None:
    repository = InMemoryJobRepository()
    scheduler = JobScheduler(repository, await registry())
    job = await scheduler.schedule(spec(), now=NOW)

    first, second = await asyncio.gather(
        repository.claim(job.id, owner="one", now=NOW, lease_ttl=timedelta(seconds=10)),
        repository.claim(job.id, owner="two", now=NOW, lease_ttl=timedelta(seconds=10)),
    )

    assert sum(item is not None for item in (first, second)) == 1


@pytest.mark.asyncio
async def test_expired_lease_is_reclaimed_with_new_fencing_token() -> None:
    repository = InMemoryJobRepository()
    scheduler = JobScheduler(repository, await registry())
    job = await scheduler.schedule(spec(attempts=2), now=NOW)
    first = await repository.claim(job.id, owner="one", now=NOW, lease_ttl=timedelta(seconds=1))
    assert first is not None

    second = await repository.claim(
        job.id,
        owner="two",
        now=NOW + timedelta(seconds=1),
        lease_ttl=timedelta(seconds=1),
    )

    assert second is not None
    assert second.token != first.token
    assert second.attempt == 2
    with pytest.raises(JobLeaseLostError):
        await repository.complete(first, {}, now=NOW + timedelta(milliseconds=500))


@pytest.mark.asyncio
async def test_cancelled_job_never_runs() -> None:
    scheduler = JobScheduler(InMemoryJobRepository(), await registry())
    job = await scheduler.schedule(spec(), now=NOW)

    assert await scheduler.cancel(job.id, now=NOW)
    assert await scheduler.run_due(now=NOW) == ()
    loaded = await scheduler.get(job.id)
    assert loaded is not None and loaded.status is JobStatus.CANCELLED


def test_contracts_reject_naive_time_and_invalid_retry() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        JobSchedule(datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="positive"):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError, match="positive"):
        JobSpec(capability="x", schedule=JobSchedule(NOW), deadline=0)


def test_job_id_type_is_uuid() -> None:
    assert isinstance(UUID(int=0), UUID)
