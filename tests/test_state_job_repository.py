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
    JobAlreadyExistsError,
    JobPersistenceError,
    JobRepositoryClosedError,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
    RetryPolicy,
    StateJobRepository,
)
from phoenix_os.state import ABSENT_VERSION, MemoryStateStore, StateKey

NOW = datetime(2026, 1, 1, tzinfo=UTC)
JOB_ID = UUID("12345678-1234-5678-1234-567812345678")


def spec(*, attempts: int = 2, interval: timedelta | None = None) -> JobSpec:
    return JobSpec(
        capability="test.echo",
        schedule=JobSchedule(NOW, interval=interval),
        arguments={"value": 7, "nested": {"safe": True}},
        context=CapabilityContext(
            principal="tester",
            request_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            correlation_id="job-correlation",
            confirmed=True,
            permissions=frozenset({"test.echo"}),
            metadata={"tenant": "alpha"},
        ),
        retry=RetryPolicy(
            max_attempts=attempts,
            initial_delay=timedelta(seconds=5),
            multiplier=3,
            max_delay=timedelta(minutes=1),
        ),
        deadline=10,
        metadata={"purpose": "test"},
    )


async def registry(*, fail_once: bool = False) -> CapabilityRegistry:
    result = CapabilityRegistry()
    calls = 0

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if fail_once and calls == 1:
            raise RuntimeError("sensitive provider detail")
        return {"value": invocation.arguments["value"]}

    await result.register(CapabilityDescriptor("test.echo"), provider)
    return result


@pytest.mark.asyncio
async def test_state_repository_round_trips_complete_job_spec() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    first = StateJobRepository(store)
    scheduler = JobScheduler(first, await registry())
    created = await scheduler.schedule(spec(interval=timedelta(minutes=2)), job_id=JOB_ID, now=NOW)

    await first.close()
    reopened = StateJobRepository(store)
    loaded = await reopened.get(JOB_ID)

    assert loaded == created
    assert loaded is not None
    assert loaded.spec.context.permissions == frozenset({"test.echo"})
    assert loaded.spec.arguments == {"value": 7, "nested": {"safe": True}}
    assert loaded.spec.retry.max_delay == timedelta(minutes=1)


@pytest.mark.asyncio
async def test_scheduled_job_executes_after_repository_restart() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    first = StateJobRepository(store)
    first_scheduler = JobScheduler(first, await registry())
    await first_scheduler.schedule(spec(), job_id=JOB_ID, now=NOW)
    await first.close()

    second = StateJobRepository(store)
    second_scheduler = JobScheduler(second, await registry())
    runs = await second_scheduler.run_due(now=NOW)
    loaded = await second.get(JOB_ID)

    assert len(runs) == 1
    assert runs[0].status is JobStatus.SUCCEEDED
    assert loaded is not None and loaded.output == {"value": 7}


@pytest.mark.asyncio
async def test_retry_state_survives_restart_and_completes() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    capabilities = await registry(fail_once=True)
    first = StateJobRepository(store)
    scheduler = JobScheduler(first, capabilities)
    await scheduler.schedule(spec(), job_id=JOB_ID, now=NOW)

    first_runs = await scheduler.run_due(now=NOW)
    await first.close()
    second = StateJobRepository(store)
    restarted = JobScheduler(second, capabilities)
    second_runs = await restarted.run_due(now=NOW + timedelta(seconds=5))
    loaded = await second.get(JOB_ID)

    assert first_runs[0].status is JobStatus.RETRYING
    assert second_runs[0].status is JobStatus.SUCCEEDED
    assert loaded is not None and loaded.attempts == 2


@pytest.mark.asyncio
async def test_expired_persisted_lease_is_reclaimed_after_restart() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    first = StateJobRepository(store)
    scheduler = JobScheduler(first, await registry())
    await scheduler.schedule(spec(), job_id=JOB_ID, now=NOW)
    original = await first.claim(
        JOB_ID,
        owner="worker-one",
        now=NOW,
        lease_ttl=timedelta(seconds=1),
    )
    assert original is not None
    await first.close()

    reopened = StateJobRepository(store)
    due = await reopened.list_due(NOW + timedelta(seconds=1), limit=10)
    replacement = await reopened.claim(
        JOB_ID,
        owner="worker-two",
        now=NOW + timedelta(seconds=1),
        lease_ttl=timedelta(seconds=1),
    )

    assert [record.id for record in due] == [JOB_ID]
    assert replacement is not None
    assert replacement.token != original.token
    assert replacement.attempt == 2


@pytest.mark.asyncio
async def test_repository_instances_serialize_competing_claims() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    first = StateJobRepository(store)
    second = StateJobRepository(store)
    scheduler = JobScheduler(first, await registry())
    await scheduler.schedule(spec(), job_id=JOB_ID, now=NOW)

    one, two = await asyncio.gather(
        first.claim(
            JOB_ID,
            owner="one",
            now=NOW,
            lease_ttl=timedelta(seconds=10),
        ),
        second.claim(
            JOB_ID,
            owner="two",
            now=NOW,
            lease_ttl=timedelta(seconds=10),
        ),
    )

    assert sum(lease is not None for lease in (one, two)) == 1


@pytest.mark.asyncio
async def test_cancellation_is_visible_after_restart() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    first = StateJobRepository(store)
    scheduler = JobScheduler(first, await registry())
    await scheduler.schedule(spec(), job_id=JOB_ID, now=NOW)
    assert await first.cancel(JOB_ID, now=NOW)
    await first.close()

    reopened = StateJobRepository(store)
    loaded = await reopened.get(JOB_ID)

    assert loaded is not None and loaded.status is JobStatus.CANCELLED
    assert await reopened.list_due(NOW, limit=10) == ()


@pytest.mark.asyncio
async def test_duplicate_id_is_rejected_across_repository_instances() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    first = StateJobRepository(store)
    second = StateJobRepository(store)
    scheduler = JobScheduler(first, await registry())
    created = await scheduler.schedule(spec(), job_id=JOB_ID, now=NOW)

    with pytest.raises(JobAlreadyExistsError):
        await second.add(created)


@pytest.mark.asyncio
async def test_invalid_persisted_schema_is_rejected_safely() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    key = StateKey("jobs", f"j_{JOB_ID.hex}", dict)
    await store.put(
        key,
        {"schema_version": 999},
        expected_version=ABSENT_VERSION,
    )
    repository = StateJobRepository(store)

    with pytest.raises(JobPersistenceError, match="persisted job record is invalid"):
        await repository.get(JOB_ID)


@pytest.mark.asyncio
async def test_repository_close_does_not_close_borrowed_state_store() -> None:
    store = MemoryStateStore(clock=lambda: NOW)
    repository = StateJobRepository(store)
    await repository.close()

    assert repository.closed
    assert not store.closed
    with pytest.raises(JobRepositoryClosedError):
        await repository.list_all()
