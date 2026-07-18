from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    AuditCategory,
    AuditLedger,
    AuditOutcome,
    AuditQuery,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    InMemoryAuditStore,
    InMemoryJobRepository,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
    ServiceDefinition,
)


@pytest.mark.asyncio
async def test_runtime_owns_job_worker_and_audits_safe_job_facts() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    capabilities = CapabilityRegistry(events=events)

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"result": invocation.arguments["value"]}

    await capabilities.register(CapabilityDescriptor("test.echo"), provider)
    audit_store = InMemoryAuditStore()
    ledger = AuditLedger(audit_store, events=events)
    scheduler = JobScheduler(InMemoryJobRepository(), capabilities, events=events)
    runtime = await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        audit=ledger,
        jobs=scheduler,
        job_poll_interval=0.01,
    ).assemble()

    assert runtime.service("jobs") is scheduler
    await runtime.start()
    now = datetime.now(UTC)
    job = await scheduler.schedule(
        JobSpec(
            capability="test.echo",
            schedule=JobSchedule(now),
            arguments={"value": 7, "password": "never-journal-this"},
        ),
        now=now,
    )

    for _ in range(100):
        loaded = await scheduler.get(job.id)
        if loaded is not None and loaded.status is JobStatus.SUCCEEDED:
            break
        await asyncio.sleep(0.01)
    else:
        pytest.fail("Runtime job worker did not execute scheduled job")

    snapshot = await runtime.snapshot()
    assert snapshot.components[-1] == "jobs"
    await runtime.stop()

    records = await audit_store.read(AuditQuery(limit=1000))
    job_records = [record for record in records if record.event.name.startswith("job.")]
    assert [record.event.name for record in job_records] == [
        "job.scheduled",
        "job.started",
        "job.completed",
    ]
    assert all(record.event.category is AuditCategory.JOB for record in job_records)
    assert all(record.event.outcome is AuditOutcome.SUCCEEDED for record in job_records)
    assert "never-journal-this" not in repr(job_records)
    assert scheduler.closed


def test_jobs_is_a_reserved_service_name() -> None:
    with pytest.raises(ValueError, match="reserved"):
        ServiceDefinition("jobs", lambda resolver, config: object())
