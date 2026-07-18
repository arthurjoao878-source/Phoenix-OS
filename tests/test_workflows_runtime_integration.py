from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    AuditCategory,
    AuditLedger,
    AuditQuery,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    InMemoryAuditStore,
    InMemoryJobRepository,
    InMemoryWorkflowRepository,
    JobScheduler,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
    ServiceDefinition,
    WorkflowDefinition,
    WorkflowOrchestrator,
    WorkflowStatus,
    WorkflowStep,
)


@pytest.mark.asyncio
async def test_runtime_owns_workflow_worker_and_audits_safe_graph_facts() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    capabilities = CapabilityRegistry(events=events)

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"step": invocation.capability}

    await capabilities.register(CapabilityDescriptor("release.prepare"), provider)
    await capabilities.register(CapabilityDescriptor("release.publish"), provider)
    audit_store = InMemoryAuditStore()
    ledger = AuditLedger(audit_store, events=events)
    scheduler = JobScheduler(InMemoryJobRepository(), capabilities, events=events)
    orchestrator = WorkflowOrchestrator(
        InMemoryWorkflowRepository(),
        scheduler,
        events=events,
    )
    runtime = await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        audit=ledger,
        jobs=scheduler,
        job_poll_interval=0.01,
        workflows=orchestrator,
        workflow_poll_interval=0.01,
    ).assemble()

    assert runtime.service("jobs") is scheduler
    assert runtime.service("workflows") is orchestrator
    await runtime.start()
    workflow = await orchestrator.start(
        WorkflowDefinition(
            "release",
            (
                WorkflowStep(
                    "prepare",
                    "release.prepare",
                    arguments={"password": "never-journal-this"},
                ),
                WorkflowStep(
                    "publish",
                    "release.publish",
                    dependencies=frozenset({"prepare"}),
                ),
            ),
        ),
        now=datetime.now(UTC),
    )

    for _ in range(200):
        loaded = await orchestrator.get(workflow.id)
        if loaded is not None and loaded.status is WorkflowStatus.SUCCEEDED:
            break
        await asyncio.sleep(0.01)
    else:
        pytest.fail("Runtime workflow worker did not complete the graph")

    snapshot = await runtime.snapshot()
    assert snapshot.components[-2:] == ("jobs", "workflows")
    await runtime.stop()

    records = await audit_store.read(AuditQuery(limit=1000))
    workflow_records = [record for record in records if record.event.name.startswith("workflow.")]
    assert [record.event.name for record in workflow_records] == [
        "workflow.started",
        "workflow.step.started",
        "workflow.step.succeeded",
        "workflow.step.started",
        "workflow.step.succeeded",
        "workflow.succeeded",
    ]
    assert all(record.event.category is AuditCategory.WORKFLOW for record in workflow_records)
    assert "never-journal-this" not in repr(workflow_records)
    assert orchestrator.closed
    assert scheduler.closed


def test_workflows_is_a_reserved_service_name() -> None:
    with pytest.raises(ValueError, match="reserved"):
        ServiceDefinition("workflows", lambda resolver, config: object())


@pytest.mark.asyncio
async def test_runtime_requires_jobs_when_workflows_are_enabled() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    capabilities = CapabilityRegistry(events=events)
    orchestrator = WorkflowOrchestrator(
        InMemoryWorkflowRepository(),
        JobScheduler(InMemoryJobRepository(), capabilities),
    )

    with pytest.raises(ValueError, match="requires a Runtime-owned job scheduler"):
        RuntimeAssembler(
            kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            workflows=orchestrator,
        )
