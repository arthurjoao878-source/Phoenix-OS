from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

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
    RetryPolicy,
)
from phoenix_os.workflows import (
    InMemoryWorkflowRepository,
    WorkflowDefinition,
    WorkflowOrchestrator,
    WorkflowOrchestratorClosedError,
    WorkflowPlanner,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepStatus,
    workflow_job_id,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
WORKFLOW_ID = UUID("00000000-0000-0000-0000-000000000016")


def definition(*, retry_attempts: int = 1) -> WorkflowDefinition:
    return WorkflowDefinition(
        "release",
        (
            WorkflowStep("prepare", "release.prepare"),
            WorkflowStep(
                "tests",
                "release.tests",
                dependencies=frozenset({"prepare"}),
                retry=RetryPolicy(
                    max_attempts=retry_attempts,
                    initial_delay=timedelta(seconds=5),
                ),
            ),
            WorkflowStep(
                "package",
                "release.package",
                dependencies=frozenset({"prepare"}),
            ),
            WorkflowStep(
                "publish",
                "release.publish",
                dependencies=frozenset({"tests", "package"}),
            ),
        ),
    )


async def registry(*, fail: str | None = None) -> CapabilityRegistry:
    capabilities = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        if invocation.capability == fail:
            raise RuntimeError("provider detail")
        return {"step": invocation.capability}

    for name in (
        "release.prepare",
        "release.tests",
        "release.package",
        "release.publish",
    ):
        await capabilities.register(CapabilityDescriptor(name), provider)
    return capabilities


@pytest.mark.asyncio
async def test_start_schedules_root_with_deterministic_job_id() -> None:
    jobs = JobScheduler(InMemoryJobRepository(), await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)

    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)
    prepare = workflow.steps["prepare"]
    job = await jobs.get(workflow_job_id(WORKFLOW_ID, "prepare"))

    assert workflow.status is WorkflowStatus.RUNNING
    assert workflow.revision == 1
    assert prepare.status is WorkflowStepStatus.RUNNING
    assert prepare.job_id == workflow_job_id(WORKFLOW_ID, "prepare")
    assert job is not None
    assert job.spec.metadata["phoenix.workflow_step"] == "prepare"


@pytest.mark.asyncio
async def test_success_releases_fan_out_in_declaration_order() -> None:
    job_repository = InMemoryJobRepository()
    jobs = JobScheduler(job_repository, await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)

    await jobs.run_due(now=NOW)
    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=1))

    assert workflow.steps["prepare"].status is WorkflowStepStatus.SUCCEEDED
    assert workflow.steps["tests"].status is WorkflowStepStatus.RUNNING
    assert workflow.steps["package"].status is WorkflowStepStatus.RUNNING
    assert workflow.steps["publish"].status is WorkflowStepStatus.BLOCKED
    scheduled = await job_repository.list_all()
    assert {job.spec.capability for job in scheduled} == {
        "release.prepare",
        "release.tests",
        "release.package",
    }


@pytest.mark.asyncio
async def test_fan_in_waits_for_every_dependency() -> None:
    job_repository = InMemoryJobRepository()
    jobs = JobScheduler(job_repository, await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)
    await jobs.run_due(now=NOW)
    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=1))

    tests_job_id = workflow_job_id(workflow.id, "tests")
    lease = await job_repository.claim(
        tests_job_id,
        owner="test",
        now=NOW + timedelta(seconds=1),
        lease_ttl=timedelta(seconds=30),
    )
    assert lease is not None
    await job_repository.complete(
        lease,
        {"tests": "passed"},
        now=NOW + timedelta(seconds=2),
    )

    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=2))

    assert workflow.steps["tests"].status is WorkflowStepStatus.SUCCEEDED
    assert workflow.steps["package"].status is WorkflowStepStatus.RUNNING
    assert workflow.steps["publish"].status is WorkflowStepStatus.BLOCKED
    assert await jobs.get(workflow_job_id(workflow.id, "publish")) is None


@pytest.mark.asyncio
async def test_complete_graph_succeeds_across_fan_out_and_fan_in() -> None:
    jobs = JobScheduler(InMemoryJobRepository(), await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)

    await jobs.run_due(now=NOW)
    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=1))
    await jobs.run_due(now=NOW + timedelta(seconds=1))
    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=2))
    assert workflow.steps["publish"].status is WorkflowStepStatus.RUNNING
    await jobs.run_due(now=NOW + timedelta(seconds=2))
    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=3))

    assert workflow.status is WorkflowStatus.SUCCEEDED
    assert workflow.finished_at == NOW + timedelta(seconds=3)
    assert all(step.status is WorkflowStepStatus.SUCCEEDED for step in workflow.steps.values())


@pytest.mark.asyncio
async def test_retrying_job_keeps_step_running_until_success() -> None:
    calls = 0
    capabilities = await registry()

    async def flaky(invocation: CapabilityInvocation) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("provider detail")
        return {"step": invocation.capability}

    registration = await capabilities.register(CapabilityDescriptor("release.flaky"), flaky)
    assert registration.name == "release.flaky"
    retry_definition = WorkflowDefinition(
        "retry",
        (
            WorkflowStep(
                "flaky",
                "release.flaky",
                retry=RetryPolicy(
                    max_attempts=2,
                    initial_delay=timedelta(seconds=5),
                ),
            ),
        ),
    )
    jobs = JobScheduler(InMemoryJobRepository(), capabilities)
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(retry_definition, now=NOW)

    first = await jobs.run_due(now=NOW)
    waiting = await orchestrator.advance(workflow.id, now=NOW)
    second = await jobs.run_due(now=NOW + timedelta(seconds=5))
    completed = await orchestrator.advance(
        workflow.id,
        now=NOW + timedelta(seconds=5),
    )

    assert first[0].status is JobStatus.RETRYING
    assert waiting.steps["flaky"].status is WorkflowStepStatus.RUNNING
    assert second[0].status is JobStatus.SUCCEEDED
    assert completed.status is WorkflowStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_failed_step_cancels_outstanding_siblings_and_descendants() -> None:
    job_repository = InMemoryJobRepository()
    jobs = JobScheduler(job_repository, await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)
    await jobs.run_due(now=NOW)
    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=1))

    tests_job_id = workflow_job_id(workflow.id, "tests")
    package_job_id = workflow_job_id(workflow.id, "package")
    lease = await job_repository.claim(
        tests_job_id,
        owner="test",
        now=NOW + timedelta(seconds=1),
        lease_ttl=timedelta(seconds=30),
    )
    assert lease is not None
    await job_repository.fail(
        lease,
        "CapabilityExecutionError",
        now=NOW + timedelta(seconds=2),
    )

    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=2))
    package_job = await jobs.get(package_job_id)

    assert workflow.status is WorkflowStatus.FAILED
    assert workflow.error == "tests: CapabilityExecutionError"
    assert workflow.steps["tests"].status is WorkflowStepStatus.FAILED
    assert workflow.steps["package"].status is WorkflowStepStatus.CANCELLED
    assert workflow.steps["publish"].status is WorkflowStepStatus.CANCELLED
    assert package_job is not None and package_job.status is JobStatus.CANCELLED


@pytest.mark.asyncio
async def test_explicit_cancel_propagates_to_every_open_step() -> None:
    jobs = JobScheduler(InMemoryJobRepository(), await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)

    workflow = await orchestrator.cancel(workflow.id, now=NOW + timedelta(seconds=1))
    job = await jobs.get(workflow_job_id(workflow.id, "prepare"))

    assert workflow.status is WorkflowStatus.CANCELLED
    assert all(step.status is WorkflowStepStatus.CANCELLED for step in workflow.steps.values())
    assert job is not None and job.status is JobStatus.CANCELLED


@pytest.mark.asyncio
async def test_external_job_cancellation_cancels_workflow() -> None:
    jobs = JobScheduler(InMemoryJobRepository(), await registry())
    orchestrator = WorkflowOrchestrator(InMemoryWorkflowRepository(), jobs)
    workflow = await orchestrator.start(definition(), workflow_id=WORKFLOW_ID, now=NOW)
    prepare_job = workflow_job_id(workflow.id, "prepare")
    await jobs.cancel(prepare_job, now=NOW + timedelta(seconds=1))

    workflow = await orchestrator.advance(workflow.id, now=NOW + timedelta(seconds=1))

    assert workflow.status is WorkflowStatus.CANCELLED
    assert workflow.steps["prepare"].status is WorkflowStepStatus.CANCELLED
    assert workflow.steps["publish"].status is WorkflowStepStatus.CANCELLED


@pytest.mark.asyncio
async def test_recovery_attaches_job_created_before_workflow_revision_update() -> None:
    workflow_repository = InMemoryWorkflowRepository()
    job_repository = InMemoryJobRepository()
    jobs = JobScheduler(job_repository, await registry())
    planner = WorkflowPlanner()
    record = planner.instantiate(definition(), workflow_id=WORKFLOW_ID, now=NOW)
    await workflow_repository.add(record)
    prepare = record.definition.step("prepare")
    job_id = workflow_job_id(record.id, prepare.id)
    await jobs.schedule(
        JobSpec(
            capability=prepare.capability,
            schedule=JobSchedule(NOW),
            arguments=prepare.arguments,
            context=prepare.context,
            retry=prepare.retry,
            deadline=prepare.deadline,
            metadata=prepare.metadata,
        ),
        job_id=job_id,
        now=NOW,
    )
    orchestrator = WorkflowOrchestrator(workflow_repository, jobs)

    recovered = await orchestrator.recover(now=NOW)
    snapshot = await jobs.snapshot()

    assert recovered[0].steps["prepare"].job_id == job_id
    assert recovered[0].status is WorkflowStatus.RUNNING
    assert snapshot.jobs == 1


@pytest.mark.asyncio
async def test_closed_orchestrator_rejects_access_without_closing_dependencies() -> None:
    workflow_repository = InMemoryWorkflowRepository()
    jobs = JobScheduler(InMemoryJobRepository(), await registry())
    orchestrator = WorkflowOrchestrator(workflow_repository, jobs)
    await orchestrator.close()

    with pytest.raises(WorkflowOrchestratorClosedError):
        await orchestrator.list_all()

    assert not workflow_repository.closed
    assert not jobs.closed


def test_workflow_job_id_is_stable_and_validates_step_id() -> None:
    assert workflow_job_id(WORKFLOW_ID, "prepare") == workflow_job_id(
        WORKFLOW_ID,
        " prepare ",
    )
    with pytest.raises(ValueError, match="must not be blank"):
        workflow_job_id(WORKFLOW_ID, " ")
