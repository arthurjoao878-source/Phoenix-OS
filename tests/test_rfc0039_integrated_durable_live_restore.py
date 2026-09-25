from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedAgentRunBinding,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedBudgetUsage,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedTaskId,
    IntegratedTaskRequest,
    NormalizedPlan,
    PlanRevision,
)
from phoenix_os.integrated_agent.durable_live_restore import (
    restore_integrated_durable_recovery_live_state,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentConfigurationError,
    IntegratedAgentRejectedError,
    IntegratedAgentStaleError,
)
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 9, 9, 3, 20, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=4001))
_TASK_ID = IntegratedTaskId(UUID(int=4002))
_AGENT_ID = AgentId("assistant")
_LOCAL_PROVIDER_ID = ModelProviderId("local")


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("development"),
        generation=IntegratedExecutionProfileGeneration(10),
        agent_id=_AGENT_ID,
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="user-model",
                    source_kind=IntegratedDataSourceKind.USER_TASK,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                ),
            )
        ),
        budget_extension=IntegratedBudgetExtension(
            max_integrated_steps=4,
            max_plan_revisions=3,
        ),
    )


def _admission(profile: IntegratedExecutionProfile) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        AgentServiceConfiguration(
            agent_id=_AGENT_ID,
            provider_id=_LOCAL_PROVIDER_ID,
            model_id=ModelId("chat"),
        ),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=_TASK_ID,
        objective="Continue the exact reviewed durable task.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=_AGENT_ID,
        provider_id=_LOCAL_PROVIDER_ID,
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_RUN_ID,
        created_at=_NOW - timedelta(minutes=5),
        deadline=_NOW + timedelta(minutes=15),
    )


async def _reviewed_seed(
    profile: IntegratedExecutionProfile,
) -> tuple[
    AgentRunRequest,
    tuple[IntegratedAgentRunBinding, IntegratedDataProvenance],
]:
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    guard.begin_run(task, lease.request)
    provenance = guard.current_provenance(_RUN_ID)
    assert provenance is not None
    effective_request = lease.request
    binding = lease.binding
    guard.release_run(_RUN_ID)
    await lease.release()
    return effective_request, (binding, provenance)


@pytest.mark.asyncio
async def test_restore_live_state_reuses_exact_reviewed_identity_and_releases_as_one_scope() -> (
    None
):
    profile = _profile()
    task = _task()
    effective_request, seed = await _reviewed_seed(profile)
    expected_binding, provenance = seed

    admission = _admission(profile)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile, provenance_provider=guard)

    live = await restore_integrated_durable_recovery_live_state(
        admission=admission,
        execution_guard=guard,
        planner=planner,
        task=task,
        request=effective_request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
        plan=None,
    )
    assert live.binding == expected_binding
    assert live.request == effective_request
    assert await admission.binding_for_run(_RUN_ID) == expected_binding
    assert await admission.request_for_run(_RUN_ID) == effective_request
    assert guard.current_provenance(_RUN_ID) == provenance
    assert guard.current_budget_usage(_RUN_ID) == IntegratedBudgetUsage()
    assert planner.current_revision(_RUN_ID) == 0
    assert planner.current_plan(_RUN_ID) is None

    await live.release()
    await live.release()

    assert live.released is True
    assert await admission.binding_for_run(_RUN_ID) is None
    assert await admission.request_for_run(_RUN_ID) is None
    assert guard.current_provenance(_RUN_ID) is None
    assert guard.current_budget_usage(_RUN_ID) is None
    assert planner.current_revision(_RUN_ID) is None
    assert planner.current_plan(_RUN_ID) is None

    restored_again = await restore_integrated_durable_recovery_live_state(
        admission=admission,
        execution_guard=guard,
        planner=planner,
        task=task,
        request=effective_request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
        plan=None,
    )
    try:
        assert restored_again.binding == expected_binding
        assert guard.current_provenance(_RUN_ID) == provenance
        assert planner.current_revision(_RUN_ID) == 0
    finally:
        await restored_again.release()


@pytest.mark.asyncio
async def test_restore_live_state_restores_exact_reviewed_plan_and_budget() -> None:
    profile = _profile()
    task = _task()
    effective_request, seed = await _reviewed_seed(profile)
    _binding, provenance = seed
    usage = IntegratedBudgetUsage(integrated_steps=1, plan_revisions=1)
    plan = NormalizedPlan.create(
        task_id=task.task_id,
        revision=PlanRevision(1),
        statements=("continue from reviewed context",),
        provenance=provenance,
    )

    admission = _admission(profile)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile, provenance_provider=guard)

    live = await restore_integrated_durable_recovery_live_state(
        admission=admission,
        execution_guard=guard,
        planner=planner,
        task=task,
        request=effective_request,
        provenance=provenance,
        budget_usage=usage,
        plan=plan,
    )
    try:
        assert guard.current_budget_usage(_RUN_ID) == usage
        assert planner.current_revision(_RUN_ID) == 1
        assert planner.current_plan(_RUN_ID) == plan
    finally:
        await live.release()


@pytest.mark.asyncio
async def test_restore_live_state_rolls_back_admission_when_guard_rejects() -> None:
    profile = _profile()
    task = _task()
    effective_request, seed = await _reviewed_seed(profile)
    _binding, provenance = seed

    admission = _admission(profile)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    different_task = IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=4091)),
        objective="Different immutable task identity.",
    )
    guard.begin_run(different_task, effective_request)
    guard.release_run(_RUN_ID)
    planner = IntegratedPlanner(profile, provenance_provider=guard)

    with pytest.raises(IntegratedAgentStaleError):
        await restore_integrated_durable_recovery_live_state(
            admission=admission,
            execution_guard=guard,
            planner=planner,
            task=task,
            request=effective_request,
            provenance=provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
        )

    assert await admission.binding_for_run(_RUN_ID) is None
    assert await admission.request_for_run(_RUN_ID) is None
    assert guard.current_provenance(_RUN_ID) is None
    assert planner.current_revision(_RUN_ID) is None


@pytest.mark.asyncio
async def test_restore_live_state_rolls_back_guard_and_admission_when_planner_rejects() -> None:
    profile = _profile()
    task = _task()
    effective_request, seed = await _reviewed_seed(profile)
    binding, provenance = seed

    admission = _admission(profile)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    different_task = IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=4092)),
        objective="Different immutable planner binding.",
    )
    different_admission = _admission(profile)
    different_lease = await different_admission.admit(different_task, effective_request)
    planner.begin_run(different_lease.binding)
    planner.release_run(_RUN_ID)
    await different_lease.release()

    with pytest.raises(IntegratedAgentRejectedError):
        await restore_integrated_durable_recovery_live_state(
            admission=admission,
            execution_guard=guard,
            planner=planner,
            task=task,
            request=effective_request,
            provenance=provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
        )

    assert await admission.binding_for_run(_RUN_ID) is None
    assert await admission.request_for_run(_RUN_ID) is None
    assert guard.current_provenance(_RUN_ID) is None
    assert guard.current_budget_usage(_RUN_ID) is None
    assert planner.current_revision(_RUN_ID) is None


@pytest.mark.asyncio
async def test_restore_live_state_rejects_mismatched_provenance_owner_before_mutation() -> None:
    profile = _profile()
    task = _task()
    effective_request, seed = await _reviewed_seed(profile)
    _binding, provenance = seed

    admission = _admission(profile)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile)

    with pytest.raises(IntegratedAgentConfigurationError):
        await restore_integrated_durable_recovery_live_state(
            admission=admission,
            execution_guard=guard,
            planner=planner,
            task=task,
            request=effective_request,
            provenance=provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
        )

    assert await admission.binding_for_run(_RUN_ID) is None
    assert await admission.request_for_run(_RUN_ID) is None
    assert guard.current_provenance(_RUN_ID) is None
    assert planner.current_revision(_RUN_ID) is None
