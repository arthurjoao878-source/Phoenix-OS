from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import AgentId, AgentMessage, AgentMessageRole, AgentRunId
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
    INTEGRATED_AGENT_HEALTH_RESOURCE,
    INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedAgentAdministration,
    IntegratedAgentAdministrationAccessDeniedError,
    IntegratedAgentAdmission,
    IntegratedAgentExecutionGuard,
    IntegratedBudgetUsage,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedExecutionProfileSelection,
    IntegratedLocalTransformBinding,
    IntegratedPlanner,
    IntegratedTaskId,
    IntegratedTaskRequest,
    integrated_agent_inspection_resource,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 29, 1, tzinfo=UTC)


def _policy() -> IntegratedDataFlowPolicy:
    return IntegratedDataFlowPolicy(
        (
            IntegratedDataFlowRoute(
                route_id="user-model",
                source_kind=IntegratedDataSourceKind.USER_TASK,
                sink=IntegratedDataSink.MODEL,
                disposition=IntegratedDataFlowDisposition.ALLOW,
            ),
        )
    )


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("integrated-research"),
        generation=IntegratedExecutionProfileGeneration(7),
        agent_id=AgentId("research-agent"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=_policy(),
    )


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "PROMPT_SECRET_SHOULD_NEVER_ENTER_ADMIN_OUTPUT",
            ),
        ),
        run_id=AgentRunId(UUID("11111111-1111-1111-1111-111111111111")),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=10),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222")),
        objective="TASK_SECRET_SHOULD_NEVER_ENTER_ADMIN_OUTPUT",
    )


class _RuntimeStub:
    def __init__(
        self,
        admission: IntegratedAgentAdmission,
        planner: IntegratedPlanner,
        guard: IntegratedAgentExecutionGuard,
    ) -> None:
        self._admission = admission
        self._planner = planner
        self._guard = guard

    @property
    def state(self) -> AgentServiceState:
        return AgentServiceState.RUNNING

    @property
    def admission(self) -> IntegratedAgentAdmission:
        return self._admission

    @property
    def planner(self) -> IntegratedPlanner | None:
        return self._planner

    @property
    def execution_guard(self) -> IntegratedAgentExecutionGuard | None:
        return self._guard

    @property
    def composition(self) -> object | None:
        return None


def _components() -> tuple[
    IntegratedAgentAdmission,
    IntegratedPlanner,
    IntegratedAgentExecutionGuard,
    IntegratedAgentAdministration,
]:
    profile = _profile()
    admission = IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        _configuration(),
    )
    guard = IntegratedAgentExecutionGuard(profile)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    administration = IntegratedAgentAdministration(_RuntimeStub(admission, planner, guard))
    return admission, planner, guard, administration


def _service_context(
    permission: str,
    resource: str,
    *,
    authenticated: bool = True,
) -> SecurityContext:
    return SecurityContext(
        principal="service:operator",
        principal_type=PrincipalType.SERVICE,
        authenticated=authenticated,
        permissions=frozenset({permission}),
        attributes={"resource": resource},
    )


@pytest.mark.asyncio
async def test_health_snapshot_is_content_free_and_separately_authorized() -> None:
    admission, planner, guard, administration = _components()

    with pytest.raises(IntegratedAgentAdministrationAccessDeniedError):
        await administration.snapshot(
            _service_context(
                INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
                INTEGRATED_AGENT_HEALTH_RESOURCE,
            )
        )

    with pytest.raises(IntegratedAgentAdministrationAccessDeniedError):
        await administration.snapshot(
            _service_context(
                INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
                "integrated-agent:wrong",
            )
        )

    snapshot = await administration.snapshot(
        _service_context(
            INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
            INTEGRATED_AGENT_HEALTH_RESOURCE,
        )
    )

    assert snapshot.runtime_state is AgentServiceState.RUNNING
    assert snapshot.profile_id == IntegratedExecutionProfileId("integrated-research")
    assert snapshot.profile_generation == IntegratedExecutionProfileGeneration(7)
    assert snapshot.admission_closed is False
    assert snapshot.planner_configured is True
    assert snapshot.planner_closed is False
    assert snapshot.execution_guard_configured is True
    assert snapshot.execution_guard_closed is False
    assert snapshot.composition_configured is False

    serialized = repr(snapshot)
    assert "TASK_SECRET_SHOULD_NEVER_ENTER_ADMIN_OUTPUT" not in serialized
    assert "PROMPT_SECRET_SHOULD_NEVER_ENTER_ADMIN_OUTPUT" not in serialized

    planner.close()
    guard.close()
    await admission.close()


@pytest.mark.asyncio
async def test_redacted_run_inspection_requires_distinct_exact_run_resource() -> None:
    admission, planner, guard, administration = _components()
    task = _task()
    request = _request()

    lease = await admission.admit(task, request)
    guard.begin_run(task, lease.request)
    planner.begin_run(lease.binding)

    with pytest.raises(IntegratedAgentAdministrationAccessDeniedError):
        await administration.inspect_run(
            request.run_id,
            _service_context(
                INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
                integrated_agent_inspection_resource(request.run_id),
            ),
        )

    other_run = AgentRunId(UUID("33333333-3333-3333-3333-333333333333"))
    with pytest.raises(IntegratedAgentAdministrationAccessDeniedError):
        await administration.inspect_run(
            request.run_id,
            _service_context(
                INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
                integrated_agent_inspection_resource(other_run),
            ),
        )

    inspection = await administration.inspect_run(
        request.run_id,
        _service_context(
            INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
            integrated_agent_inspection_resource(request.run_id),
        ),
    )
    assert inspection is not None
    assert inspection.task_id == task.task_id
    assert inspection.run_id == request.run_id
    assert inspection.profile_id == IntegratedExecutionProfileId("integrated-research")
    assert inspection.profile_generation == IntegratedExecutionProfileGeneration(7)
    assert inspection.plan_revision is None
    assert inspection.budget_usage == IntegratedBudgetUsage()
    assert inspection.failure_class is None
    assert inspection.provenance_source_kinds == (IntegratedDataSourceKind.USER_TASK,)

    serialized = repr(inspection)
    assert "TASK_SECRET_SHOULD_NEVER_ENTER_ADMIN_OUTPUT" not in serialized
    assert "PROMPT_SECRET_SHOULD_NEVER_ENTER_ADMIN_OUTPUT" not in serialized
    assert str(task.digest) not in serialized

    planner.release_run(request.run_id)
    guard.release_run(request.run_id)
    await lease.release()

    assert (
        await administration.inspect_run(
            request.run_id,
            _service_context(
                INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
                integrated_agent_inspection_resource(request.run_id),
            ),
        )
        is None
    )

    planner.close()
    guard.close()
    await admission.close()


@pytest.mark.asyncio
async def test_administration_denies_unauthenticated_service_context() -> None:
    admission, planner, guard, administration = _components()

    with pytest.raises(IntegratedAgentAdministrationAccessDeniedError):
        await administration.snapshot(
            _service_context(
                INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
                INTEGRATED_AGENT_HEALTH_RESOURCE,
                authenticated=False,
            )
        )

    planner.close()
    guard.close()
    await admission.close()
