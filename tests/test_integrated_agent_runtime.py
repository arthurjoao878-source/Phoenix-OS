from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunResult,
    AgentRunStatus,
)
from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import (
    AgentServiceConfiguration,
    AgentToolConfiguration,
)
from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedAgentAdmission,
    IntegratedAgentConfigurationError,
    IntegratedAgentExecutionGuard,
    IntegratedAgentRuntime,
    IntegratedAgentToolComposition,
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
    integrated_plan_update_registration,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 27, 3, tzinfo=UTC)


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


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("integrated-research"),
        generation=IntegratedExecutionProfileGeneration(7),
        agent_id=AgentId("research-agent"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id="integrated.plan.update",
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=_policy(),
    )


def _admission(
    configuration: AgentServiceConfiguration | None = None,
) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((_profile(),)),
        IntegratedExecutionProfileSelection(
            profile_id=IntegratedExecutionProfileId("integrated-research"),
            generation=IntegratedExecutionProfileGeneration(7),
        ),
        configuration or _configuration(),
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "compare suppliers"),),
        run_id=AgentRunId(UUID("11111111-1111-1111-1111-111111111111")),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=10),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222")),
        objective="Compare reviewed suppliers and return a report.",
    )


def _security_context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


class _RecordingAgentService:
    def __init__(self, configuration: AgentServiceConfiguration) -> None:
        self._configuration = configuration
        self._state = AgentServiceState.CREATED
        self.start_calls = 0
        self.stop_calls = 0
        self.run_calls: list[AgentRunRequest] = []
        self.authority_bindings: list[AgentRunAuthorityBinding | None] = []
        self.cancellations: list[AgentCancellationToken | None] = []

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    @property
    def state(self) -> AgentServiceState:
        return self._state

    async def start(self, context: RuntimeContext) -> None:
        assert isinstance(context, RuntimeContext)
        self.start_calls += 1
        self._state = AgentServiceState.RUNNING

    async def stop(self, context: RuntimeContext) -> None:
        assert isinstance(context, RuntimeContext)
        self.stop_calls += 1
        self._state = AgentServiceState.STOPPED

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult:
        assert isinstance(context, SecurityContext)
        self.run_calls.append(request)
        self.authority_bindings.append(_authority_binding)
        self.cancellations.append(cancellation)
        return AgentRunResult(
            run_id=request.run_id,
            status=AgentRunStatus.COMPLETED,
            model_turns=1,
            tool_calls=0,
            final_output="done",
        )


@pytest.mark.asyncio
async def test_runtime_reuses_agent_run_id_and_passes_server_binding_into_existing_service() -> (
    None
):
    configuration = _configuration()
    service = _RecordingAgentService(configuration)
    admission = _admission(configuration)
    runtime = IntegratedAgentRuntime(service, admission)
    assert not hasattr(runtime, "_active")
    assert not hasattr(runtime, "_state")
    context = RuntimeContext(services={})
    security = _security_context()
    cancellation = AgentCancellationToken()
    request = _request()

    await runtime.start(context)
    result = await runtime.run(
        _task(),
        request,
        security,
        cancellation=cancellation,
    )

    assert result.run_id == request.run_id
    assert len(service.run_calls) == 1
    assert service.run_calls[0].run_id == request.run_id
    assert service.cancellations == [cancellation]
    assert len(service.authority_bindings) == 1
    authority = service.authority_bindings[0]
    assert authority is not None
    assert dict(authority.attributes)["integrated_profile_id"] == "integrated-research"
    assert dict(authority.attributes)["integrated_profile_generation"] == "7"
    assert dict(authority.attributes)["integrated_task_digest"] == str(_task().digest)
    assert await admission.binding_for_run(request.run_id) is None

    await runtime.stop(context)
    assert service.start_calls == 1
    assert service.stop_calls == 1
    assert admission.closed


def test_runtime_rejects_mismatched_agent_service_configuration() -> None:
    configuration = _configuration()
    admission = _admission(configuration)
    other = AgentServiceConfiguration(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("other"),
        model_id=ModelId("chat"),
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentRuntime(_RecordingAgentService(other), admission)


class _ToolRecordingAgentService(_RecordingAgentService):
    def __init__(
        self,
        configuration: AgentServiceConfiguration,
        registry: ToolRegistry,
    ) -> None:
        super().__init__(configuration)
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        return self._registry


def _tool_configuration(planner: IntegratedPlanner) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(planner.descriptor),),
    )


def test_runtime_requires_exact_sealed_composition_for_visible_tools() -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = _tool_configuration(planner)
    admission = IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )
    service = _ToolRecordingAgentService(configuration, ToolRegistry())

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentRuntime(service, admission, planner=planner)


def test_runtime_accepts_exact_reviewed_composition_and_registry() -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = _tool_configuration(planner)
    admission = IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )
    binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(binding, IntegratedLocalTransformBinding)
    registration = integrated_plan_update_registration(binding, planner)
    composition = IntegratedAgentToolComposition(profile, (registration,))
    registry = composition.build_registry()
    service = _ToolRecordingAgentService(configuration, registry)

    runtime = IntegratedAgentRuntime(
        service,
        admission,
        planner=planner,
        composition=composition,
    )

    assert runtime.composition is composition
    assert registry.sealed is True


def test_runtime_rejects_planner_not_bound_to_execution_guard_provenance() -> None:
    profile = _profile()
    guard = IntegratedAgentExecutionGuard(profile)
    planner = IntegratedPlanner(profile)
    configuration = _configuration()
    admission = IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentRuntime(
            _RecordingAgentService(configuration),
            admission,
            planner=planner,
            execution_guard=guard,
        )
