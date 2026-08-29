from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.authorization import (
    DelegatingAgentModelTurnAuthorizer,
    PolicyEngineAgentRunAuthorizer,
    PolicyEngineToolAuthorizer,
)
from phoenix_os.agent.configuration import AgentServiceConfiguration, AgentToolConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunStatus,
)
from phoenix_os.agent.errors import AgentErrorCode
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
)
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.service import AgentService
from phoenix_os.events import EventBus
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.inference.authorization import PolicyEngineInferenceAuthorizer
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedAgentAdmission,
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
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 29, 1, tzinfo=UTC)
_AGENT_ID = AgentId("research-agent")
_PROVIDER_ID = ModelProviderId("deterministic")
_MODEL_ID = ModelId("chat")
_PROFILE_ID = IntegratedExecutionProfileId("integrated-e2e")
_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(7)


def _allow_all_policy() -> PolicyEngine:
    return PolicyEngine((PolicyRule("allow-e2e", PolicyEffect.ALLOW),))


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="integrated-e2e",
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222")),
        objective="Return one reviewed deterministic result.",
    )


def _request(configuration: AgentServiceConfiguration) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "Produce the reviewed deterministic result.",
            ),
        ),
        limits=configuration.limits,
        run_id=AgentRunId(UUID("11111111-1111-1111-1111-111111111111")),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=10),
    )


def _policy(*, allow_user_result: bool) -> IntegratedDataFlowPolicy:
    routes = [
        IntegratedDataFlowRoute(
            route_id="user-model",
            source_kind=IntegratedDataSourceKind.USER_TASK,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
    ]
    if allow_user_result:
        routes.extend(
            (
                IntegratedDataFlowRoute(
                    route_id="user-result",
                    source_kind=IntegratedDataSourceKind.USER_TASK,
                    sink=IntegratedDataSink.USER_RESULT,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                    requires_audience_match=True,
                ),
                IntegratedDataFlowRoute(
                    route_id="model-result",
                    source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
                    sink=IntegratedDataSink.USER_RESULT,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                    requires_audience_match=True,
                ),
            )
        )
    return IntegratedDataFlowPolicy(tuple(routes))


def _profile(*, allow_user_result: bool) -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=_policy(allow_user_result=allow_user_result),
    )


def _runtime(
    *,
    final_output: str,
    allow_user_result: bool,
) -> tuple[
    IntegratedAgentRuntime,
    AgentService,
    IntegratedAgentAdmission,
    DeterministicModelTurnAdapter,
]:
    profile = _profile(allow_user_result=allow_user_result)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    plan_binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(plan_binding, IntegratedLocalTransformBinding)
    composition = IntegratedAgentToolComposition(
        profile,
        (integrated_plan_update_registration(plan_binding, planner),),
    )
    configuration = AgentServiceConfiguration(
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        tools=tuple(AgentToolConfiguration(descriptor) for descriptor in composition.descriptors),
    )
    registry = composition.build_registry()
    model = DeterministicModelTurnAdapter((DeterministicFinalTurn(final_output),))
    policy = _allow_all_policy()
    agent_admission = AgentAdmissionController(configuration.limits)
    loop = AgentLoop(
        run_authorizer=PolicyEngineAgentRunAuthorizer(policy),
        model_authorizer=DelegatingAgentModelTurnAuthorizer(
            PolicyEngineInferenceAuthorizer(policy)
        ),
        tool_authorizer=PolicyEngineToolAuthorizer(policy),
        model_adapter=model,
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        admission=agent_admission,
        execution_interceptor=guard,
        clock=lambda: _NOW,
    )
    service = AgentService(
        loop,
        registry,
        agent_admission,
        configuration,
        events=EventBus(),
        model_adapter=model,
        tool_adapters=composition.adapters,
    )
    integrated_admission = IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )
    runtime = IntegratedAgentRuntime(
        service,
        integrated_admission,
        planner=planner,
        composition=composition,
        execution_guard=guard,
    )
    return runtime, service, integrated_admission, model


@pytest.mark.asyncio
async def test_integrated_runtime_completes_deterministic_end_to_end_result() -> None:
    output = "reviewed deterministic result"
    runtime, service, integrated_admission, model = _runtime(
        final_output=output,
        allow_user_result=True,
    )
    runtime_context = RuntimeContext(services={})
    request = _request(service.configuration)

    await runtime.start(runtime_context)
    try:
        result = await runtime.run(
            _task(),
            request,
            _context(),
        )

        assert result.status is AgentRunStatus.COMPLETED
        assert result.run_id == request.run_id
        assert result.final_output == output
        assert result.model_turns == 1
        assert result.tool_calls == 0
        assert model.remaining_turns == 0
        assert len(model.requests) == 1
        assert model.requests[0].run_id == request.run_id
        assert await integrated_admission.binding_for_run(request.run_id) is None

        snapshot = await service.snapshot()
        assert snapshot.started == 1
        assert snapshot.completed == 1
        assert snapshot.failed == 0
        assert snapshot.active == 0
    finally:
        await runtime.stop(runtime_context)


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_integrated_runtime_blocks_final_output_without_user_result_route() -> None:
    secret = "MODEL_OUTPUT_MUST_NOT_ESCAPE"
    runtime, service, integrated_admission, model = _runtime(
        final_output=secret,
        allow_user_result=False,
    )
    runtime_context = RuntimeContext(services={})
    request = _request(service.configuration)

    await runtime.start(runtime_context)
    try:
        result = await runtime.run(
            _task(),
            request,
            _context(),
        )

        assert result.status is AgentRunStatus.FAILED
        assert result.final_output is None
        assert result.error_code == AgentErrorCode.AUTHORIZATION_REJECTED.value
        assert result.model_turns == 1
        assert result.tool_calls == 0
        assert model.remaining_turns == 0
        assert len(model.requests) == 1
        assert await integrated_admission.binding_for_run(request.run_id) is None

        snapshot = await service.snapshot()
        assert snapshot.started == 1
        assert snapshot.completed == 0
        assert snapshot.rejected == 1
        assert snapshot.failed == 0
        assert snapshot.active == 0
    finally:
        await runtime.stop(runtime_context)
