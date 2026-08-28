from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentLimits,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    AgentStepId,
    AgentToolConfiguration,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicToolTurn,
    ToolCallId,
    ToolInvocationRequest,
    ToolRegistry,
    ToolResultStatus,
)
from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentJsonValue
from phoenix_os.agent.errors import AgentSchemaError, ToolExecutionError
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor, ToolResourceResolutionContext
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedAgentAdmission,
    IntegratedAgentConfigurationError,
    IntegratedAgentRuntime,
    IntegratedAgentToolComposition,
    IntegratedBudgetExtension,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
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

_NOW = datetime(2026, 8, 27, 6, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID("11111111-1111-1111-1111-111111111111"))
_TASK_ID = IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222"))


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


def _profile(*, max_plan_revisions: int = 4) -> IntegratedExecutionProfile:
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
        budget_extension=IntegratedBudgetExtension(max_plan_revisions=max_plan_revisions),
    )


def _configuration(planner: IntegratedPlanner) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(planner.descriptor),),
    )


def _request(*, run_id: AgentRunId = _RUN_ID) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "compare suppliers"),),
        limits=AgentLimits(),
        run_id=run_id,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=10),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=_TASK_ID,
        objective="Compare reviewed suppliers and return a report.",
    )


def _admission(
    profile: IntegratedExecutionProfile,
    configuration: AgentServiceConfiguration,
) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )


def _security_context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


class _BoundRunAuthorizer:
    def __init__(self) -> None:
        self.bound: list[tuple[AgentRunRequest, AgentRunAuthorityBinding]] = []

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        del request, context
        raise AssertionError("bound integrated run used unbound authorization")

    async def authorize_bound(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        binding: AgentRunAuthorityBinding,
    ) -> None:
        assert context.authenticated
        self.bound.append((request, binding))


class _ModelAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)


class _ToolAuthorizer:
    def __init__(self) -> None:
        self.requests: list[ToolInvocationRequest] = []

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        assert descriptor.tool_id == request.tool_id
        self.requests.append(request)


@pytest.mark.asyncio
async def test_plan_resource_is_server_bound_and_identity_injection_is_rejected() -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    request = _request()
    lease = await admission.admit(_task(), request)
    planner.begin_run(lease.binding)
    registry = ToolRegistry()
    registry.register_tool(
        planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )
    context = ToolResourceResolutionContext(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=AgentStepId(UUID("33333333-3333-3333-3333-333333333333")),
    )

    resolution = registry.admit_tool_call(
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        {"statements": ["research reviewed suppliers", "produce report"]},
        resolution_context=context,
    )

    assert resolution.resolved_resource == (
        f"integrated-plan:task/{_TASK_ID}/run/{_RUN_ID}/revision/0"
    )
    with pytest.raises(AgentSchemaError):
        registry.admit_tool_call(
            INTEGRATED_PLAN_UPDATE_TOOL_ID,
            {
                "statements": ["research reviewed suppliers"],
                "task_id": "forged",
            },
            resolution_context=context,
        )
    with pytest.raises(ToolExecutionError):
        registry.admit_tool_call(
            INTEGRATED_PLAN_UPDATE_TOOL_ID,
            {"statements": ["research reviewed suppliers"]},
        )

    planner.release_run(lease.binding.run_id)
    await lease.release()


@pytest.mark.parametrize(
    "forged_field",
    (
        "agent_id",
        "run_id",
        "task_id",
        "revision",
        "resolved_resource",
        "profile_id",
        "profile_generation",
        "credential",
        "secret",
        "approval",
        "authority",
    ),
)
@pytest.mark.asyncio
async def test_plan_update_rejects_model_fabricated_authority_fields(
    forged_field: str,
) -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    lease = await admission.admit(_task(), _request())
    planner.begin_run(lease.binding)
    registry = ToolRegistry()
    registry.register_tool(
        planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )
    context = ToolResourceResolutionContext(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=AgentStepId(),
    )

    with pytest.raises(AgentSchemaError):
        registry.admit_tool_call(
            INTEGRATED_PLAN_UPDATE_TOOL_ID,
            {
                "statements": ["research reviewed suppliers"],
                forged_field: "forged",
            },
            resolution_context=context,
        )

    planner.release_run(lease.binding.run_id)
    await lease.release()


@pytest.mark.asyncio
async def test_plan_revision_digest_and_stale_resource_are_deterministic() -> None:
    profile = _profile(max_plan_revisions=2)
    planner = IntegratedPlanner(profile)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    request = _request()
    lease = await admission.admit(_task(), request)
    planner.begin_run(lease.binding)
    registry = ToolRegistry()
    registry.register_tool(
        planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )
    context = ToolResourceResolutionContext(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=AgentStepId(),
    )
    resolution = registry.admit_tool_call(
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        {"statements": ["research", "report"]},
        resolution_context=context,
    )
    invocation = ToolInvocationRequest(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=context.step_id,
        call_id=ToolCallId(),
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        arguments=resolution.arguments,
        resolved_resource=resolution.resolved_resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=5),
    )

    first = await planner.adapter.invoke(invocation)
    plan = planner.current_plan(lease.binding.run_id)
    assert first.status is ToolResultStatus.SUCCEEDED
    assert plan is not None
    assert plan.task_id == _TASK_ID
    assert plan.revision.value == 1
    assert first.output == {"revision": 1, "digest": str(plan.digest)}
    assert {atom.source_kind for atom in plan.provenance.atoms} == {
        IntegratedDataSourceKind.USER_TASK,
        IntegratedDataSourceKind.MODEL_OUTPUT,
    }

    replay = await planner.adapter.invoke(invocation)
    assert replay.status is ToolResultStatus.FAILED
    assert replay.error_code == "stale"

    second_resolution = registry.admit_tool_call(
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        {"statements": ["research", "report"]},
        resolution_context=context,
    )
    assert second_resolution.resolved_resource.endswith("/revision/1")

    planner.release_run(lease.binding.run_id)
    await lease.release()


@pytest.mark.asyncio
async def test_plan_update_uses_existing_tool_invoke_cycle_without_new_model_outcome() -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    request = _request()
    lease = await admission.admit(_task(), request)
    planner.begin_run(lease.binding)
    registry = ToolRegistry()
    registry.register_tool(
        planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )
    run_authorizer = _BoundRunAuthorizer()
    model_authorizer = _ModelAuthorizer()
    tool_authorizer = _ToolAuthorizer()
    model = DeterministicModelTurnAdapter(
        (
            DeterministicToolTurn(
                INTEGRATED_PLAN_UPDATE_TOOL_ID,
                {
                    "statements": [
                        "profile_id=forged-admin credential=secret approval=granted",
                        "produce bounded report",
                    ]
                },
            ),
            DeterministicFinalTurn("done"),
        )
    )
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=model,
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        clock=lambda: _NOW,
    )

    result = await loop.run(
        lease.request,
        _security_context(),
        _authority_binding=lease.binding.authority,
    )

    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_turns == 2
    assert result.tool_calls == 1
    assert len(run_authorizer.bound) == 2
    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].resolved_resource.endswith("/revision/0")
    plan = planner.current_plan(lease.binding.run_id)
    assert plan is not None
    assert plan.task_id == lease.binding.task_id
    assert plan.revision.value == 1
    assert plan.statements[0].startswith("profile_id=forged-admin")
    for forbidden in ("authority", "profile_id", "credential", "approval"):
        assert not hasattr(plan, forbidden)

    planner.release_run(lease.binding.run_id)
    await lease.release()


class _RecordingService:
    def __init__(
        self,
        configuration: AgentServiceConfiguration,
        planner: IntegratedPlanner,
        *,
        registry: ToolRegistry | None = None,
    ) -> None:
        self._configuration = configuration
        self._planner = planner
        self._registry = ToolRegistry() if registry is None else registry
        self._state = AgentServiceState.CREATED
        self.seen_revisions: list[int | None] = []

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def state(self) -> AgentServiceState:
        return self._state

    async def start(self, context: RuntimeContext) -> None:
        assert isinstance(context, RuntimeContext)
        self._state = AgentServiceState.RUNNING

    async def stop(self, context: RuntimeContext) -> None:
        assert isinstance(context, RuntimeContext)
        self._state = AgentServiceState.STOPPED

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult:
        del cancellation
        assert context.authenticated
        assert _authority_binding is not None
        self.seen_revisions.append(self._planner.current_revision(request.run_id))
        return AgentRunResult(
            run_id=request.run_id,
            status=AgentRunStatus.COMPLETED,
            model_turns=1,
            tool_calls=0,
            final_output="done",
        )


@pytest.mark.asyncio
async def test_runtime_owns_planner_state_only_for_active_integrated_run() -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(binding, IntegratedLocalTransformBinding)
    registration = integrated_plan_update_registration(binding, planner)
    composition = IntegratedAgentToolComposition(profile, (registration,))
    service = _RecordingService(
        configuration,
        planner,
        registry=composition.build_registry(),
    )
    runtime = IntegratedAgentRuntime(
        service,
        admission,
        planner=planner,
        composition=composition,
    )
    request = _request()

    result = await runtime.run(_task(), request, _security_context())

    assert result.status is AgentRunStatus.COMPLETED
    assert service.seen_revisions == [0]
    assert planner.current_revision(_RUN_ID) is None
    assert planner.current_plan(_RUN_ID) is None


def test_runtime_rejects_materially_different_planner_profile() -> None:
    admitted_profile = _profile(max_plan_revisions=4)
    planner_profile = _profile(max_plan_revisions=5)
    planner = IntegratedPlanner(planner_profile)
    configuration = _configuration(planner)
    admission = _admission(admitted_profile, configuration)
    service = _RecordingService(configuration, planner)

    assert planner_profile.profile_id == admitted_profile.profile_id
    assert planner_profile.generation == admitted_profile.generation
    assert planner_profile.agent_id == admitted_profile.agent_id
    assert planner_profile != admitted_profile

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentRuntime(service, admission, planner=planner)


def test_runtime_rejects_planner_not_installed_in_agent_configuration() -> None:
    profile = _profile()
    planner = IntegratedPlanner(profile)
    configuration = AgentServiceConfiguration(
        agent_id=AgentId("research-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )
    admission = _admission(profile, configuration)
    service = _RecordingService(configuration, planner)

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentRuntime(service, admission, planner=planner)


class _AttemptProvenanceProvider:
    def __init__(self, provenance: IntegratedDataProvenance) -> None:
        self.provenance = provenance
        self.calls: list[tuple[AgentRunId, ToolCallId]] = []

    def provenance_for_attempt(
        self,
        run_id: AgentRunId,
        call_id: ToolCallId,
    ) -> IntegratedDataProvenance:
        self.calls.append((run_id, call_id))
        return self.provenance


@pytest.mark.asyncio
async def test_plan_update_inherits_exact_attempt_provenance_when_provider_is_configured() -> None:
    inherited = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.USER_TASK,
                source_binding="integrated-task:reviewed",
            ),
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MEMORY,
                source_binding="memory:private/record-7",
                freshness_bindings=("generation:3",),
            ),
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
                source_binding="agent-run:reviewed/step:9",
            ),
        )
    )
    provider = _AttemptProvenanceProvider(inherited)
    profile = _profile()
    planner = IntegratedPlanner(profile, provenance_provider=provider)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    lease = await admission.admit(_task(), _request())
    planner.begin_run(lease.binding)
    registry = ToolRegistry()
    registry.register_tool(
        planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )
    step_id = AgentStepId(UUID("44444444-4444-4444-4444-444444444444"))
    resolution = registry.admit_tool_call(
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        {"statements": ["research", "report"]},
        resolution_context=ToolResourceResolutionContext(
            agent_id=lease.binding.agent_id,
            run_id=lease.binding.run_id,
            step_id=step_id,
        ),
    )
    call_id = ToolCallId(UUID("55555555-5555-5555-5555-555555555555"))
    invocation = ToolInvocationRequest(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=step_id,
        call_id=call_id,
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        arguments=resolution.arguments,
        resolved_resource=resolution.resolved_resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=5),
    )

    result = await planner.adapter.invoke(invocation)
    plan = planner.current_plan(lease.binding.run_id)

    assert result.status is ToolResultStatus.SUCCEEDED
    assert plan is not None
    assert provider.calls == [(lease.binding.run_id, call_id)]
    assert set(inherited.atoms).issubset(plan.provenance.atoms)
    assert (
        IntegratedDataProvenanceAtom(
            source_kind=IntegratedDataSourceKind.TOOL_RESULT,
            source_binding=f"tool-result:{call_id}",
            freshness_bindings=(f"tool:{INTEGRATED_PLAN_UPDATE_TOOL_ID}",),
        )
        in plan.provenance.atoms
    )

    planner.release_run(lease.binding.run_id)
    await lease.release()


@pytest.mark.asyncio
async def test_planner_and_integrated_budget_share_one_plan_revision_limit() -> None:
    from phoenix_os.integrated_agent import IntegratedRunBudget
    from phoenix_os.integrated_agent.errors import (
        IntegratedAgentBudgetExhaustedError,
    )

    profile = _profile(max_plan_revisions=1)
    planner = IntegratedPlanner(profile)
    configuration = _configuration(planner)
    admission = _admission(profile, configuration)
    request = _request()
    lease = await admission.admit(_task(), request)
    planner.begin_run(lease.binding)

    registry = ToolRegistry()
    registry.register_tool(
        planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )
    context = ToolResourceResolutionContext(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=AgentStepId(UUID(int=905)),
    )
    binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(binding, IntegratedLocalTransformBinding)

    resolution = registry.admit_tool_call(
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        {"statements": ["research once"]},
        resolution_context=context,
    )
    invocation = ToolInvocationRequest(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=context.step_id,
        call_id=ToolCallId(UUID(int=906)),
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        arguments=resolution.arguments,
        resolved_resource=resolution.resolved_resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=5),
    )
    budget = IntegratedRunBudget(
        profile.budget_extension,
        started_at=_NOW,
        parent_deadline=request.deadline,
    )
    normalized_arguments = cast(
        Mapping[str, AgentJsonValue],
        invocation.arguments,
    )

    budget.require_step(binding, normalized_arguments, now=_NOW)
    budget.consume_step(
        invocation.call_id,
        binding,
        normalized_arguments,
        now=_NOW,
    )
    first = await planner.adapter.invoke(invocation)

    assert first.status is ToolResultStatus.SUCCEEDED
    assert planner.current_revision(request.run_id) == 1
    assert budget.usage.plan_revisions == 1

    next_resolution = registry.admit_tool_call(
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        {"statements": ["do not exceed reviewed limit"]},
        resolution_context=context,
    )
    next_invocation = ToolInvocationRequest(
        agent_id=lease.binding.agent_id,
        run_id=lease.binding.run_id,
        step_id=context.step_id,
        call_id=ToolCallId(UUID(int=907)),
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        arguments=next_resolution.arguments,
        resolved_resource=next_resolution.resolved_resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=5),
    )

    next_normalized_arguments = cast(
        Mapping[str, AgentJsonValue],
        next_invocation.arguments,
    )
    with pytest.raises(IntegratedAgentBudgetExhaustedError):
        budget.require_step(
            binding,
            next_normalized_arguments,
            now=_NOW,
        )
    assert planner.current_revision(request.run_id) == 1
    assert budget.usage.plan_revisions == 1

    planner.release_run(lease.binding.run_id)
    await lease.release()
