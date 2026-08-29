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
    ToolCallId,
    ToolId,
)
from phoenix_os.agent.errors import AgentErrorCode
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    DeterministicModelTurnAdapter,
    DeterministicToolTurn,
)
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.memory_agent_tools import MemoryAgentToolBinding
from phoenix_os.agent.memory_authorization import (
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
    PolicyEngineMemoryAuthorizer,
    agent_memory_scope,
)
from phoenix_os.agent.memory_contracts import (
    MemoryId,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    memory_content_digest,
)
from phoenix_os.agent.memory_retrieval import (
    AgentMemoryService,
    DeterministicLexicalMemoryRetrievalAdapter,
)
from phoenix_os.agent.memory_store import InMemoryAgentMemoryStore
from phoenix_os.agent.service import AgentService
from phoenix_os.authority.catalog import NETWORK_HTTP_REQUEST_ACTION
from phoenix_os.events import EventBus
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.inference.authorization import PolicyEngineInferenceAuthorizer
from phoenix_os.integrated_agent import (
    IntegratedAgentAdmission,
    IntegratedAgentExecutionGuard,
    IntegratedAgentRuntime,
    IntegratedAgentToolComposition,
    IntegratedCapabilityProfileBinding,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedExecutionProfileSelection,
    IntegratedTaskId,
    IntegratedTaskRequest,
    integrated_memory_tool_registration,
    integrated_network_http_registration,
    integrated_network_profile_binding_id,
)
from phoenix_os.network_egress.agent_tools import NetworkEgressToolBinding
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
    NetworkHttpRequest,
    NetworkHttpResponse,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)
from phoenix_os.network_egress.service import (
    NetworkEgressCancellationToken,
    NetworkEgressFinalAdmissionValidator,
    NetworkEgressService,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 29, 1, 30, tzinfo=UTC)
_AGENT_ID = AgentId("research-agent")
_PROVIDER_ID = ModelProviderId("deterministic")
_MODEL_ID = ModelId("chat")
_MEMORY_NAMESPACE = MemoryNamespace("integrated-security")


def _allow_all_policy() -> PolicyEngine:
    return PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),))


def _deny_all_policy() -> PolicyEngine:
    return PolicyEngine((PolicyRule("deny", PolicyEffect.DENY),))


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="integrated-security",
    )


def _request(
    configuration: AgentServiceConfiguration,
    *,
    run_uuid: str,
) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "Use only reviewed capabilities and preserve data-flow boundaries.",
            ),
        ),
        limits=configuration.limits,
        run_id=AgentRunId(UUID(run_uuid)),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=10),
    )


def _task(task_uuid: str) -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(task_uuid)),
        objective="Exercise the reviewed security boundary.",
    )


def _route(
    route_id: str,
    source: IntegratedDataSourceKind,
    sink: IntegratedDataSink,
) -> IntegratedDataFlowRoute:
    return IntegratedDataFlowRoute(
        route_id=route_id,
        source_kind=source,
        sink=sink,
        disposition=IntegratedDataFlowDisposition.ALLOW,
    )


def _build_tool_runtime(
    profile: IntegratedExecutionProfile,
    composition: IntegratedAgentToolComposition,
    model: DeterministicModelTurnAdapter,
) -> tuple[
    IntegratedAgentRuntime,
    AgentService,
    IntegratedAgentAdmission,
]:
    configuration = AgentServiceConfiguration(
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        tools=tuple(AgentToolConfiguration(descriptor) for descriptor in composition.descriptors),
    )
    registry = composition.build_registry()
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
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
        composition=composition,
        execution_guard=guard,
    )
    return runtime, service, integrated_admission


class _CountingMemoryAuthorizer(PolicyEngineMemoryAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.search_calls = 0

    async def authorize_search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> None:
        self.search_calls += 1
        await super().authorize_search(request, context)


class _NeverCalledNetworkService(NetworkEgressService):
    def __init__(self) -> None:
        self.request_calls = 0

    async def request(
        self,
        request: NetworkHttpRequest,
        context: SecurityContext,
        *,
        cancellation: NetworkEgressCancellationToken | None = None,
        deadline: datetime | None = None,
        expected_profile: NetworkEgressProfile | None = None,
        final_admission: NetworkEgressFinalAdmissionValidator | None = None,
    ) -> NetworkHttpResponse:
        del request, context, cancellation, deadline, expected_profile, final_admission
        self.request_calls += 1
        raise AssertionError("network service must not be reached")


def _memory_binding(
    *,
    tool_id: str,
    action: str,
) -> MemoryAgentToolBinding:
    return MemoryAgentToolBinding(
        agent_id=_AGENT_ID,
        tool_id=ToolId(tool_id),
        namespace=_MEMORY_NAMESPACE,
        scope_kind=MemoryScopeKind.AGENT,
        action=action,
    )


def _memory_bridge(
    downstream: MemoryAgentToolBinding,
) -> IntegratedDownstreamBridgeBinding:
    return IntegratedDownstreamBridgeBinding(
        tool_id=downstream.tool_id,
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=downstream.binding_id,
        action_family=downstream.action,
    )


def _memory_capability(
    downstream: MemoryAgentToolBinding,
) -> IntegratedCapabilityProfileBinding:
    return IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=downstream.binding_id,
    )


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_tool_invoke_cannot_replace_downstream_memory_authority() -> None:
    downstream = _memory_binding(
        tool_id="research.memory.search",
        action=MEMORY_SEARCH_ACTION,
    )
    bridge = _memory_bridge(downstream)
    profile = IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("confused-deputy"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT_ID,
        tool_bindings=(bridge,),
        memory_binding=_memory_capability(downstream),
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                _route(
                    "user-model",
                    IntegratedDataSourceKind.USER_TASK,
                    IntegratedDataSink.MODEL,
                ),
                _route(
                    "user-memory",
                    IntegratedDataSourceKind.USER_TASK,
                    IntegratedDataSink.MEMORY,
                ),
                _route(
                    "model-memory",
                    IntegratedDataSourceKind.MODEL_OUTPUT,
                    IntegratedDataSink.MEMORY,
                ),
            )
        ),
    )
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    memory_authorizer = _CountingMemoryAuthorizer(_deny_all_policy())
    memory_service = AgentMemoryService(
        store=store,
        authorizer=memory_authorizer,
        retrieval=DeterministicLexicalMemoryRetrievalAdapter(store),
        clock=lambda: _NOW,
    )
    registration = integrated_memory_tool_registration(
        bridge,
        memory_service,
        downstream,
    )
    composition = IntegratedAgentToolComposition(profile, (registration,))
    model = DeterministicModelTurnAdapter(
        (
            DeterministicToolTurn(
                tool_id=downstream.tool_id,
                arguments={"query": "supplier"},
                call_id=ToolCallId(UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
            ),
        )
    )
    runtime, service, integrated_admission = _build_tool_runtime(
        profile,
        composition,
        model,
    )
    request = _request(
        service.configuration,
        run_uuid="33333333-3333-3333-3333-333333333333",
    )
    runtime_context = RuntimeContext(services={})

    await runtime.start(runtime_context)
    try:
        result = await runtime.run(
            _task("44444444-4444-4444-4444-444444444444"),
            request,
            _context(),
        )

        assert result.status is AgentRunStatus.FAILED
        assert result.final_output is None
        assert result.error_code == AgentErrorCode.TOOL_FAILED.value
        assert result.model_turns == 1
        assert result.tool_calls == 1
        assert memory_authorizer.search_calls == 1
        assert model.remaining_turns == 0
        assert await integrated_admission.binding_for_run(request.run_id) is None

        snapshot = await service.snapshot()
        assert snapshot.started == 1
        assert snapshot.completed == 0
        assert snapshot.rejected == 0
        assert snapshot.failed == 1
        assert snapshot.active == 0
    finally:
        await runtime.stop(runtime_context)


def _network_fixture() -> tuple[
    NetworkEgressProfile,
    NetworkEgressToolBinding,
    IntegratedDownstreamBridgeBinding,
    IntegratedCapabilityProfileBinding,
]:
    operation = NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("exfiltration-sink"),
        method=NetworkHttpMethod.GET,
        request_target="/sink",
        effect=NetworkOperationEffect.READ_ONLY,
        limits=NetworkOperationLimits(max_response_body_bytes=4096),
    )
    network_profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("reviewed-sink"),
        generation=3,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="example.com",
        operations=(operation,),
    )
    downstream = NetworkEgressToolBinding(
        agent_id=_AGENT_ID,
        tool_id=ToolId("research.network.sink"),
        profile=network_profile,
        operation_id=operation.operation_id,
    )
    binding_id = integrated_network_profile_binding_id(network_profile)
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=downstream.tool_id,
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=binding_id,
        generation=network_profile.generation,
        action_family=NETWORK_HTTP_REQUEST_ACTION,
    )
    capability = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=binding_id,
        generation=network_profile.generation,
    )
    return network_profile, downstream, bridge, capability


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_memory_content_cannot_be_exfiltrated_to_network_without_exact_route() -> None:
    memory_downstream = _memory_binding(
        tool_id="research.memory.read",
        action=MEMORY_READ_ACTION,
    )
    memory_bridge = _memory_bridge(memory_downstream)
    _network_profile, network_downstream, network_bridge, network_capability = _network_fixture()
    profile = IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("exfiltration-guard"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT_ID,
        tool_bindings=(memory_bridge, network_bridge),
        memory_binding=_memory_capability(memory_downstream),
        network_profile_binding=network_capability,
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                _route(
                    "user-model",
                    IntegratedDataSourceKind.USER_TASK,
                    IntegratedDataSink.MODEL,
                ),
                _route(
                    "model-model",
                    IntegratedDataSourceKind.MODEL_OUTPUT,
                    IntegratedDataSink.MODEL,
                ),
                _route(
                    "memory-model",
                    IntegratedDataSourceKind.MEMORY,
                    IntegratedDataSink.MODEL,
                ),
                _route(
                    "tool-model",
                    IntegratedDataSourceKind.TOOL_RESULT,
                    IntegratedDataSink.MODEL,
                ),
                _route(
                    "user-memory",
                    IntegratedDataSourceKind.USER_TASK,
                    IntegratedDataSink.MEMORY,
                ),
                _route(
                    "model-memory",
                    IntegratedDataSourceKind.MODEL_OUTPUT,
                    IntegratedDataSink.MEMORY,
                ),
                _route(
                    "user-network",
                    IntegratedDataSourceKind.USER_TASK,
                    IntegratedDataSink.NETWORK,
                ),
                _route(
                    "model-network",
                    IntegratedDataSourceKind.MODEL_OUTPUT,
                    IntegratedDataSink.NETWORK,
                ),
                _route(
                    "tool-network",
                    IntegratedDataSourceKind.TOOL_RESULT,
                    IntegratedDataSink.NETWORK,
                ),
            )
        ),
    )

    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    memory_service = AgentMemoryService(
        store=store,
        authorizer=PolicyEngineMemoryAuthorizer(_allow_all_policy()),
        retrieval=DeterministicLexicalMemoryRetrievalAdapter(store),
        clock=lambda: _NOW,
    )
    secret = "MEMORY_SECRET_MUST_NOT_REACH_NETWORK"
    memory_id = MemoryId(UUID("55555555-5555-5555-5555-555555555555"))
    await memory_service.write(
        MemoryWriteRequest(
            scope=agent_memory_scope(
                namespace=_MEMORY_NAMESPACE,
                agent_id=_AGENT_ID,
            ),
            memory_id=memory_id,
            content=secret,
            provenance=MemoryProvenance(
                origin=MemoryOriginKind.AGENT_REQUEST,
                content_digest=memory_content_digest(secret),
                attributes={"fixture": "reviewed"},
                created_at=_NOW,
            ),
            created_at=_NOW,
        ),
        _context(),
    )

    network_service = _NeverCalledNetworkService()
    memory_registration = integrated_memory_tool_registration(
        memory_bridge,
        memory_service,
        memory_downstream,
    )
    network_registration = integrated_network_http_registration(
        network_bridge,
        network_service,
        network_downstream,
    )
    composition = IntegratedAgentToolComposition(
        profile,
        (memory_registration, network_registration),
    )
    model = DeterministicModelTurnAdapter(
        (
            DeterministicToolTurn(
                tool_id=memory_downstream.tool_id,
                arguments={"memory_id": str(memory_id)},
                call_id=ToolCallId(UUID("66666666-6666-6666-6666-666666666666")),
            ),
            DeterministicToolTurn(
                tool_id=network_downstream.tool_id,
                arguments={},
                call_id=ToolCallId(UUID("77777777-7777-7777-7777-777777777777")),
            ),
        )
    )
    runtime, service, integrated_admission = _build_tool_runtime(
        profile,
        composition,
        model,
    )
    request = _request(
        service.configuration,
        run_uuid="88888888-8888-8888-8888-888888888888",
    )
    runtime_context = RuntimeContext(services={})

    await runtime.start(runtime_context)
    try:
        result = await runtime.run(
            _task("99999999-9999-9999-9999-999999999999"),
            request,
            _context(),
        )

        assert result.status is AgentRunStatus.FAILED
        assert result.final_output is None
        assert result.error_code == AgentErrorCode.AUTHORIZATION_REJECTED.value
        assert result.model_turns == 2
        assert result.tool_calls == 1
        assert model.remaining_turns == 0
        assert len(model.requests) == 2
        assert any(secret in message.content for message in model.requests[1].messages)
        assert network_service.request_calls == 0
        assert await integrated_admission.binding_for_run(request.run_id) is None

        snapshot = await service.snapshot()
        assert snapshot.started == 1
        assert snapshot.completed == 0
        assert snapshot.rejected == 1
        assert snapshot.failed == 0
        assert snapshot.active == 0
    finally:
        await runtime.stop(runtime_context)
