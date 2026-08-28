import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentId,
    AgentJsonInput,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ToolAdapter, ToolDescriptor
from phoenix_os.host_automation.contracts import HostEpoch
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    IntegratedAgentExecutionGuard,
    IntegratedBudgetExtension,
    IntegratedCapabilityProfileBinding,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedFailureClass,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentStaleError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.execution_guard import _tool_result_provenance
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 27, 20, tzinfo=UTC)


def _context() -> SecurityContext:
    return SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        session_id=UUID(int=77),
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "do the task"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )


def _descriptor(tool_id: str, *, effect: ToolEffect) -> ToolDescriptor:
    schema = ToolSchema(kind=ToolSchemaType.OBJECT)
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=tool_id,
        description="integrated guard test tool",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=4096,
        max_output_bytes=4096,
        timeout=timedelta(seconds=10),
        resolver_id=f"resolver.{tool_id}",
        adapter_id=f"adapter.{tool_id}",
    )


def _profile() -> IntegratedExecutionProfile:
    memory_binding_id = "agent-memory:research/scope:agent"
    network_binding_id = "network:profile/research"
    host_binding_id = "host-automation:integrated-host"
    memory = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("memory.read"),
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=memory_binding_id,
        action_family="memory.read",
    )
    network = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("network.request"),
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=network_binding_id,
        action_family="network.request",
        generation=3,
    )
    host = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("host.clipboard.write"),
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=host_binding_id,
        action_family="host.clipboard.write",
    )
    routes = (
        IntegratedDataFlowRoute(
            route_id="user-model",
            source_kind=IntegratedDataSourceKind.USER_TASK,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="model-model",
            source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="user-memory",
            source_kind=IntegratedDataSourceKind.USER_TASK,
            sink=IntegratedDataSink.MEMORY,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="model-memory",
            source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
            sink=IntegratedDataSink.MEMORY,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="memory-model",
            source_kind=IntegratedDataSourceKind.MEMORY,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="tool-model",
            source_kind=IntegratedDataSourceKind.TOOL_RESULT,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="user-network",
            source_kind=IntegratedDataSourceKind.USER_TASK,
            sink=IntegratedDataSink.NETWORK,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="model-network",
            source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
            sink=IntegratedDataSink.NETWORK,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
        IntegratedDataFlowRoute(
            route_id="tool-network",
            source_kind=IntegratedDataSourceKind.TOOL_RESULT,
            sink=IntegratedDataSink.NETWORK,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
    )
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=AgentId("assistant"),
        tool_bindings=(memory, network, host),
        data_flow_policy=IntegratedDataFlowPolicy(routes),
        budget_extension=IntegratedBudgetExtension(max_integrated_steps=8),
        memory_binding=IntegratedCapabilityProfileBinding(
            boundary=IntegratedDownstreamBoundary.MEMORY,
            binding_id=memory_binding_id,
        ),
        network_profile_binding=IntegratedCapabilityProfileBinding(
            boundary=IntegratedDownstreamBoundary.NETWORK,
            binding_id=network_binding_id,
            generation=3,
        ),
        host_profile_binding=IntegratedCapabilityProfileBinding(
            boundary=IntegratedDownstreamBoundary.HOST,
            binding_id=host_binding_id,
        ),
    )


def _turn(request: AgentRunRequest, step_id: AgentStepId) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=request.run_id,
        step_id=step_id,
        messages=request.messages,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def _invocation(
    request: AgentRunRequest,
    step_id: AgentStepId,
    call_id: ToolCallId,
    tool_id: str,
    resource: str,
) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=request.agent_id,
        run_id=request.run_id,
        step_id=step_id,
        call_id=call_id,
        tool_id=ToolId(tool_id),
        arguments={},
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


@pytest.mark.asyncio
async def test_tool_result_provenance_is_inherited_and_memory_to_network_denies() -> None:
    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    task = IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=1)),
        objective="Use reviewed data.",
    )
    token = AgentCancellationToken()
    context = _context()
    guard.begin_run(task, request)

    first_step = AgentStepId(UUID(int=2))
    await guard.before_model_turn(_turn(request, first_step), context, token)
    memory_descriptor = _descriptor("memory.read", effect=ToolEffect.READ_ONLY)
    memory_call = ToolCallId(UUID(int=3))
    memory_id = str(UUID(int=303))
    memory_incarnation = str(UUID(int=304))
    memory_invocation = _invocation(
        request,
        first_step,
        memory_call,
        "memory.read",
        (f"agent-memory:research/scope:agent:assistant/record:{memory_id}"),
    )
    await guard.before_tool_authorization(
        memory_invocation,
        memory_descriptor,
        context,
        token,
    )
    await guard.before_tool_invocation(
        memory_invocation,
        memory_descriptor,
        context,
        token,
    )
    await guard.after_tool_result(
        memory_invocation,
        memory_descriptor,
        ToolInvocationResult(
            run_id=request.run_id,
            step_id=first_step,
            call_id=memory_call,
            tool_id=ToolId("memory.read"),
            status=ToolResultStatus.SUCCEEDED,
            output={
                "found": True,
                "memory_id": memory_id,
                "incarnation": memory_incarnation,
                "version": 7,
                "content_digest": "sha256:" + "a" * 64,
            },
            started_at=_NOW,
            completed_at=_NOW,
        ),
        context,
        token,
    )

    provenance = guard.current_provenance(request.run_id)
    assert provenance is not None
    kinds = {atom.source_kind for atom in provenance.atoms}
    assert IntegratedDataSourceKind.MEMORY in kinds
    assert IntegratedDataSourceKind.TOOL_RESULT in kinds

    second_step = AgentStepId(UUID(int=4))
    await guard.before_model_turn(_turn(request, second_step), context, token)
    network_invocation = _invocation(
        request,
        second_step,
        ToolCallId(UUID(int=5)),
        "network.request",
        "network:profile/research",
    )
    with pytest.raises(AgentAuthorizationRejectedError):
        await guard.before_tool_authorization(
            network_invocation,
            _descriptor(
                "network.request",
                effect=ToolEffect.EXTERNAL_COMMUNICATION,
            ),
            context,
            token,
        )

    assert guard.failure_for(request.run_id) is IntegratedFailureClass.DATA_FLOW_DENIED


@pytest.mark.asyncio
async def test_final_output_is_not_released_without_exact_user_result_routes() -> None:
    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    task = IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=6)),
        objective="Return reviewed data.",
    )
    guard.begin_run(task, request)
    token = AgentCancellationToken()
    turn = _turn(request, AgentStepId(UUID(int=7)))
    await guard.before_model_turn(turn, _context(), token)

    with pytest.raises(AgentAuthorizationRejectedError):
        await guard.before_final_output(
            turn,
            "protected result",
            _context(),
            token,
        )

    assert guard.failure_for(request.run_id) is IntegratedFailureClass.DATA_FLOW_DENIED


def test_execution_guard_exposes_only_pending_exact_attempt_provenance() -> None:
    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    task = IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=301)),
        objective="Use reviewed data.",
    )
    guard.begin_run(task, request)

    with pytest.raises(IntegratedAgentStaleError):
        guard.provenance_for_attempt(
            request.run_id,
            ToolCallId(UUID(int=302)),
        )


@pytest.mark.asyncio
async def test_indeterminate_effect_blocks_later_effectful_integrated_attempt() -> None:
    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=501)),
            objective="Perform one bounded effect.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=502))
    await guard.before_model_turn(_turn(request, step), context, token)
    descriptor = _descriptor(
        "network.request",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )
    first = _invocation(
        request,
        step,
        ToolCallId(UUID(int=503)),
        "network.request",
        "network:profile/research",
    )
    await guard.before_tool_authorization(first, descriptor, context, token)
    await guard.before_tool_invocation(first, descriptor, context, token)
    await guard.after_tool_result(
        first,
        descriptor,
        ToolInvocationResult(
            run_id=request.run_id,
            step_id=step,
            call_id=first.call_id,
            tool_id=first.tool_id,
            status=ToolResultStatus.INDETERMINATE,
            error_code="timeout",
            started_at=_NOW,
            completed_at=_NOW,
        ),
        context,
        token,
    )

    second = _invocation(
        request,
        step,
        ToolCallId(UUID(int=504)),
        "network.request",
        "network:profile/research",
    )
    with pytest.raises(ToolExecutionError):
        await guard.before_tool_authorization(second, descriptor, context, token)

    assert guard.failure_for(request.run_id) is IntegratedFailureClass.INDETERMINATE_EFFECT


@pytest.mark.asyncio
async def test_final_admission_observes_cancellation_before_effect() -> None:
    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=511)),
            objective="Perform one bounded effect.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=512))
    await guard.before_model_turn(_turn(request, step), context, token)
    descriptor = _descriptor(
        "network.request",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )
    invocation = _invocation(
        request,
        step,
        ToolCallId(UUID(int=513)),
        "network.request",
        "network:profile/research",
    )
    await guard.before_tool_authorization(invocation, descriptor, context, token)
    await guard.before_tool_invocation(invocation, descriptor, context, token)
    token.cancel()

    with pytest.raises(AgentCancelledError):
        await guard.final_tool_admission(
            invocation,
            descriptor,
            context,
            token,
        )


@pytest.mark.asyncio
async def test_final_admission_observes_integrated_deadline_before_effect() -> None:
    current = _NOW

    def clock() -> datetime:
        return current

    guard = IntegratedAgentExecutionGuard(_profile(), clock=clock)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=521)),
            objective="Perform one bounded effect.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=522))
    await guard.before_model_turn(_turn(request, step), context, token)
    descriptor = _descriptor(
        "network.request",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )
    invocation = _invocation(
        request,
        step,
        ToolCallId(UUID(int=523)),
        "network.request",
        "network:profile/research",
    )
    await guard.before_tool_authorization(invocation, descriptor, context, token)
    await guard.before_tool_invocation(invocation, descriptor, context, token)
    current = request.deadline

    with pytest.raises(AgentTimeoutError):
        await guard.final_tool_admission(
            invocation,
            descriptor,
            context,
            token,
        )


@pytest.mark.asyncio
async def test_memory_boundary_requires_explicit_memory_sink_route() -> None:
    profile = _profile()
    restricted = replace(
        profile,
        data_flow_policy=IntegratedDataFlowPolicy(
            tuple(
                route
                for route in profile.data_flow_policy.routes
                if route.sink is not IntegratedDataSink.MEMORY
            )
        ),
    )
    guard = IntegratedAgentExecutionGuard(restricted, clock=lambda: _NOW)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=601)),
            objective="Read one reviewed memory.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=602))
    await guard.before_model_turn(_turn(request, step), context, token)

    with pytest.raises(AgentAuthorizationRejectedError):
        await guard.before_tool_authorization(
            _invocation(
                request,
                step,
                ToolCallId(UUID(int=603)),
                "memory.read",
                "memory:research/record-1",
            ),
            _descriptor("memory.read", effect=ToolEffect.READ_ONLY),
            context,
            token,
        )

    assert guard.failure_for(request.run_id) is IntegratedFailureClass.DATA_FLOW_DENIED


@pytest.mark.asyncio
async def test_host_effect_requires_explicit_host_effect_sink_route() -> None:
    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=611)),
            objective="Write one reviewed clipboard value.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=612))
    await guard.before_model_turn(_turn(request, step), context, token)

    with pytest.raises(AgentAuthorizationRejectedError):
        await guard.before_tool_authorization(
            _invocation(
                request,
                step,
                ToolCallId(UUID(int=613)),
                "host.clipboard.write",
                "host-automation:integrated-host/clipboard",
            ),
            _descriptor(
                "host.clipboard.write",
                effect=ToolEffect.IRREVERSIBLE_WRITE,
            ),
            context,
            token,
        )

    assert guard.failure_for(request.run_id) is IntegratedFailureClass.DATA_FLOW_DENIED


class _EpochToolAdapter:
    adapter_id = "epoch-test"
    tool_id = ToolId("host.clipboard.read")

    def __init__(self, epoch: HostEpoch) -> None:
        self._epoch = epoch

    @property
    def host_epoch(self) -> HostEpoch:
        return self._epoch

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise AssertionError("test adapter must not be invoked")


def _base_provenance() -> IntegratedDataProvenance:
    return IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.USER_TASK,
                source_binding="integrated-task:00000000-0000-0000-0000-000000000700",
            ),
        )
    )


def _successful_result(
    invocation: ToolInvocationRequest,
    output: dict[str, AgentJsonInput],
) -> ToolInvocationResult:
    return ToolInvocationResult(
        run_id=invocation.run_id,
        step_id=invocation.step_id,
        call_id=invocation.call_id,
        tool_id=invocation.tool_id,
        status=ToolResultStatus.SUCCEEDED,
        output=output,
        started_at=_NOW,
        completed_at=_NOW,
    )


def _exact_invocation(
    *,
    tool_id: str,
    resource: str,
    arguments: dict[str, AgentJsonInput] | None = None,
    call: int,
) -> ToolInvocationRequest:
    request = _request()
    return ToolInvocationRequest(
        agent_id=request.agent_id,
        run_id=request.run_id,
        step_id=AgentStepId(UUID(int=call + 1)),
        call_id=ToolCallId(UUID(int=call)),
        tool_id=ToolId(tool_id),
        arguments={} if arguments is None else arguments,
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_exact_memory_result_provenance_binds_record_freshness() -> None:
    memory_id = str(UUID(int=701))
    incarnation = str(UUID(int=702))
    resource = f"agent-memory:research/scope:agent:assistant/record:{memory_id}"
    invocation = _exact_invocation(
        tool_id="memory.read",
        resource=resource,
        arguments={"memory_id": memory_id},
        call=703,
    )
    binding = IntegratedDownstreamBridgeBinding(
        tool_id=invocation.tool_id,
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id="agent-memory:research/scope:agent",
        action_family="memory.read",
    )
    provenance = _tool_result_provenance(
        _base_provenance(),
        binding,
        invocation,
        _successful_result(
            invocation,
            {
                "found": True,
                "memory_id": memory_id,
                "incarnation": incarnation,
                "version": 9,
                "content_digest": "sha256:" + "b" * 64,
            },
        ),
    )

    atom = next(
        item for item in provenance.atoms if item.source_kind is IntegratedDataSourceKind.MEMORY
    )
    assert atom.source_binding == resource
    assert f"incarnation:{incarnation}" in atom.freshness_bindings
    assert "version:9" in atom.freshness_bindings
    assert "content-digest:sha256:" + "b" * 64 in atom.freshness_bindings


def test_exact_workspace_result_provenance_binds_artifact_freshness() -> None:
    artifact_id = str(UUID(int=711))
    resource = f"agent-workspace:research/scope:agent:assistant/artifact:{artifact_id}"
    invocation = _exact_invocation(
        tool_id="workspace.read",
        resource=resource,
        arguments={"artifact_id": artifact_id},
        call=712,
    )
    binding = IntegratedDownstreamBridgeBinding(
        tool_id=invocation.tool_id,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id="agent-workspace:research/scope:agent",
        action_family="workspace.read",
    )
    provenance = _tool_result_provenance(
        _base_provenance(),
        binding,
        invocation,
        _successful_result(
            invocation,
            {
                "found": True,
                "artifact_id": artifact_id,
                "version": 4,
                "content_digest": "sha256:" + "c" * 64,
            },
        ),
    )

    atom = next(
        item for item in provenance.atoms if item.source_kind is IntegratedDataSourceKind.WORKSPACE
    )
    assert atom.source_binding == resource
    assert "version:4" in atom.freshness_bindings
    assert "content-digest:sha256:" + "c" * 64 in atom.freshness_bindings


def test_exact_network_and_browser_result_provenance_preserves_generation() -> None:
    network_resource = "network-egress:research/generation:4/operation:lookup"
    network_invocation = _exact_invocation(
        tool_id="network.lookup",
        resource=network_resource,
        call=721,
    )
    network_binding = IntegratedDownstreamBridgeBinding(
        tool_id=network_invocation.tool_id,
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id="network:profile/research",
        generation=4,
        action_family="network.http.request",
    )
    network_provenance = _tool_result_provenance(
        _base_provenance(),
        network_binding,
        network_invocation,
        _successful_result(network_invocation, {"status_code": 200}),
    )
    network_atom = next(
        item
        for item in network_provenance.atoms
        if item.source_kind is IntegratedDataSourceKind.NETWORK
    )
    assert network_atom.source_binding == network_resource
    assert "binding-generation:4" in network_atom.freshness_bindings

    session_id = str(UUID(int=722))
    page_id = str(UUID(int=723))
    browser_invocation = _exact_invocation(
        tool_id="browser.page.read",
        resource=("browser:research/generation:9/action:browser.page.read/tool:browser.page.read"),
        arguments={
            "session_id": session_id,
            "page_id": page_id,
            "revision": 6,
        },
        call=724,
    )
    browser_binding = IntegratedDownstreamBridgeBinding(
        tool_id=browser_invocation.tool_id,
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id="browser:profile/research",
        generation=9,
        action_family="browser.page.read",
    )
    browser_provenance = _tool_result_provenance(
        _base_provenance(),
        browser_binding,
        browser_invocation,
        _successful_result(
            browser_invocation,
            {
                "session_id": session_id,
                "page_id": page_id,
                "revision": 7,
            },
        ),
    )
    browser_atom = next(
        item
        for item in browser_provenance.atoms
        if item.source_kind is IntegratedDataSourceKind.BROWSER
    )
    assert browser_atom.source_binding == (
        f"browser:profile/research/generation:9/session:{session_id}/page:{page_id}"
    )
    assert "revision:7" in browser_atom.freshness_bindings


def test_host_clipboard_provenance_uses_epoch_out_of_band_and_content_digest() -> None:
    epoch = HostEpoch(UUID(int=731))
    binding_id = "host-automation:host:integrated-host"
    invocation = _exact_invocation(
        tool_id="host.clipboard.read",
        resource=f"{binding_id}/clipboard:text",
        call=732,
    )
    binding = IntegratedDownstreamBridgeBinding(
        tool_id=invocation.tool_id,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=binding_id,
        action_family="host.clipboard.read",
    )
    result = _successful_result(invocation, {"text": "reviewed clipboard"})
    adapter: ToolAdapter = _EpochToolAdapter(epoch)

    provenance = _tool_result_provenance(
        _base_provenance(),
        binding,
        invocation,
        result,
        adapter=adapter,
    )
    atom = next(
        item
        for item in provenance.atoms
        if item.source_kind is IntegratedDataSourceKind.HOST_CLIPBOARD
    )
    assert atom.source_binding == f"{binding_id}/epoch:{epoch}/clipboard:text"
    digest = "sha256:" + hashlib.sha256(b"reviewed clipboard").hexdigest()
    assert f"content-digest:{digest}" in atom.freshness_bindings

    with pytest.raises(IntegratedAgentValidationError):
        _tool_result_provenance(
            _base_provenance(),
            binding,
            invocation,
            result,
        )


@pytest.mark.asyncio
async def test_memory_write_final_admission_issues_exact_lineage_grant() -> None:
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_from_persistence_attributes,
    )

    profile = _profile()
    assert profile.memory_binding is not None
    write_binding = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("memory.write"),
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=profile.memory_binding.binding_id,
        action_family="memory.write",
        generation=profile.memory_binding.generation,
    )
    profile = replace(
        profile,
        tool_bindings=(*profile.tool_bindings, write_binding),
    )
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=701)),
            objective="Persist reviewed derived memory.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=702))
    await guard.before_model_turn(_turn(request, step), context, token)
    memory_id = UUID(int=703)
    invocation = _invocation(
        request,
        step,
        ToolCallId(UUID(int=704)),
        "memory.write",
        (f"agent-memory:research/scope:agent:assistant/record:{memory_id}"),
    )
    descriptor = _descriptor(
        "memory.write",
        effect=ToolEffect.REVERSIBLE_WRITE,
    )
    await guard.before_tool_authorization(
        invocation,
        descriptor,
        context,
        token,
    )
    await guard.before_tool_invocation(
        invocation,
        descriptor,
        context,
        token,
    )

    expected = guard.provenance_for_attempt(
        request.run_id,
        invocation.call_id,
    )
    grant = await guard.final_tool_admission(
        invocation,
        descriptor,
        context,
        token,
    )

    assert grant is not None
    assert (
        integrated_provenance_from_persistence_attributes(grant.provenance_attributes) == expected
    )


@pytest.mark.asyncio
async def test_final_admission_rehydrates_exact_persisted_lineage() -> None:
    from phoenix_os.agent.tools import ToolFinalAdmissionContext
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_to_persistence_attributes,
    )

    guard = IntegratedAgentExecutionGuard(_profile(), clock=lambda: _NOW)
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=741)),
            objective="Read one persisted reviewed memory.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=742))
    await guard.before_model_turn(_turn(request, step), context, token)

    memory_id = UUID(int=743)
    invocation = _invocation(
        request,
        step,
        ToolCallId(UUID(int=744)),
        "memory.read",
        (f"agent-memory:research/scope:agent:assistant/record:{memory_id}"),
    )
    descriptor = _descriptor("memory.read", effect=ToolEffect.READ_ONLY)
    await guard.before_tool_authorization(
        invocation,
        descriptor,
        context,
        token,
    )
    await guard.before_tool_invocation(
        invocation,
        descriptor,
        context,
        token,
    )

    persisted_atom = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.NETWORK,
        source_binding="network:profile/research/generation:3/operation:fetch",
        freshness_bindings=("profile-generation:3",),
    )
    persisted = IntegratedDataProvenance((persisted_atom,))
    await guard.final_tool_admission(
        invocation,
        descriptor,
        context,
        token,
        ToolFinalAdmissionContext(
            source_provenance_attributes=(
                integrated_provenance_to_persistence_attributes(persisted),
            ),
        ),
    )

    pending = guard.provenance_for_attempt(
        request.run_id,
        invocation.call_id,
    )
    assert persisted_atom in pending.atoms


def _workspace_export_profile(
    *,
    allow_network_export: bool,
) -> IntegratedExecutionProfile:
    from dataclasses import replace as dataclass_replace

    base = _profile()
    binding_id = "agent-workspace:research/scope:agent"
    workspace = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("workspace.export"),
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=binding_id,
        action_family="workspace.export",
    )
    routes = list(base.data_flow_policy.routes)
    routes.extend(
        (
            IntegratedDataFlowRoute(
                route_id="user-workspace-export",
                source_kind=IntegratedDataSourceKind.USER_TASK,
                sink=IntegratedDataSink.WORKSPACE_EXPORT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
            ),
            IntegratedDataFlowRoute(
                route_id="model-workspace-export",
                source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
                sink=IntegratedDataSink.WORKSPACE_EXPORT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
            ),
            IntegratedDataFlowRoute(
                route_id="workspace-workspace-export",
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                sink=IntegratedDataSink.WORKSPACE_EXPORT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                source_scope=("agent-workspace:research/scope:agent:assistant"),
            ),
        )
    )
    if allow_network_export:
        routes.append(
            IntegratedDataFlowRoute(
                route_id="network-workspace-export",
                source_kind=IntegratedDataSourceKind.NETWORK,
                sink=IntegratedDataSink.WORKSPACE_EXPORT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                source_scope="network:profile/research",
                required_freshness_bindings=("binding-generation:3",),
            )
        )
    return dataclass_replace(
        base,
        tool_bindings=(*base.tool_bindings, workspace),
        data_flow_policy=IntegratedDataFlowPolicy(tuple(routes)),
        workspace_binding=IntegratedCapabilityProfileBinding(
            boundary=IntegratedDownstreamBoundary.WORKSPACE,
            binding_id=binding_id,
        ),
    )


async def _prepare_workspace_export_attempt(
    guard: IntegratedAgentExecutionGuard,
    *,
    artifact_id: str,
    version: int,
) -> tuple[
    AgentRunRequest,
    ToolInvocationRequest,
    ToolDescriptor,
    AgentCancellationToken,
    SecurityContext,
]:
    request = _request()
    guard.begin_run(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID(int=801)),
            objective="Export one reviewed persisted artifact.",
        ),
        request,
    )
    token = AgentCancellationToken()
    context = _context()
    step = AgentStepId(UUID(int=802))
    await guard.before_model_turn(_turn(request, step), context, token)
    invocation = ToolInvocationRequest(
        agent_id=request.agent_id,
        run_id=request.run_id,
        step_id=step,
        call_id=ToolCallId(UUID(int=803)),
        tool_id=ToolId("workspace.export"),
        arguments={
            "artifact_id": artifact_id,
            "expected_version": version,
            "destination_reference": "reviewed-destination",
        },
        resolved_resource=(
            f"agent-workspace:research/scope:agent:assistant/artifact:{artifact_id}"
        ),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    descriptor = _descriptor(
        "workspace.export",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )
    await guard.before_tool_authorization(
        invocation,
        descriptor,
        context,
        token,
    )
    await guard.before_tool_invocation(
        invocation,
        descriptor,
        context,
        token,
    )
    return request, invocation, descriptor, token, context


@pytest.mark.asyncio
async def test_workspace_export_rehydrates_lineage_and_denies_before_effect() -> None:
    from phoenix_os.agent.tools import ToolFinalAdmissionContext
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_to_persistence_attributes,
    )

    guard = IntegratedAgentExecutionGuard(
        _workspace_export_profile(allow_network_export=False),
        clock=lambda: _NOW,
    )
    artifact_id = str(UUID(int=804))
    version = 4
    request, invocation, descriptor, token, context = await _prepare_workspace_export_attempt(
        guard,
        artifact_id=artifact_id,
        version=version,
    )
    persisted = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.NETWORK,
                source_binding=("network:profile/research/generation:3/operation:fetch"),
                freshness_bindings=("binding-generation:3",),
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await guard.final_tool_admission(
            invocation,
            descriptor,
            context,
            token,
            ToolFinalAdmissionContext(
                source_provenance_attributes=(
                    integrated_provenance_to_persistence_attributes(persisted),
                ),
                source_record_version=version,
                source_content_digest="sha256:" + "d" * 64,
            ),
        )

    assert guard.failure_for(request.run_id) is IntegratedFailureClass.DATA_FLOW_DENIED


@pytest.mark.asyncio
async def test_workspace_export_admits_exact_artifact_source_freshness() -> None:
    from phoenix_os.agent.tools import ToolFinalAdmissionContext
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_to_persistence_attributes,
    )

    guard = IntegratedAgentExecutionGuard(
        _workspace_export_profile(allow_network_export=True),
        clock=lambda: _NOW,
    )
    artifact_id = str(UUID(int=805))
    version = 7
    request, invocation, descriptor, token, context = await _prepare_workspace_export_attempt(
        guard,
        artifact_id=artifact_id,
        version=version,
    )
    persisted_atom = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.NETWORK,
        source_binding=("network:profile/research/generation:3/operation:fetch"),
        freshness_bindings=("binding-generation:3",),
    )
    digest = "sha256:" + "e" * 64
    await guard.final_tool_admission(
        invocation,
        descriptor,
        context,
        token,
        ToolFinalAdmissionContext(
            source_provenance_attributes=(
                integrated_provenance_to_persistence_attributes(
                    IntegratedDataProvenance((persisted_atom,))
                ),
            ),
            source_record_version=version,
            source_content_digest=digest,
        ),
    )

    pending = guard.provenance_for_attempt(
        request.run_id,
        invocation.call_id,
    )
    assert persisted_atom in pending.atoms
    workspace_atom = next(
        atom for atom in pending.atoms if atom.source_kind is IntegratedDataSourceKind.WORKSPACE
    )
    assert workspace_atom.source_binding == invocation.resolved_resource
    assert f"version:{version}" in workspace_atom.freshness_bindings
    assert f"content-digest:{digest}" in workspace_atom.freshness_bindings
