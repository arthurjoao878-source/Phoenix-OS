from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from phoenix_os.agent import (
    AgentAuthorizationRejectedError,
    AgentCancellationToken,
    AgentId,
    AgentLimitExceededError,
    AgentLimits,
    AgentLoop,
    AgentMalformedProposalError,
    AgentMessage,
    AgentMessageRole,
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentModelTurnResult,
    AgentRunRequest,
    AgentRunStatus,
    AgentServiceUnavailableError,
    AgentStepId,
    BoundedAgentExecutor,
    DefaultAgentInferenceRequestFactory,
    InferenceBackedAgentModelTurnAdapter,
    ToolCallId,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolOutputSchema,
    ToolRegistry,
    ToolSchema,
    ToolSchemaType,
    decode_agent_model_turn_envelope,
    validate_agent_run_model_turn_inference_binding,
)
from phoenix_os.events import EventBus
from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceRequest,
    ModelDescriptor,
    ModelId,
    ModelProviderId,
)
from phoenix_os.inference.configuration import (
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
)
from phoenix_os.inference.execution import InferenceRuntime
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.inference.service import InferenceService
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _run_request(now: datetime) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "perform the task"),),
        limits=AgentLimits(max_output_tokens=128),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )


def _turn(request: AgentRunRequest, now: datetime, *tools: ToolDescriptor) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=request.run_id,
        step_id=AgentStepId(),
        messages=request.messages,
        tools=tools,
        created_at=now,
        deadline=now + timedelta(seconds=30),
    )


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "key": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"key"}),
    )


def _descriptor() -> ToolDescriptor:
    schema = _schema()
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="Look up one reviewed value.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=5),
        resolver_id="static-resource",
        adapter_id="deterministic-read-only",
    )


class _RecordingInferenceAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)
        self.contexts.append(context)


class _RunAuthorizer:
    def __init__(self) -> None:
        self.requests: list[AgentRunRequest] = []

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)


class _ModelAuthorizer(_RecordingInferenceAuthorizer):
    pass


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
        assert request.tool_id == descriptor.tool_id
        self.requests.append(request)


def _inference_service(
    response_text: str,
) -> tuple[
    InferenceService,
    DeterministicModelProvider,
    _RecordingInferenceAuthorizer,
]:
    provider_id = ModelProviderId("local")
    model_id = ModelId("chat")
    provider = DeterministicModelProvider(
        {model_id: response_text},
        provider_id=provider_id,
    )
    descriptor = ModelDescriptor(
        provider_id=provider_id,
        model_id=model_id,
        provider_model_name="fixture-chat",
        capabilities=provider.capabilities,
    )
    configuration = InferenceServiceConfiguration(
        providers=(InferenceProviderConfiguration(provider_id=provider_id),),
        models=(descriptor,),
    )
    registry = ModelProviderRegistry()
    registry.register_provider(provider)
    registry.register_model(descriptor)
    authorizer = _RecordingInferenceAuthorizer()
    runtime = InferenceRuntime(registry, authorizer)
    service = InferenceService(
        runtime,
        registry,
        configuration,
        events=EventBus(),
    )
    return service, provider, authorizer


def test_structured_model_turn_envelope_decodes_exact_final_or_one_tool() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    turn = _turn(run, now, _descriptor())

    final = decode_agent_model_turn_envelope(
        '{"version":1,"kind":"final","content":"done"}',
        turn,
    )
    assert final.kind is AgentModelTurnKind.FINAL_OUTPUT
    assert final.final_output == "done"

    tool = decode_agent_model_turn_envelope(
        '{"version":1,"kind":"tool","tool":"lookup","arguments":{"key":"alpha"}}',
        turn,
    )
    assert tool.kind is AgentModelTurnKind.TOOL_PROPOSAL
    assert tool.proposal is not None
    assert tool.proposal.tool_id == ToolId("lookup")
    assert tool.proposal.arguments == {"key": "alpha"}

    malformed = (
        '{"version":1,"kind":"final","content":"a","content":"b"}',
        '{"version":1,"kind":"tool","tool":"lookup","arguments":{},"content":"mixed"}',
        '{"version":1,"kind":"tool","tool":"unknown","arguments":{}}',
        '{"version":1,"kind":"tool","tool":"lookup","arguments":[]}',
        '{"version":2,"kind":"final","content":"wrong version"}',
        '{"version":1,"kind":"tool","tool":["lookup","other"],"arguments":{}}',
        '{"version":1,"kind":"tool","tool":"lookup","arguments":{},"tools":["lookup"]}',
    )
    for value in malformed:
        with pytest.raises(AgentMalformedProposalError):
            decode_agent_model_turn_envelope(value, turn)


def test_inference_factory_prepends_bounded_phoenix_context_for_admitted_tools() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    descriptor = _descriptor()
    turn = _turn(run, now, descriptor)

    inference = DefaultAgentInferenceRequestFactory().create(run, turn)

    assert inference.messages[0].role.value == "system"
    assert inference.messages[0].metadata == {"phoenix_model_turn_protocol": "1"}
    context = json.loads(inference.messages[0].content)
    assert context["version"] == 1
    assert context["kind"] == "phoenix.agent.model-turn-context"
    assert context["tool_outcome_allowed"] is True
    assert context["result_contract"]["final"] == {
        "version": 1,
        "kind": "final",
        "content": "string",
    }
    assert context["result_contract"]["tool"] == {
        "version": 1,
        "kind": "tool",
        "tool": "tool_id",
        "arguments": {},
    }
    assert len(context["tools"]) == 1
    tool = context["tools"][0]
    assert set(tool) == {
        "tool_id",
        "name",
        "description",
        "input_schema",
        "effect",
        "approval_may_be_required",
    }
    assert tool["tool_id"] == "lookup"
    assert tool["input_schema"]["type"] == "object"
    assert tool["input_schema"]["required"] == ["key"]
    assert tool["input_schema"]["additionalProperties"] is False
    assert "resolver_id" not in tool
    assert "adapter_id" not in tool
    assert "output_schema" not in tool
    assert "metadata" not in tool
    assert inference.messages[1].content == "perform the task"


def test_inference_factory_wraps_tool_results_as_untrusted_model_data() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    call_id = ToolCallId()
    tool_message = AgentMessage(
        AgentMessageRole.TOOL,
        '{"key":"value"}',
        tool_call_id=call_id,
        metadata={"tool_id": "lookup"},
    )
    turn = AgentModelTurnRequest(
        run_id=run.run_id,
        step_id=AgentStepId(),
        messages=(*run.messages, tool_message),
        tools=(_descriptor(),),
        created_at=now,
        deadline=now + timedelta(seconds=30),
    )

    inference = DefaultAgentInferenceRequestFactory().create(run, turn)
    translated = inference.messages[-1]

    assert translated.role.value == "user"
    assert translated.metadata["agent_role"] == "tool"
    assert translated.metadata["trust"] == "untrusted_tool_output"
    wrapped = json.loads(translated.content)
    assert wrapped == {
        "version": 1,
        "kind": "phoenix.agent.tool-result",
        "tool_call_id": str(call_id),
        "tool_id": "lookup",
        "trust": "untrusted_tool_output",
        "content": '{"key":"value"}',
    }


def test_inference_factory_fails_closed_when_tool_context_exceeds_bound() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    tools = tuple(
        replace(
            _descriptor(),
            tool_id=ToolId(f"lookup-{index}"),
            description="x" * 2_048,
        )
        for index in range(20)
    )
    turn = _turn(run, now, *tools)

    with pytest.raises(AgentLimitExceededError):
        DefaultAgentInferenceRequestFactory().create(run, turn)


def test_run_turn_inference_binding_rejects_model_or_message_redirection() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    turn = _turn(run, now)
    inference = DefaultAgentInferenceRequestFactory().create(run, turn)

    validate_agent_run_model_turn_inference_binding(run, turn, inference)

    rejected = (
        replace(inference, provider_id=ModelProviderId("other")),
        replace(inference, model_id=ModelId("other")),
        replace(inference, max_output_tokens=run.limits.max_output_tokens + 1),
        replace(inference, deadline=turn.deadline + timedelta(microseconds=1)),
        replace(inference, correlation_id="redirected-correlation"),
        replace(
            inference,
            metadata={
                "agent_run_id": str(turn.run_id),
                "agent_step_id": str(AgentStepId()),
            },
        ),
        replace(
            inference,
            messages=(replace(inference.messages[0], content="redirected content"),),
        ),
    )
    for redirected in rejected:
        with pytest.raises(AgentAuthorizationRejectedError):
            validate_agent_run_model_turn_inference_binding(
                run,
                turn,
                redirected,
            )


@pytest.mark.asyncio
async def test_inference_backed_adapter_requires_bound_path_and_uses_service_once() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    turn = _turn(run, now)
    inference = DefaultAgentInferenceRequestFactory().create(run, turn)
    service, provider, runtime_authorizer = _inference_service(
        '{"version":1,"kind":"final","content":"done"}'
    )
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)
    adapter = InferenceBackedAgentModelTurnAdapter(service)
    context = _context()

    try:
        with pytest.raises(AgentServiceUnavailableError):
            await adapter.complete_turn(turn)
        assert len(provider.requests) == 0

        result = await BoundedAgentExecutor().complete_model_turn(
            adapter,
            turn,
            inference_request=inference,
            context=context,
            timeout_seconds=5,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )
    finally:
        await service.stop(runtime_context)

    assert result.kind is AgentModelTurnKind.FINAL_OUTPUT
    assert result.final_output == "done"
    assert len(provider.requests) == 1
    assert provider.requests[0] is inference
    assert runtime_authorizer.requests == [inference]
    assert len(runtime_authorizer.contexts) == 1
    assert runtime_authorizer.contexts[0] is context


@pytest.mark.asyncio
async def test_agent_loop_real_turn_reuses_exact_inference_request_through_rfc0026() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    service, provider, runtime_authorizer = _inference_service(
        '{"version":1,"kind":"final","content":"complete"}'
    )
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    run_authorizer = _RunAuthorizer()
    model_authorizer = _ModelAuthorizer()
    tool_authorizer = _ToolAuthorizer()
    adapter = InferenceBackedAgentModelTurnAdapter(service)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=adapter,
        registry=ToolRegistry(),
    )
    context = _context()

    try:
        result = await loop.run(run, context)
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert len(run_authorizer.requests) == 2
    assert len(model_authorizer.requests) == 2
    assert model_authorizer.requests[0] is model_authorizer.requests[1]
    assert len(model_authorizer.contexts) == 2
    assert all(item is context for item in model_authorizer.contexts)
    assert runtime_authorizer.requests == [model_authorizer.requests[0]]
    assert len(runtime_authorizer.contexts) == 1
    assert runtime_authorizer.contexts[0] is context
    assert len(provider.requests) == 1
    assert provider.requests[0] is model_authorizer.requests[0]
    assert tool_authorizer.requests == []


def test_structured_model_turn_envelope_rejects_utf8_depth_and_nonfinite_values() -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    turn = _turn(run, now, _descriptor())

    invalid_utf8 = '{"version":1,"kind":"final","content":"\\ud800"}'
    too_deep = (
        '{"version":1,"kind":"tool","tool":"lookup","arguments":{"key":'
        + ("[" * 40)
        + "0"
        + ("]" * 40)
        + "}}"
    )
    nonfinite = '{"version":1,"kind":"tool","tool":"lookup","arguments":{"key":1e9999}}'

    for value in (invalid_utf8, too_deep, nonfinite):
        with pytest.raises(AgentMalformedProposalError):
            decode_agent_model_turn_envelope(value, turn)


class _RejectingContextualAdapter:
    def __init__(self, exception: Exception) -> None:
        self._exception = exception

    @property
    def adapter_id(self) -> str:
        return "rejecting-contextual"

    async def complete_turn(
        self,
        request: AgentModelTurnRequest,
    ) -> AgentModelTurnResult:
        raise AssertionError("contextual adapter must not use the legacy path")

    async def complete_turn_with_inference(
        self,
        request: AgentModelTurnRequest,
        inference_request: InferenceRequest,
        context: SecurityContext,
    ) -> AgentModelTurnResult:
        raise self._exception


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_type",
    [
        AgentAuthorizationRejectedError,
        AgentLimitExceededError,
    ],
)
async def test_bounded_executor_preserves_safe_contextual_rejections(
    exception_type: type[Exception],
) -> None:
    now = datetime.now(UTC)
    run = _run_request(now)
    turn = _turn(run, now)
    inference = DefaultAgentInferenceRequestFactory().create(run, turn)

    with pytest.raises(exception_type):
        await BoundedAgentExecutor().complete_model_turn(
            _RejectingContextualAdapter(exception_type()),
            turn,
            inference_request=inference,
            context=_context(),
            timeout_seconds=5,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )


def test_inference_backed_adapter_rejects_non_service_construction() -> None:
    with pytest.raises(TypeError):
        InferenceBackedAgentModelTurnAdapter(cast(InferenceService, object()))
