from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentId,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicSideEffectTool,
    DeterministicToolTurn,
    StaticToolResourceResolver,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolOutputSchema,
    ToolRegistry,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.tools import ToolAdapter, ToolFinalAdmissionContext
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 27, 20, tzinfo=UTC)


class _RunAuthorizer:
    async def authorize(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
    ) -> None:
        del request
        assert context.authenticated


class _ModelAuthorizer:
    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        del request
        assert context.authenticated


class _ToolAuthorizer:
    def __init__(self) -> None:
        self.requests: list[ToolInvocationRequest] = []

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        assert descriptor.tool_id == request.tool_id
        assert context.authenticated
        self.requests.append(request)


class _DenyingExecutionInterceptor:
    def __init__(self, *, deny_tool: bool = False, deny_final: bool = False) -> None:
        self.deny_tool = deny_tool
        self.deny_final = deny_final
        self.tool_checks = 0
        self.final_checks = 0

    async def before_model_turn(
        self,
        turn: AgentModelTurnRequest,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        del turn, context, cancellation

    async def before_tool_authorization(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        del invocation, descriptor, context, cancellation
        self.tool_checks += 1
        if self.deny_tool:
            raise AgentAuthorizationRejectedError()

    async def before_tool_invocation(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        del invocation, descriptor, context, cancellation

    async def final_tool_admission(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        details: ToolFinalAdmissionContext | None = None,
    ) -> None:
        del invocation, descriptor, context, cancellation, details

    async def after_tool_result(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        result: ToolInvocationResult,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        adapter: ToolAdapter | None = None,
    ) -> None:
        del invocation, descriptor, result, context, cancellation, adapter

    async def before_final_output(
        self,
        turn: AgentModelTurnRequest,
        final_output: str,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        del turn, final_output, context, cancellation
        self.final_checks += 1
        if self.deny_final:
            raise AgentAuthorizationRejectedError()


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "hello"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )


def _descriptor(adapter_id: str) -> ToolDescriptor:
    schema = ToolSchema(kind=ToolSchemaType.OBJECT)
    return ToolDescriptor(
        tool_id=ToolId("write"),
        name="write",
        description="test effectful tool",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
        approval_may_be_required=True,
        max_input_bytes=4096,
        max_output_bytes=4096,
        timeout=timedelta(seconds=10),
        resolver_id="static-resource",
        adapter_id=adapter_id,
    )


@pytest.mark.asyncio
async def test_execution_interceptor_denial_precedes_tool_authorization() -> None:
    registry = ToolRegistry()
    tool = DeterministicSideEffectTool(ToolId("write"), {})
    registry.register_tool(
        _descriptor(tool.adapter_id),
        resolver=StaticToolResourceResolver("static-resource", "test:write"),
        adapter=tool,
    )
    interceptor = _DenyingExecutionInterceptor(deny_tool=True)
    tool_authorizer = _ToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=_ModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter((DeterministicToolTurn(ToolId("write"), {}),)),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        execution_interceptor=interceptor,
        clock=lambda: _NOW,
    )

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.FAILED
    assert interceptor.tool_checks == 1
    assert tool_authorizer.requests == []
    assert tool.effect_count == 0


@pytest.mark.asyncio
async def test_execution_interceptor_denial_prevents_final_output_release() -> None:
    interceptor = _DenyingExecutionInterceptor(deny_final=True)
    loop = AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=_ModelAuthorizer(),
        tool_authorizer=_ToolAuthorizer(),
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("protected"),)),
        registry=ToolRegistry(),
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        execution_interceptor=interceptor,
        clock=lambda: _NOW,
    )

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.FAILED
    assert result.final_output is None
    assert interceptor.final_checks == 1
