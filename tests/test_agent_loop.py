from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentId,
    AgentLimits,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    DeterministicSideEffectTool,
    DeterministicToolTurn,
    InMemoryToolApprovalService,
    StaticToolResourceResolver,
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolOutputSchema,
    ToolRegistry,
    ToolResultStatus,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _context(principal: str = "service:assistant") -> SecurityContext:
    return SecurityContext(
        principal=principal,
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


def _object_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"value"}),
    )


def _descriptor(
    *,
    tool_id: str = "lookup",
    effect: ToolEffect = ToolEffect.READ_ONLY,
    adapter_id: str = "deterministic-read-only",
) -> ToolDescriptor:
    schema = _object_schema()
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name="Reviewed tool",
        description="Perform one bounded reviewed operation.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=10),
        resolver_id="static-resource",
        adapter_id=adapter_id,
    )


class _RunAuthorizer:
    def __init__(self) -> None:
        self.requests: list[AgentRunRequest] = []

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)


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


class _ImmediateApprovalResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        approver: SecurityContext,
    ) -> None:
        self.service = service
        self.approver = approver
        self.challenges: list[ToolApprovalChallenge] = []

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        self.challenges.append(challenge)
        return await self.service.approve(challenge.approval_id, self.approver)


class _FailingTool:
    adapter_id = "failing-tool"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.calls = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.calls += 1
        raise RuntimeError("private external failure")


class _ContextualLoopTool:
    adapter_id = "contextual-loop-tool"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.contexts: list[SecurityContext] = []
        self.plain_calls = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        self.plain_calls += 1
        raise AssertionError("AgentLoop used legacy invoke path")

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        self.contexts.append(context)
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "contextual"},
            started_at=request.created_at,
            completed_at=request.created_at,
        )


def _loop(
    turns: Sequence[DeterministicModelTurn],
    *,
    registry: ToolRegistry | None = None,
    approval_service: InMemoryToolApprovalService | None = None,
    approval_resolver: _ImmediateApprovalResolver | None = None,
) -> tuple[AgentLoop, _RunAuthorizer, _ModelAuthorizer, _ToolAuthorizer]:
    run_authorizer = _RunAuthorizer()
    model_authorizer = _ModelAuthorizer()
    tool_authorizer = _ToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(turns),
        registry=registry or ToolRegistry(),
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        approval_service=approval_service,
        approval_resolver=approval_resolver,
        clock=lambda: _NOW,
    )
    return loop, run_authorizer, model_authorizer, tool_authorizer


@pytest.mark.asyncio
async def test_final_only_run_authorizes_once_and_completes() -> None:
    loop, run_auth, model_auth, tool_auth = _loop((DeterministicFinalTurn("done"),))

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "done"
    assert result.model_turns == 1
    assert result.tool_calls == 0
    assert len(run_auth.requests) == 1
    assert len(model_auth.requests) == 1
    assert tool_auth.requests == []


@pytest.mark.asyncio
async def test_read_only_tool_cycle_is_serial_and_authorized_per_turn() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor()
    adapter = DeterministicReadOnlyTool("lookup", {"value": "fixed"})
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    loop, _run_auth, model_auth, tool_auth = _loop(
        (
            DeterministicToolTurn(ToolId("lookup"), {"value": "input"}),
            DeterministicFinalTurn("complete"),
        ),
        registry=registry,
    )

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_turns == 2
    assert result.tool_calls == 1
    assert len(model_auth.requests) == 2
    assert (
        model_auth.requests[0].metadata["agent_step_id"]
        != model_auth.requests[1].metadata["agent_step_id"]
    )
    assert len(tool_auth.requests) == 1
    assert tool_auth.requests[0].agent_id == AgentId("assistant")
    assert len(adapter.requests) == 1


@pytest.mark.asyncio
async def test_accumulated_prompt_limit_stops_before_another_model_turn() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor()
    adapter = DeterministicReadOnlyTool("lookup", {"value": "fixed"})
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    loop, _run_auth, model_auth, _tool_auth = _loop(
        (
            DeterministicToolTurn(ToolId("lookup"), {"value": "input"}),
            DeterministicFinalTurn("not reached"),
        ),
        registry=registry,
    )
    request = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "hello"),),
        limits=AgentLimits(max_prompt_bytes=10),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )

    result = await loop.run(request, _context())

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "limit_exceeded"
    assert result.model_turns == 1
    assert result.tool_calls == 1
    assert len(model_auth.requests) == 1


@pytest.mark.asyncio
async def test_side_effect_tool_requires_and_consumes_exact_approval() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor(
        tool_id="write",
        effect=ToolEffect.REVERSIBLE_WRITE,
        adapter_id="deterministic-side-effect",
    )
    adapter = DeterministicSideEffectTool("write", {"value": "written"})
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    service = InMemoryToolApprovalService(clock=lambda: _NOW)
    resolver = _ImmediateApprovalResolver(service, _context("service:approver"))
    loop, _run_auth, _model_auth, _tool_auth = _loop(
        (
            DeterministicToolTurn(ToolId("write"), {"value": "input"}),
            DeterministicFinalTurn("complete"),
        ),
        registry=registry,
        approval_service=service,
        approval_resolver=resolver,
    )

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.COMPLETED
    assert adapter.effect_count == 1
    assert len(resolver.challenges) == 1
    snapshot = await service.snapshot()
    assert snapshot.consumed == 1
    assert snapshot.pending == 0


@pytest.mark.asyncio
async def test_missing_approval_fails_before_side_effect_execution() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor(
        tool_id="write",
        effect=ToolEffect.REVERSIBLE_WRITE,
        adapter_id="deterministic-side-effect",
    )
    adapter = DeterministicSideEffectTool("write", {"value": "written"})
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    loop, _run_auth, _model_auth, _tool_auth = _loop(
        (DeterministicToolTurn(ToolId("write"), {"value": "input"}),),
        registry=registry,
    )

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "approval_rejected"
    assert adapter.effect_count == 0


@pytest.mark.asyncio
async def test_ambiguous_tool_failure_is_terminal_and_never_retried() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor(adapter_id="failing-tool")
    adapter = _FailingTool()
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    loop, _run_auth, _model_auth, _tool_auth = _loop(
        (DeterministicToolTurn(ToolId("lookup"), {"value": "input"}),),
        registry=registry,
    )

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_pre_cancelled_run_rejects_all_new_work() -> None:
    loop, run_auth, model_auth, tool_auth = _loop((DeterministicFinalTurn("not reached"),))
    cancellation = AgentCancellationToken()
    cancellation.cancel()

    result = await loop.run(_request(), _context(), cancellation=cancellation)

    assert result.status is AgentRunStatus.CANCELLED
    assert result.error_code == "cancelled"
    assert run_auth.requests == []
    assert model_auth.requests == []
    assert tool_auth.requests == []


@pytest.mark.asyncio
async def test_agent_loop_forwards_exact_security_context_to_contextual_tool() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor(adapter_id="contextual-loop-tool")
    adapter = _ContextualLoopTool()
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    loop, _run_auth, _model_auth, _tool_auth = _loop(
        (
            DeterministicToolTurn(ToolId("lookup"), {"value": "input"}),
            DeterministicFinalTurn("complete"),
        ),
        registry=registry,
    )
    context = _context()

    result = await loop.run(_request(), context)

    assert result.status is AgentRunStatus.COMPLETED
    assert adapter.contexts == [context]
    assert adapter.contexts[0] is context
    assert adapter.plain_calls == 0
