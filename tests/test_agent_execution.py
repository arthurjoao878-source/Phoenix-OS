import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentCancelledError,
    AgentId,
    AgentMalformedProposalError,
    AgentMessage,
    AgentMessageRole,
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentModelTurnResult,
    AgentRunId,
    AgentServiceUnavailableError,
    AgentStepId,
    AgentTimeoutError,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    ToolCallId,
    ToolDescriptor,
    ToolEffect,
    ToolExecutionError,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolOutputSchema,
    ToolResultStatus,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ContextualToolAdapter
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _schema(name: str) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={name: ToolSchema(kind=ToolSchemaType.STRING, max_length=128)},
        required=frozenset({name}),
    )


def _descriptor(*, max_output_bytes: int = 4_096) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="Look up one deterministic test value.",
        input_schema=ToolInputSchema(_schema("key")),
        output_schema=ToolOutputSchema(_schema("value")),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=max_output_bytes,
        timeout=timedelta(seconds=5),
        resolver_id="lookup-resolver",
        adapter_id="deterministic-read-only",
    )


def _turn_request(*tools: ToolDescriptor) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=AgentRunId(),
        step_id=AgentStepId(),
        messages=(AgentMessage(AgentMessageRole.USER, "perform the task"),),
        tools=tools,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=30),
    )


def _invocation(*, agent_id: str | None = "assistant") -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=None if agent_id is None else AgentId(agent_id),
        run_id=AgentRunId(),
        step_id=AgentStepId(),
        call_id=ToolCallId(),
        tool_id=ToolId("lookup"),
        arguments={"key": "alpha"},
        resolved_resource="fixture:lookup",
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=5),
    )


class _SlowModelAdapter:
    adapter_id = "slow-model"

    def __init__(self) -> None:
        self.calls = 0
        self.cancelled = False

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        self.calls += 1
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")


class _FailingModelAdapter:
    adapter_id = "failing-model"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        raise RuntimeError("private provider failure")


class _MismatchedModelAdapter:
    adapter_id = "mismatched-model"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        return AgentModelTurnResult(
            run_id=AgentRunId(),
            step_id=request.step_id,
            kind=AgentModelTurnKind.FINAL_OUTPUT,
            final_output="unsafe",
        )


class _FailingToolAdapter:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.calls = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.calls += 1
        raise RuntimeError("private transport failure")


class _SlowToolAdapter:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.calls = 0
        self.cancelled = False

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.calls += 1
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")


class _MalformedOutputTool:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"unexpected": "value"},
            started_at=_NOW - timedelta(days=1),
            completed_at=_NOW - timedelta(days=1),
        )


class _MismatchedTool:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=ToolCallId(),
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "fixed"},
            started_at=_NOW,
            completed_at=_NOW,
        )


class _ContextualTool:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.contexts: list[SecurityContext] = []
        self.plain_calls = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        self.plain_calls += 1
        raise AssertionError("contextual adapter used legacy invoke path")

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


class _SynchronouslyFailingLegacyTool:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.calls = 0

    def invoke(
        self,
        request: ToolInvocationRequest,
    ) -> Coroutine[Any, Any, ToolInvocationResult]:
        del request
        self.calls += 1
        raise RuntimeError("synchronous private legacy failure")


class _SynchronouslyFailingContextualTool:
    adapter_id = "deterministic-read-only"
    tool_id = ToolId("lookup")

    def __init__(self) -> None:
        self.context_calls = 0
        self.plain_calls = 0

    def invoke(
        self,
        request: ToolInvocationRequest,
    ) -> Coroutine[Any, Any, ToolInvocationResult]:
        del request
        self.plain_calls += 1
        raise AssertionError("contextual adapter used legacy invoke path")

    def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> Coroutine[Any, Any, ToolInvocationResult]:
        del request, context
        self.context_calls += 1
        raise RuntimeError("synchronous private contextual failure")


@pytest.mark.asyncio
async def test_model_turn_executes_once_and_validates_exact_identity() -> None:
    request = _turn_request()
    adapter = DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))

    result = await BoundedAgentExecutor(clock=lambda: _NOW).complete_model_turn(
        adapter,
        request,
        timeout_seconds=1,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )

    assert result.final_output == "done"
    assert adapter.requests == (request,)

    with pytest.raises(AgentMalformedProposalError):
        await BoundedAgentExecutor(clock=lambda: _NOW).complete_model_turn(
            _MismatchedModelAdapter(),
            request,
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )


@pytest.mark.asyncio
async def test_model_timeout_cancels_once_without_retry() -> None:
    adapter = _SlowModelAdapter()

    with pytest.raises(AgentTimeoutError):
        await BoundedAgentExecutor(clock=lambda: _NOW).complete_model_turn(
            adapter,
            _turn_request(),
            timeout_seconds=0.01,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )

    assert adapter.calls == 1
    assert adapter.cancelled is True


@pytest.mark.asyncio
async def test_model_rejects_cancelled_or_failed_work_safely() -> None:
    cancellation = AgentCancellationToken()
    cancellation.cancel()

    with pytest.raises(AgentCancelledError):
        await BoundedAgentExecutor(clock=lambda: _NOW).complete_model_turn(
            _SlowModelAdapter(),
            _turn_request(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=cancellation,
        )
    with pytest.raises(AgentServiceUnavailableError):
        await BoundedAgentExecutor(clock=lambda: _NOW).complete_model_turn(
            _FailingModelAdapter(),
            _turn_request(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )


@pytest.mark.asyncio
async def test_tool_execution_rejects_missing_agent_binding_before_adapter_call() -> None:
    adapter = DeterministicReadOnlyTool("lookup", {"value": "fixed"})

    with pytest.raises(ToolExecutionError):
        await BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
            adapter,
            _invocation(agent_id=None),
            _descriptor(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )

    assert adapter.requests == ()


@pytest.mark.asyncio
async def test_tool_success_is_schema_validated_and_runtime_timed() -> None:
    request = _invocation()
    adapter = DeterministicReadOnlyTool("lookup", {"value": "fixed"})
    times = iter((_NOW, _NOW + timedelta(seconds=1)))

    result = await BoundedAgentExecutor(clock=lambda: next(times)).invoke_tool(
        adapter,
        request,
        _descriptor(),
        timeout_seconds=2,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output == {"value": "fixed"}
    assert result.started_at == _NOW
    assert result.completed_at == _NOW + timedelta(seconds=1)
    assert adapter.requests == (request,)


@pytest.mark.asyncio
async def test_tool_exception_and_timeout_are_indeterminate_without_retry() -> None:
    failing = _FailingToolAdapter()
    failed = await BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
        failing,
        _invocation(),
        _descriptor(),
        timeout_seconds=1,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )
    assert failed.status is ToolResultStatus.INDETERMINATE
    assert failed.error_code == "execution_indeterminate"
    assert failing.calls == 1

    slow = _SlowToolAdapter()
    timed_out = await BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
        slow,
        _invocation(),
        _descriptor(),
        timeout_seconds=0.01,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )
    assert timed_out.status is ToolResultStatus.INDETERMINATE
    assert timed_out.error_code == "execution_timeout"
    assert slow.calls == 1
    assert slow.cancelled is True


@pytest.mark.asyncio
async def test_active_tool_cancellation_is_indeterminate_and_pre_cancel_rejects_work() -> None:
    slow = _SlowToolAdapter()
    cancellation = AgentCancellationToken()
    task = asyncio.create_task(
        BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
            slow,
            _invocation(),
            _descriptor(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=cancellation,
        )
    )
    await asyncio.sleep(0)
    cancellation.cancel()
    result = await task

    assert result.status is ToolResultStatus.INDETERMINATE
    assert result.error_code == "execution_cancelled"
    assert slow.calls == 1

    before_start = AgentCancellationToken()
    before_start.cancel()
    never_called = _SlowToolAdapter()
    with pytest.raises(AgentCancelledError):
        await BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
            never_called,
            _invocation(),
            _descriptor(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=before_start,
        )
    assert never_called.calls == 0


@pytest.mark.asyncio
async def test_tool_result_identity_and_output_schema_fail_closed() -> None:
    executor = BoundedAgentExecutor(clock=lambda: _NOW)

    with pytest.raises(ToolExecutionError):
        await executor.invoke_tool(
            _MismatchedTool(),
            _invocation(),
            _descriptor(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )
    with pytest.raises(ToolExecutionError):
        await executor.invoke_tool(
            _MalformedOutputTool(),
            _invocation(),
            _descriptor(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )


@pytest.mark.asyncio
async def test_contextual_tool_requires_explicit_security_context_and_skips_legacy_path() -> None:
    request = _invocation()
    adapter = _ContextualTool()
    context = SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )

    assert isinstance(adapter, ContextualToolAdapter)
    result = await BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
        adapter,
        request,
        _descriptor(),
        context=context,
        timeout_seconds=1,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output == {"value": "contextual"}
    assert adapter.contexts == [context]
    assert adapter.plain_calls == 0

    missing_context = _ContextualTool()
    with pytest.raises(ToolExecutionError):
        await BoundedAgentExecutor(clock=lambda: _NOW).invoke_tool(
            missing_context,
            request,
            _descriptor(),
            timeout_seconds=1,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )
    assert missing_context.contexts == []
    assert missing_context.plain_calls == 0


@pytest.mark.asyncio
async def test_tool_initiation_failures_are_indeterminate_inside_executor_boundary() -> None:
    executor = BoundedAgentExecutor(clock=lambda: _NOW)

    legacy = _SynchronouslyFailingLegacyTool()
    legacy_result = await executor.invoke_tool(
        legacy,
        _invocation(),
        _descriptor(),
        timeout_seconds=1,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )

    assert legacy_result.status is ToolResultStatus.INDETERMINATE
    assert legacy_result.error_code == "execution_indeterminate"
    assert legacy.calls == 1

    contextual = _SynchronouslyFailingContextualTool()
    context = SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )
    contextual_result = await executor.invoke_tool(
        contextual,
        _invocation(),
        _descriptor(),
        context=context,
        timeout_seconds=1,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
    )

    assert contextual_result.status is ToolResultStatus.INDETERMINATE
    assert contextual_result.error_code == "execution_indeterminate"
    assert contextual.context_calls == 1
    assert contextual.plain_calls == 0
