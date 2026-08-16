"""Bounded no-retry execution for one model turn or one tool invocation."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from phoenix_os.agent.contracts import (
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
    canonical_agent_json_bytes,
)
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentMalformedProposalError,
    AgentServiceUnavailableError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentModelTurnResult,
)
from phoenix_os.agent.schemas import validate_tool_output
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import ContextualToolAdapter, ToolAdapter, ToolDescriptor
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_positive_seconds(value: float, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} must be a number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError(f"{label} must be finite and greater than zero")
    return normalized


def validate_agent_model_turn_result(
    request: AgentModelTurnRequest,
    result: AgentModelTurnResult,
) -> AgentModelTurnResult:
    """Reject model output that escapes the exact admitted turn contract."""

    if not isinstance(request, AgentModelTurnRequest):
        raise TypeError("request must be AgentModelTurnRequest")
    if not isinstance(result, AgentModelTurnResult):
        raise AgentMalformedProposalError()
    if result.run_id != request.run_id or result.step_id != request.step_id:
        raise AgentMalformedProposalError()

    if result.kind is AgentModelTurnKind.FINAL_OUTPUT:
        return result
    if result.kind is not AgentModelTurnKind.TOOL_PROPOSAL or result.proposal is None:
        raise AgentMalformedProposalError()

    proposal = result.proposal
    admitted = {descriptor.tool_id for descriptor in request.tools}
    if (
        proposal.run_id != request.run_id
        or proposal.step_id != request.step_id
        or proposal.tool_id not in admitted
        or proposal.created_at < request.created_at
        or proposal.deadline > request.deadline
    ):
        raise AgentMalformedProposalError()
    return result


def validate_tool_invocation_result(
    request: ToolInvocationRequest,
    descriptor: ToolDescriptor,
    result: ToolInvocationResult,
    *,
    started_at: datetime,
    completed_at: datetime,
) -> ToolInvocationResult:
    """Return a Phoenix-owned result after exact identity and schema validation."""

    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    if not isinstance(result, ToolInvocationResult):
        raise ToolExecutionError()
    _require_aware(started_at, "started_at")
    _require_aware(completed_at, "completed_at")
    if completed_at < started_at:
        raise ValueError("completed_at cannot be before started_at")
    if descriptor.tool_id != request.tool_id:
        raise ToolExecutionError()
    if (
        result.run_id != request.run_id
        or result.step_id != request.step_id
        or result.call_id != request.call_id
        or result.tool_id != request.tool_id
    ):
        raise ToolExecutionError()

    if result.status is ToolResultStatus.SUCCEEDED:
        if result.output is None:
            raise ToolExecutionError()
        try:
            output = validate_tool_output(descriptor.output_schema, result.output)
            encoded = canonical_agent_json_bytes(output)
        except Exception as exception:
            raise ToolExecutionError() from exception
        if len(encoded) > descriptor.max_output_bytes:
            raise ToolExecutionError()
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output=output,
            started_at=started_at,
            completed_at=completed_at,
        )

    return ToolInvocationResult(
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        status=result.status,
        error_code=result.error_code,
        started_at=started_at,
        completed_at=completed_at,
    )


class BoundedAgentExecutor:
    """Execute exactly once with finite timeout, cancellation, and safe outcomes."""

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock

    async def complete_model_turn(
        self,
        adapter: AgentModelTurnAdapter,
        request: AgentModelTurnRequest,
        *,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
    ) -> AgentModelTurnResult:
        """Run one independently authorized model turn without transparent retry."""

        if not isinstance(adapter, AgentModelTurnAdapter):
            raise TypeError("adapter must implement AgentModelTurnAdapter")
        if not isinstance(request, AgentModelTurnRequest):
            raise TypeError("request must be AgentModelTurnRequest")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        timeout = _require_positive_seconds(timeout_seconds, "timeout_seconds")
        grace = _require_positive_seconds(cancellation_grace, "cancellation_grace")
        cancellation.raise_if_cancelled()
        started_at = self._now()
        remaining = (request.deadline - started_at).total_seconds()
        if remaining <= 0:
            raise AgentTimeoutError()
        effective_timeout = min(timeout, remaining)

        try:
            result = await _await_controlled(
                adapter.complete_turn(request),
                timeout_seconds=effective_timeout,
                cancellation_grace=grace,
                cancellation=cancellation,
            )
        except (AgentCancelledError, AgentTimeoutError, AgentMalformedProposalError):
            raise
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            raise AgentServiceUnavailableError() from exception
        return validate_agent_model_turn_result(request, result)

    async def invoke_tool(
        self,
        adapter: ToolAdapter,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        *,
        context: SecurityContext | None = None,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
    ) -> ToolInvocationResult:
        """Invoke one tool once; ambiguous failures become indeterminate results."""

        if not isinstance(adapter, ToolAdapter):
            raise TypeError("adapter must implement ToolAdapter")
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if context is not None and not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext or None")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        if adapter.tool_id != request.tool_id or descriptor.tool_id != request.tool_id:
            raise ToolExecutionError()

        timeout = _require_positive_seconds(timeout_seconds, "timeout_seconds")
        grace = _require_positive_seconds(cancellation_grace, "cancellation_grace")
        cancellation.raise_if_cancelled()
        started_at = self._now()
        remaining = (request.deadline - started_at).total_seconds()
        if remaining <= 0:
            raise AgentTimeoutError()
        effective_timeout = min(timeout, descriptor.timeout.total_seconds(), remaining)

        if isinstance(adapter, ContextualToolAdapter) and context is None:
            raise ToolExecutionError()

        try:
            if isinstance(adapter, ContextualToolAdapter):
                assert context is not None
                operation = adapter.invoke_with_context(request, context)
            else:
                operation = adapter.invoke(request)
            result = await _await_controlled(
                operation,
                timeout_seconds=effective_timeout,
                cancellation_grace=grace,
                cancellation=cancellation,
            )
        except AgentCancelledError:
            return self._indeterminate(
                request,
                started_at=started_at,
                error_code="execution_cancelled",
            )
        except AgentTimeoutError:
            return self._indeterminate(
                request,
                started_at=started_at,
                error_code="execution_timeout",
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return self._indeterminate(
                request,
                started_at=started_at,
                error_code="execution_indeterminate",
            )

        return validate_tool_invocation_result(
            request,
            descriptor,
            result,
            started_at=started_at,
            completed_at=self._completed_at(started_at),
        )

    def _indeterminate(
        self,
        request: ToolInvocationRequest,
        *,
        started_at: datetime,
        error_code: str,
    ) -> ToolInvocationResult:
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.INDETERMINATE,
            error_code=error_code,
            started_at=started_at,
            completed_at=self._completed_at(started_at),
        )

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, "clock result")
        return value

    def _completed_at(self, started_at: datetime) -> datetime:
        value = self._now()
        return max(started_at, value)


async def _await_controlled[T](
    awaitable: Awaitable[T],
    *,
    timeout_seconds: float,
    cancellation_grace: float,
    cancellation: AgentCancellationToken,
) -> T:
    operation = asyncio.ensure_future(awaitable)
    cancellation_waiter = asyncio.create_task(cancellation.wait())
    try:
        done, _pending = await asyncio.wait(
            {operation, cancellation_waiter},
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancellation_waiter in done:
            await _cancel_future(operation, grace=cancellation_grace)
            raise AgentCancelledError()
        if operation in done:
            return operation.result()
        await _cancel_future(operation, grace=cancellation_grace)
        raise AgentTimeoutError()
    except asyncio.CancelledError:
        await _cancel_future(operation, grace=cancellation_grace)
        raise
    finally:
        await _stop_waiter(cancellation_waiter)


async def _cancel_future[T](
    future: asyncio.Future[T],
    *,
    grace: float,
) -> None:
    if not future.done():
        future.cancel()
    done, _pending = await asyncio.wait({future}, timeout=grace)
    if future in done:
        _consume_future(future)
    else:
        future.add_done_callback(_consume_future)


async def _stop_waiter(waiter: asyncio.Task[None]) -> None:
    if not waiter.done():
        waiter.cancel()
    try:
        await waiter
    except asyncio.CancelledError:
        pass


def _consume_future[T](future: asyncio.Future[T]) -> None:
    if future.cancelled():
        return
    try:
        future.exception()
    except BaseException:
        pass
