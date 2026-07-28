"""Deterministic serial agent loop over reviewed Phoenix boundaries."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, runtime_checkable

from phoenix_os.agent.approval import (
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolApprovalService,
    tool_descriptor_requires_approval,
)
from phoenix_os.agent.authorization import (
    AgentModelTurnAuthorizer,
    AgentRunAuthorizer,
    ToolAuthorizer,
)
from phoenix_os.agent.codec import (
    canonical_tool_call_proposal_bytes,
    canonical_tool_invocation_result_bytes,
)
from phoenix_os.agent.contracts import (
    MAX_AGENT_MESSAGE_COUNT,
    AgentJsonValue,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunResult,
    AgentStepId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
    canonical_agent_json_bytes,
)
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentCancelledError,
    AgentError,
    AgentErrorCode,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    ToolExecutionError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnKind,
    AgentModelTurnRequest,
)
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.state import AgentCancellationToken, AgentRunStateMachine
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.inference import (
    InferenceMessage,
    InferenceRequest,
    InferenceRole,
)
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@runtime_checkable
class AgentInferenceRequestFactory(Protocol):
    """Create the exact RFC-0026 request authorized for one agent model turn."""

    def create(
        self,
        request: AgentRunRequest,
        turn: AgentModelTurnRequest,
    ) -> InferenceRequest: ...


class DefaultAgentInferenceRequestFactory:
    """Create content-bounded inference authorization requests from agent messages."""

    def create(
        self,
        request: AgentRunRequest,
        turn: AgentModelTurnRequest,
    ) -> InferenceRequest:
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(turn, AgentModelTurnRequest):
            raise TypeError("turn must be AgentModelTurnRequest")
        if turn.run_id != request.run_id:
            raise ValueError("model turn does not belong to the agent run")
        return InferenceRequest(
            provider_id=request.provider_id,
            model_id=request.model_id,
            messages=tuple(_to_inference_message(message) for message in turn.messages),
            max_output_tokens=request.limits.max_output_tokens,
            metadata={
                "agent_run_id": str(turn.run_id),
                "agent_step_id": str(turn.step_id),
            },
            correlation_id=str(turn.run_id),
            created_at=turn.created_at,
            deadline=turn.deadline,
        )


@runtime_checkable
class ToolApprovalResolver(Protocol):
    """Return server-issued evidence after one externally reviewed challenge."""

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence: ...


class AgentLoop:
    """Run one bounded serial model/tool cycle without autonomous retry."""

    def __init__(
        self,
        *,
        run_authorizer: AgentRunAuthorizer,
        model_authorizer: AgentModelTurnAuthorizer,
        tool_authorizer: ToolAuthorizer,
        model_adapter: AgentModelTurnAdapter,
        registry: ToolRegistry,
        executor: BoundedAgentExecutor | None = None,
        inference_requests: AgentInferenceRequestFactory | None = None,
        approval_service: ToolApprovalService | None = None,
        approval_resolver: ToolApprovalResolver | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(run_authorizer, AgentRunAuthorizer):
            raise TypeError("run_authorizer must implement AgentRunAuthorizer")
        if not isinstance(model_authorizer, AgentModelTurnAuthorizer):
            raise TypeError("model_authorizer must implement AgentModelTurnAuthorizer")
        if not isinstance(tool_authorizer, ToolAuthorizer):
            raise TypeError("tool_authorizer must implement ToolAuthorizer")
        if not isinstance(model_adapter, AgentModelTurnAdapter):
            raise TypeError("model_adapter must implement AgentModelTurnAdapter")
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be ToolRegistry")
        resolved_executor = executor or BoundedAgentExecutor(clock=clock)
        if not isinstance(resolved_executor, BoundedAgentExecutor):
            raise TypeError("executor must be BoundedAgentExecutor")
        resolved_factory = inference_requests or DefaultAgentInferenceRequestFactory()
        if not isinstance(resolved_factory, AgentInferenceRequestFactory):
            raise TypeError("inference_requests must implement AgentInferenceRequestFactory")
        if (approval_service is None) != (approval_resolver is None):
            raise ValueError("approval_service and approval_resolver must be configured together")
        if approval_service is not None and not isinstance(approval_service, ToolApprovalService):
            raise TypeError("approval_service must implement ToolApprovalService")
        if approval_resolver is not None and not isinstance(
            approval_resolver, ToolApprovalResolver
        ):
            raise TypeError("approval_resolver must implement ToolApprovalResolver")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._run_authorizer = run_authorizer
        self._model_authorizer = model_authorizer
        self._tool_authorizer = tool_authorizer
        self._model_adapter = model_adapter
        self._registry = registry
        self._executor = resolved_executor
        self._inference_requests = resolved_factory
        self._approval_service = approval_service
        self._approval_resolver = approval_resolver
        self._clock = clock

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
    ) -> AgentRunResult:
        """Execute one in-memory run to exactly one safe terminal result."""

        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        token = cancellation or AgentCancellationToken()
        if not isinstance(token, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")

        state = AgentRunStateMachine(
            request.run_id,
            request.limits,
            created_at=request.created_at,
            deadline=request.deadline,
        )
        messages = list(request.messages)

        try:
            token.raise_if_cancelled()
            await self._run_authorizer.authorize(request, context)
            while True:
                token.raise_if_cancelled()
                now = self._now()
                _require_prompt_limits(messages, request)
                state.start_inference(now=now)
                turn = AgentModelTurnRequest(
                    run_id=request.run_id,
                    step_id=AgentStepId(),
                    messages=tuple(messages),
                    tools=self._registry.list_descriptors(),
                    created_at=now,
                    deadline=_deadline(
                        now,
                        state.budget.deadline,
                        request.limits.model_turn_timeout,
                    ),
                )
                inference_request = self._inference_requests.create(request, turn)
                await self._model_authorizer.authorize(inference_request, context)
                model_result = await self._executor.complete_model_turn(
                    self._model_adapter,
                    turn,
                    timeout_seconds=state.budget.model_timeout_seconds(now=self._now()),
                    cancellation_grace=request.limits.cancellation_grace.total_seconds(),
                    cancellation=token,
                )
                token.raise_if_cancelled()

                if model_result.kind is AgentModelTurnKind.FINAL_OUTPUT:
                    assert model_result.final_output is not None
                    state.budget.record_model_usage(len(model_result.final_output.encode("utf-8")))
                    state.complete(now=self._now())
                    return self._result(
                        request,
                        state,
                        final_output=model_result.final_output,
                    )

                assert model_result.proposal is not None
                state.budget.record_model_usage(
                    len(canonical_tool_call_proposal_bytes(model_result.proposal))
                )
                state.start_proposal_validation(now=self._now())
                resolution = self._registry.admit_tool_call(
                    model_result.proposal.tool_id,
                    model_result.proposal.arguments,
                )
                _require_structured_limits(
                    resolution.arguments,
                    max_depth=request.limits.max_structured_depth,
                    max_items=request.limits.max_structured_items,
                )
                argument_bytes = len(canonical_agent_json_bytes(resolution.arguments))
                state.budget.require_argument_bytes(argument_bytes)
                invocation_created_at = self._now()
                invocation = ToolInvocationRequest(
                    run_id=request.run_id,
                    step_id=turn.step_id,
                    call_id=model_result.proposal.call_id,
                    tool_id=resolution.descriptor.tool_id,
                    arguments=resolution.arguments,
                    resolved_resource=resolution.resolved_resource,
                    created_at=invocation_created_at,
                    deadline=_deadline(
                        invocation_created_at,
                        state.budget.deadline,
                        request.limits.tool_call_timeout,
                        resolution.descriptor.timeout,
                        model_result.proposal.deadline - invocation_created_at,
                    ),
                )

                state.start_tool_authorization(now=self._now())
                await self._tool_authorizer.authorize(
                    invocation,
                    resolution.descriptor,
                    context,
                )
                if tool_descriptor_requires_approval(resolution.descriptor):
                    await self._approve(
                        invocation,
                        resolution.descriptor,
                        context,
                        state=state,
                        cancellation=token,
                    )

                token.raise_if_cancelled()
                state.start_tool_invocation(now=self._now())
                tool_result = await self._executor.invoke_tool(
                    self._registry.resolve_adapter(invocation.tool_id),
                    invocation,
                    resolution.descriptor,
                    timeout_seconds=state.budget.tool_timeout_seconds(now=self._now()),
                    cancellation_grace=request.limits.cancellation_grace.total_seconds(),
                    cancellation=token,
                )
                token.raise_if_cancelled()
                state.start_result_validation(now=self._now())
                encoded_result = canonical_tool_invocation_result_bytes(tool_result)
                state.budget.require_result_bytes(len(encoded_result))
                state.budget.record_tool_result(len(encoded_result))

                if tool_result.status is not ToolResultStatus.SUCCEEDED:
                    raise ToolExecutionError()
                assert tool_result.output is not None
                validated_output = cast(
                    Mapping[str, AgentJsonValue],
                    tool_result.output,
                )
                _require_structured_limits(
                    validated_output,
                    max_depth=request.limits.max_structured_depth,
                    max_items=request.limits.max_structured_items,
                )
                messages.append(_tool_message(tool_result))
        except AgentCancelledError:
            self._cancel_state(state)
            return self._result(
                request,
                state,
                error_code=AgentErrorCode.CANCELLED.value,
            )
        except asyncio.CancelledError:
            token.cancel()
            self._cancel_state(state)
            raise
        except AgentError as exception:
            self._fail_state(state)
            return self._result(
                request,
                state,
                error_code=exception.code.value,
            )
        except Exception:
            self._fail_state(state)
            return self._result(
                request,
                state,
                error_code=AgentErrorCode.SERVICE_UNAVAILABLE.value,
            )

    async def _approve(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        *,
        state: AgentRunStateMachine,
        cancellation: AgentCancellationToken,
    ) -> None:
        service = self._approval_service
        resolver = self._approval_resolver
        if service is None or resolver is None:
            raise AgentApprovalRejectedError()
        state.start_approval(now=self._now())
        challenge = await service.request(invocation, descriptor, context)
        evidence = await _await_approval(
            resolver.resolve(challenge),
            timeout_seconds=state.budget.approval_timeout_seconds(now=self._now()),
            cancellation_grace=state.budget.limits.cancellation_grace.total_seconds(),
            cancellation=cancellation,
        )
        if not isinstance(evidence, ToolApprovalEvidence):
            raise AgentApprovalRejectedError()
        await service.verify_and_consume(
            evidence,
            invocation,
            descriptor,
            context,
        )

    def _result(
        self,
        request: AgentRunRequest,
        state: AgentRunStateMachine,
        *,
        final_output: str | None = None,
        error_code: str | None = None,
    ) -> AgentRunResult:
        snapshot = state.snapshot()
        return AgentRunResult(
            run_id=request.run_id,
            status=snapshot.status,
            model_turns=snapshot.model_turns,
            tool_calls=snapshot.tool_calls,
            final_output=final_output,
            error_code=error_code,
            started_at=request.created_at,
            completed_at=max(request.created_at, snapshot.updated_at, self._now()),
        )

    def _cancel_state(self, state: AgentRunStateMachine) -> None:
        if not state.terminal:
            state.cancel(now=max(state.snapshot().updated_at, self._now()))

    def _fail_state(self, state: AgentRunStateMachine) -> None:
        if not state.terminal:
            state.fail(now=max(state.snapshot().updated_at, self._now()))

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, "clock result")
        return value


def _to_inference_message(message: AgentMessage) -> InferenceMessage:
    role = {
        AgentMessageRole.SYSTEM: InferenceRole.SYSTEM,
        AgentMessageRole.USER: InferenceRole.USER,
        AgentMessageRole.ASSISTANT: InferenceRole.ASSISTANT,
        AgentMessageRole.TOOL: InferenceRole.USER,
    }[message.role]
    metadata = {"agent_role": message.role.value}
    if message.tool_call_id is not None:
        metadata["tool_call_id"] = str(message.tool_call_id)
    return InferenceMessage(role=role, content=message.content, metadata=metadata)


def _tool_message(result: ToolInvocationResult) -> AgentMessage:
    if result.status is not ToolResultStatus.SUCCEEDED or result.output is None:
        raise ToolExecutionError()
    output = cast(Mapping[str, AgentJsonValue], result.output)
    return AgentMessage(
        role=AgentMessageRole.TOOL,
        content=canonical_agent_json_bytes(output).decode("utf-8"),
        tool_call_id=result.call_id,
        metadata={
            "tool_id": str(result.tool_id),
            "trust": "untrusted_tool_output",
        },
    )


def _require_prompt_limits(
    messages: Sequence[AgentMessage],
    request: AgentRunRequest,
) -> None:
    if len(messages) > MAX_AGENT_MESSAGE_COUNT:
        raise AgentLimitExceededError()
    encoded = sum(len(message.content.encode("utf-8")) for message in messages)
    if encoded > request.limits.max_prompt_bytes:
        raise AgentLimitExceededError()


def _require_structured_limits(
    value: AgentJsonValue,
    *,
    max_depth: int,
    max_items: int,
) -> None:
    count = 0

    def visit(item: AgentJsonValue, depth: int) -> None:
        nonlocal count
        if depth > max_depth:
            raise AgentLimitExceededError()
        count += 1
        if count > max_items:
            raise AgentLimitExceededError()
        if isinstance(item, Mapping):
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, tuple):
            for child in item:
                visit(child, depth + 1)

    visit(value, 0)


def _deadline(now: datetime, total: datetime, *limits: timedelta) -> datetime:
    _require_aware(now, "now")
    _require_aware(total, "total deadline")
    candidates = [total]
    for limit in limits:
        if not isinstance(limit, timedelta):
            raise TypeError("deadline limits must be timedeltas")
        if limit <= timedelta(0):
            raise AgentServiceUnavailableError()
        candidates.append(now + limit)
    deadline = min(candidates)
    if deadline <= now:
        raise AgentServiceUnavailableError()
    return deadline


async def _await_approval(
    awaitable: Awaitable[ToolApprovalEvidence],
    *,
    timeout_seconds: float,
    cancellation_grace: float,
    cancellation: AgentCancellationToken,
) -> ToolApprovalEvidence:
    operation = asyncio.ensure_future(awaitable)
    waiter = asyncio.create_task(cancellation.wait())
    try:
        done, _pending = await asyncio.wait(
            {operation, waiter},
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if waiter in done:
            await _cancel_future(operation, cancellation_grace)
            raise AgentCancelledError()
        if operation in done:
            try:
                return operation.result()
            except AgentError:
                raise
            except Exception as exception:
                raise AgentApprovalRejectedError() from exception
        await _cancel_future(operation, cancellation_grace)
        raise AgentApprovalRejectedError()
    except asyncio.CancelledError:
        await _cancel_future(operation, cancellation_grace)
        raise
    finally:
        if not waiter.done():
            waiter.cancel()
        try:
            await waiter
        except asyncio.CancelledError:
            pass


async def _cancel_future[T](future: asyncio.Future[T], grace: float) -> None:
    if not future.done():
        future.cancel()
    done, _pending = await asyncio.wait({future}, timeout=grace)
    if future in done:
        _consume_future(future)
    else:
        future.add_done_callback(_consume_future)


def _consume_future[T](future: asyncio.Future[T]) -> None:
    if future.cancelled():
        return
    try:
        future.exception()
    except BaseException:
        pass
