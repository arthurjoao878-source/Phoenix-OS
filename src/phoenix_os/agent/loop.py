"""Deterministic serial agent loop over reviewed Phoenix boundaries."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, runtime_checkable

from phoenix_os.agent.admission import AgentAdmissionController, AgentAdmissionLease
from phoenix_os.agent.approval import (
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolApprovalService,
    tool_descriptor_requires_approval,
)
from phoenix_os.agent.authorization import (
    AgentModelTurnAuthorizer,
    AgentRunAuthorityBinding,
    AgentRunAuthorizer,
    BoundAgentRunAuthorizer,
    ToolAuthorizer,
    canonical_tool_argument_digest,
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
    ToolApprovalId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
    canonical_agent_json_bytes,
)
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentError,
    AgentErrorCode,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnKind,
    AgentModelTurnRequest,
)
from phoenix_os.agent.memory_retrieval import (
    AgentMemoryContextProvider,
    memory_context_messages,
)
from phoenix_os.agent.model_turn import (
    agent_message_to_inference_message,
    validate_agent_run_model_turn_inference_binding,
)
from phoenix_os.agent.observer import (
    AgentObserver,
    AgentOperation,
    AgentOperationObservation,
    AgentOperationOutcome,
    NullAgentObserver,
    resolved_resource_category,
)
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.state import AgentCancellationToken, AgentRunStateMachine
from phoenix_os.agent.tools import (
    FinalAdmissionContextualToolAdapter,
    ToolAdapter,
    ToolDescriptor,
    ToolFinalAdmissionContext,
    ToolFinalAdmissionGrant,
    ToolFinalAdmissionValidator,
    ToolResourceResolutionContext,
)
from phoenix_os.agent.workspace_context import (
    AgentArtifactContextProvider,
    artifact_context_messages,
)
from phoenix_os.authority import (
    AuthorityFreshnessRejectedError,
    AuthorityFreshnessValidator,
)
from phoenix_os.inference import InferenceRequest
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
            messages=tuple(
                agent_message_to_inference_message(message) for message in turn.messages
            ),
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


@runtime_checkable
class AgentExecutionInterceptor(Protocol):
    """Optional server-owned run interceptor around existing RFC-0027 boundaries."""

    async def before_model_turn(
        self,
        turn: AgentModelTurnRequest,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None: ...

    async def before_tool_authorization(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None: ...

    async def before_tool_invocation(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None: ...

    async def final_tool_admission(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        details: ToolFinalAdmissionContext | None = None,
    ) -> ToolFinalAdmissionGrant | None: ...

    async def after_tool_result(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        result: ToolInvocationResult,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        adapter: ToolAdapter | None = None,
    ) -> None: ...

    async def before_final_output(
        self,
        turn: AgentModelTurnRequest,
        final_output: str,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None: ...


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
        authority_freshness: AuthorityFreshnessValidator | None = None,
        executor: BoundedAgentExecutor | None = None,
        inference_requests: AgentInferenceRequestFactory | None = None,
        approval_service: ToolApprovalService | None = None,
        approval_resolver: ToolApprovalResolver | None = None,
        admission: AgentAdmissionController | None = None,
        observer: AgentObserver | None = None,
        memory_context: AgentMemoryContextProvider | None = None,
        artifact_context: AgentArtifactContextProvider | None = None,
        execution_interceptor: AgentExecutionInterceptor | None = None,
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
        if authority_freshness is not None and not isinstance(
            authority_freshness, AuthorityFreshnessValidator
        ):
            raise TypeError("authority_freshness must implement AuthorityFreshnessValidator")
        resolved_admission = admission or AgentAdmissionController()
        if not isinstance(resolved_admission, AgentAdmissionController):
            raise TypeError("admission must be AgentAdmissionController")
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
        resolved_observer = NullAgentObserver() if observer is None else observer
        if not isinstance(resolved_observer, AgentObserver):
            raise TypeError("observer must implement AgentObserver")
        if memory_context is not None and not isinstance(
            memory_context, AgentMemoryContextProvider
        ):
            raise TypeError("memory_context must implement AgentMemoryContextProvider")
        if artifact_context is not None and not isinstance(
            artifact_context, AgentArtifactContextProvider
        ):
            raise TypeError("artifact_context must implement AgentArtifactContextProvider")
        if execution_interceptor is not None and not isinstance(
            execution_interceptor, AgentExecutionInterceptor
        ):
            raise TypeError("execution_interceptor must implement AgentExecutionInterceptor")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._run_authorizer = run_authorizer
        self._model_authorizer = model_authorizer
        self._tool_authorizer = tool_authorizer
        self._authority_freshness = authority_freshness
        self._model_adapter = model_adapter
        self._registry = registry
        self._admission = resolved_admission
        self._executor = resolved_executor
        self._inference_requests = resolved_factory
        self._approval_service = approval_service
        self._approval_resolver = approval_resolver
        self._observer = resolved_observer
        self._memory_context = memory_context
        self._artifact_context = artifact_context
        self._execution_interceptor = execution_interceptor
        self._clock = clock

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def execution_interceptor(self) -> AgentExecutionInterceptor | None:
        return self._execution_interceptor

    @property
    def memory_context_provider(self) -> AgentMemoryContextProvider | None:
        return self._memory_context

    @property
    def artifact_context_provider(self) -> AgentArtifactContextProvider | None:
        return self._artifact_context

    async def revalidate_run_authority(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        binding: AgentRunAuthorityBinding,
    ) -> None:
        """Reapply current bound run policy and authority freshness without execution."""

        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not isinstance(binding, AgentRunAuthorityBinding):
            raise TypeError("binding must be AgentRunAuthorityBinding")
        await self._authorize_fresh_run_admission(request, context, binding)

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult:
        """Execute one in-memory run to exactly one safe terminal result."""

        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        token = cancellation or AgentCancellationToken()
        if not isinstance(token, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        if _authority_binding is not None and not isinstance(
            _authority_binding,
            AgentRunAuthorityBinding,
        ):
            raise TypeError("_authority_binding must be AgentRunAuthorityBinding")
        run_lease: AgentAdmissionLease | None = None

        state = AgentRunStateMachine(
            request.run_id,
            request.limits,
            created_at=request.created_at,
            deadline=request.deadline,
        )
        messages = list(request.messages)

        try:
            token.raise_if_cancelled()
            await self._authorize_observed(
                self._authorize_run(request, context, _authority_binding),
                AgentOperationObservation(
                    operation=AgentOperation.RUN_AUTHORIZATION,
                    outcome=AgentOperationOutcome.SUCCEEDED,
                    agent_id=request.agent_id,
                    run_id=request.run_id,
                ),
                context,
            )
            try:
                run_lease = await self._admission.acquire_run(
                    request.limits,
                    timeout_seconds=_remaining_seconds(request.deadline, self._now()),
                    cancellation=token,
                )
            except BaseException as exception:
                await self._observe_exception(
                    AgentOperation.RUN_ADMISSION,
                    request,
                    context,
                    exception,
                )
                raise

            token.raise_if_cancelled()
            try:
                await self._authorize_fresh_run_admission(request, context, _authority_binding)
            except BaseException as exception:
                await self._observe_exception(
                    AgentOperation.RUN_AUTHORIZATION,
                    request,
                    context,
                    exception,
                )
                raise
            token.raise_if_cancelled()
            await self._observe(
                AgentOperationObservation(
                    operation=AgentOperation.RUN_ADMISSION,
                    outcome=AgentOperationOutcome.SUCCEEDED,
                    agent_id=request.agent_id,
                    run_id=request.run_id,
                ),
                context,
            )

            if self._memory_context is not None:
                memory_block = await self._memory_context.context_for_run(request, context)
                if memory_block is not None:
                    messages.extend(memory_context_messages(memory_block))
                    _require_prompt_limits(messages, request)

            if self._artifact_context is not None:
                artifact_block = await self._artifact_context.context_for_run(request, context)
                if artifact_block is not None:
                    messages.extend(artifact_context_messages(artifact_block))
                    _require_prompt_limits(messages, request)

            while True:
                token.raise_if_cancelled()
                now = self._now()
                _require_prompt_limits(messages, request)
                state.start_inference(now=now)
                model_turn = state.budget.model_turns
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
                if self._execution_interceptor is not None:
                    await self._execution_interceptor.before_model_turn(
                        turn,
                        context,
                        token,
                    )
                inference_request = self._inference_requests.create(request, turn)
                validate_agent_run_model_turn_inference_binding(
                    request,
                    turn,
                    inference_request,
                )
                await self._authorize_observed(
                    self._model_authorizer.authorize(inference_request, context),
                    AgentOperationObservation(
                        operation=AgentOperation.MODEL_AUTHORIZATION,
                        outcome=AgentOperationOutcome.SUCCEEDED,
                        agent_id=request.agent_id,
                        run_id=request.run_id,
                        step_id=turn.step_id,
                        model_turn=model_turn,
                    ),
                    context,
                )
                model_lease = await self._admission.acquire_model(
                    request.limits,
                    timeout_seconds=state.budget.model_timeout_seconds(now=self._now()),
                    cancellation=token,
                )
                try:
                    token.raise_if_cancelled()
                    try:
                        await self._authorize_fresh_model_admission(
                            inference_request,
                            context,
                        )
                    except BaseException as exception:
                        await self._observe_exception(
                            AgentOperation.MODEL_AUTHORIZATION,
                            request,
                            context,
                            exception,
                            step_id=turn.step_id,
                            model_turn=model_turn,
                        )
                        raise
                    token.raise_if_cancelled()

                    model_started = time.perf_counter()
                    try:
                        await self._observe(
                            AgentOperationObservation(
                                operation=AgentOperation.MODEL_TURN,
                                outcome=AgentOperationOutcome.STARTED,
                                agent_id=request.agent_id,
                                run_id=request.run_id,
                                step_id=turn.step_id,
                                model_turn=model_turn,
                            ),
                            context,
                        )
                        model_result = await self._executor.complete_model_turn(
                            self._model_adapter,
                            turn,
                            inference_request=inference_request,
                            context=context,
                            timeout_seconds=state.budget.model_timeout_seconds(now=self._now()),
                            cancellation_grace=request.limits.cancellation_grace.total_seconds(),
                            cancellation=token,
                        )
                    except BaseException as exception:
                        await self._observe_exception(
                            AgentOperation.MODEL_TURN,
                            request,
                            context,
                            exception,
                            step_id=turn.step_id,
                            model_turn=model_turn,
                            duration_ms=_duration_ms(model_started),
                        )
                        raise
                finally:
                    await model_lease.release()
                await self._observe(
                    AgentOperationObservation(
                        operation=AgentOperation.MODEL_TURN,
                        outcome=AgentOperationOutcome.SUCCEEDED,
                        agent_id=request.agent_id,
                        run_id=request.run_id,
                        step_id=turn.step_id,
                        model_turn=model_turn,
                        duration_ms=_duration_ms(model_started),
                    ),
                    context,
                )
                token.raise_if_cancelled()

                if model_result.kind is AgentModelTurnKind.FINAL_OUTPUT:
                    assert model_result.final_output is not None
                    if self._execution_interceptor is not None:
                        await self._execution_interceptor.before_final_output(
                            turn,
                            model_result.final_output,
                            context,
                            token,
                        )
                    state.budget.record_model_usage(len(model_result.final_output.encode("utf-8")))
                    state.complete(now=self._now())
                    return self._result(
                        request,
                        state,
                        final_output=model_result.final_output,
                    )

                assert model_result.proposal is not None
                proposal = model_result.proposal
                state.budget.record_model_usage(len(canonical_tool_call_proposal_bytes(proposal)))
                state.start_proposal_validation(now=self._now())
                try:
                    resolution = self._registry.admit_tool_call(
                        proposal.tool_id,
                        proposal.arguments,
                        resolution_context=ToolResourceResolutionContext(
                            agent_id=request.agent_id,
                            run_id=request.run_id,
                            step_id=turn.step_id,
                        ),
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
                        agent_id=request.agent_id,
                        run_id=request.run_id,
                        step_id=turn.step_id,
                        call_id=proposal.call_id,
                        tool_id=resolution.descriptor.tool_id,
                        arguments=resolution.arguments,
                        resolved_resource=resolution.resolved_resource,
                        created_at=invocation_created_at,
                        deadline=_deadline(
                            invocation_created_at,
                            state.budget.deadline,
                            request.limits.tool_call_timeout,
                            resolution.descriptor.timeout,
                            proposal.deadline - invocation_created_at,
                        ),
                    )
                except BaseException as exception:
                    await self._observe_exception(
                        AgentOperation.PROPOSAL_VALIDATION,
                        request,
                        context,
                        exception,
                        step_id=turn.step_id,
                        call_id=proposal.call_id,
                        tool_id=proposal.tool_id,
                        model_turn=model_turn,
                    )
                    raise
                await self._observe(
                    AgentOperationObservation(
                        operation=AgentOperation.PROPOSAL_VALIDATION,
                        outcome=AgentOperationOutcome.SUCCEEDED,
                        agent_id=request.agent_id,
                        run_id=request.run_id,
                        step_id=turn.step_id,
                        call_id=invocation.call_id,
                        tool_id=invocation.tool_id,
                        effect=resolution.descriptor.effect,
                        argument_digest=canonical_tool_argument_digest(invocation.arguments),
                        resource_category=resolved_resource_category(invocation.resolved_resource),
                        model_turn=model_turn,
                    ),
                    context,
                )

                if self._execution_interceptor is not None:
                    await self._execution_interceptor.before_tool_authorization(
                        invocation,
                        resolution.descriptor,
                        context,
                        token,
                    )
                state.start_tool_authorization(now=self._now())
                await self._authorize_observed(
                    self._tool_authorizer.authorize(
                        invocation,
                        resolution.descriptor,
                        context,
                    ),
                    AgentOperationObservation(
                        operation=AgentOperation.TOOL_AUTHORIZATION,
                        outcome=AgentOperationOutcome.SUCCEEDED,
                        agent_id=request.agent_id,
                        run_id=request.run_id,
                        step_id=invocation.step_id,
                        call_id=invocation.call_id,
                        tool_id=invocation.tool_id,
                        effect=resolution.descriptor.effect,
                        argument_digest=canonical_tool_argument_digest(invocation.arguments),
                        resource_category=resolved_resource_category(invocation.resolved_resource),
                        model_turn=model_turn,
                    ),
                    context,
                )
                if tool_descriptor_requires_approval(resolution.descriptor):
                    await self._approve(
                        request,
                        invocation,
                        resolution.descriptor,
                        context,
                        state=state,
                        cancellation=token,
                        model_turn=model_turn,
                    )

                token.raise_if_cancelled()
                tool_lease = await self._admission.acquire_tool(
                    request.limits,
                    timeout_seconds=state.budget.tool_timeout_seconds(now=self._now()),
                    cancellation=token,
                )
                try:
                    token.raise_if_cancelled()
                    try:
                        await self._authorize_fresh_tool_admission(
                            invocation,
                            resolution.descriptor,
                            context,
                        )
                    except BaseException as exception:
                        await self._observe_exception(
                            AgentOperation.TOOL_AUTHORIZATION,
                            request,
                            context,
                            exception,
                            step_id=invocation.step_id,
                            call_id=invocation.call_id,
                            tool_id=invocation.tool_id,
                            effect=resolution.descriptor.effect,
                            argument_digest=canonical_tool_argument_digest(invocation.arguments),
                            resource_category=resolved_resource_category(
                                invocation.resolved_resource
                            ),
                            model_turn=model_turn,
                        )
                        raise
                    token.raise_if_cancelled()
                    if self._execution_interceptor is not None:
                        await self._execution_interceptor.before_tool_invocation(
                            invocation,
                            resolution.descriptor,
                            context,
                            token,
                        )
                    token.raise_if_cancelled()
                    state.start_tool_invocation(now=self._now())
                    tool_call = state.budget.tool_calls
                    tool_started = time.perf_counter()
                    try:
                        await self._observe(
                            self._tool_observation(
                                request,
                                invocation,
                                resolution.descriptor,
                                operation=AgentOperation.TOOL_INVOCATION,
                                outcome=AgentOperationOutcome.STARTED,
                                model_turn=model_turn,
                                tool_call=tool_call,
                            ),
                            context,
                        )
                        adapter = self._registry.resolve_adapter(invocation.tool_id)
                        final_admission = (
                            self._tool_final_admission_validator(
                                invocation,
                                resolution.descriptor,
                                context,
                                token,
                            )
                            if isinstance(adapter, FinalAdmissionContextualToolAdapter)
                            else None
                        )
                        tool_result = await self._executor.invoke_tool(
                            adapter,
                            invocation,
                            resolution.descriptor,
                            context=context,
                            final_admission=final_admission,
                            timeout_seconds=state.budget.tool_timeout_seconds(now=self._now()),
                            cancellation_grace=request.limits.cancellation_grace.total_seconds(),
                            cancellation=token,
                        )
                    except BaseException as exception:
                        await self._observe_exception(
                            AgentOperation.TOOL_INVOCATION,
                            request,
                            context,
                            exception,
                            step_id=invocation.step_id,
                            call_id=invocation.call_id,
                            tool_id=invocation.tool_id,
                            effect=resolution.descriptor.effect,
                            argument_digest=canonical_tool_argument_digest(invocation.arguments),
                            resource_category=resolved_resource_category(
                                invocation.resolved_resource
                            ),
                            model_turn=model_turn,
                            tool_call=tool_call,
                            duration_ms=_duration_ms(tool_started),
                        )
                        raise
                finally:
                    await tool_lease.release()
                tool_outcome = (
                    AgentOperationOutcome.SUCCEEDED
                    if tool_result.status is ToolResultStatus.SUCCEEDED
                    else AgentOperationOutcome.INDETERMINATE
                )
                await self._observe(
                    self._tool_observation(
                        request,
                        invocation,
                        resolution.descriptor,
                        operation=AgentOperation.TOOL_INVOCATION,
                        outcome=tool_outcome,
                        model_turn=model_turn,
                        tool_call=tool_call,
                        duration_ms=_duration_ms(tool_started),
                        error_code=tool_result.error_code,
                    ),
                    context,
                )
                token.raise_if_cancelled()
                state.start_result_validation(now=self._now())
                encoded_result = canonical_tool_invocation_result_bytes(tool_result)
                state.budget.require_result_bytes(len(encoded_result))
                state.budget.record_tool_result(len(encoded_result))
                if self._execution_interceptor is not None:
                    await self._execution_interceptor.after_tool_result(
                        invocation,
                        resolution.descriptor,
                        tool_result,
                        context,
                        token,
                        adapter,
                    )

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
        finally:
            if run_lease is not None:
                await run_lease.release()

    async def _authorize_run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        authority_binding: AgentRunAuthorityBinding | None,
    ) -> None:
        if authority_binding is None:
            await self._run_authorizer.authorize(request, context)
            return
        authorizer = self._run_authorizer
        if not isinstance(authorizer, BoundAgentRunAuthorizer):
            raise AgentAuthorizationRejectedError()
        await authorizer.authorize_bound(request, context, authority_binding)

    async def _validate_authority_freshness(
        self,
        context: SecurityContext,
    ) -> None:
        validator = self._authority_freshness
        if validator is None:
            if context.session_id is not None:
                raise AgentAuthorizationRejectedError()
            return
        try:
            await validator.validate(context)
        except AuthorityFreshnessRejectedError as exception:
            raise AgentAuthorizationRejectedError() from exception

    async def _authorize_fresh_run_admission(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        authority_binding: AgentRunAuthorityBinding | None,
    ) -> None:
        await self._validate_authority_freshness(context)
        await self._authorize_run(request, context, authority_binding)

    async def _authorize_fresh_model_admission(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        await self._validate_authority_freshness(context)
        await self._model_authorizer.authorize(request, context)

    async def _authorize_fresh_tool_admission(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        await self._validate_authority_freshness(context)
        await self._tool_authorizer.authorize(invocation, descriptor, context)

    def _tool_final_admission_validator(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> ToolFinalAdmissionValidator:
        async def validate(
            details: ToolFinalAdmissionContext | None = None,
        ) -> ToolFinalAdmissionGrant | None:
            cancellation.raise_if_cancelled()
            await self._authorize_fresh_tool_admission(invocation, descriptor, context)
            cancellation.raise_if_cancelled()
            grant = None
            if self._execution_interceptor is not None:
                grant = await self._execution_interceptor.final_tool_admission(
                    invocation,
                    descriptor,
                    context,
                    cancellation,
                    details,
                )
            cancellation.raise_if_cancelled()
            return grant

        return validate

    async def _approve(
        self,
        request: AgentRunRequest,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        *,
        state: AgentRunStateMachine,
        cancellation: AgentCancellationToken,
        model_turn: int,
    ) -> None:
        service = self._approval_service
        resolver = self._approval_resolver
        if service is None or resolver is None:
            raise AgentApprovalRejectedError()
        state.start_approval(now=self._now())
        try:
            challenge = await service.request(invocation, descriptor, context)
        except BaseException as exception:
            await self._observe_exception(
                AgentOperation.APPROVAL,
                request,
                context,
                exception,
                step_id=invocation.step_id,
                call_id=invocation.call_id,
                tool_id=invocation.tool_id,
                effect=descriptor.effect,
                argument_digest=canonical_tool_argument_digest(invocation.arguments),
                resource_category=resolved_resource_category(invocation.resolved_resource),
                model_turn=model_turn,
            )
            raise
        await self._observe(
            self._tool_observation(
                request,
                invocation,
                descriptor,
                operation=AgentOperation.APPROVAL,
                outcome=AgentOperationOutcome.REQUESTED,
                model_turn=model_turn,
                approval_id=challenge.approval_id,
            ),
            context,
        )
        try:
            evidence = await _await_approval(
                resolver.resolve(challenge),
                timeout_seconds=state.budget.approval_timeout_seconds(now=self._now()),
                cancellation_grace=state.budget.limits.cancellation_grace.total_seconds(),
                cancellation=cancellation,
            )
            if not isinstance(evidence, ToolApprovalEvidence):
                raise AgentApprovalRejectedError()
        except BaseException as exception:
            await self._observe_exception(
                AgentOperation.APPROVAL,
                request,
                context,
                exception,
                step_id=invocation.step_id,
                call_id=invocation.call_id,
                tool_id=invocation.tool_id,
                approval_id=challenge.approval_id,
                effect=descriptor.effect,
                argument_digest=canonical_tool_argument_digest(invocation.arguments),
                resource_category=resolved_resource_category(invocation.resolved_resource),
                model_turn=model_turn,
            )
            raise
        await self._observe(
            self._tool_observation(
                request,
                invocation,
                descriptor,
                operation=AgentOperation.APPROVAL,
                outcome=AgentOperationOutcome.APPROVED,
                model_turn=model_turn,
                approval_id=evidence.approval_id,
            ),
            context,
        )
        try:
            await service.verify_and_consume(
                evidence,
                invocation,
                descriptor,
                context,
            )
        except BaseException as exception:
            await self._observe_exception(
                AgentOperation.APPROVAL,
                request,
                context,
                exception,
                step_id=invocation.step_id,
                call_id=invocation.call_id,
                tool_id=invocation.tool_id,
                approval_id=evidence.approval_id,
                effect=descriptor.effect,
                argument_digest=canonical_tool_argument_digest(invocation.arguments),
                resource_category=resolved_resource_category(invocation.resolved_resource),
                model_turn=model_turn,
            )
            raise
        await self._observe(
            self._tool_observation(
                request,
                invocation,
                descriptor,
                operation=AgentOperation.APPROVAL,
                outcome=AgentOperationOutcome.CONSUMED,
                model_turn=model_turn,
                approval_id=evidence.approval_id,
            ),
            context,
        )

    async def _authorize_observed(
        self,
        awaitable: Awaitable[object],
        succeeded: AgentOperationObservation,
        context: SecurityContext,
    ) -> None:
        try:
            await awaitable
        except BaseException as exception:
            await self._observe_exception(
                succeeded.operation,
                None,
                context,
                exception,
                template=succeeded,
            )
            raise
        await self._observe(succeeded, context)

    async def _observe(
        self,
        observation: AgentOperationObservation,
        context: SecurityContext,
    ) -> None:
        try:
            await self._observer.record(observation, context)
        except Exception:
            pass

    async def _observe_exception(
        self,
        operation: AgentOperation,
        request: AgentRunRequest | None,
        context: SecurityContext,
        exception: BaseException,
        *,
        template: AgentOperationObservation | None = None,
        step_id: AgentStepId | None = None,
        call_id: ToolCallId | None = None,
        tool_id: ToolId | None = None,
        approval_id: ToolApprovalId | None = None,
        effect: ToolEffect | None = None,
        argument_digest: str | None = None,
        resource_category: str | None = None,
        duration_ms: int | None = None,
        model_turn: int | None = None,
        tool_call: int | None = None,
    ) -> None:
        if template is not None:
            agent_id = template.agent_id
            run_id = template.run_id
            step_id = template.step_id
            call_id = template.call_id
            tool_id = template.tool_id
            approval_id = template.approval_id
            effect = template.effect
            argument_digest = template.argument_digest
            resource_category = template.resource_category
            model_turn = template.model_turn
            tool_call = template.tool_call
        else:
            if request is None:
                raise ValueError("request or template is required")
            agent_id = request.agent_id
            run_id = request.run_id
        outcome, error_code = _operation_failure(exception)
        await self._observe(
            AgentOperationObservation(
                operation=operation,
                outcome=outcome,
                agent_id=agent_id,
                run_id=run_id,
                step_id=step_id,
                call_id=call_id,
                tool_id=tool_id,
                approval_id=approval_id,
                effect=effect,
                argument_digest=argument_digest,
                resource_category=resource_category,
                duration_ms=duration_ms,
                model_turn=model_turn,
                tool_call=tool_call,
                error_code=error_code,
            ),
            context,
        )

    @staticmethod
    def _tool_observation(
        request: AgentRunRequest,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        *,
        operation: AgentOperation,
        outcome: AgentOperationOutcome,
        model_turn: int,
        tool_call: int | None = None,
        approval_id: ToolApprovalId | None = None,
        duration_ms: int | None = None,
        error_code: str | None = None,
    ) -> AgentOperationObservation:
        return AgentOperationObservation(
            operation=operation,
            outcome=outcome,
            agent_id=request.agent_id,
            run_id=request.run_id,
            step_id=invocation.step_id,
            call_id=invocation.call_id,
            tool_id=invocation.tool_id,
            approval_id=approval_id,
            effect=descriptor.effect,
            argument_digest=canonical_tool_argument_digest(invocation.arguments),
            resource_category=resolved_resource_category(invocation.resolved_resource),
            duration_ms=duration_ms,
            model_turn=model_turn,
            tool_call=tool_call,
            error_code=error_code,
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


def _duration_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1_000))


def _operation_failure(exception: BaseException) -> tuple[AgentOperationOutcome, str]:
    if isinstance(exception, (asyncio.CancelledError, AgentCancelledError)):
        return AgentOperationOutcome.CANCELLED, AgentErrorCode.CANCELLED.value
    if isinstance(exception, AgentTimeoutError):
        return AgentOperationOutcome.TIMED_OUT, AgentErrorCode.TIMEOUT.value
    if isinstance(exception, AgentError):
        rejected = {
            AgentErrorCode.APPROVAL_REJECTED,
            AgentErrorCode.AUTHORIZATION_REJECTED,
            AgentErrorCode.LIMIT_EXCEEDED,
            AgentErrorCode.MALFORMED_PROPOSAL,
            AgentErrorCode.SCHEMA_INVALID,
            AgentErrorCode.TOOL_NOT_FOUND,
        }
        outcome = (
            AgentOperationOutcome.REJECTED
            if exception.code in rejected
            else AgentOperationOutcome.FAILED
        )
        return outcome, exception.code.value
    return AgentOperationOutcome.FAILED, AgentErrorCode.SERVICE_UNAVAILABLE.value


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


def _remaining_seconds(deadline: datetime, now: datetime) -> float:
    _require_aware(deadline, "deadline")
    _require_aware(now, "now")
    remaining = (deadline - now).total_seconds()
    if remaining <= 0:
        raise AgentTimeoutError()
    return remaining


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
