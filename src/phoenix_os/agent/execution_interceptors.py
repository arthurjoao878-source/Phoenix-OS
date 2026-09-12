"""Deterministic fail-closed composition for server-owned agent execution interceptors."""

from __future__ import annotations

from phoenix_os.agent.contracts import ToolInvocationRequest, ToolInvocationResult
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.loop import AgentExecutionInterceptor
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolAdapter,
    ToolDescriptor,
    ToolFinalAdmissionContext,
    ToolFinalAdmissionGrant,
)
from phoenix_os.policy import SecurityContext


class ChainedAgentExecutionInterceptor:
    """Apply multiple execution interceptors in one deterministic fail-closed chain."""

    def __init__(self, interceptors: tuple[AgentExecutionInterceptor, ...]) -> None:
        if not isinstance(interceptors, tuple):
            raise TypeError("interceptors must be a tuple")
        if not interceptors:
            raise ValueError("interceptors must not be empty")
        if any(
            not isinstance(interceptor, AgentExecutionInterceptor) for interceptor in interceptors
        ):
            raise TypeError("interceptors must implement AgentExecutionInterceptor")
        self._interceptors = interceptors

    @property
    def interceptors(self) -> tuple[AgentExecutionInterceptor, ...]:
        return self._interceptors

    async def before_model_turn(
        self,
        turn: AgentModelTurnRequest,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        for interceptor in self._interceptors:
            await interceptor.before_model_turn(turn, context, cancellation)

    async def before_tool_authorization(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        for interceptor in self._interceptors:
            await interceptor.before_tool_authorization(
                invocation,
                descriptor,
                context,
                cancellation,
            )

    async def before_tool_invocation(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        for interceptor in self._interceptors:
            await interceptor.before_tool_invocation(
                invocation,
                descriptor,
                context,
                cancellation,
            )

    async def final_tool_admission(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        details: ToolFinalAdmissionContext | None = None,
    ) -> ToolFinalAdmissionGrant | None:
        selected: ToolFinalAdmissionGrant | None = None
        for interceptor in self._interceptors:
            candidate = await interceptor.final_tool_admission(
                invocation,
                descriptor,
                context,
                cancellation,
                details,
            )
            if candidate is None:
                continue
            if not isinstance(candidate, ToolFinalAdmissionGrant):
                raise TypeError("execution interceptor final admission must return a grant or None")
            if selected is not None:
                raise AgentStateConflictError()
            selected = candidate
        return selected

    async def after_tool_result(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        result: ToolInvocationResult,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        adapter: ToolAdapter | None = None,
    ) -> None:
        for interceptor in self._interceptors:
            await interceptor.after_tool_result(
                invocation,
                descriptor,
                result,
                context,
                cancellation,
                adapter,
            )

    async def before_final_output(
        self,
        turn: AgentModelTurnRequest,
        final_output: str,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        for interceptor in self._interceptors:
            await interceptor.before_final_output(
                turn,
                final_output,
                context,
                cancellation,
            )


class _ProtocolProbeInterceptor:
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
    ) -> ToolFinalAdmissionGrant | None:
        del invocation, descriptor, context, cancellation, details
        return None

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


assert isinstance(
    ChainedAgentExecutionInterceptor((_ProtocolProbeInterceptor(),)),
    AgentExecutionInterceptor,
)
