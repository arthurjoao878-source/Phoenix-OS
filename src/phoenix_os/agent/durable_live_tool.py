"""Live durable tool execution over the existing AgentLoop seam."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentRunId, ToolInvocationRequest, ToolInvocationResult
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import CheckpointEnvelope
from phoenix_os.agent.durable_lease_keepalive import (
    StoreBackedDurableLeaseKeepaliveFactory,
)
from phoenix_os.agent.durable_tool import (
    DurableToolAttemptBinding,
    DurableToolPreSubmitValidator,
)
from phoenix_os.agent.durable_tool_execution import (
    DurableToolResultMetadataProjectorFactory,
    execute_durable_tool,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolAdapter,
    ToolDescriptor,
    ToolFinalAdmissionValidator,
)
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@runtime_checkable
class DurableToolBindingProvider(Protocol):
    """Resolve exact durable authority for one already-authorized live tool call."""

    async def bind(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        *,
        now: datetime,
    ) -> DurableToolAttemptBinding: ...


class DurableAgentToolExecutionDriver:
    """Execute live tool calls through the reviewed RFC-0028 attempt lifecycle."""

    def __init__(
        self,
        *,
        binding_provider: DurableToolBindingProvider,
        recorder: DurableExecutionAttemptRecorder,
        lease_keepalive_factory: StoreBackedDurableLeaseKeepaliveFactory | None = None,
        pre_submit_validator: DurableToolPreSubmitValidator | None = None,
        result_metadata_projector_factory: DurableToolResultMetadataProjectorFactory | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(binding_provider, DurableToolBindingProvider):
            raise TypeError("binding_provider must implement DurableToolBindingProvider")
        if not isinstance(recorder, DurableExecutionAttemptRecorder):
            raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
        if lease_keepalive_factory is not None and not isinstance(
            lease_keepalive_factory,
            StoreBackedDurableLeaseKeepaliveFactory,
        ):
            raise TypeError(
                "lease_keepalive_factory must be StoreBackedDurableLeaseKeepaliveFactory or None"
            )
        if pre_submit_validator is not None and not isinstance(
            pre_submit_validator,
            DurableToolPreSubmitValidator,
        ):
            raise TypeError(
                "pre_submit_validator must implement DurableToolPreSubmitValidator or None"
            )
        if result_metadata_projector_factory is not None and not isinstance(
            result_metadata_projector_factory,
            DurableToolResultMetadataProjectorFactory,
        ):
            raise TypeError(
                "result_metadata_projector_factory must implement "
                "DurableToolResultMetadataProjectorFactory or be None"
            )
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._binding_provider = binding_provider
        self._recorder = recorder
        self._lease_keepalive_factory = lease_keepalive_factory
        self._pre_submit_validator = pre_submit_validator
        self._result_metadata_projector_factory = result_metadata_projector_factory
        self._clock = clock
        self._agent_run_id: AgentRunId | None = None
        self._last_checkpoint: CheckpointEnvelope | None = None

    @property
    def last_checkpoint(self) -> CheckpointEnvelope | None:
        return self._last_checkpoint

    async def execute(
        self,
        executor: BoundedAgentExecutor,
        adapter: ToolAdapter,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
        prepare_time: datetime,
    ) -> ToolInvocationResult:
        if not isinstance(executor, BoundedAgentExecutor):
            raise TypeError("executor must be BoundedAgentExecutor")
        if not isinstance(adapter, ToolAdapter):
            raise TypeError("adapter must implement ToolAdapter")
        if not isinstance(invocation, ToolInvocationRequest):
            raise TypeError("invocation must be ToolInvocationRequest")
        if not isinstance(descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if final_admission is not None and not callable(final_admission):
            raise TypeError("final_admission must be callable or None")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        _require_timezone_aware(prepare_time, label="prepare_time")

        if self._agent_run_id is None:
            self._agent_run_id = invocation.run_id
        elif self._agent_run_id != invocation.run_id:
            raise AgentStateConflictError()

        binding = await self._binding_provider.bind(
            invocation,
            descriptor,
            now=prepare_time,
        )
        if not isinstance(binding, DurableToolAttemptBinding):
            raise TypeError("binding_provider must return DurableToolAttemptBinding")

        if binding.invocation is not invocation or binding.descriptor is not descriptor:
            raise AgentStateConflictError()

        keepalive = (
            None
            if self._lease_keepalive_factory is None
            else self._lease_keepalive_factory.create(binding.lease)
        )
        executed = await execute_durable_tool(
            binding,
            self._recorder,
            executor,
            adapter,
            context=context,
            final_admission=final_admission,
            timeout_seconds=timeout_seconds,
            cancellation_grace=cancellation_grace,
            cancellation=cancellation,
            prepare_time=prepare_time,
            lease_keepalive=keepalive,
            pre_submit_validator=self._pre_submit_validator,
            result_metadata_projector_factory=self._result_metadata_projector_factory,
            clock=self._clock,
        )
        self._last_checkpoint = executed.checkpoint
        return executed.result
