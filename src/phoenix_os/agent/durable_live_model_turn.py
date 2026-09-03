"""Live durable model-turn execution over the existing AgentLoop seam."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import CheckpointEnvelope
from phoenix_os.agent.durable_model_turn import DurableModelTurnAttemptBinding
from phoenix_os.agent.durable_model_turn_execution import execute_durable_model_turn
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnRequest,
    AgentModelTurnResult,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.inference import InferenceRequest
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@runtime_checkable
class DurableModelTurnBindingProvider(Protocol):
    """Resolve the exact durable authority for one already-built live model turn."""

    async def bind(
        self,
        turn: AgentModelTurnRequest,
        inference_request: InferenceRequest,
        *,
        now: datetime,
    ) -> DurableModelTurnAttemptBinding: ...


class DurableAgentModelTurnExecutionDriver:
    """Execute live model turns through the reviewed RFC-0038 durable lifecycle.

    One instance is intentionally scoped to one live AgentRunId. It neither
    creates durable runs nor invents checkpoints, leases, or step identities.
    """

    def __init__(
        self,
        *,
        binding_provider: DurableModelTurnBindingProvider,
        recorder: DurableExecutionAttemptRecorder,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(binding_provider, DurableModelTurnBindingProvider):
            raise TypeError("binding_provider must implement DurableModelTurnBindingProvider")
        if not isinstance(recorder, DurableExecutionAttemptRecorder):
            raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._binding_provider = binding_provider
        self._recorder = recorder
        self._clock = clock
        self._agent_run_id: AgentRunId | None = None
        self._last_checkpoint: CheckpointEnvelope | None = None

    @property
    def last_checkpoint(self) -> CheckpointEnvelope | None:
        return self._last_checkpoint

    async def execute(
        self,
        executor: BoundedAgentExecutor,
        adapter: AgentModelTurnAdapter,
        turn: AgentModelTurnRequest,
        inference_request: InferenceRequest,
        context: SecurityContext,
        *,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
        prepare_time: datetime,
    ) -> AgentModelTurnResult:
        if not isinstance(executor, BoundedAgentExecutor):
            raise TypeError("executor must be BoundedAgentExecutor")
        if not isinstance(adapter, AgentModelTurnAdapter):
            raise TypeError("adapter must implement AgentModelTurnAdapter")
        if not isinstance(turn, AgentModelTurnRequest):
            raise TypeError("turn must be AgentModelTurnRequest")
        if not isinstance(inference_request, InferenceRequest):
            raise TypeError("inference_request must be InferenceRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        _require_timezone_aware(prepare_time, label="prepare_time")

        if self._agent_run_id is None:
            self._agent_run_id = turn.run_id
        elif self._agent_run_id != turn.run_id:
            raise AgentStateConflictError()

        binding = await self._binding_provider.bind(
            turn,
            inference_request,
            now=prepare_time,
        )
        if not isinstance(binding, DurableModelTurnAttemptBinding):
            raise TypeError("binding_provider must return DurableModelTurnAttemptBinding")

        # Reuse the exact live objects that already crossed AgentLoop authorization.
        if binding.turn is not turn or binding.inference_request is not inference_request:
            raise AgentStateConflictError()

        executed = await execute_durable_model_turn(
            binding,
            self._recorder,
            executor,
            adapter,
            context=context,
            timeout_seconds=timeout_seconds,
            cancellation_grace=cancellation_grace,
            cancellation=cancellation,
            prepare_time=prepare_time,
            clock=self._clock,
        )
        self._last_checkpoint = executed.checkpoint
        return executed.result
