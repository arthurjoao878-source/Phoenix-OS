"""Durable outcome lifecycle for one exact provider-neutral model turn."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_model_turn import (
    DurableModelTurnAttemptBinding,
    DurableModelTurnSubmissionGate,
    prepare_durable_model_turn_submission,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentLimitExceededError,
    AgentMalformedProposalError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentTimeoutError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnKind,
    AgentModelTurnResult,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DurableModelTurnExecutionResult:
    """One validated model result paired with its authoritative SUCCEEDED checkpoint."""

    result: AgentModelTurnResult
    checkpoint: CheckpointEnvelope

    def __post_init__(self) -> None:
        if not isinstance(self.result, AgentModelTurnResult):
            raise TypeError("result must be AgentModelTurnResult")
        if not isinstance(self.checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        attempt = self.checkpoint.metadata.active_attempt
        expected_operation = (
            CheckpointNextOperation.COMPLETE
            if self.result.kind is AgentModelTurnKind.FINAL_OUTPUT
            else CheckpointNextOperation.VALIDATE_PROPOSAL
        )
        if (
            self.checkpoint.status is not DurableRunStatus.ACTIVE
            or self.checkpoint.agent_run_id != self.result.run_id
            or self.checkpoint.step_id != self.result.step_id
            or self.checkpoint.metadata.next_operation is not expected_operation
            or attempt is None
            or attempt.status is not ExecutionAttemptStatus.SUCCEEDED
            or attempt.agent_run_id != self.result.run_id
            or attempt.step_id != self.result.step_id
        ):
            raise AgentStateConflictError()


def _success_next_operation(result: AgentModelTurnResult) -> CheckpointNextOperation:
    if result.kind is AgentModelTurnKind.FINAL_OUTPUT:
        return CheckpointNextOperation.COMPLETE
    if result.kind is AgentModelTurnKind.TOOL_PROPOSAL:
        return CheckpointNextOperation.VALIDATE_PROPOSAL
    raise AgentStateConflictError()


async def _record_known_model_failure(
    binding: DurableModelTurnAttemptBinding,
    gate: DurableModelTurnSubmissionGate,
    recorder: DurableExecutionAttemptRecorder,
    exception: (
        AgentAuthorizationRejectedError
        | AgentCancelledError
        | AgentLimitExceededError
        | AgentMalformedProposalError
        | AgentServiceUnavailableError
        | AgentTimeoutError
    ),
    *,
    now: datetime,
) -> CheckpointEnvelope:
    _require_timezone_aware(now, label="now")
    started = gate.started_checkpoint
    checkpoint = gate.prepared_checkpoint if started is None else started

    if started is not None and isinstance(
        exception,
        (AgentCancelledError, AgentTimeoutError, AgentServiceUnavailableError),
    ):
        return await recorder.mark_indeterminate(
            checkpoint.durable_run_id,
            gate.attempt_id,
            expected_version=checkpoint.run_version,
            lease=binding.lease,
            reason=IndeterminateReason.PROVIDER_STATUS_UNKNOWN,
            now=now,
        )

    if isinstance(exception, AgentCancelledError):
        status = ExecutionAttemptStatus.CANCELLED
        error_code = None
    elif isinstance(exception, AgentTimeoutError):
        status = ExecutionAttemptStatus.TIMED_OUT
        error_code = exception.code.value
    else:
        status = ExecutionAttemptStatus.FAILED
        error_code = exception.code.value

    return await recorder.mark_terminal(
        checkpoint.durable_run_id,
        gate.attempt_id,
        expected_version=checkpoint.run_version,
        lease=binding.lease,
        status=status,
        now=now,
        error_code=error_code,
    )


async def execute_durable_model_turn(
    binding: DurableModelTurnAttemptBinding,
    recorder: DurableExecutionAttemptRecorder,
    executor: BoundedAgentExecutor,
    adapter: AgentModelTurnAdapter,
    *,
    context: SecurityContext | None = None,
    timeout_seconds: float,
    cancellation_grace: float,
    cancellation: AgentCancellationToken,
    prepare_time: datetime,
    clock: Callable[[], datetime] = _utc_now,
) -> DurableModelTurnExecutionResult:
    """Execute exactly once and persist only content-free durable attempt outcomes."""

    if not isinstance(binding, DurableModelTurnAttemptBinding):
        raise TypeError("binding must be DurableModelTurnAttemptBinding")
    if not isinstance(recorder, DurableExecutionAttemptRecorder):
        raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
    if not isinstance(executor, BoundedAgentExecutor):
        raise TypeError("executor must be BoundedAgentExecutor")
    if not isinstance(adapter, AgentModelTurnAdapter):
        raise TypeError("adapter must implement AgentModelTurnAdapter")
    if context is not None and not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext or None")
    if not isinstance(cancellation, AgentCancellationToken):
        raise TypeError("cancellation must be AgentCancellationToken")
    _require_timezone_aware(prepare_time, label="prepare_time")
    if not callable(clock):
        raise TypeError("clock must be callable")

    gate = await prepare_durable_model_turn_submission(
        binding,
        recorder,
        now=prepare_time,
        clock=clock,
    )

    try:
        result = await executor.complete_model_turn(
            adapter,
            binding.turn,
            inference_request=binding.inference_request,
            context=context,
            submission_gate=gate,
            timeout_seconds=timeout_seconds,
            cancellation_grace=cancellation_grace,
            cancellation=cancellation,
        )
    except (
        AgentAuthorizationRejectedError,
        AgentCancelledError,
        AgentLimitExceededError,
        AgentMalformedProposalError,
        AgentServiceUnavailableError,
        AgentTimeoutError,
    ) as exception:
        now = clock()
        _require_timezone_aware(now, label="clock result")
        await _record_known_model_failure(
            binding,
            gate,
            recorder,
            exception,
            now=now,
        )
        raise

    started = gate.started_checkpoint
    if started is None:
        raise AgentStateConflictError()
    now = clock()
    _require_timezone_aware(now, label="clock result")
    terminal = await recorder.mark_terminal(
        started.durable_run_id,
        gate.attempt_id,
        expected_version=started.run_version,
        lease=binding.lease,
        status=ExecutionAttemptStatus.SUCCEEDED,
        now=now,
        next_operation=_success_next_operation(result),
    )
    return DurableModelTurnExecutionResult(result=result, checkpoint=terminal)
