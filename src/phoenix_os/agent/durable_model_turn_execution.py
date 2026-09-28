"""Durable outcome lifecycle for one exact provider-neutral model turn."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from phoenix_os.agent.codec import canonical_tool_call_proposal_bytes
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_lease_keepalive import (
    DurableLeaseCallKeepalive,
    DurableSubmissionStartedSignal,
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
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _model_attempt_budget(
    budget: AgentBudgetSnapshot,
    result: AgentModelTurnResult | None = None,
) -> AgentBudgetSnapshot:
    accounted_steps = budget.model_turns + budget.tool_calls
    if budget.steps == accounted_steps:
        steps = budget.steps + 1
    elif budget.steps == accounted_steps + 1:
        steps = budget.steps
    else:
        raise AgentStateConflictError()

    model_output_bytes = budget.model_output_bytes
    input_tokens = budget.input_tokens
    output_tokens = budget.output_tokens
    if result is not None:
        if result.kind is AgentModelTurnKind.FINAL_OUTPUT:
            if result.final_output is None:
                raise AgentStateConflictError()
            encoded_bytes = len(result.final_output.encode("utf-8"))
        elif result.kind is AgentModelTurnKind.TOOL_PROPOSAL:
            if result.proposal is None:
                raise AgentStateConflictError()
            encoded_bytes = len(canonical_tool_call_proposal_bytes(result.proposal))
        else:
            raise AgentStateConflictError()
        model_output_bytes += encoded_bytes
        input_tokens += result.input_tokens
        output_tokens += result.output_tokens

    try:
        return replace(
            budget,
            steps=steps,
            model_turns=budget.model_turns + 1,
            model_output_bytes=model_output_bytes,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
    except (TypeError, ValueError) as exception:
        raise AgentStateConflictError() from exception


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
            budget=_model_attempt_budget(binding.checkpoint.metadata.budget),
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
        budget=(
            None if started is None else _model_attempt_budget(binding.checkpoint.metadata.budget)
        ),
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
    lease_keepalive: DurableLeaseCallKeepalive | None = None,
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
    if lease_keepalive is not None and not isinstance(
        lease_keepalive,
        DurableLeaseCallKeepalive,
    ):
        raise TypeError("lease_keepalive must be DurableLeaseCallKeepalive or None")
    _require_timezone_aware(prepare_time, label="prepare_time")
    if not callable(clock):
        raise TypeError("clock must be callable")

    started_signal = None if lease_keepalive is None else DurableSubmissionStartedSignal()
    if lease_keepalive is not None:
        assert started_signal is not None
        lease_keepalive.start(
            started_signal=started_signal,
            cancellation=cancellation,
        )

    try:
        gate = await prepare_durable_model_turn_submission(
            binding,
            recorder,
            now=prepare_time,
            submission_started_signal=started_signal,
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
            if lease_keepalive is not None:
                await lease_keepalive.stop()
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await _record_known_model_failure(
                binding,
                gate,
                recorder,
                exception,
                now=now,
            )
            if lease_keepalive is not None:
                keepalive_failure = lease_keepalive.failure
                if keepalive_failure is not None:
                    raise keepalive_failure from exception
            raise

        if lease_keepalive is not None:
            await lease_keepalive.stop()
            keepalive_failure = lease_keepalive.failure
            if keepalive_failure is not None:
                started = gate.started_checkpoint
                if started is None:
                    raise keepalive_failure
                now = clock()
                _require_timezone_aware(now, label="clock result")
                await recorder.mark_indeterminate(
                    started.durable_run_id,
                    gate.attempt_id,
                    expected_version=started.run_version,
                    lease=binding.lease,
                    reason=IndeterminateReason.PROVIDER_STATUS_UNKNOWN,
                    now=now,
                    budget=_model_attempt_budget(
                        binding.checkpoint.metadata.budget,
                        result,
                    ),
                )
                raise keepalive_failure

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
            budget=_model_attempt_budget(
                binding.checkpoint.metadata.budget,
                result,
            ),
        )
        return DurableModelTurnExecutionResult(result=result, checkpoint=terminal)
    finally:
        if lease_keepalive is not None:
            await lease_keepalive.stop()
