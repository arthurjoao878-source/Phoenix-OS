"""Durable RFC-0039 workspace patch physical-effect integration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from phoenix_os.agent.checkout_patch_commit import CheckoutPatchCommitTicket
from phoenix_os.agent.checkout_patch_physical import (
    CheckoutPatchCommitIndeterminateError,
    CheckoutPatchPhysicalCommitResult,
    commit_checkout_patch_physical,
)
from phoenix_os.agent.checkout_patch_preparation import CheckoutPatchPreparation
from phoenix_os.agent.checkout_workspace import (
    CheckoutReadResult,
    RegisteredDevelopmentCheckoutAdapter,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_lease_keepalive import (
    DurableLeaseCallKeepalive,
    DurableSubmissionStartedSignal,
)
from phoenix_os.agent.durable_tool import (
    DurableToolAttemptBinding,
    DurableToolPreSubmitValidator,
    DurableToolSubmissionGate,
    prepare_durable_tool_submission,
)
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentStateConflictError,
    AgentTimeoutError,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolFinalAdmissionContext,
    ToolFinalAdmissionGrant,
    ToolFinalAdmissionValidator,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_started_patch_attempt(
    binding: DurableToolAttemptBinding,
    gate: DurableToolSubmissionGate,
    checkpoint: CheckpointEnvelope,
) -> None:
    attempt = checkpoint.metadata.active_attempt
    if (
        checkpoint.agent_run_id != binding.invocation.run_id
        or checkpoint.step_id != binding.invocation.step_id
        or attempt is None
        or attempt.attempt_id != gate.attempt_id
        or attempt.status is not ExecutionAttemptStatus.STARTED
        or attempt.tool_call_id != binding.invocation.call_id
        or attempt.tool_effect is not binding.descriptor.effect
        or attempt.external_request_digest != binding.external_request_digest
    ):
        raise AgentStateConflictError()


async def _stop_keepalive(
    lease_keepalive: DurableLeaseCallKeepalive | None,
) -> BaseException | None:
    if lease_keepalive is None:
        return None
    await lease_keepalive.stop()
    return lease_keepalive.failure


async def commit_checkout_patch_durable(
    binding: DurableToolAttemptBinding,
    recorder: DurableExecutionAttemptRecorder,
    adapter: RegisteredDevelopmentCheckoutAdapter,
    current_read_result: CheckoutReadResult,
    preparation: CheckoutPatchPreparation,
    ticket: CheckoutPatchCommitTicket,
    *,
    run_id: AgentRunId,
    step_id: AgentStepId,
    call_id: ToolCallId,
    prepare_time: datetime,
    physical_pre_effect_validator: Callable[[], None],
    pre_submit_validator: DurableToolPreSubmitValidator | None = None,
    final_admission: ToolFinalAdmissionValidator | None = None,
    mutation_bytes: int = 0,
    cancellation: AgentCancellationToken | None = None,
    lease_keepalive: DurableLeaseCallKeepalive | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> tuple[CheckoutPatchPhysicalCommitResult, CheckpointEnvelope]:
    """Persist PREPARED/STARTED around one non-retriable physical patch effect."""

    _require_timezone_aware(prepare_time, label="prepare_time")
    if not callable(physical_pre_effect_validator):
        raise TypeError("physical_pre_effect_validator must be callable")
    if final_admission is not None and not callable(final_admission):
        raise TypeError("final_admission must be callable or None")
    if isinstance(mutation_bytes, bool) or not isinstance(mutation_bytes, int):
        raise TypeError("mutation_bytes must be an int")
    if mutation_bytes < 0:
        raise ValueError("mutation_bytes must be non-negative")
    if mutation_bytes and final_admission is None:
        raise ValueError("non-zero mutation_bytes require final_admission")
    if cancellation is not None and not isinstance(cancellation, AgentCancellationToken):
        raise TypeError("cancellation must be AgentCancellationToken or None")
    if lease_keepalive is not None and not isinstance(
        lease_keepalive,
        DurableLeaseCallKeepalive,
    ):
        raise TypeError("lease_keepalive must be DurableLeaseCallKeepalive or None")
    if lease_keepalive is not None and cancellation is None:
        raise ValueError("lease_keepalive requires cancellation")
    if not callable(clock):
        raise TypeError("clock must be callable")
    if (
        run_id != binding.invocation.run_id
        or step_id != binding.invocation.step_id
        or call_id != binding.invocation.call_id
    ):
        raise AgentStateConflictError()

    started_signal = None if lease_keepalive is None else DurableSubmissionStartedSignal()
    if lease_keepalive is not None:
        assert started_signal is not None
        assert cancellation is not None
        lease_keepalive.start(
            started_signal=started_signal,
            cancellation=cancellation,
        )

    try:
        gate = await prepare_durable_tool_submission(
            binding,
            recorder,
            now=prepare_time,
            pre_submit_validator=pre_submit_validator,
            submission_started_signal=started_signal,
            clock=clock,
        )
        await gate.before_submit()

        started = gate.started_checkpoint
        if started is None:
            raise AgentStateConflictError()
        _require_started_patch_attempt(binding, gate, started)

        def validate_immediately_before_effect() -> None:
            now = clock()
            _require_timezone_aware(now, label="clock result")
            binding.require_ready(now=now)
            if cancellation is not None:
                cancellation.raise_if_cancelled()
            current_started = gate.started_checkpoint
            if current_started is None or current_started != started:
                raise AgentStateConflictError()
            _require_started_patch_attempt(binding, gate, current_started)
            physical_pre_effect_validator()

        try:
            if cancellation is not None:
                cancellation.raise_if_cancelled()
            if final_admission is not None:
                grant = await final_admission(
                    ToolFinalAdmissionContext(mutation_bytes=mutation_bytes)
                )
                if grant is not None and not isinstance(grant, ToolFinalAdmissionGrant):
                    raise TypeError("final_admission must return ToolFinalAdmissionGrant or None")
            if cancellation is not None:
                cancellation.raise_if_cancelled()

            physical_result = commit_checkout_patch_physical(
                adapter,
                current_read_result,
                preparation,
                ticket,
                run_id=run_id,
                step_id=step_id,
                call_id=call_id,
                pre_effect_validator=validate_immediately_before_effect,
            )
        except CheckoutPatchCommitIndeterminateError as exception:
            keepalive_failure = await _stop_keepalive(lease_keepalive)
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await recorder.mark_indeterminate(
                started.durable_run_id,
                gate.attempt_id,
                expected_version=started.run_version,
                lease=binding.lease,
                reason=IndeterminateReason.TOOL_STATUS_UNKNOWN,
                now=now,
            )
            if keepalive_failure is not None:
                raise keepalive_failure from exception
            raise
        except AgentCancelledError as exception:
            keepalive_failure = await _stop_keepalive(lease_keepalive)
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await recorder.mark_terminal(
                started.durable_run_id,
                gate.attempt_id,
                expected_version=started.run_version,
                lease=binding.lease,
                status=ExecutionAttemptStatus.CANCELLED,
                now=now,
            )
            if keepalive_failure is not None:
                raise keepalive_failure from exception
            raise
        except AgentTimeoutError as exception:
            keepalive_failure = await _stop_keepalive(lease_keepalive)
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await recorder.mark_terminal(
                started.durable_run_id,
                gate.attempt_id,
                expected_version=started.run_version,
                lease=binding.lease,
                status=ExecutionAttemptStatus.TIMED_OUT,
                now=now,
                error_code=exception.code.value,
            )
            if keepalive_failure is not None:
                raise keepalive_failure from exception
            raise
        except Exception as exception:
            keepalive_failure = await _stop_keepalive(lease_keepalive)
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await recorder.mark_terminal(
                started.durable_run_id,
                gate.attempt_id,
                expected_version=started.run_version,
                lease=binding.lease,
                status=ExecutionAttemptStatus.FAILED,
                now=now,
                error_code="workspace_patch_pre_effect_failed",
            )
            if keepalive_failure is not None:
                raise keepalive_failure from exception
            raise

        keepalive_failure = await _stop_keepalive(lease_keepalive)
        if keepalive_failure is not None:
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await recorder.mark_indeterminate(
                started.durable_run_id,
                gate.attempt_id,
                expected_version=started.run_version,
                lease=binding.lease,
                reason=IndeterminateReason.TOOL_STATUS_UNKNOWN,
                now=now,
            )
            raise keepalive_failure

        now = clock()
        _require_timezone_aware(now, label="clock result")
        terminal = await recorder.mark_terminal(
            started.durable_run_id,
            gate.attempt_id,
            expected_version=started.run_version,
            lease=binding.lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            now=now,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        )
        return physical_result, terminal
    finally:
        if lease_keepalive is not None:
            await lease_keepalive.stop()
