"""Durable outcome lifecycle for one exact provider-neutral tool invocation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import ToolInvocationResult, ToolResultStatus
from phoenix_os.agent.durable_attempts import (
    DurableExecutionAttemptRecorder,
    DurableTerminalMetadataProjectingAttemptRecorder,
)
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
from phoenix_os.agent.durable_metadata import DurableCheckpointMetadataProjector
from phoenix_os.agent.durable_tool import (
    DurableToolAttemptBinding,
    DurableToolPreSubmitValidator,
    DurableToolSubmissionGate,
    prepare_durable_tool_submission,
)
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolAdapter,
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
class DurableToolResultMetadataProjectorFactory(Protocol):
    """Build one server-owned terminal metadata projector from a successful live tool result."""

    def create_projector(
        self,
        binding: DurableToolAttemptBinding,
        result: ToolInvocationResult,
    ) -> DurableCheckpointMetadataProjector | None: ...


@dataclass(frozen=True, slots=True)
class DurableToolExecutionResult:
    """One validated live tool result paired with its authoritative checkpoint."""

    result: ToolInvocationResult
    checkpoint: CheckpointEnvelope

    def __post_init__(self) -> None:
        if not isinstance(self.result, ToolInvocationResult):
            raise TypeError("result must be ToolInvocationResult")
        if not isinstance(self.checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")

        attempt = self.checkpoint.metadata.active_attempt
        if (
            self.checkpoint.agent_run_id != self.result.run_id
            or self.checkpoint.step_id != self.result.step_id
            or attempt is None
            or attempt.tool_call_id != self.result.call_id
        ):
            raise AgentStateConflictError()

        if self.result.status is ToolResultStatus.SUCCEEDED:
            if (
                self.checkpoint.status is not DurableRunStatus.ACTIVE
                or self.checkpoint.metadata.next_operation
                is not CheckpointNextOperation.VALIDATE_RESULT
                or attempt.status is not ExecutionAttemptStatus.SUCCEEDED
            ):
                raise AgentStateConflictError()
            return

        if self.result.status is ToolResultStatus.INDETERMINATE:
            if (
                self.checkpoint.status is not DurableRunStatus.INDETERMINATE_TOOL
                or self.checkpoint.metadata.next_operation
                is not CheckpointNextOperation.OPERATOR_REVIEW
                or attempt.status is not ExecutionAttemptStatus.INDETERMINATE
                or attempt.indeterminate_reason is not IndeterminateReason.TOOL_STATUS_UNKNOWN
            ):
                raise AgentStateConflictError()
            return

        expected_status = (
            ExecutionAttemptStatus.FAILED
            if self.result.status is ToolResultStatus.FAILED
            else ExecutionAttemptStatus.CANCELLED
        )
        if (
            self.result.status not in {ToolResultStatus.FAILED, ToolResultStatus.CANCELLED}
            or self.checkpoint.status is not DurableRunStatus.PAUSED_OPERATOR
            or self.checkpoint.metadata.next_operation
            is not CheckpointNextOperation.OPERATOR_REVIEW
            or attempt.status is not expected_status
        ):
            raise AgentStateConflictError()


async def _record_tool_exception(
    binding: DurableToolAttemptBinding,
    gate: DurableToolSubmissionGate,
    recorder: DurableExecutionAttemptRecorder,
    exception: (
        AgentCancelledError
        | AgentLimitExceededError
        | AgentTimeoutError
        | AgentServiceUnavailableError
        | ToolExecutionError
    ),
    *,
    now: datetime,
) -> CheckpointEnvelope:
    _require_timezone_aware(now, label="now")
    started = gate.started_checkpoint
    checkpoint = gate.prepared_checkpoint if started is None else started

    if started is not None:
        return await recorder.mark_indeterminate(
            checkpoint.durable_run_id,
            gate.attempt_id,
            expected_version=checkpoint.run_version,
            lease=binding.lease,
            reason=IndeterminateReason.TOOL_STATUS_UNKNOWN,
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


def _successful_result_metadata_projector(
    factory: DurableToolResultMetadataProjectorFactory | None,
    binding: DurableToolAttemptBinding,
    result: ToolInvocationResult,
) -> DurableCheckpointMetadataProjector | None:
    if factory is None:
        return None
    try:
        projector = factory.create_projector(binding, result)
    except AgentStateConflictError:
        raise
    except Exception as exception:
        raise AgentStateConflictError() from exception
    if projector is not None and not isinstance(projector, DurableCheckpointMetadataProjector):
        raise AgentStateConflictError()
    return projector


async def _record_tool_result(
    binding: DurableToolAttemptBinding,
    gate: DurableToolSubmissionGate,
    recorder: DurableExecutionAttemptRecorder,
    result: ToolInvocationResult,
    *,
    now: datetime,
    result_metadata_projector_factory: DurableToolResultMetadataProjectorFactory | None = None,
) -> CheckpointEnvelope:
    _require_timezone_aware(now, label="now")
    started = gate.started_checkpoint
    if started is None:
        raise AgentStateConflictError()

    if result.status is ToolResultStatus.SUCCEEDED:
        projector = _successful_result_metadata_projector(
            result_metadata_projector_factory,
            binding,
            result,
        )
        if projector is None:
            return await recorder.mark_terminal(
                started.durable_run_id,
                gate.attempt_id,
                expected_version=started.run_version,
                lease=binding.lease,
                status=ExecutionAttemptStatus.SUCCEEDED,
                now=now,
                next_operation=CheckpointNextOperation.VALIDATE_RESULT,
            )
        if not isinstance(recorder, DurableTerminalMetadataProjectingAttemptRecorder):
            raise AgentStateConflictError()
        return await recorder.mark_terminal_projected(
            started.durable_run_id,
            gate.attempt_id,
            expected_version=started.run_version,
            lease=binding.lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            now=now,
            metadata_projector=projector,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        )
    if result.status is ToolResultStatus.INDETERMINATE:
        return await recorder.mark_indeterminate(
            started.durable_run_id,
            gate.attempt_id,
            expected_version=started.run_version,
            lease=binding.lease,
            reason=IndeterminateReason.TOOL_STATUS_UNKNOWN,
            now=now,
        )
    if result.status is ToolResultStatus.FAILED:
        return await recorder.mark_terminal(
            started.durable_run_id,
            gate.attempt_id,
            expected_version=started.run_version,
            lease=binding.lease,
            status=ExecutionAttemptStatus.FAILED,
            now=now,
            error_code=result.error_code,
        )
    if result.status is ToolResultStatus.CANCELLED:
        return await recorder.mark_terminal(
            started.durable_run_id,
            gate.attempt_id,
            expected_version=started.run_version,
            lease=binding.lease,
            status=ExecutionAttemptStatus.CANCELLED,
            now=now,
        )
    raise AgentStateConflictError()


async def execute_durable_tool(
    binding: DurableToolAttemptBinding,
    recorder: DurableExecutionAttemptRecorder,
    executor: BoundedAgentExecutor,
    adapter: ToolAdapter,
    *,
    context: SecurityContext | None = None,
    final_admission: ToolFinalAdmissionValidator | None = None,
    timeout_seconds: float,
    cancellation_grace: float,
    cancellation: AgentCancellationToken,
    prepare_time: datetime,
    lease_keepalive: DurableLeaseCallKeepalive | None = None,
    pre_submit_validator: DurableToolPreSubmitValidator | None = None,
    result_metadata_projector_factory: DurableToolResultMetadataProjectorFactory | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> DurableToolExecutionResult:
    """Execute exactly once and persist only content-free durable tool outcomes."""

    if not isinstance(binding, DurableToolAttemptBinding):
        raise TypeError("binding must be DurableToolAttemptBinding")
    if not isinstance(recorder, DurableExecutionAttemptRecorder):
        raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
    if not isinstance(executor, BoundedAgentExecutor):
        raise TypeError("executor must be BoundedAgentExecutor")
    if not isinstance(adapter, ToolAdapter):
        raise TypeError("adapter must implement ToolAdapter")
    if context is not None and not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext or None")
    if final_admission is not None and not callable(final_admission):
        raise TypeError("final_admission must be callable or None")
    if not isinstance(cancellation, AgentCancellationToken):
        raise TypeError("cancellation must be AgentCancellationToken")
    if lease_keepalive is not None and not isinstance(
        lease_keepalive,
        DurableLeaseCallKeepalive,
    ):
        raise TypeError("lease_keepalive must be DurableLeaseCallKeepalive or None")
    if pre_submit_validator is not None and not isinstance(
        pre_submit_validator,
        DurableToolPreSubmitValidator,
    ):
        raise TypeError("pre_submit_validator must implement DurableToolPreSubmitValidator or None")
    if result_metadata_projector_factory is not None and not isinstance(
        result_metadata_projector_factory,
        DurableToolResultMetadataProjectorFactory,
    ):
        raise TypeError(
            "result_metadata_projector_factory must implement "
            "DurableToolResultMetadataProjectorFactory or be None"
        )
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
        gate = await prepare_durable_tool_submission(
            binding,
            recorder,
            now=prepare_time,
            pre_submit_validator=pre_submit_validator,
            submission_started_signal=started_signal,
            clock=clock,
        )

        try:
            result = await executor.invoke_tool(
                adapter,
                binding.invocation,
                binding.descriptor,
                context=context,
                final_admission=final_admission,
                submission_gate=gate,
                timeout_seconds=timeout_seconds,
                cancellation_grace=cancellation_grace,
                cancellation=cancellation,
            )
        except AgentStateConflictError:
            raise
        except (
            AgentCancelledError,
            AgentLimitExceededError,
            AgentTimeoutError,
            AgentServiceUnavailableError,
            ToolExecutionError,
        ) as exception:
            if lease_keepalive is not None:
                await lease_keepalive.stop()
            now = clock()
            _require_timezone_aware(now, label="clock result")
            await _record_tool_exception(
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
                    reason=IndeterminateReason.TOOL_STATUS_UNKNOWN,
                    now=now,
                )
                raise keepalive_failure

        now = clock()
        _require_timezone_aware(now, label="clock result")
        checkpoint = await _record_tool_result(
            binding,
            gate,
            recorder,
            result,
            now=now,
            result_metadata_projector_factory=result_metadata_projector_factory,
        )
        return DurableToolExecutionResult(result=result, checkpoint=checkpoint)
    finally:
        if lease_keepalive is not None:
            await lease_keepalive.stop()
