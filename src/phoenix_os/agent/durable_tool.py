"""Exact durable binding and STARTED gate for one live tool invocation."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.codec import canonical_tool_invocation_request_bytes
from phoenix_os.agent.contracts import ToolInvocationRequest
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableLease,
    DurableRunStatus,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_lease_keepalive import DurableSubmissionStartedSignal
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.tools import ToolDescriptor


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DurableToolAttemptBinding:
    """Bind one durable tool boundary to the exact already-authorized invocation."""

    checkpoint: CheckpointEnvelope
    lease: DurableLease
    invocation: ToolInvocationRequest
    descriptor: ToolDescriptor
    external_request_digest: CheckpointDigest = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(self.lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(self.invocation, ToolInvocationRequest):
            raise TypeError("invocation must be ToolInvocationRequest")
        if not isinstance(self.descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")

        checkpoint = self.checkpoint
        invocation = self.invocation
        if (
            checkpoint.status is not DurableRunStatus.ACTIVE
            or checkpoint.status.terminal
            or checkpoint.metadata.next_operation is not CheckpointNextOperation.TOOL_INVOCATION
            or checkpoint.durable_run_id != self.lease.run_id
            or checkpoint.agent_run_id != invocation.run_id
            or checkpoint.step_id != invocation.step_id
            or checkpoint.metadata.active_attempt is not None
            or invocation.agent_id is None
            or checkpoint.metadata.agent_id != invocation.agent_id
            or self.descriptor.tool_id != invocation.tool_id
            or invocation.deadline > checkpoint.metadata.budget.deadline
        ):
            raise AgentStateConflictError()

        encoded = canonical_tool_invocation_request_bytes(invocation)
        object.__setattr__(
            self,
            "external_request_digest",
            CheckpointDigest(hashlib.sha256(encoded).hexdigest()),
        )

    def require_ready(self, *, now: datetime) -> None:
        """Fail closed if this exact tool binding is no longer executable now."""

        _require_timezone_aware(now, label="now")
        checkpoint = self.checkpoint
        invocation = self.invocation
        if (
            not self.lease.active_at(now)
            or now < checkpoint.created_at
            or now < invocation.created_at
            or now >= checkpoint.metadata.retention_deadline
            or now >= checkpoint.metadata.budget.deadline
            or now >= invocation.deadline
        ):
            raise AgentStateConflictError()


@runtime_checkable
class DurableToolPreSubmitValidator(Protocol):
    """Validate one prepared durable tool invocation immediately before STARTED."""

    def validate_submission(
        self,
        binding: DurableToolAttemptBinding,
        prepared_checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> None: ...


def _require_prepared_tool_attempt(
    checkpoint: CheckpointEnvelope,
    *,
    binding: DurableToolAttemptBinding,
) -> ExecutionAttempt:
    attempt = checkpoint.metadata.active_attempt
    if (
        checkpoint.status is not DurableRunStatus.ACTIVE
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.TOOL_INVOCATION
        or checkpoint.durable_run_id != binding.lease.run_id
        or checkpoint.agent_run_id != binding.invocation.run_id
        or checkpoint.step_id != binding.invocation.step_id
        or attempt is None
        or attempt.kind is not ExecutionAttemptKind.TOOL_INVOCATION
        or attempt.status is not ExecutionAttemptStatus.PREPARED
        or attempt.agent_run_id != binding.invocation.run_id
        or attempt.step_id != binding.invocation.step_id
        or attempt.tool_call_id != binding.invocation.call_id
        or attempt.tool_effect is not binding.descriptor.effect
        or attempt.external_request_digest != binding.external_request_digest
    ):
        raise AgentStateConflictError()
    return attempt


class DurableToolSubmissionGate:
    """Single-use STARTED transition immediately before tool adapter dispatch."""

    def __init__(
        self,
        *,
        recorder: DurableExecutionAttemptRecorder,
        prepared_checkpoint: CheckpointEnvelope,
        binding: DurableToolAttemptBinding,
        pre_submit_validator: DurableToolPreSubmitValidator | None = None,
        submission_started_signal: DurableSubmissionStartedSignal | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(recorder, DurableExecutionAttemptRecorder):
            raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
        if not isinstance(prepared_checkpoint, CheckpointEnvelope):
            raise TypeError("prepared_checkpoint must be CheckpointEnvelope")
        if not isinstance(binding, DurableToolAttemptBinding):
            raise TypeError("binding must be DurableToolAttemptBinding")
        if pre_submit_validator is not None and not isinstance(
            pre_submit_validator,
            DurableToolPreSubmitValidator,
        ):
            raise TypeError(
                "pre_submit_validator must implement DurableToolPreSubmitValidator or None"
            )
        if submission_started_signal is not None and not isinstance(
            submission_started_signal,
            DurableSubmissionStartedSignal,
        ):
            raise TypeError(
                "submission_started_signal must be DurableSubmissionStartedSignal or None"
            )
        if not callable(clock):
            raise TypeError("clock must be callable")

        attempt = _require_prepared_tool_attempt(prepared_checkpoint, binding=binding)
        self._recorder = recorder
        self._prepared_checkpoint = prepared_checkpoint
        self._binding = binding
        self._pre_submit_validator = pre_submit_validator
        self._attempt_id = attempt.attempt_id
        self._submission_started_signal = (
            DurableSubmissionStartedSignal()
            if submission_started_signal is None
            else submission_started_signal
        )
        self._clock = clock
        self._started_checkpoint: CheckpointEnvelope | None = None

    @property
    def prepared_checkpoint(self) -> CheckpointEnvelope:
        return self._prepared_checkpoint

    @property
    def started_checkpoint(self) -> CheckpointEnvelope | None:
        return self._started_checkpoint

    @property
    def attempt_id(self) -> ExecutionAttemptId:
        return self._attempt_id

    async def before_submit(self) -> None:
        if self._started_checkpoint is not None:
            raise AgentStateConflictError()
        now = self._clock()
        _require_timezone_aware(now, label="clock result")
        self._binding.require_ready(now=now)

        prepared = self._prepared_checkpoint
        attempt = _require_prepared_tool_attempt(prepared, binding=self._binding)
        if self._pre_submit_validator is not None:
            self._pre_submit_validator.validate_submission(
                self._binding,
                prepared,
                now=now,
            )
        started = await self._recorder.mark_started(
            prepared.durable_run_id,
            attempt.attempt_id,
            expected_version=prepared.run_version,
            lease=self._binding.lease,
            now=now,
        )
        started_attempt = started.metadata.active_attempt
        if (
            started_attempt is None
            or started_attempt.attempt_id != attempt.attempt_id
            or started_attempt.kind is not ExecutionAttemptKind.TOOL_INVOCATION
            or started_attempt.status is not ExecutionAttemptStatus.STARTED
            or started_attempt.tool_call_id != self._binding.invocation.call_id
            or started_attempt.tool_effect is not self._binding.descriptor.effect
            or started_attempt.external_request_digest != self._binding.external_request_digest
        ):
            raise AgentStateConflictError()
        self._started_checkpoint = started
        self._submission_started_signal.mark_started()


async def prepare_durable_tool_submission(
    binding: DurableToolAttemptBinding,
    recorder: DurableExecutionAttemptRecorder,
    *,
    now: datetime,
    pre_submit_validator: DurableToolPreSubmitValidator | None = None,
    submission_started_signal: DurableSubmissionStartedSignal | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> DurableToolSubmissionGate:
    """Persist PREPARED and return the exact single-use tool STARTED gate."""

    if not isinstance(binding, DurableToolAttemptBinding):
        raise TypeError("binding must be DurableToolAttemptBinding")
    if not isinstance(recorder, DurableExecutionAttemptRecorder):
        raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
    if pre_submit_validator is not None and not isinstance(
        pre_submit_validator,
        DurableToolPreSubmitValidator,
    ):
        raise TypeError("pre_submit_validator must implement DurableToolPreSubmitValidator or None")
    if submission_started_signal is not None and not isinstance(
        submission_started_signal,
        DurableSubmissionStartedSignal,
    ):
        raise TypeError("submission_started_signal must be DurableSubmissionStartedSignal or None")
    _require_timezone_aware(now, label="now")
    if not callable(clock):
        raise TypeError("clock must be callable")

    binding.require_ready(now=now)
    prepared = await recorder.prepare_tool_attempt(
        binding.checkpoint.durable_run_id,
        expected_version=binding.checkpoint.run_version,
        lease=binding.lease,
        tool_call_id=binding.invocation.call_id,
        tool_effect=binding.descriptor.effect,
        external_request_digest=binding.external_request_digest,
        now=now,
    )
    _require_prepared_tool_attempt(prepared, binding=binding)
    return DurableToolSubmissionGate(
        recorder=recorder,
        prepared_checkpoint=prepared,
        binding=binding,
        pre_submit_validator=pre_submit_validator,
        submission_started_signal=submission_started_signal,
        clock=clock,
    )
