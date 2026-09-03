"""Exact provider-neutral binding for one durable RFC-0026 model-turn attempt."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

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
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.model_turn import validate_agent_model_turn_inference_binding
from phoenix_os.inference.codec import canonical_inference_request_bytes
from phoenix_os.inference.contracts import InferenceRequest


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DurableModelTurnAttemptBinding:
    """Bind one durable checkpoint to the exact already-authorized inference request.

    This object performs no provider call and no durable mutation. The durable
    attempt recorder remains the sole owner of PREPARED/STARTED/terminal
    transitions, while RFC-0026 remains the sole owner of provider execution.
    """

    checkpoint: CheckpointEnvelope
    lease: DurableLease
    turn: AgentModelTurnRequest
    inference_request: InferenceRequest
    external_request_digest: CheckpointDigest = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(self.lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(self.turn, AgentModelTurnRequest):
            raise TypeError("turn must be AgentModelTurnRequest")
        if not isinstance(self.inference_request, InferenceRequest):
            raise TypeError("inference_request must be InferenceRequest")

        checkpoint = self.checkpoint
        turn = self.turn
        if (
            checkpoint.status is not DurableRunStatus.ACTIVE
            or checkpoint.status.terminal
            or checkpoint.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or checkpoint.durable_run_id != self.lease.run_id
            or checkpoint.agent_run_id != turn.run_id
            or checkpoint.step_id != turn.step_id
            or turn.deadline > checkpoint.metadata.budget.deadline
        ):
            raise AgentStateConflictError()

        active_attempt = checkpoint.metadata.active_attempt
        if active_attempt is not None and not active_attempt.status.terminal:
            raise AgentStateConflictError()

        validate_agent_model_turn_inference_binding(turn, self.inference_request)
        encoded = canonical_inference_request_bytes(self.inference_request)
        object.__setattr__(
            self,
            "external_request_digest",
            CheckpointDigest(hashlib.sha256(encoded).hexdigest()),
        )

    def require_ready(self, *, now: datetime) -> None:
        """Fail closed if this exact binding is no longer executable now."""

        _require_timezone_aware(now, label="now")
        checkpoint = self.checkpoint
        if (
            not self.lease.active_at(now)
            or now < checkpoint.created_at
            or now >= checkpoint.metadata.retention_deadline
            or now >= checkpoint.metadata.budget.deadline
            or now >= self.turn.deadline
        ):
            raise AgentStateConflictError()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_prepared_model_attempt(
    checkpoint: CheckpointEnvelope,
    *,
    lease: DurableLease,
    turn: AgentModelTurnRequest,
    external_request_digest: CheckpointDigest,
) -> ExecutionAttempt:
    attempt = checkpoint.metadata.active_attempt
    if (
        checkpoint.status is not DurableRunStatus.ACTIVE
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
        or checkpoint.durable_run_id != lease.run_id
        or checkpoint.agent_run_id != turn.run_id
        or checkpoint.step_id != turn.step_id
        or attempt is None
        or attempt.kind is not ExecutionAttemptKind.MODEL_TURN
        or attempt.status is not ExecutionAttemptStatus.PREPARED
        or attempt.agent_run_id != turn.run_id
        or attempt.step_id != turn.step_id
        or attempt.external_request_digest != external_request_digest
    ):
        raise AgentStateConflictError()
    return attempt


class DurableModelTurnSubmissionGate:
    """Single-use STARTED transition immediately before model adapter dispatch."""

    def __init__(
        self,
        *,
        recorder: DurableExecutionAttemptRecorder,
        prepared_checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        turn: AgentModelTurnRequest,
        external_request_digest: CheckpointDigest,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(recorder, DurableExecutionAttemptRecorder):
            raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
        if not isinstance(prepared_checkpoint, CheckpointEnvelope):
            raise TypeError("prepared_checkpoint must be CheckpointEnvelope")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(turn, AgentModelTurnRequest):
            raise TypeError("turn must be AgentModelTurnRequest")
        if not isinstance(external_request_digest, CheckpointDigest):
            raise TypeError("external_request_digest must be CheckpointDigest")
        if not callable(clock):
            raise TypeError("clock must be callable")

        attempt = _require_prepared_model_attempt(
            prepared_checkpoint,
            lease=lease,
            turn=turn,
            external_request_digest=external_request_digest,
        )
        self._recorder = recorder
        self._prepared_checkpoint = prepared_checkpoint
        self._lease = lease
        self._turn = turn
        self._external_request_digest = external_request_digest
        self._attempt_id = attempt.attempt_id
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
        checkpoint = self._prepared_checkpoint
        if (
            not self._lease.active_at(now)
            or now < checkpoint.created_at
            or now >= checkpoint.metadata.retention_deadline
            or now >= checkpoint.metadata.budget.deadline
            or now >= self._turn.deadline
        ):
            raise AgentStateConflictError()

        attempt = _require_prepared_model_attempt(
            checkpoint,
            lease=self._lease,
            turn=self._turn,
            external_request_digest=self._external_request_digest,
        )
        started = await self._recorder.mark_started(
            checkpoint.durable_run_id,
            attempt.attempt_id,
            expected_version=checkpoint.run_version,
            lease=self._lease,
            now=now,
        )
        started_attempt = started.metadata.active_attempt
        if (
            started_attempt is None
            or started_attempt.attempt_id != attempt.attempt_id
            or started_attempt.kind is not ExecutionAttemptKind.MODEL_TURN
            or started_attempt.status is not ExecutionAttemptStatus.STARTED
            or started_attempt.external_request_digest != self._external_request_digest
        ):
            raise AgentStateConflictError()
        self._started_checkpoint = started


async def prepare_durable_model_turn_submission(
    binding: DurableModelTurnAttemptBinding,
    recorder: DurableExecutionAttemptRecorder,
    *,
    now: datetime,
    clock: Callable[[], datetime] = _utc_now,
) -> DurableModelTurnSubmissionGate:
    """Persist PREPARED and return the single-use exact STARTED submission gate."""

    if not isinstance(binding, DurableModelTurnAttemptBinding):
        raise TypeError("binding must be DurableModelTurnAttemptBinding")
    if not isinstance(recorder, DurableExecutionAttemptRecorder):
        raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
    _require_timezone_aware(now, label="now")
    if not callable(clock):
        raise TypeError("clock must be callable")

    binding.require_ready(now=now)
    prepared = await recorder.prepare_model_attempt(
        binding.checkpoint.durable_run_id,
        expected_version=binding.checkpoint.run_version,
        lease=binding.lease,
        external_request_digest=binding.external_request_digest,
        now=now,
    )
    _require_prepared_model_attempt(
        prepared,
        lease=binding.lease,
        turn=binding.turn,
        external_request_digest=binding.external_request_digest,
    )
    return DurableModelTurnSubmissionGate(
        recorder=recorder,
        prepared_checkpoint=prepared,
        lease=binding.lease,
        turn=binding.turn,
        external_request_digest=binding.external_request_digest,
        clock=clock,
    )
