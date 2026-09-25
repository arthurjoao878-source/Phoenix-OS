"""Explicit fail-closed context-resupply pause for RFC-0036 durable recovery."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime

from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import DurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
    ExecutionAttempt,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    ReconciliationDecision,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_mutation import append_durable_checkpoint_confirmed
from phoenix_os.agent.durable_reconciliation import DurableReconciliationDispositionRecord
from phoenix_os.agent.durable_status_lookup import (
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
)
from phoenix_os.agent.durable_metadata import validate_durable_checkpoint_history
from phoenix_os.agent.durable_recovery import (
    classify_recovery_checkpoint,
    validate_authoritative_checkpoint_history,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.integrated_agent.contracts import (
    IntegratedOrchestrationPhase,
    IntegratedWaitingReason,
)
from phoenix_os.integrated_agent.durable_projection import (
    RFC0036_DURABLE_METADATA_PREFIX,
    decode_integrated_durable_projection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
    IntegratedDurableRecoveryResumeGate,
    IntegratedDurableResumeState,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IntegratedDurableContextResupplyCoordinator:
    """Persist only the explicit metadata-only planning context-resupply pause."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
        compatibility_validator: DurableCompatibilityValidator,
        resume_gate: IntegratedDurableRecoveryResumeGate,
        history_validator: IntegratedDurableRecoveryHistoryValidator | None = None,
        checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(compatibility_validator, DurableCompatibilityValidator):
            raise TypeError("compatibility_validator must implement DurableCompatibilityValidator")
        if not isinstance(resume_gate, IntegratedDurableRecoveryResumeGate):
            raise TypeError("resume_gate must be IntegratedDurableRecoveryResumeGate")
        selected_history_validator = (
            IntegratedDurableRecoveryHistoryValidator()
            if history_validator is None
            else history_validator
        )
        if not isinstance(
            selected_history_validator,
            IntegratedDurableRecoveryHistoryValidator,
        ):
            raise TypeError("history_validator must be IntegratedDurableRecoveryHistoryValidator")
        if not callable(checkpoint_id_factory):
            raise TypeError("checkpoint_id_factory must be callable")
        bound_lease_manager = getattr(store, "lease_manager", None)
        if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
            raise ValueError("lease_manager must match the durable store lease manager")

        self._store = store
        self._lease_manager = lease_manager
        self._compatibility_validator = compatibility_validator
        self._resume_gate = resume_gate
        self._history_validator = selected_history_validator
        self._checkpoint_id_factory = checkpoint_id_factory
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def history_validator(self) -> IntegratedDurableRecoveryHistoryValidator:
        return self._history_validator

    async def pause_candidate(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
        clock: Callable[[], datetime] = _utc_now,
    ) -> CheckpointEnvelope:
        """Persist WAITING/CONTEXT_RESUPPLY with one coordinator-owned lease."""

        self._ensure_open()
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id must be a non-empty string")
        _require_timezone_aware(now)

        lease = await self._lease_manager.acquire(
            run_id,
            owner_id=owner_id.strip(),
            now=now,
        )
        try:
            return await self.pause_candidate_with_lease(
                run_id,
                lease=lease,
                now=now,
                clock=clock,
            )
        finally:
            release_now = clock()
            _require_timezone_aware(release_now)
            await self._lease_manager.release(lease, now=release_now)

    async def pause_candidate_with_lease(
        self,
        run_id: DurableAgentRunId,
        *,
        lease: DurableLease,
        now: datetime,
        clock: Callable[[], datetime] = _utc_now,
    ) -> CheckpointEnvelope:
        """Persist the resupply pause using one caller-owned current fenced lease."""

        self._ensure_open()
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if lease.run_id != run_id:
            raise AgentStateConflictError()
        if not callable(clock):
            raise TypeError("clock must be callable")
        _require_timezone_aware(now)

        authoritative_lease = await self._lease_manager.require_current(lease, now=now)
        self._ensure_open()
        if authoritative_lease != lease:
            raise AgentStateConflictError()

        current = await self._store.get_current(run_id)
        if current is None or current.status.terminal:
            raise AgentStateConflictError()
        history = await self._store.list_history(run_id, limit=current.sequence.value)
        validate_authoritative_checkpoint_history(current, history)
        validate_durable_checkpoint_history(self._history_validator, current, history)

        projection = decode_integrated_durable_projection(current)
        if projection is None:
            raise AgentStateConflictError()
        if _is_context_resupply_pause(current, projection.waiting_reason):
            return current

        compatibility = self._compatibility_validator.validate(current)
        if not compatibility.compatible:
            raise AgentStateConflictError()

        source_projection = projection
        target_step_id = current.step_id
        if _is_exact_rfc0039_recovering_orphan(current, history):
            previous = history[-2]
            previous_projection = decode_integrated_durable_projection(previous)
            if previous_projection is None:
                raise AgentStateConflictError()
            source_projection = previous_projection
            target_step_id = previous.step_id
        elif _is_safe_cancelled_model_attempt(current, projection.waiting_reason):
            pass
        else:
            point, disposition = classify_recovery_checkpoint(current, now=now)
            if (
                point is not RecoveryPoint.SAFE_BOUNDARY
                or disposition is not RecoveryDisposition.RESUME
                or current.status not in {DurableRunStatus.CREATED, DurableRunStatus.ACTIVE}
                or current.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
                or current.metadata.active_attempt is not None
            ):
                raise AgentStateConflictError()
            resume_state = await self._resume_gate.assess_resume_state(current, now=now)
            if resume_state is not IntegratedDurableResumeState.CONTEXT_RESUPPLY:
                raise AgentStateConflictError()

        mutation_now = clock()
        _require_timezone_aware(mutation_now)
        if mutation_now < now:
            raise AgentStateConflictError()
        authoritative_lease = await self._lease_manager.require_current(
            authoritative_lease,
            now=mutation_now,
        )
        if authoritative_lease != lease or await self._store.get_current(run_id) != current:
            raise AgentStateConflictError()

        checkpoint_id = self._checkpoint_id_factory()
        if not isinstance(checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id_factory must return CheckpointId")
        if checkpoint_id == current.checkpoint_id:
            raise AgentStateConflictError()

        waiting_projection = replace(
            source_projection,
            orchestration_phase=IntegratedOrchestrationPhase.WAITING,
            waiting_reason=IntegratedWaitingReason.CONTEXT_RESUPPLY,
            current_agent_step_id=target_step_id,
            current_attempt_id=None,
        )
        unreserved = {
            key: value
            for key, value in current.metadata.metadata.items()
            if not key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
        }
        metadata_values = merge_integrated_durable_projection(unreserved, waiting_projection)
        proposed = seal_checkpoint_envelope(
            replace(
                current,
                checkpoint_id=checkpoint_id,
                sequence=current.sequence.next(),
                previous_digest=current.digest,
                run_version=current.run_version.next(),
                status=DurableRunStatus.PAUSED_OPERATOR,
                step_id=target_step_id,
                metadata=replace(
                    current.metadata,
                    next_operation=CheckpointNextOperation.MODEL_TURN,
                    active_attempt=None,
                    metadata=metadata_values,
                ),
                created_at=mutation_now,
            )
        )
        transitioned = await append_durable_checkpoint_confirmed(
            self._store,
            current=current,
            intended=proposed,
            lease=authoritative_lease,
            now=mutation_now,
        )
        post_history = await self._store.list_history(run_id, limit=transitioned.sequence.value)
        validate_authoritative_checkpoint_history(transitioned, post_history)
        validate_durable_checkpoint_history(self._history_validator, transitioned, post_history)
        post_point, post_disposition = classify_recovery_checkpoint(transitioned, now=mutation_now)
        post_projection = decode_integrated_durable_projection(transitioned)
        if (
            post_point is not RecoveryPoint.OPERATOR_PAUSE
            or post_disposition is not RecoveryDisposition.PAUSE_OPERATOR
            or post_projection is None
            or post_projection.orchestration_phase is not IntegratedOrchestrationPhase.WAITING
            or post_projection.waiting_reason is not IntegratedWaitingReason.CONTEXT_RESUPPLY
            or post_projection.current_attempt_id is not None
            or transitioned.metadata.active_attempt is not None
            or post_projection.last_safe_boundary != source_projection.last_safe_boundary
        ):
            raise AgentStateConflictError()
        return transitioned

    async def close(self) -> None:
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("integrated context-resupply coordinator is closed")



def _is_safe_cancelled_model_attempt(
    checkpoint: CheckpointEnvelope,
    waiting_reason: IntegratedWaitingReason | None,
) -> bool:
    attempt = checkpoint.metadata.active_attempt
    if (
        checkpoint.status is not DurableRunStatus.PAUSED_OPERATOR
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
        or attempt is None
        or attempt.kind is not ExecutionAttemptKind.MODEL_TURN
        or attempt.status is not ExecutionAttemptStatus.CANCELLED
        or attempt.completed_at is None
        or attempt.agent_run_id != checkpoint.agent_run_id
        or checkpoint.step_id is None
        or attempt.step_id != checkpoint.step_id
    ):
        return False
    if attempt.started_at is None:
        return waiting_reason in {None, IntegratedWaitingReason.CONTEXT_RESUPPLY}
    if waiting_reason not in {
        IntegratedWaitingReason.RECONCILIATION,
        IntegratedWaitingReason.CONTEXT_RESUPPLY,
    }:
        return False
    return _reconciliation_proves_not_started(checkpoint, attempt)


def _reconciliation_proves_not_started(
    checkpoint: CheckpointEnvelope,
    attempt: ExecutionAttempt,
) -> bool:
    try:
        record = DurableReconciliationDispositionRecord.from_metadata(checkpoint.metadata.metadata)
    except (TypeError, ValueError, OverflowError):
        return False
    return (
        record.run_id == checkpoint.durable_run_id
        and record.attempt_id == attempt.attempt_id
        and record.decision is ReconciliationDecision.CONFIRM_NOT_STARTED
        and record.external_status is DurableAttemptExternalStatus.NOT_STARTED
        and record.lookup_outcome is DurableAttemptStatusLookupOutcome.OBSERVED
        and record.result_status is DurableRunStatus.PAUSED_OPERATOR
        and record.result_attempt_status is ExecutionAttemptStatus.CANCELLED
        and record.evidence_digest is not None
        and attempt.external_request_digest == record.external_request_digest
        and record.applied_at <= checkpoint.created_at
    )


def _is_exact_rfc0039_recovering_orphan(
    checkpoint: CheckpointEnvelope,
    history: tuple[CheckpointEnvelope, ...],
) -> bool:
    if (
        checkpoint.status is not DurableRunStatus.RECOVERING
        or checkpoint.step_id is not None
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
        or checkpoint.metadata.active_attempt is not None
        or len(history) < 2
    ):
        return False
    previous = history[-2]
    previous_projection = decode_integrated_durable_projection(previous)
    current_projection = decode_integrated_durable_projection(checkpoint)
    if previous_projection is None or current_projection is None:
        return False

    expected_projection = replace(
        previous_projection,
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        waiting_reason=None,
        current_agent_step_id=None,
        current_attempt_id=None,
    )
    previous_unreserved = {
        key: value
        for key, value in previous.metadata.metadata.items()
        if not key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
    }
    expected_metadata_values = merge_integrated_durable_projection(
        previous_unreserved,
        expected_projection,
    )
    expected_metadata = replace(
        previous.metadata,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        metadata=expected_metadata_values,
    )
    return (
        previous.status is DurableRunStatus.PAUSED_OPERATOR
        and previous.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        and previous.metadata.active_attempt is None
        and previous_projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
        and previous_projection.waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
        and current_projection == expected_projection
        and checkpoint.previous_digest == previous.digest
        and checkpoint.sequence == previous.sequence.next()
        and checkpoint.run_version == previous.run_version.next()
        and checkpoint.metadata == expected_metadata
    )


def _is_context_resupply_pause(
    checkpoint: CheckpointEnvelope,
    waiting_reason: IntegratedWaitingReason | None,
) -> bool:
    return (
        checkpoint.status is DurableRunStatus.PAUSED_OPERATOR
        and checkpoint.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        and checkpoint.metadata.active_attempt is None
        and waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
    )


def _require_timezone_aware(now: datetime) -> None:
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
