"""Explicit fail-closed context-resupply pause for RFC-0036 durable recovery."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime

from phoenix_os.agent.durable_codec import (
    checkpoint_envelope_digest,
    seal_checkpoint_envelope,
)
from phoenix_os.agent.durable_compatibility import DurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunStore,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
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

    async def pause_candidate(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Persist WAITING/CONTEXT_RESUPPLY without granting continuation authority."""

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
            self._ensure_open()
            current = await self._store.get_current(run_id)
            if current is None or current.status.terminal:
                raise AgentStateConflictError()
            history = await self._store.list_history(
                run_id,
                limit=current.sequence.value,
            )
            _validate_authoritative_history(current, history)
            self._history_validator.validate_history(current, history)

            projection = decode_integrated_durable_projection(current)
            if projection is None:
                raise AgentStateConflictError()
            if _is_context_resupply_pause(current, projection.waiting_reason):
                return current

            compatibility = self._compatibility_validator.validate(current)
            if not compatibility.compatible:
                raise AgentStateConflictError()
            point, disposition = classify_recovery_checkpoint(current, now=now)
            if (
                point is not RecoveryPoint.SAFE_BOUNDARY
                or disposition is not RecoveryDisposition.RESUME
                or current.status not in {DurableRunStatus.CREATED, DurableRunStatus.ACTIVE}
                or current.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
                or current.metadata.active_attempt is not None
            ):
                raise AgentStateConflictError()

            resume_state = await self._resume_gate.assess_resume_state(
                current,
                now=now,
            )
            if resume_state is not IntegratedDurableResumeState.CONTEXT_RESUPPLY:
                raise AgentStateConflictError()

            checkpoint_id = self._checkpoint_id_factory()
            if not isinstance(checkpoint_id, CheckpointId):
                raise TypeError("checkpoint_id_factory must return CheckpointId")
            if checkpoint_id == current.checkpoint_id:
                raise AgentStateConflictError()

            waiting_projection = replace(
                projection,
                orchestration_phase=IntegratedOrchestrationPhase.WAITING,
                waiting_reason=IntegratedWaitingReason.CONTEXT_RESUPPLY,
                current_attempt_id=None,
            )
            unreserved = {
                key: value
                for key, value in current.metadata.metadata.items()
                if not key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
            }
            metadata_values = merge_integrated_durable_projection(
                unreserved,
                waiting_projection,
            )
            proposed = seal_checkpoint_envelope(
                replace(
                    current,
                    checkpoint_id=checkpoint_id,
                    sequence=current.sequence.next(),
                    previous_digest=current.digest,
                    run_version=current.run_version.next(),
                    status=DurableRunStatus.PAUSED_OPERATOR,
                    metadata=replace(
                        current.metadata,
                        active_attempt=None,
                        metadata=metadata_values,
                    ),
                    created_at=now,
                )
            )
            transitioned = await self._store.append(
                proposed,
                expected_version=current.run_version,
                lease=lease,
                now=now,
            )
            authoritative = await self._store.get_current(run_id)
            if authoritative != transitioned:
                raise AgentStateConflictError()
            post_history = await self._store.list_history(
                run_id,
                limit=transitioned.sequence.value,
            )
            _validate_authoritative_history(transitioned, post_history)
            self._history_validator.validate_history(transitioned, post_history)
            post_point, post_disposition = classify_recovery_checkpoint(
                transitioned,
                now=now,
            )
            post_projection = decode_integrated_durable_projection(transitioned)
            if (
                post_point is not RecoveryPoint.OPERATOR_PAUSE
                or post_disposition is not RecoveryDisposition.PAUSE_OPERATOR
                or post_projection is None
                or post_projection.orchestration_phase is not IntegratedOrchestrationPhase.WAITING
                or post_projection.waiting_reason is not IntegratedWaitingReason.CONTEXT_RESUPPLY
                or post_projection.last_safe_boundary != projection.last_safe_boundary
            ):
                raise AgentStateConflictError()
            return transitioned
        finally:
            await self._lease_manager.release(lease, now=now)

    async def close(self) -> None:
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("integrated context-resupply coordinator is closed")


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


def _validate_authoritative_history(
    current: CheckpointEnvelope,
    history: tuple[CheckpointEnvelope, ...],
) -> None:
    if not history or history[-1] != current:
        raise AgentStateConflictError()
    if len(history) != current.sequence.value:
        raise AgentStateConflictError()
    previous: CheckpointEnvelope | None = None
    for index, checkpoint in enumerate(history, start=1):
        if checkpoint.sequence.value != index:
            raise AgentStateConflictError()
        if checkpoint.durable_run_id != current.durable_run_id:
            raise AgentStateConflictError()
        if checkpoint.agent_run_id != current.agent_run_id:
            raise AgentStateConflictError()
        if checkpoint.digest != checkpoint_envelope_digest(checkpoint):
            raise AgentStateConflictError()
        if previous is None:
            if checkpoint.previous_digest is not None:
                raise AgentStateConflictError()
        else:
            if checkpoint.previous_digest != previous.digest:
                raise AgentStateConflictError()
            if checkpoint.run_version != previous.run_version.next():
                raise AgentStateConflictError()
        previous = checkpoint
