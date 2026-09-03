"""Fenced store-backed binding for one already-authorized live model turn."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime

from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_metadata import (
    DurableCheckpointMetadataProjector,
    project_durable_checkpoint_metadata,
)
from phoenix_os.agent.durable_model_turn import DurableModelTurnAttemptBinding
from phoenix_os.agent.durable_mutation import append_durable_checkpoint_confirmed
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.model_turn import validate_agent_model_turn_inference_binding
from phoenix_os.inference import InferenceRequest


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


class StoreBackedDurableModelTurnBindingProvider:
    """Bind a live AgentStepId through one confirmed durable safe boundary."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
        lease: DurableLease,
        metadata_projector: DurableCheckpointMetadataProjector | None = None,
        checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if metadata_projector is not None and not isinstance(
            metadata_projector,
            DurableCheckpointMetadataProjector,
        ):
            raise TypeError("metadata_projector must implement DurableCheckpointMetadataProjector")
        if not callable(checkpoint_id_factory):
            raise TypeError("checkpoint_id_factory must be callable")

        bound_lease_manager = getattr(store, "lease_manager", None)
        if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
            raise ValueError("lease_manager must match the durable store lease manager")

        self._store = store
        self._lease_manager = lease_manager
        self._lease = lease
        self._metadata_projector = metadata_projector
        self._checkpoint_id_factory = checkpoint_id_factory

    async def bind(
        self,
        turn: AgentModelTurnRequest,
        inference_request: InferenceRequest,
        *,
        now: datetime,
    ) -> DurableModelTurnAttemptBinding:
        if not isinstance(turn, AgentModelTurnRequest):
            raise TypeError("turn must be AgentModelTurnRequest")
        if not isinstance(inference_request, InferenceRequest):
            raise TypeError("inference_request must be InferenceRequest")
        _require_timezone_aware(now, label="now")

        # Reject inference substitution before any durable mutation.
        validate_agent_model_turn_inference_binding(turn, inference_request)

        lease = await self._lease_manager.require_current(
            self._lease,
            now=now,
        )
        self._lease = lease

        current = await self._store.get_current(lease.run_id)
        if current is None:
            raise AgentStateConflictError()

        self._require_bindable(
            current,
            lease=lease,
            turn=turn,
            now=now,
        )

        active_attempt = current.metadata.active_attempt

        if current.step_id == turn.step_id:
            # A prebound root is valid only before an attempt exists.
            if active_attempt is not None:
                raise AgentStateConflictError()
            checkpoint = current

        elif current.step_id is None:
            if active_attempt is not None:
                raise AgentStateConflictError()
            checkpoint = await self._append_step_binding(
                current,
                lease=lease,
                turn=turn,
                now=now,
            )

        else:
            # Moving to another live step requires durable proof that the
            # preceding step's external attempt already terminated.
            if (
                active_attempt is None
                or not active_attempt.status.terminal
                or active_attempt.agent_run_id != current.agent_run_id
                or active_attempt.step_id != current.step_id
            ):
                raise AgentStateConflictError()

            checkpoint = await self._append_step_binding(
                current,
                lease=lease,
                turn=turn,
                now=now,
            )

        return DurableModelTurnAttemptBinding(
            checkpoint=checkpoint,
            lease=lease,
            turn=turn,
            inference_request=inference_request,
        )

    @staticmethod
    def _require_bindable(
        current: CheckpointEnvelope,
        *,
        lease: DurableLease,
        turn: AgentModelTurnRequest,
        now: datetime,
    ) -> None:
        if (
            current.status is not DurableRunStatus.ACTIVE
            or current.status.terminal
            or current.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or current.durable_run_id != lease.run_id
            or current.agent_run_id != turn.run_id
            or now < current.created_at
            or now < turn.created_at
            or now >= current.metadata.retention_deadline
            or now >= current.metadata.budget.deadline
            or now >= turn.deadline
            or turn.deadline > current.metadata.budget.deadline
        ):
            raise AgentStateConflictError()

        active_attempt = current.metadata.active_attempt
        if active_attempt is not None and not active_attempt.status.terminal:
            raise AgentStateConflictError()

    async def _append_step_binding(
        self,
        current: CheckpointEnvelope,
        *,
        lease: DurableLease,
        turn: AgentModelTurnRequest,
        now: datetime,
    ) -> CheckpointEnvelope:
        checkpoint_id = self._checkpoint_id_factory()
        if not isinstance(checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id_factory must return CheckpointId")

        metadata_values = project_durable_checkpoint_metadata(
            self._metadata_projector,
            current,
            checkpoint_id=checkpoint_id,
            status=DurableRunStatus.ACTIVE,
            step_id=turn.step_id,
            next_operation=CheckpointNextOperation.MODEL_TURN,
            active_attempt=None,
            metadata=current.metadata.metadata,
        )
        metadata = replace(
            current.metadata,
            next_operation=CheckpointNextOperation.MODEL_TURN,
            active_attempt=None,
            metadata=metadata_values,
        )
        candidate = seal_checkpoint_envelope(
            replace(
                current,
                checkpoint_id=checkpoint_id,
                sequence=current.sequence.next(),
                previous_digest=current.digest,
                run_version=current.run_version.next(),
                status=DurableRunStatus.ACTIVE,
                step_id=turn.step_id,
                metadata=metadata,
                created_at=now,
                digest=CheckpointDigest("0" * 64),
            )
        )
        return await append_durable_checkpoint_confirmed(
            self._store,
            current=current,
            intended=candidate,
            lease=lease,
            now=now,
        )
