"""Authorized same-lease durable activation for an already-prepared RFC-0039 resume."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableLease,
    DurableRunStatus,
    ReconciliationDecision,
    ResumeReason,
    ResumeRequest,
)
from phoenix_os.agent.durable_metadata import (
    project_durable_checkpoint_metadata,
    validate_durable_checkpoint_history,
)
from phoenix_os.agent.durable_mutation import append_durable_checkpoint_confirmed
from phoenix_os.agent.durable_reconciliation import DurableReconciliationDispositionRecord
from phoenix_os.agent.durable_recovery import validate_authoritative_checkpoint_history
from phoenix_os.agent.durable_state import DurableRunStateMachine
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.control_plane.task_resume_preparation import (
    PreparedSameLeaseDurableTaskResume,
)
from phoenix_os.control_plane.task_runtime_bridge import (
    TaskExecutionAuthority,
    authorize_operator_durable_task_resume,
)
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskResumeSupport,
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedOrchestrationPhase,
    IntegratedWaitingReason,
)
from phoenix_os.integrated_agent.durable_projection import (
    RFC0036_DURABLE_METADATA_PREFIX,
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import IntegratedDurableResumeState


def _utc_now() -> datetime:
    return datetime.now(UTC)


class TaskResumeActivationError(RuntimeError):
    """Content-free failure while activating one authorized prepared resume."""


@dataclass(frozen=True, slots=True)
class SameLeaseDurableTaskResumeActivation:
    """Exact durable checkpoints committed while retaining the prepared lease."""

    prepared: PreparedSameLeaseDurableTaskResume
    recovering_checkpoint: CheckpointEnvelope
    checkpoint: CheckpointEnvelope

    def __post_init__(self) -> None:
        if not isinstance(self.prepared, PreparedSameLeaseDurableTaskResume):
            raise TypeError("prepared must be PreparedSameLeaseDurableTaskResume")
        if not isinstance(self.recovering_checkpoint, CheckpointEnvelope):
            raise TypeError("recovering_checkpoint must be CheckpointEnvelope")
        if not isinstance(self.checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")

        source = self.prepared.checkpoint
        recovering = self.recovering_checkpoint
        active = self.checkpoint
        source_projection = decode_integrated_durable_projection(source)
        recovering_projection = decode_integrated_durable_projection(recovering)
        active_projection = decode_integrated_durable_projection(active)
        if (
            source_projection is None
            or recovering_projection is None
            or active_projection is None
            or source_projection.orchestration_phase is not IntegratedOrchestrationPhase.WAITING
            or source_projection.waiting_reason is not IntegratedWaitingReason.CONTEXT_RESUPPLY
            or recovering_projection.orchestration_phase
            is not IntegratedOrchestrationPhase.EXECUTING
            or recovering_projection.waiting_reason is not None
            or recovering_projection.current_agent_step_id is not None
            or recovering.step_id is not None
            or active_projection.orchestration_phase is not IntegratedOrchestrationPhase.EXECUTING
            or active_projection.waiting_reason is not None
            or active_projection.current_agent_step_id is not None
            or active.step_id is not None
            or recovering_projection.budget_extension_usage
            != source_projection.budget_extension_usage
            or active_projection.budget_extension_usage != source_projection.budget_extension_usage
            or recovering.durable_run_id != source.durable_run_id
            or recovering.agent_run_id != source.agent_run_id
            or recovering.status is not DurableRunStatus.RECOVERING
            or recovering.sequence != source.sequence.next()
            or recovering.run_version != source.run_version.next()
            or recovering.previous_digest != source.digest
            or recovering.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or recovering.metadata.active_attempt is not None
            or recovering.metadata.budget != source.metadata.budget
            or active.durable_run_id != source.durable_run_id
            or active.agent_run_id != source.agent_run_id
            or active.status is not DurableRunStatus.ACTIVE
            or active.sequence != recovering.sequence.next()
            or active.run_version != recovering.run_version.next()
            or active.previous_digest != recovering.digest
            or active.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or active.metadata.active_attempt is not None
            or active.metadata.budget != source.metadata.budget
        ):
            raise TaskResumeActivationError()


async def activate_prepared_same_lease_durable_task_resume(
    *,
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    support: ServerOwnedDurableIntegratedTaskResumeSupport,
    prepared: PreparedSameLeaseDurableTaskResume,
    authority: TaskExecutionAuthority,
    now: datetime,
    clock: Callable[[], datetime] = _utc_now,
    checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
) -> SameLeaseDurableTaskResumeActivation:
    """Activate one prepared operator resume without acquiring or releasing a lease."""

    if not isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime):
        raise TypeError("owner must be ServerOwnedDurableIntegratedTaskRuntime")
    if not isinstance(support, ServerOwnedDurableIntegratedTaskResumeSupport):
        raise TypeError("support must be ServerOwnedDurableIntegratedTaskResumeSupport")
    if not isinstance(prepared, PreparedSameLeaseDurableTaskResume):
        raise TypeError("prepared must be PreparedSameLeaseDurableTaskResume")
    if not isinstance(authority, TaskExecutionAuthority):
        raise TypeError("authority must be TaskExecutionAuthority")
    if not callable(clock):
        raise TypeError("clock must be callable")
    if not callable(checkpoint_id_factory):
        raise TypeError("checkpoint_id_factory must be callable")
    _require_timezone_aware(now)

    if (
        prepared.released
        or support.context is not authority.context
        or support.context_resupply.closed
    ):
        raise TaskResumeActivationError()

    stack = owner.durable_stack
    lease = prepared.durable_lease
    source = prepared.checkpoint
    resume_request = prepared.resume_request
    live_request = prepared.live_state.request
    live_binding = prepared.live_state.binding
    source_projection = decode_integrated_durable_projection(source)

    if (
        source_projection is None
        or source_projection.orchestration_phase is not IntegratedOrchestrationPhase.WAITING
        or source_projection.waiting_reason is not IntegratedWaitingReason.CONTEXT_RESUPPLY
        or source_projection.current_attempt_id is not None
        or source_projection.current_agent_step_id != source.step_id
        or source.durable_run_id != lease.run_id
        or source.agent_run_id != live_request.run_id
        or live_binding.run_id != source.agent_run_id
        or source.status is not DurableRunStatus.PAUSED_OPERATOR
        or source.status.terminal
        or source.status.indeterminate
        or source.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
        or source.metadata.active_attempt is not None
        or resume_request.run_id != source.durable_run_id
        or resume_request.reason is not ResumeReason.OPERATOR_REQUEST
        or resume_request.expected_version != source.run_version
        or resume_request.generation != lease.generation
        or resume_request.actor_id != authority.context.principal
        or now < source.created_at
        or now < resume_request.requested_at
        or now >= source.metadata.retention_deadline
        or now >= source.metadata.budget.deadline
        or now >= live_request.deadline
    ):
        raise TaskResumeActivationError()

    reconciliation_keys = _reconciliation_keys_to_consume(source)
    gate_now = _clock_now(clock, not_before=now)
    authoritative_lease = await stack.lease_manager.require_current(lease, now=gate_now)
    if authoritative_lease != lease or await stack.store.get_current(lease.run_id) != source:
        raise TaskResumeActivationError()
    current_request = await owner.admission.request_for_run(source.agent_run_id)
    current_binding = await owner.admission.binding_for_run(source.agent_run_id)
    if current_request != live_request or current_binding != live_binding:
        raise TaskResumeActivationError()
    history = await stack.store.list_history(source.durable_run_id, limit=source.sequence.value)
    validate_authoritative_checkpoint_history(source, history)
    validate_durable_checkpoint_history(stack.history_validator, source, history)
    compatibility = stack.compatibility_validator.validate(source)
    if compatibility.agent_id != source.metadata.agent_id or not compatibility.compatible:
        raise TaskResumeActivationError()
    resume_state = await support.resume_gate.assess_resume_state(
        source,
        now=gate_now,
    )
    if resume_state is not IntegratedDurableResumeState.READY:
        raise TaskResumeActivationError()
    authorization_now = _clock_now(clock, not_before=gate_now)
    current_authorization = await authorize_operator_durable_task_resume(
        checkpoint=source,
        lease_manager=stack.lease_manager,
        lease=lease,
        authority=authority,
        actor_id=resume_request.actor_id,
        now=authorization_now,
    )
    _require_same_resume_authorization(
        current_authorization,
        prepared=resume_request,
        now=authorization_now,
    )
    recovering_now = _clock_now(clock, not_before=authorization_now)
    authoritative_lease = await stack.lease_manager.require_current(
        authoritative_lease,
        now=recovering_now,
    )
    if authoritative_lease != lease or await stack.store.get_current(lease.run_id) != source:
        raise TaskResumeActivationError()
    machine = DurableRunStateMachine.from_checkpoint(source)
    machine.transition(DurableRunStatus.RECOVERING, now=recovering_now)
    recovering = await _append_recovering_status(
        owner,
        source,
        source_projection=source_projection,
        lease=authoritative_lease,
        now=recovering_now,
        checkpoint_id_factory=checkpoint_id_factory,
    )
    await _validate_persisted_history(owner, recovering)
    active_now = _clock_now(clock, not_before=recovering_now)
    authoritative_lease = await stack.lease_manager.require_current(
        authoritative_lease,
        now=active_now,
    )
    if authoritative_lease != lease or await stack.store.get_current(lease.run_id) != recovering:
        raise TaskResumeActivationError()
    machine.transition(DurableRunStatus.ACTIVE, now=active_now)
    active = await _append_projected_status(
        owner,
        recovering,
        lease=authoritative_lease,
        status=DurableRunStatus.ACTIVE,
        now=active_now,
        checkpoint_id_factory=checkpoint_id_factory,
        metadata_keys_to_drop=reconciliation_keys,
    )
    await _validate_persisted_history(owner, active)

    return SameLeaseDurableTaskResumeActivation(
        prepared=prepared,
        recovering_checkpoint=recovering,
        checkpoint=active,
    )


async def _append_recovering_status(
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    current: CheckpointEnvelope,
    *,
    source_projection: IntegratedOrchestrationCheckpointProjection,
    lease: DurableLease,
    now: datetime,
    checkpoint_id_factory: Callable[[], CheckpointId],
) -> CheckpointEnvelope:
    if not isinstance(source_projection, IntegratedOrchestrationCheckpointProjection):
        raise TypeError("source_projection must be IntegratedOrchestrationCheckpointProjection")
    checkpoint_id = checkpoint_id_factory()
    if not isinstance(checkpoint_id, CheckpointId):
        raise TypeError("checkpoint_id_factory must return CheckpointId")

    recovering_projection = replace(
        source_projection,
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        waiting_reason=None,
        current_agent_step_id=None,
        current_attempt_id=None,
    )
    unreserved = {
        key: value
        for key, value in current.metadata.metadata.items()
        if not key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
    }
    metadata_values = merge_integrated_durable_projection(
        unreserved,
        recovering_projection,
    )
    candidate = _candidate(
        current,
        checkpoint_id=checkpoint_id,
        status=DurableRunStatus.RECOVERING,
        metadata_values=metadata_values,
        now=now,
    )
    return await append_durable_checkpoint_confirmed(
        owner.durable_stack.store,
        current=current,
        intended=candidate,
        lease=lease,
        now=now,
    )


async def _append_projected_status(
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    current: CheckpointEnvelope,
    *,
    lease: DurableLease,
    status: DurableRunStatus,
    now: datetime,
    checkpoint_id_factory: Callable[[], CheckpointId],
    metadata_keys_to_drop: frozenset[str] = frozenset(),
) -> CheckpointEnvelope:
    checkpoint_id = checkpoint_id_factory()
    if not isinstance(checkpoint_id, CheckpointId):
        raise TypeError("checkpoint_id_factory must return CheckpointId")

    base_metadata = {
        key: value
        for key, value in current.metadata.metadata.items()
        if key not in metadata_keys_to_drop
    }
    metadata_values = project_durable_checkpoint_metadata(
        owner.durable_stack.metadata_projector,
        current,
        checkpoint_id=checkpoint_id,
        status=status,
        step_id=current.step_id,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        metadata=base_metadata,
    )
    candidate = _candidate(
        current,
        checkpoint_id=checkpoint_id,
        status=status,
        metadata_values=metadata_values,
        now=now,
    )
    return await append_durable_checkpoint_confirmed(
        owner.durable_stack.store,
        current=current,
        intended=candidate,
        lease=lease,
        now=now,
    )


def _candidate(
    current: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId,
    status: DurableRunStatus,
    metadata_values: Mapping[str, str],
    now: datetime,
) -> CheckpointEnvelope:
    if not isinstance(metadata_values, Mapping):
        raise TypeError("metadata_values must be a mapping")
    try:
        metadata = replace(
            current.metadata,
            next_operation=CheckpointNextOperation.MODEL_TURN,
            active_attempt=None,
            metadata=metadata_values,
        )
        return seal_checkpoint_envelope(
            replace(
                current,
                checkpoint_id=checkpoint_id,
                sequence=current.sequence.next(),
                previous_digest=current.digest,
                run_version=current.run_version.next(),
                status=status,
                step_id=None,
                metadata=metadata,
                created_at=now,
                digest=CheckpointDigest("0" * 64),
            )
        )
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentStateConflictError() from exception


async def _validate_persisted_history(
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    current: CheckpointEnvelope,
) -> None:
    history = await owner.durable_stack.store.list_history(
        current.durable_run_id,
        limit=current.sequence.value,
    )
    validate_authoritative_checkpoint_history(current, history)
    validate_durable_checkpoint_history(
        owner.durable_stack.history_validator,
        current,
        history,
    )
    projection = decode_integrated_durable_projection(current)
    if projection is None:
        raise TaskResumeActivationError()
    if current.status is DurableRunStatus.RECOVERING:
        if (
            projection.orchestration_phase is not IntegratedOrchestrationPhase.EXECUTING
            or projection.waiting_reason is not None
            or current.step_id is not None
            or projection.current_agent_step_id is not None
        ):
            raise TaskResumeActivationError()
    elif current.status is DurableRunStatus.ACTIVE:
        if (
            projection.orchestration_phase is not IntegratedOrchestrationPhase.EXECUTING
            or projection.waiting_reason is not None
            or current.step_id is not None
            or projection.current_agent_step_id is not None
        ):
            raise TaskResumeActivationError()
    else:
        raise TaskResumeActivationError()


def _reconciliation_keys_to_consume(
    checkpoint: CheckpointEnvelope,
) -> frozenset[str]:
    prefixed = frozenset(
        key for key in checkpoint.metadata.metadata if key.startswith("reconciliation.")
    )
    if not prefixed:
        return frozenset()
    try:
        record = DurableReconciliationDispositionRecord.from_metadata(checkpoint.metadata.metadata)
    except (TypeError, ValueError, OverflowError) as exception:
        raise TaskResumeActivationError() from exception
    if (
        record.run_id != checkpoint.durable_run_id
        or record.decision is not ReconciliationDecision.CONFIRM_NOT_STARTED
        or record.result_status is not DurableRunStatus.PAUSED_OPERATOR
        or record.applied_at > checkpoint.created_at
    ):
        raise TaskResumeActivationError()
    return frozenset(record.to_metadata())


def _clock_now(clock: Callable[[], datetime], *, not_before: datetime) -> datetime:
    value = clock()
    _require_timezone_aware(value)
    if value < not_before:
        raise TaskResumeActivationError()
    return value


def _require_same_resume_authorization(
    current: ResumeRequest,
    *,
    prepared: ResumeRequest,
    now: datetime,
) -> None:
    if (
        not isinstance(current, ResumeRequest)
        or current.run_id != prepared.run_id
        or current.actor_id != prepared.actor_id
        or current.reason is not ResumeReason.OPERATOR_REQUEST
        or prepared.reason is not ResumeReason.OPERATOR_REQUEST
        or current.expected_version != prepared.expected_version
        or current.generation != prepared.generation
        or current.requested_at != now
    ):
        raise TaskResumeActivationError()


def _require_timezone_aware(value: datetime) -> None:
    if not isinstance(value, datetime):
        raise TypeError("now must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
