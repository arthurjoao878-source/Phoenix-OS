"""Caller-owned same-lease resume preparation for RFC-0039 durable tasks."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.agent.durable_attempts import DurablePreparedAttemptRecoveryRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    RecoveryDisposition,
    ResumeRequest,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_metadata import validate_durable_checkpoint_history
from phoenix_os.agent.durable_recovery import (
    DurableSameLeaseIndeterminateRecoveryCoordinator,
    validate_authoritative_checkpoint_history,
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
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedOrchestrationPhase,
    IntegratedTaskRequest,
    IntegratedWaitingReason,
    NormalizedPlan,
)
from phoenix_os.integrated_agent.durable_live_restore import (
    IntegratedDurableRecoveryLiveStateLease,
    restore_integrated_durable_recovery_live_state,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    integrated_data_flow_context_digest,
)
from phoenix_os.integrated_agent.durable_recovery import IntegratedDurableResumeState
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.policy import PrincipalType


def _utc_now() -> datetime:
    return datetime.now(UTC)


class TaskResumePreparationError(RuntimeError):
    """Content-free failure while preparing one exact same-run durable resume."""


class PreparedSameLeaseDurableTaskResume:
    """Own one restored live-state scope plus its caller-owned fenced durable lease."""

    def __init__(
        self,
        *,
        lease_manager: DurableLeaseManager,
        durable_lease: DurableLease,
        checkpoint: CheckpointEnvelope,
        resume_request: ResumeRequest,
        live_state: IntegratedDurableRecoveryLiveStateLease,
    ) -> None:
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(durable_lease, DurableLease):
            raise TypeError("durable_lease must be DurableLease")
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(resume_request, ResumeRequest):
            raise TypeError("resume_request must be ResumeRequest")
        if not isinstance(live_state, IntegratedDurableRecoveryLiveStateLease):
            raise TypeError("live_state must be IntegratedDurableRecoveryLiveStateLease")
        if (
            checkpoint.durable_run_id != durable_lease.run_id
            or resume_request.run_id != durable_lease.run_id
            or resume_request.expected_version != checkpoint.run_version
            or resume_request.generation != durable_lease.generation
        ):
            raise TaskResumePreparationError()

        self._lease_manager = lease_manager
        self._durable_lease = durable_lease
        self._checkpoint = checkpoint
        self._resume_request = resume_request
        self._live_state = live_state
        self._released = False
        self._lock = asyncio.Lock()

    @property
    def durable_lease(self) -> DurableLease:
        return self._durable_lease

    @property
    def checkpoint(self) -> CheckpointEnvelope:
        return self._checkpoint

    @property
    def resume_request(self) -> ResumeRequest:
        return self._resume_request

    @property
    def live_state(self) -> IntegratedDurableRecoveryLiveStateLease:
        return self._live_state

    @property
    def released(self) -> bool:
        return self._released

    async def release(self, *, now: datetime) -> None:
        """Release restored live state and only the still-current owned durable lease."""

        _require_timezone_aware(now)
        async with self._lock:
            if self._released:
                return
            cleanup = asyncio.create_task(
                _release_prepared_scope(
                    lease_manager=self._lease_manager,
                    durable_lease=self._durable_lease,
                    live_state=self._live_state,
                    now=now,
                )
            )
            pending_cancellation: asyncio.CancelledError | None = None
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError as exception:
                    if pending_cancellation is None:
                        pending_cancellation = exception
                except BaseException:
                    break
            cleanup.result()
            self._released = True
            if pending_cancellation is not None:
                raise pending_cancellation


async def prepare_same_lease_durable_task_resume(
    *,
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    support: ServerOwnedDurableIntegratedTaskResumeSupport,
    durable_run_id: DurableAgentRunId,
    authority: TaskExecutionAuthority,
    lease_owner_id: str,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
    provenance: IntegratedDataProvenance,
    budget_usage: IntegratedBudgetUsage,
    plan: NormalizedPlan | None,
    now: datetime,
    clock: Callable[[], datetime] | None = None,
) -> PreparedSameLeaseDurableTaskResume:
    """Prepare an existing paused run for continuation without executing it."""

    if not isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime):
        raise TypeError("owner must be ServerOwnedDurableIntegratedTaskRuntime")
    if not isinstance(support, ServerOwnedDurableIntegratedTaskResumeSupport):
        raise TypeError("support must be ServerOwnedDurableIntegratedTaskResumeSupport")
    if not isinstance(durable_run_id, DurableAgentRunId):
        raise TypeError("durable_run_id must be DurableAgentRunId")
    if not isinstance(authority, TaskExecutionAuthority):
        raise TypeError("authority must be TaskExecutionAuthority")
    if not isinstance(lease_owner_id, str) or not lease_owner_id.strip():
        raise ValueError("lease_owner_id must be a non-empty string")
    if lease_owner_id != lease_owner_id.strip():
        raise ValueError("lease_owner_id must be canonical")
    if not isinstance(task, IntegratedTaskRequest):
        raise TypeError("task must be IntegratedTaskRequest")
    if not isinstance(request, AgentRunRequest):
        raise TypeError("request must be AgentRunRequest")
    if not isinstance(provenance, IntegratedDataProvenance):
        raise TypeError("provenance must be IntegratedDataProvenance")
    if not isinstance(budget_usage, IntegratedBudgetUsage):
        raise TypeError("budget_usage must be IntegratedBudgetUsage")
    if plan is not None and not isinstance(plan, NormalizedPlan):
        raise TypeError("plan must be NormalizedPlan or None")
    _require_timezone_aware(now)
    if clock is not None and not callable(clock):
        raise TypeError("clock must be callable or None")
    selected_clock: Callable[[], datetime] = (lambda: now) if clock is None else clock

    planner = owner.planner
    if planner is None:
        raise TaskResumePreparationError()
    if (
        support.context is not authority.context
        or authority.context.principal_type is not PrincipalType.USER
        or support.context_resupply.closed
        or support.context_resupply.history_validator is not support.history_validator
    ):
        raise TaskResumePreparationError()
    configuration = owner.service.configuration
    if (
        integrated_durable_run_id(request.run_id) != durable_run_id
        or request.agent_id != owner.profile.agent_id
        or request.agent_id != configuration.agent_id
        or request.provider_id != configuration.provider_id
        or request.model_id != configuration.model_id
    ):
        raise TaskResumePreparationError()

    lease_manager = owner.durable_stack.lease_manager
    durable_lease = await lease_manager.acquire(
        durable_run_id,
        owner_id=lease_owner_id,
        now=now,
    )
    live_state: IntegratedDurableRecoveryLiveStateLease | None = None
    try:
        authoritative_lease = await lease_manager.require_current(durable_lease, now=now)
        if authoritative_lease != durable_lease:
            raise TaskResumePreparationError()
        checkpoint = await owner.durable_stack.store.get_current(durable_run_id)
        if checkpoint is None:
            raise TaskResumePreparationError()
        history = await owner.durable_stack.store.list_history(
            durable_run_id,
            limit=checkpoint.sequence.value,
        )
        validate_authoritative_checkpoint_history(checkpoint, history)
        validate_durable_checkpoint_history(support.history_validator, checkpoint, history)
        projection = decode_integrated_durable_projection(checkpoint)
        if projection is None:
            raise TaskResumePreparationError()
        _require_reviewed_binding_inputs(
            owner=owner,
            checkpoint=checkpoint,
            projection=projection,
            task=task,
            request=request,
            provenance=provenance,
            budget_usage=budget_usage,
            plan=plan,
        )
        compatibility = owner.durable_stack.compatibility_validator.validate(checkpoint)
        if compatibility.agent_id != checkpoint.metadata.agent_id or not compatibility.compatible:
            raise TaskResumePreparationError()

        attempt = checkpoint.metadata.active_attempt
        if (
            checkpoint.status is DurableRunStatus.ACTIVE
            and checkpoint.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
            and attempt is not None
            and attempt.kind is ExecutionAttemptKind.MODEL_TURN
            and attempt.status is ExecutionAttemptStatus.PREPARED
            and attempt.started_at is None
        ):
            recorder = owner.durable_stack.attempt_recorder
            if not isinstance(recorder, DurablePreparedAttemptRecoveryRecorder):
                raise TaskResumePreparationError()
            mutation_now = _clock_now(selected_clock, not_before=now)
            checkpoint = await recorder.cancel_prepared_not_started(
                durable_run_id,
                expected_version=checkpoint.run_version,
                lease=authoritative_lease,
                now=mutation_now,
            )
            now = mutation_now
        elif (
            checkpoint.status is DurableRunStatus.ACTIVE
            and checkpoint.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
            and attempt is not None
            and attempt.kind is ExecutionAttemptKind.MODEL_TURN
            and attempt.status is ExecutionAttemptStatus.STARTED
        ):
            recovery = owner.durable_stack.recovery_coordinator
            if not isinstance(recovery, DurableSameLeaseIndeterminateRecoveryCoordinator):
                raise TaskResumePreparationError()
            assessment = await recovery.persist_indeterminate_candidate_with_lease(
                durable_run_id,
                lease=authoritative_lease,
                now=now,
                clock=selected_clock,
                reason=IndeterminateReason.PROVIDER_STATUS_UNKNOWN,
            )
            if (
                assessment.status is not DurableRunStatus.INDETERMINATE_MODEL
                or assessment.disposition is not RecoveryDisposition.PAUSE_OPERATOR
            ):
                raise TaskResumePreparationError()
            raise TaskResumePreparationError()

        normalization_now = _clock_now(selected_clock, not_before=now)
        checkpoint = await support.context_resupply.pause_candidate_with_lease(
            durable_run_id,
            lease=authoritative_lease,
            now=normalization_now,
            clock=selected_clock,
        )
        now = normalization_now
        _require_resumable_checkpoint(checkpoint, durable_run_id=durable_run_id, request=request)
        history = await owner.durable_stack.store.list_history(
            durable_run_id,
            limit=checkpoint.sequence.value,
        )
        validate_authoritative_checkpoint_history(checkpoint, history)
        validate_durable_checkpoint_history(support.history_validator, checkpoint, history)
        projection = decode_integrated_durable_projection(checkpoint)
        if projection is None:
            raise TaskResumePreparationError()
        _require_reviewed_restore_inputs(
            owner=owner,
            checkpoint=checkpoint,
            projection=projection,
            task=task,
            provenance=provenance,
            budget_usage=budget_usage,
            plan=plan,
        )
        live_state = await restore_integrated_durable_recovery_live_state(
            admission=owner.admission,
            execution_guard=owner.execution_guard,
            planner=planner,
            task=task,
            request=request,
            provenance=provenance,
            budget_usage=budget_usage,
            plan=plan,
        )
        gate_now = _clock_now(selected_clock, not_before=now)
        resume_state = await support.resume_gate.assess_resume_state(
            checkpoint,
            now=gate_now,
        )
        if resume_state is not IntegratedDurableResumeState.READY:
            raise TaskResumePreparationError()
        renew_now = _clock_now(selected_clock, not_before=gate_now)
        durable_lease = await lease_manager.renew(durable_lease, now=renew_now)
        authorization_now = _clock_now(selected_clock, not_before=renew_now)
        resume_request = await authorize_operator_durable_task_resume(
            checkpoint=checkpoint,
            lease_manager=lease_manager,
            lease=durable_lease,
            authority=authority,
            actor_id=authority.context.principal,
            now=authorization_now,
        )
        final_now = _clock_now(selected_clock, not_before=authorization_now)
        if await lease_manager.require_current(durable_lease, now=final_now) != durable_lease:
            raise TaskResumePreparationError()
        return PreparedSameLeaseDurableTaskResume(
            lease_manager=lease_manager,
            durable_lease=durable_lease,
            checkpoint=checkpoint,
            resume_request=resume_request,
            live_state=live_state,
        )
    except BaseException as primary:
        cleanup_now: datetime | None = None
        try:
            candidate_now = selected_clock()
            _require_timezone_aware(candidate_now)
            if candidate_now >= now:
                cleanup_now = candidate_now
        except BaseException:
            cleanup_now = None

        cleanup = asyncio.create_task(
            _release_prepared_scope(
                lease_manager=lease_manager,
                durable_lease=durable_lease,
                live_state=live_state,
                now=cleanup_now,
            )
        )
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except BaseException:
                continue
        try:
            cleanup.result()
        except BaseException as cleanup_error:
            raise primary from cleanup_error
        raise


def _require_reviewed_binding_inputs(
    *,
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    checkpoint: CheckpointEnvelope,
    projection: IntegratedOrchestrationCheckpointProjection,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
    provenance: IntegratedDataProvenance,
    budget_usage: IntegratedBudgetUsage,
    plan: NormalizedPlan | None,
) -> None:
    if (
        checkpoint.agent_run_id != request.run_id
        or checkpoint.metadata.agent_id != owner.profile.agent_id
        or projection.task_id != task.task_id
        or projection.task_digest != task.digest
        or projection.execution_profile_id != owner.profile.profile_id
        or projection.execution_profile_generation != owner.profile.generation
        or projection.budget_extension_usage != budget_usage
        or projection.data_flow_context_digest is None
        or projection.data_flow_context_digest != integrated_data_flow_context_digest(provenance)
    ):
        raise TaskResumePreparationError()
    expected_revision = projection.plan_revision
    if expected_revision is None:
        if plan is not None or projection.plan_digest is not None:
            raise TaskResumePreparationError()
    elif (
        plan is None
        or plan.task_id != task.task_id
        or plan.revision != expected_revision
        or plan.digest != projection.plan_digest
    ):
        raise TaskResumePreparationError()


def _require_resumable_checkpoint(
    checkpoint: CheckpointEnvelope,
    *,
    durable_run_id: DurableAgentRunId,
    request: AgentRunRequest,
) -> None:
    if (
        checkpoint.durable_run_id != durable_run_id
        or checkpoint.agent_run_id != request.run_id
        or checkpoint.status is not DurableRunStatus.PAUSED_OPERATOR
        or checkpoint.status.terminal
        or checkpoint.status.indeterminate
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
        or checkpoint.metadata.active_attempt is not None
    ):
        raise TaskResumePreparationError()


def _require_reviewed_restore_inputs(
    *,
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    checkpoint: CheckpointEnvelope,
    projection: IntegratedOrchestrationCheckpointProjection,
    task: IntegratedTaskRequest,
    provenance: IntegratedDataProvenance,
    budget_usage: IntegratedBudgetUsage,
    plan: NormalizedPlan | None,
) -> None:
    if (
        projection.task_id != task.task_id
        or projection.task_digest != task.digest
        or projection.execution_profile_id != owner.profile.profile_id
        or projection.execution_profile_generation != owner.profile.generation
        or projection.orchestration_phase is not IntegratedOrchestrationPhase.WAITING
        or projection.waiting_reason is not IntegratedWaitingReason.CONTEXT_RESUPPLY
        or projection.current_attempt_id is not None
        or projection.budget_extension_usage != budget_usage
        or projection.data_flow_context_digest is None
        or projection.data_flow_context_digest != integrated_data_flow_context_digest(provenance)
    ):
        raise TaskResumePreparationError()

    expected_revision = projection.plan_revision
    if expected_revision is None:
        if plan is not None or projection.plan_digest is not None:
            raise TaskResumePreparationError()
    elif (
        plan is None
        or plan.task_id != task.task_id
        or plan.revision != expected_revision
        or plan.digest != projection.plan_digest
    ):
        raise TaskResumePreparationError()

    if checkpoint.metadata.agent_id != owner.profile.agent_id:
        raise TaskResumePreparationError()


def _require_timezone_aware(value: datetime) -> None:
    if not isinstance(value, datetime):
        raise TypeError("now must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must be timezone-aware")


async def _release_prepared_scope(
    *,
    lease_manager: DurableLeaseManager,
    durable_lease: DurableLease,
    live_state: IntegratedDurableRecoveryLiveStateLease | None,
    now: datetime | None,
) -> None:
    failure: BaseException | None = None
    if live_state is not None:
        try:
            await live_state.release()
        except BaseException as exception:
            failure = exception
    if now is not None:
        try:
            current = await lease_manager.get_current(durable_lease.run_id, now=now)
            if current == durable_lease:
                await lease_manager.release(durable_lease, now=now)
        except BaseException as exception:
            if failure is None:
                failure = exception
    if failure is not None:
        raise failure


def _clock_now(clock: Callable[[], datetime], *, not_before: datetime) -> datetime:
    value = clock()
    _require_timezone_aware(value)
    if value < not_before:
        raise TaskResumePreparationError()
    return value
