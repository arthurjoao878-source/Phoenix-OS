"""Caller-owned same-lease resume preparation for RFC-0039 durable tasks."""

from __future__ import annotations

import asyncio
from datetime import datetime

from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    RecoveryDisposition,
    RecoveryPoint,
    ResumeRequest,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_metadata import validate_durable_checkpoint_history
from phoenix_os.agent.durable_recovery import (
    classify_recovery_checkpoint,
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
        """Release restored live state first and the same durable lease exactly once."""

        _require_timezone_aware(now)
        async with self._lock:
            if self._released:
                return
            await self._live_state.release()
            await self._lease_manager.release(self._durable_lease, now=now)
            self._released = True


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
        authoritative_lease = await lease_manager.require_current(
            durable_lease,
            now=now,
        )
        if authoritative_lease != durable_lease:
            raise TaskResumePreparationError()

        checkpoint = await owner.durable_stack.store.get_current(durable_run_id)
        if checkpoint is None:
            raise TaskResumePreparationError()
        _require_resumable_checkpoint(
            checkpoint,
            durable_run_id=durable_run_id,
            request=request,
        )

        history = await owner.durable_stack.store.list_history(
            durable_run_id,
            limit=checkpoint.sequence.value,
        )
        validate_authoritative_checkpoint_history(checkpoint, history)
        validate_durable_checkpoint_history(
            support.history_validator,
            checkpoint,
            history,
        )

        compatibility = owner.durable_stack.compatibility_validator.validate(checkpoint)
        if compatibility.agent_id != checkpoint.metadata.agent_id or not compatibility.compatible:
            raise TaskResumePreparationError()

        recovery_point, recovery_disposition = classify_recovery_checkpoint(
            checkpoint,
            now=now,
        )
        if (
            recovery_point is not RecoveryPoint.OPERATOR_PAUSE
            or recovery_disposition is not RecoveryDisposition.PAUSE_OPERATOR
        ):
            raise TaskResumePreparationError()

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

        resume_state = await support.resume_gate.assess_resume_state(
            checkpoint,
            now=now,
        )
        if resume_state is not IntegratedDurableResumeState.READY:
            raise TaskResumePreparationError()

        resume_request = await authorize_operator_durable_task_resume(
            checkpoint=checkpoint,
            lease_manager=lease_manager,
            lease=durable_lease,
            authority=authority,
            actor_id=authority.context.principal,
            now=now,
        )

        authoritative_lease = await lease_manager.require_current(
            durable_lease,
            now=now,
        )
        if authoritative_lease != durable_lease:
            raise TaskResumePreparationError()

        return PreparedSameLeaseDurableTaskResume(
            lease_manager=lease_manager,
            durable_lease=durable_lease,
            checkpoint=checkpoint,
            resume_request=resume_request,
            live_state=live_state,
        )
    except BaseException:
        try:
            if live_state is not None:
                await live_state.release()
        finally:
            await lease_manager.release(durable_lease, now=now)
        raise


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
