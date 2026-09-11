"""Authority-preserving RFC-0039 status/cancellation/resume seams over durable integrated runs.

This module does not acquire execution leases, create policy grants, open durable storage,
or implement a second task state machine. Callers must supply already-reviewed runtime
objects and authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from phoenix_os.agent.durable_authorization import PolicyEngineDurableResumeAuthorizer
from phoenix_os.agent.durable_cancellation import (
    DurableCancellationCoordinator,
    durable_cancellation_requested,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableCancellationRequest,
    DurableLease,
    DurableRunStatus,
    ResumeReason,
    ResumeRequest,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorProfileConfiguration,
)
from phoenix_os.integrated_agent.contracts import IntegratedOrchestrationPhase
from phoenix_os.integrated_agent.durable_projection import decode_integrated_durable_projection
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.integrated_agent.profiles import IntegratedExecutionProfile
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext


class TaskRuntimeBridgeValidationError(ValueError):
    """Content-free failure for a mismatched trusted task-runtime composition."""


@dataclass(frozen=True, slots=True)
class TaskExecutionAuthority:
    """Caller-owned execution authority; never manufactures a Phoenix policy grant."""

    policy: PolicyEngine
    context: SecurityContext

    def __post_init__(self) -> None:
        if not isinstance(self.policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        if not isinstance(self.context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if self.policy.closed:
            raise TaskRuntimeBridgeValidationError()
        if not self.context.authenticated or self.context.principal_type is PrincipalType.ANONYMOUS:
            raise TaskRuntimeBridgeValidationError()


@dataclass(frozen=True, slots=True)
class TaskStatusSummary:
    """Bounded content-free RFC-0039 task status projection."""

    schema_version: int
    task_id: str
    run_id: str
    profile_name: str
    provider_id: str
    model_id: str
    run_state: str
    current_step_category: str | None
    model_turns_used: int
    model_turns_max: int
    tool_calls_used: int
    tool_calls_max: int
    accepted_tool_proposals: int | None
    rejected_tool_proposals: int | None
    deadline_state: str
    cancellation_state: str
    provider_failure_category: str | None
    durable_recovery_disposition: str | None
    terminal_category: str | None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported task status summary version")
        for label, string_value in (
            ("task_id", self.task_id),
            ("run_id", self.run_id),
            ("profile_name", self.profile_name),
            ("provider_id", self.provider_id),
            ("model_id", self.model_id),
            ("run_state", self.run_state),
            ("deadline_state", self.deadline_state),
            ("cancellation_state", self.cancellation_state),
        ):
            if not isinstance(string_value, str) or not string_value:
                raise ValueError(f"{label} must be a non-empty string")
        for label, integer_value in (
            ("model_turns_used", self.model_turns_used),
            ("model_turns_max", self.model_turns_max),
            ("tool_calls_used", self.tool_calls_used),
            ("tool_calls_max", self.tool_calls_max),
        ):
            if (
                isinstance(integer_value, bool)
                or not isinstance(integer_value, int)
                or integer_value < 0
            ):
                raise ValueError(f"{label} must be a non-negative integer")
        for label, optional_integer_value in (
            ("accepted_tool_proposals", self.accepted_tool_proposals),
            ("rejected_tool_proposals", self.rejected_tool_proposals),
        ):
            if optional_integer_value is not None and (
                isinstance(optional_integer_value, bool)
                or not isinstance(optional_integer_value, int)
                or optional_integer_value < 0
            ):
                raise ValueError(f"{label} must be a non-negative integer or None")
        for label, optional_string_value in (
            ("current_step_category", self.current_step_category),
            ("provider_failure_category", self.provider_failure_category),
            ("durable_recovery_disposition", self.durable_recovery_disposition),
            ("terminal_category", self.terminal_category),
        ):
            if optional_string_value is not None and (
                not isinstance(optional_string_value, str) or not optional_string_value
            ):
                raise ValueError(f"{label} must be a non-empty string or None")


def project_authorized_durable_task_status(
    *,
    configuration: OperatorConfiguration,
    operator_profile: OperatorProfileConfiguration,
    execution_profile: IntegratedExecutionProfile,
    checkpoint: CheckpointEnvelope,
    now: datetime,
) -> TaskStatusSummary:
    """Project one already-authorized durable checkpoint without inventing telemetry."""

    if not isinstance(configuration, OperatorConfiguration):
        raise TypeError("configuration must be OperatorConfiguration")
    if not isinstance(operator_profile, OperatorProfileConfiguration):
        raise TypeError("operator_profile must be OperatorProfileConfiguration")
    if not isinstance(execution_profile, IntegratedExecutionProfile):
        raise TypeError("execution_profile must be IntegratedExecutionProfile")
    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    _require_timezone_aware(now, label="now")
    if now < checkpoint.created_at:
        raise TaskRuntimeBridgeValidationError()

    matching_profiles = tuple(
        item
        for item in configuration.profiles
        if item.profile_name == operator_profile.profile_name
    )
    if matching_profiles != (operator_profile,):
        raise TaskRuntimeBridgeValidationError()
    try:
        model = configuration.model(operator_profile.model_name)
        workspace = configuration.workspace(operator_profile.workspace_name)
    except KeyError as exception:
        raise TaskRuntimeBridgeValidationError() from exception
    if workspace.workspace_name != operator_profile.workspace_name:
        raise TaskRuntimeBridgeValidationError()

    projection = decode_integrated_durable_projection(checkpoint)
    if projection is None:
        raise TaskRuntimeBridgeValidationError()
    if (
        integrated_durable_run_id(checkpoint.agent_run_id) != checkpoint.durable_run_id
        or execution_profile.profile_id != projection.execution_profile_id
        or execution_profile.generation != projection.execution_profile_generation
        or execution_profile.agent_id != checkpoint.metadata.agent_id
        or not execution_profile.enabled
    ):
        raise TaskRuntimeBridgeValidationError()

    budget = checkpoint.metadata.budget
    limits = execution_profile.limits
    if budget.model_turns > limits.max_model_turns or budget.tool_calls > limits.max_tool_calls:
        raise TaskRuntimeBridgeValidationError()

    next_operation = checkpoint.metadata.next_operation
    current_step_category = (
        None
        if checkpoint.status.terminal or next_operation is CheckpointNextOperation.NONE
        else next_operation.value
    )

    cancellation_state = "not_recorded"
    if durable_cancellation_requested(checkpoint):
        cancellation_state = "requested"
    if checkpoint.status is DurableRunStatus.CANCELLED:
        cancellation_state = "cancelled"

    recovery_disposition: str | None = None
    if not checkpoint.status.terminal:
        try:
            _point, disposition = classify_recovery_checkpoint(checkpoint, now=now)
        except AgentStateConflictError as exception:
            raise TaskRuntimeBridgeValidationError() from exception
        recovery_disposition = disposition.value

    return TaskStatusSummary(
        schema_version=1,
        task_id=str(projection.task_id),
        run_id=str(checkpoint.agent_run_id),
        profile_name=operator_profile.profile_name,
        provider_id=str(model.descriptor.provider_id),
        model_id=str(model.descriptor.model_id),
        run_state=checkpoint.status.value,
        current_step_category=current_step_category,
        model_turns_used=budget.model_turns,
        model_turns_max=limits.max_model_turns,
        tool_calls_used=budget.tool_calls,
        tool_calls_max=limits.max_tool_calls,
        # RFC-0039 forbids fabricated precision. No exact persisted counters exist yet.
        accepted_tool_proposals=None,
        rejected_tool_proposals=None,
        deadline_state=("expired" if now >= budget.deadline else "remaining"),
        cancellation_state=cancellation_state,
        provider_failure_category=None,
        durable_recovery_disposition=recovery_disposition,
        terminal_category=(checkpoint.status.value if checkpoint.status.terminal else None),
    )


async def cancel_authorized_durable_task(
    *,
    checkpoint: CheckpointEnvelope,
    cancellation: DurableCancellationCoordinator,
    lease: DurableLease,
    context: SecurityContext,
    actor_id: str,
    now: datetime,
) -> CheckpointEnvelope:
    """Cancel through caller-owned fenced authority; never acquire or steal a lease."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    if not isinstance(cancellation, DurableCancellationCoordinator):
        raise TypeError("cancellation must implement DurableCancellationCoordinator")
    if not isinstance(lease, DurableLease):
        raise TypeError("lease must be DurableLease")
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not isinstance(actor_id, str) or not actor_id.strip() or actor_id != actor_id.strip():
        raise ValueError("actor_id must be a non-blank canonical string")
    _require_timezone_aware(now, label="now")
    if now < checkpoint.created_at:
        raise TaskRuntimeBridgeValidationError()
    if (
        integrated_durable_run_id(checkpoint.agent_run_id) != checkpoint.durable_run_id
        or lease.run_id != checkpoint.durable_run_id
    ):
        raise TaskRuntimeBridgeValidationError()

    request = DurableCancellationRequest(
        run_id=checkpoint.durable_run_id,
        actor_id=actor_id,
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        requested_at=now,
    )
    result = await cancellation.cancel(
        request,
        lease=lease,
        context=context,
        now=now,
    )
    if not isinstance(result, CheckpointEnvelope):
        raise TypeError("cancellation coordinator must return CheckpointEnvelope")
    if (
        result.durable_run_id != checkpoint.durable_run_id
        or result.agent_run_id != checkpoint.agent_run_id
        or integrated_durable_run_id(result.agent_run_id) != result.durable_run_id
        or not durable_cancellation_requested(result)
    ):
        raise TaskRuntimeBridgeValidationError()

    projection = decode_integrated_durable_projection(result)
    if projection is None:
        raise TaskRuntimeBridgeValidationError()
    if result.status is DurableRunStatus.CANCELLED:
        if projection.orchestration_phase is not IntegratedOrchestrationPhase.TERMINAL:
            raise TaskRuntimeBridgeValidationError()
    elif result.status.indeterminate:
        if projection.orchestration_phase is not IntegratedOrchestrationPhase.WAITING:
            raise TaskRuntimeBridgeValidationError()
    else:
        raise TaskRuntimeBridgeValidationError()
    return result


async def authorize_operator_durable_task_resume(
    *,
    checkpoint: CheckpointEnvelope,
    lease_manager: DurableLeaseManager,
    lease: DurableLease,
    authority: TaskExecutionAuthority,
    actor_id: str,
    now: datetime,
) -> ResumeRequest:
    """Authorize one operator resume over a caller-owned current fenced lease.

    This seam does not acquire a lease, mutate the checkpoint, restore integrated
    context, or execute continuation work.
    """

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    if not isinstance(lease_manager, DurableLeaseManager):
        raise TypeError("lease_manager must implement DurableLeaseManager")
    if not isinstance(lease, DurableLease):
        raise TypeError("lease must be DurableLease")
    if not isinstance(authority, TaskExecutionAuthority):
        raise TypeError("authority must be TaskExecutionAuthority")
    if not isinstance(actor_id, str) or not actor_id.strip() or actor_id != actor_id.strip():
        raise ValueError("actor_id must be a non-blank canonical string")
    _require_timezone_aware(now, label="now")
    if now < checkpoint.created_at:
        raise TaskRuntimeBridgeValidationError()
    if (
        integrated_durable_run_id(checkpoint.agent_run_id) != checkpoint.durable_run_id
        or lease.run_id != checkpoint.durable_run_id
    ):
        raise TaskRuntimeBridgeValidationError()

    request = ResumeRequest(
        run_id=checkpoint.durable_run_id,
        actor_id=actor_id,
        reason=ResumeReason.OPERATOR_REQUEST,
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        requested_at=now,
    )
    authorizer = PolicyEngineDurableResumeAuthorizer(
        authority.policy,
        lease_manager,
        clock=lambda: now,
    )
    await authorizer.authorize(
        request,
        checkpoint,
        lease,
        authority.context,
    )
    return request


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
