"""RFC-0036 projection updates for authoritative RFC-0028 checkpoint transitions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType

from phoenix_os.agent.contracts import AgentRunId, AgentStepId
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttempt,
    ExecutionAttemptStatus,
    RecoveryPoint,
)
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.integrated_agent.contracts import (
    IntegratedOrchestrationPhase,
    IntegratedWaitingReason,
)
from phoenix_os.integrated_agent.durable_projection import (
    RFC0036_DURABLE_METADATA_PREFIX,
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    integrated_data_flow_context_digest,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner


class IntegratedDurableCheckpointMetadataProjector:
    """Keep RFC-0036 metadata synchronized with RFC-0028 checkpoint transitions."""

    def __init__(
        self,
        *,
        execution_guard: IntegratedAgentExecutionGuard | None = None,
        planner: IntegratedPlanner | None = None,
    ) -> None:
        if execution_guard is not None and not isinstance(
            execution_guard, IntegratedAgentExecutionGuard
        ):
            raise TypeError("execution_guard must be IntegratedAgentExecutionGuard or None")
        if planner is not None and not isinstance(planner, IntegratedPlanner):
            raise TypeError("planner must be IntegratedPlanner or None")
        if (execution_guard is None) != (planner is None):
            raise ValueError("execution_guard and planner must be supplied together")
        if (
            execution_guard is not None
            and planner is not None
            and execution_guard.profile != planner.profile
        ):
            raise ValueError("execution guard and planner profiles must match")
        self._execution_guard = execution_guard
        self._planner = planner

    def project_metadata(
        self,
        current: CheckpointEnvelope,
        *,
        checkpoint_id: CheckpointId,
        status: DurableRunStatus,
        step_id: AgentStepId | None,
        next_operation: CheckpointNextOperation,
        active_attempt: ExecutionAttempt | None,
        metadata: Mapping[str, str],
    ) -> Mapping[str, str]:
        if not isinstance(current, CheckpointEnvelope):
            raise TypeError("current must be CheckpointEnvelope")
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in metadata.items()
        ):
            raise IntegratedAgentCodecError("checkpoint transition metadata is invalid")

        projection = decode_integrated_durable_projection(current)
        current_reserved = _reserved_metadata(current.metadata.metadata)
        supplied_reserved = _reserved_metadata(metadata)
        if supplied_reserved != current_reserved:
            raise IntegratedAgentCodecError("RFC-0036 transition metadata cannot be caller-mutated")
        if projection is None:
            return MappingProxyType(dict(metadata))

        phase, waiting_reason = _transition_phase(
            projection,
            status=status,
            next_operation=next_operation,
            active_attempt=active_attempt,
        )
        last_safe_boundary = _transition_safe_boundary(
            current,
            checkpoint_id=checkpoint_id,
            status=status,
            step_id=step_id,
            next_operation=next_operation,
            active_attempt=active_attempt,
            metadata=metadata,
            previous=projection.last_safe_boundary,
        )
        updated = replace(
            projection,
            orchestration_phase=phase,
            waiting_reason=waiting_reason,
            current_agent_step_id=step_id,
            current_attempt_id=(None if active_attempt is None else active_attempt.attempt_id),
            last_safe_boundary=last_safe_boundary,
        )
        updated = _project_live_state(
            updated,
            current.agent_run_id,
            execution_guard=self._execution_guard,
            planner=self._planner,
        )
        unreserved = {
            key: value
            for key, value in metadata.items()
            if not key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
        }
        return merge_integrated_durable_projection(unreserved, updated)


def _project_live_state(
    projection: IntegratedOrchestrationCheckpointProjection,
    run_id: AgentRunId,
    *,
    execution_guard: IntegratedAgentExecutionGuard | None,
    planner: IntegratedPlanner | None,
) -> IntegratedOrchestrationCheckpointProjection:
    if execution_guard is None or planner is None:
        return projection
    budget_usage = execution_guard.current_budget_usage(run_id)
    provenance = execution_guard.current_provenance(run_id)
    revision = planner.current_revision(run_id)
    plan = planner.current_plan(run_id)
    if budget_usage is None and provenance is None and revision is None and plan is None:
        return projection
    if budget_usage is None or provenance is None or revision is None:
        raise IntegratedAgentCodecError("integrated live durable projection state is incomplete")
    if revision == 0:
        if plan is not None:
            raise IntegratedAgentCodecError(
                "integrated live durable projection plan state is inconsistent"
            )
        plan_revision = None
        plan_digest = None
    else:
        if plan is None or plan.revision.value != revision:
            raise IntegratedAgentCodecError(
                "integrated live durable projection plan state is inconsistent"
            )
        plan_revision = plan.revision
        plan_digest = plan.digest
    return replace(
        projection,
        budget_extension_usage=budget_usage,
        plan_revision=plan_revision,
        plan_digest=plan_digest,
        data_flow_context_digest=integrated_data_flow_context_digest(provenance),
    )


def _reserved_metadata(metadata: Mapping[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in metadata.items()
        if key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
    }


def _transition_phase(
    projection: IntegratedOrchestrationCheckpointProjection,
    *,
    status: DurableRunStatus,
    next_operation: CheckpointNextOperation,
    active_attempt: ExecutionAttempt | None,
) -> tuple[IntegratedOrchestrationPhase, IntegratedWaitingReason | None]:
    if status.terminal:
        return IntegratedOrchestrationPhase.TERMINAL, None
    if next_operation is CheckpointNextOperation.WAIT_APPROVAL:
        return IntegratedOrchestrationPhase.WAITING, IntegratedWaitingReason.APPROVAL
    if next_operation is CheckpointNextOperation.OPERATOR_REVIEW:
        if status.indeterminate or (
            active_attempt is not None
            and active_attempt.status is ExecutionAttemptStatus.INDETERMINATE
        ):
            return (
                IntegratedOrchestrationPhase.WAITING,
                IntegratedWaitingReason.RECONCILIATION,
            )
        if (
            projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
            and projection.waiting_reason is not IntegratedWaitingReason.APPROVAL
        ):
            return IntegratedOrchestrationPhase.WAITING, projection.waiting_reason
        return IntegratedOrchestrationPhase.WAITING, None
    if status is DurableRunStatus.PAUSED_OPERATOR:
        if (
            projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
            and projection.waiting_reason is not IntegratedWaitingReason.APPROVAL
        ):
            return IntegratedOrchestrationPhase.WAITING, projection.waiting_reason
        return IntegratedOrchestrationPhase.WAITING, None
    if projection.orchestration_phase in {
        IntegratedOrchestrationPhase.WAITING,
        IntegratedOrchestrationPhase.TERMINAL,
    }:
        raise IntegratedAgentCodecError(
            "active durable transition contradicts projected orchestration phase"
        )
    return projection.orchestration_phase, None


def _transition_safe_boundary(
    current: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId,
    status: DurableRunStatus,
    step_id: AgentStepId | None,
    next_operation: CheckpointNextOperation,
    active_attempt: ExecutionAttempt | None,
    metadata: Mapping[str, str],
    previous: CheckpointId,
) -> CheckpointId:
    if status.terminal:
        return previous
    try:
        preview = replace(
            current,
            checkpoint_id=checkpoint_id,
            status=status,
            step_id=step_id,
            metadata=replace(
                current.metadata,
                next_operation=next_operation,
                active_attempt=active_attempt,
                metadata=metadata,
            ),
        )
        point, _disposition = classify_recovery_checkpoint(
            preview,
            now=current.created_at,
        )
    except (TypeError, ValueError, AgentStateConflictError) as exception:
        raise IntegratedAgentCodecError(
            "durable checkpoint transition is not classifiable"
        ) from exception
    if point is RecoveryPoint.SAFE_BOUNDARY:
        return checkpoint_id
    return previous
