"""Fail-closed RFC-0036 validation over authoritative RFC-0028 checkpoint history."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import cast

from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    RecoveryPoint,
)
from phoenix_os.agent.durable_metadata import DurableCheckpointHistoryValidator
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.integrated_agent.admission import IntegratedAgentAdmission
from phoenix_os.integrated_agent.contracts import IntegratedOrchestrationPhase
from phoenix_os.integrated_agent.durable_live_revalidation import (
    IntegratedDurableRecoveryLiveRevalidator,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    integrated_data_flow_context_digest,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner


class IntegratedDurableResumeState(StrEnum):
    """Transient live-state result for one structurally resumable checkpoint."""

    READY = "ready"
    CONTEXT_RESUPPLY = "context_resupply"
    DENIED = "denied"


class IntegratedDurableRecoveryResumeGate:
    """Require exact live RFC-0036 binding and reviewed context for resume."""

    def __init__(
        self,
        admission: IntegratedAgentAdmission,
        execution_guard: IntegratedAgentExecutionGuard,
        *,
        planner: IntegratedPlanner | None = None,
        live_revalidator: IntegratedDurableRecoveryLiveRevalidator | None = None,
    ) -> None:
        if not isinstance(admission, IntegratedAgentAdmission):
            raise TypeError("admission must be IntegratedAgentAdmission")
        if not isinstance(execution_guard, IntegratedAgentExecutionGuard):
            raise TypeError("execution_guard must be IntegratedAgentExecutionGuard")
        if planner is not None and not isinstance(planner, IntegratedPlanner):
            raise TypeError("planner must be IntegratedPlanner or None")
        if live_revalidator is not None and not isinstance(
            live_revalidator,
            IntegratedDurableRecoveryLiveRevalidator,
        ):
            raise TypeError(
                "live_revalidator must implement IntegratedDurableRecoveryLiveRevalidator"
            )
        self._admission = admission
        self._execution_guard = execution_guard
        self._planner = planner
        self._live_revalidator = live_revalidator

    async def assess_resume_state(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> IntegratedDurableResumeState:
        """Classify exact live recovery state without mutating durable state."""

        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(now, datetime):
            raise TypeError("now must be a datetime")
        projection = decode_integrated_durable_projection(checkpoint)
        if projection is None:
            return IntegratedDurableResumeState.READY
        live_revalidator = self._live_revalidator
        if live_revalidator is None:
            return IntegratedDurableResumeState.DENIED
        admission = self._admission
        guard = self._execution_guard
        if admission.closed or guard.closed:
            return IntegratedDurableResumeState.DENIED
        binding = await admission.binding_for_run(checkpoint.agent_run_id)
        request = await admission.request_for_run(checkpoint.agent_run_id)
        if binding is None or request is None:
            return IntegratedDurableResumeState.DENIED
        profile = admission.profile
        configuration = admission.service_configuration
        if (
            binding.run_id != checkpoint.agent_run_id
            or binding.task_id != projection.task_id
            or binding.task_digest != projection.task_digest
            or binding.profile_id != projection.execution_profile_id
            or binding.profile_generation != projection.execution_profile_generation
            or binding.agent_id != checkpoint.metadata.agent_id
            or configuration.agent_id != binding.agent_id
            or profile.agent_id != binding.agent_id
            or profile.profile_id != binding.profile_id
            or profile.generation != binding.profile_generation
            or guard.profile != profile
        ):
            return IntegratedDurableResumeState.DENIED
        if guard.failure_for(checkpoint.agent_run_id) is not None:
            return IntegratedDurableResumeState.DENIED
        planner = self._planner
        if planner is not None and (planner.closed or planner.profile != profile):
            return IntegratedDurableResumeState.DENIED
        run_current = await live_revalidator.revalidate_run(
            checkpoint,
            binding,
            request,
            now=now,
        )
        if type(run_current) is not bool:
            raise TypeError("live run revalidation must return bool")
        if not run_current:
            return IntegratedDurableResumeState.DENIED

        budget_usage = guard.current_budget_usage(checkpoint.agent_run_id)
        provenance = guard.current_provenance(checkpoint.agent_run_id)
        current_revision = (
            None if planner is None else planner.current_revision(checkpoint.agent_run_id)
        )
        current_plan = None if planner is None else planner.current_plan(checkpoint.agent_run_id)
        expected_context_digest = projection.data_flow_context_digest
        if (
            planner is not None
            and checkpoint.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
            and checkpoint.metadata.active_attempt is None
            and projection.orchestration_phase
            not in {
                IntegratedOrchestrationPhase.WAITING,
                IntegratedOrchestrationPhase.TERMINAL,
            }
            and expected_context_digest is not None
            and budget_usage is None
            and provenance is None
            and current_revision is None
            and current_plan is None
        ):
            return IntegratedDurableResumeState.CONTEXT_RESUPPLY

        expected_revision = projection.plan_revision
        if expected_revision is not None:
            if planner is None:
                return IntegratedDurableResumeState.DENIED
            if (
                current_revision != expected_revision.value
                or current_plan is None
                or current_plan.revision != expected_revision
                or current_plan.digest != projection.plan_digest
            ):
                return IntegratedDurableResumeState.DENIED
        elif planner is not None and (current_revision != 0 or current_plan is not None):
            return IntegratedDurableResumeState.DENIED
        if expected_context_digest is None:
            return IntegratedDurableResumeState.DENIED
        if budget_usage != projection.budget_extension_usage:
            return IntegratedDurableResumeState.DENIED
        if provenance is None:
            return IntegratedDurableResumeState.DENIED
        if integrated_data_flow_context_digest(provenance) != expected_context_digest:
            return IntegratedDurableResumeState.DENIED
        context_current = await live_revalidator.revalidate_context(
            checkpoint,
            provenance,
            now=now,
        )
        if type(context_current) is not bool:
            raise TypeError("live context revalidation must return bool")
        if not context_current:
            return IntegratedDurableResumeState.DENIED
        return IntegratedDurableResumeState.READY

    async def revalidate_resume(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> bool:
        return (
            await self.assess_resume_state(checkpoint, now=now)
            is IntegratedDurableResumeState.READY
        )


class IntegratedDurableRecoveryHistoryValidator:
    """Validate persisted RFC-0036 continuity without granting recovery authority."""

    def validate_history(
        self,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None:
        if not isinstance(current, CheckpointEnvelope):
            raise TypeError("current must be CheckpointEnvelope")
        if not isinstance(history, tuple):
            raise TypeError("history must be a tuple")
        if not history or history[-1] != current:
            raise IntegratedAgentCodecError("integrated durable history is not authoritative")

        decoded = tuple(decode_integrated_durable_projection(item) for item in history)
        root = decoded[0]
        if root is None:
            if any(item is not None for item in decoded[1:]):
                raise IntegratedAgentCodecError(
                    "integrated durable projection appeared after run creation"
                )
            return
        if any(item is None for item in decoded):
            raise IntegratedAgentCodecError(
                "integrated durable projection disappeared from history"
            )

        projections = cast(
            tuple[IntegratedOrchestrationCheckpointProjection, ...],
            decoded,
        )
        safe_boundaries: dict[CheckpointId, int] = {}
        previous_projection: IntegratedOrchestrationCheckpointProjection | None = None
        previous_safe_index = -1

        for index, (checkpoint, projection) in enumerate(zip(history, projections, strict=True)):
            _validate_immutable_binding(root, projection)
            _validate_plan_budget_consistency(projection)

            if not checkpoint.status.terminal:
                try:
                    point, _disposition = classify_recovery_checkpoint(
                        checkpoint,
                        now=checkpoint.created_at,
                    )
                except (TypeError, ValueError, AgentStateConflictError) as exception:
                    raise IntegratedAgentCodecError(
                        "integrated durable checkpoint is not recoverably classifiable"
                    ) from exception
                if point is RecoveryPoint.SAFE_BOUNDARY:
                    safe_boundaries[checkpoint.checkpoint_id] = index

            safe_index = safe_boundaries.get(projection.last_safe_boundary)
            if safe_index is None:
                raise IntegratedAgentCodecError(
                    "projected last safe boundary is not an established safe checkpoint"
                )
            if safe_index < previous_safe_index:
                raise IntegratedAgentCodecError("projected last safe boundary moved backwards")
            previous_safe_index = safe_index

            if previous_projection is not None:
                _validate_progress(previous_projection, projection)
            previous_projection = projection


def _validate_immutable_binding(
    root: IntegratedOrchestrationCheckpointProjection,
    projection: IntegratedOrchestrationCheckpointProjection,
) -> None:
    if (
        projection.task_id != root.task_id
        or projection.task_digest != root.task_digest
        or projection.execution_profile_id != root.execution_profile_id
        or projection.execution_profile_generation != root.execution_profile_generation
    ):
        raise IntegratedAgentCodecError(
            "integrated durable history changed immutable task or profile binding"
        )


def _validate_plan_budget_consistency(
    projection: IntegratedOrchestrationCheckpointProjection,
) -> None:
    revision = projection.plan_revision
    if revision is not None and revision.value > projection.budget_extension_usage.plan_revisions:
        raise IntegratedAgentCodecError(
            "projected plan revision exceeds consumed plan-revision budget"
        )


def _validate_progress(
    previous: IntegratedOrchestrationCheckpointProjection,
    current: IntegratedOrchestrationCheckpointProjection,
) -> None:
    previous_budget = _budget_counters(previous)
    current_budget = _budget_counters(current)
    if any(
        current_value < previous_value
        for previous_value, current_value in zip(previous_budget, current_budget, strict=True)
    ):
        raise IntegratedAgentCodecError("integrated durable history decreased budget usage")

    previous_revision = previous.plan_revision
    current_revision = current.plan_revision
    if previous_revision is not None:
        if current_revision is None:
            raise IntegratedAgentCodecError(
                "integrated durable history removed an established plan"
            )
        if current_revision.value < previous_revision.value:
            raise IntegratedAgentCodecError("integrated durable history regressed plan revision")
        if current_revision == previous_revision and current.plan_digest != previous.plan_digest:
            raise IntegratedAgentCodecError("integrated durable history rewrote a plan revision")

    if previous.data_flow_context_digest is not None and current.data_flow_context_digest is None:
        raise IntegratedAgentCodecError(
            "integrated durable history removed data-flow context evidence"
        )


def _budget_counters(
    projection: IntegratedOrchestrationCheckpointProjection,
) -> tuple[int, int, int, int, int, int, int, int]:
    usage = projection.budget_extension_usage
    return (
        usage.plan_revisions,
        usage.integrated_steps,
        usage.browser_operations,
        usage.network_operations,
        usage.memory_operations,
        usage.workspace_operations,
        usage.workspace_mutation_bytes,
        usage.host_operations,
    )


assert isinstance(IntegratedDurableRecoveryHistoryValidator(), DurableCheckpointHistoryValidator)
