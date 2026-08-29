"""Sequence-one RFC-0036 projection for RFC-0028 durable run creation."""

from __future__ import annotations

from dataclasses import replace

from phoenix_os.agent.durable_codec import (
    checkpoint_envelope_digest,
    seal_checkpoint_envelope,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    CheckpointSequence,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    RecoveryPoint,
)
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.integrated_agent.admission import IntegratedAgentRunBinding
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedDataSourceKind,
    IntegratedOrchestrationPhase,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    integrated_data_flow_context_digest,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentValidationError


def project_integrated_durable_root(
    checkpoint: CheckpointEnvelope,
    binding: IntegratedAgentRunBinding,
    *,
    provenance: IntegratedDataProvenance,
) -> CheckpointEnvelope:
    """Bind one already-built RFC-0028 root to exact RFC-0036 orchestration identity."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    if not isinstance(binding, IntegratedAgentRunBinding):
        raise TypeError("binding must be IntegratedAgentRunBinding")
    if not isinstance(provenance, IntegratedDataProvenance):
        raise TypeError("provenance must be IntegratedDataProvenance")

    if checkpoint.digest != checkpoint_envelope_digest(checkpoint):
        raise IntegratedAgentValidationError("durable root checkpoint is not canonically sealed")
    if (
        checkpoint.sequence != CheckpointSequence(1)
        or checkpoint.run_version != DurableRunVersion(1)
        or checkpoint.previous_digest is not None
    ):
        raise IntegratedAgentValidationError(
            "integrated durable checkpoint must begin at sequence one"
        )
    if checkpoint.agent_run_id != binding.run_id:
        raise IntegratedAgentValidationError(
            "durable root agent run does not match integrated binding"
        )
    if checkpoint.metadata.agent_id != binding.agent_id:
        raise IntegratedAgentValidationError("durable root agent does not match integrated binding")
    if checkpoint.metadata.active_attempt is not None:
        raise IntegratedAgentValidationError("durable root cannot begin with an active attempt")
    budget = checkpoint.metadata.budget
    if any(
        (
            budget.steps,
            budget.model_turns,
            budget.tool_calls,
            budget.model_output_bytes,
            budget.tool_result_bytes,
            budget.input_tokens,
            budget.output_tokens,
        )
    ):
        raise IntegratedAgentValidationError(
            "integrated durable root must be created before execution budget is consumed"
        )
    if checkpoint.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN:
        raise IntegratedAgentValidationError(
            "integrated durable root must begin before a model turn"
        )
    if checkpoint.status not in {
        DurableRunStatus.CREATED,
        DurableRunStatus.ACTIVE,
    }:
        raise IntegratedAgentValidationError(
            "integrated durable root has an invalid initial status"
        )

    try:
        point, _disposition = classify_recovery_checkpoint(
            checkpoint,
            now=checkpoint.created_at,
        )
    except (AgentStateConflictError, TypeError, ValueError) as exception:
        raise IntegratedAgentValidationError(
            "integrated durable root is not classifiable"
        ) from exception
    if point is not RecoveryPoint.SAFE_BOUNDARY:
        raise IntegratedAgentValidationError("integrated durable root is not a safe boundary")

    _require_exact_task_provenance(binding, provenance)
    phase = (
        IntegratedOrchestrationPhase.CREATED
        if checkpoint.status is DurableRunStatus.CREATED
        else IntegratedOrchestrationPhase.PLANNING
    )
    expected = IntegratedOrchestrationCheckpointProjection(
        task_id=binding.task_id,
        task_digest=binding.task_digest,
        execution_profile_id=binding.profile_id,
        execution_profile_generation=binding.profile_generation,
        budget_extension_usage=IntegratedBudgetUsage(),
        data_flow_context_digest=integrated_data_flow_context_digest(provenance),
        orchestration_phase=phase,
        current_agent_step_id=checkpoint.step_id,
        last_safe_boundary=checkpoint.checkpoint_id,
    )

    existing = decode_integrated_durable_projection(checkpoint)
    if existing is not None:
        if existing != expected:
            raise IntegratedAgentValidationError(
                "durable root contains a different RFC-0036 projection"
            )
        return checkpoint

    metadata_values = merge_integrated_durable_projection(
        checkpoint.metadata.metadata,
        expected,
    )
    projected = seal_checkpoint_envelope(
        replace(
            checkpoint,
            metadata=replace(
                checkpoint.metadata,
                metadata=metadata_values,
            ),
        )
    )
    if decode_integrated_durable_projection(projected) != expected:
        raise IntegratedAgentValidationError("integrated durable root projection failed validation")
    return projected


async def create_integrated_durable_root(
    store: DurableRunStore,
    checkpoint: CheckpointEnvelope,
    binding: IntegratedAgentRunBinding,
    *,
    provenance: IntegratedDataProvenance,
) -> CheckpointEnvelope:
    """Project and publish the exact sequence-one integrated root through RFC-0028."""

    if not isinstance(store, DurableRunStore):
        raise TypeError("store must implement DurableRunStore")
    projected = project_integrated_durable_root(
        checkpoint,
        binding,
        provenance=provenance,
    )
    await store.create(projected)
    return projected


def _require_exact_task_provenance(
    binding: IntegratedAgentRunBinding,
    provenance: IntegratedDataProvenance,
) -> None:
    expected_source = f"integrated-task:{binding.task_id}"
    expected_freshness = f"task-digest:{binding.task_digest}"
    if not any(
        atom.source_kind is IntegratedDataSourceKind.USER_TASK
        and atom.source_binding == expected_source
        and expected_freshness in atom.freshness_bindings
        for atom in provenance.atoms
    ):
        raise IntegratedAgentValidationError(
            "reviewed durable root context does not match the integrated task binding"
        )
