from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentStepId,
    ToolId,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedBudgetUsage,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    integrated_data_flow_context_digest,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import IntegratedDurableRecoveryResumeGate
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentBudgetExhaustedError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.execution_control import IntegratedRunBudget
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 8, 28, 22, 0, tzinfo=UTC)
_AGENT_RUN_ID = AgentRunId(UUID(int=801))
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=802))
_STEP_ID = AgentStepId(UUID(int=803))
_CHECKPOINT_ID = CheckpointId(UUID(int=804))


class _AllowLiveRevalidator:
    async def revalidate_run(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True

    async def revalidate_context(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True


class _DenyContextLiveRevalidator(_AllowLiveRevalidator):
    async def revalidate_context(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(4),
        agent_id=AgentId("assistant"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="user-model",
                    source_kind=IntegratedDataSourceKind.USER_TASK,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                ),
            )
        ),
        budget_extension=IntegratedBudgetExtension(max_integrated_steps=2),
    )


def _admission(profile: IntegratedExecutionProfile) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        AgentServiceConfiguration(
            agent_id=AgentId("assistant"),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
        ),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=805)),
        objective="Resume with exact reviewed context and remaining budget.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_AGENT_RUN_ID,
        created_at=_NOW - timedelta(minutes=2),
        deadline=_NOW + timedelta(minutes=18),
    )


def _reviewed_provenance(
    profile: IntegratedExecutionProfile,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
) -> IntegratedDataProvenance:
    source = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    source.begin_run(task, request)
    provenance = source.current_provenance(request.run_id)
    assert provenance is not None
    source.release_run(request.run_id)
    return provenance


def _local_binding() -> IntegratedLocalTransformBinding:
    return IntegratedLocalTransformBinding(
        tool_id=ToolId("local.test"),
        transform_id="local.test",
    )


def _checkpoint(
    task: IntegratedTaskRequest,
    profile: IntegratedExecutionProfile,
    provenance: IntegratedDataProvenance,
    usage: IntegratedBudgetUsage,
) -> CheckpointEnvelope:
    projection = IntegratedOrchestrationCheckpointProjection(
        task_id=task.task_id,
        task_digest=task.digest,
        execution_profile_id=profile.profile_id,
        execution_profile_generation=profile.generation,
        budget_extension_usage=usage,
        data_flow_context_digest=integrated_data_flow_context_digest(provenance),
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        current_agent_step_id=_STEP_ID,
        last_safe_boundary=_CHECKPOINT_ID,
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=1,
                    model_turns=1,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=8,
                    output_tokens=0,
                    started_at=_NOW - timedelta(minutes=2),
                    deadline=_NOW + timedelta(minutes=18),
                ),
                compatibility=CompatibilityDigests(
                    configuration=_digest("a"),
                    tool_registry=_digest("b"),
                    model_provider=_digest("c"),
                    checkpoint_codec=_digest("d"),
                ),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata=merge_integrated_durable_projection({"tenant": "demo"}, projection),
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


def test_integrated_run_budget_restore_preserves_usage_and_remaining_limit() -> None:
    extension = IntegratedBudgetExtension(max_integrated_steps=2)
    usage = IntegratedBudgetUsage(integrated_steps=2, network_operations=1)
    budget = IntegratedRunBudget.restore(
        extension,
        started_at=_NOW - timedelta(minutes=2),
        parent_deadline=_NOW + timedelta(minutes=18),
        usage=usage,
    )

    assert budget.usage == usage
    assert budget.deadline == _NOW + timedelta(minutes=18)
    with pytest.raises(IntegratedAgentBudgetExhaustedError):
        budget.require_step(_local_binding(), {}, now=_NOW)


def test_integrated_run_budget_restore_rejects_usage_beyond_current_extension() -> None:
    with pytest.raises(IntegratedAgentBudgetExhaustedError):
        IntegratedRunBudget.restore(
            IntegratedBudgetExtension(max_integrated_steps=2),
            started_at=_NOW - timedelta(minutes=2),
            parent_deadline=_NOW + timedelta(minutes=18),
            usage=IntegratedBudgetUsage(integrated_steps=3),
        )


def test_execution_guard_restore_requires_task_provenance_and_preserves_budget() -> None:
    profile = _profile()
    task = _task()
    request = _request()
    provenance = _reviewed_provenance(profile, task, request)
    usage = IntegratedBudgetUsage(integrated_steps=1, plan_revisions=1)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)

    guard.restore_run(
        task,
        request,
        provenance=provenance,
        budget_usage=usage,
    )

    assert guard.current_provenance(request.run_id) == provenance
    assert guard.current_budget_usage(request.run_id) == usage

    other = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    wrong_provenance = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MEMORY,
                source_binding="agent-memory:research/scope:agent",
            ),
        )
    )
    with pytest.raises(IntegratedAgentValidationError):
        other.restore_run(
            task,
            request,
            provenance=wrong_provenance,
            budget_usage=usage,
        )
    assert other.current_provenance(request.run_id) is None


@pytest.mark.asyncio
async def test_resume_gate_requires_exact_restored_budget_and_reviewed_context() -> None:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    provenance = _reviewed_provenance(profile, task, lease.request)
    usage = IntegratedBudgetUsage(integrated_steps=1, plan_revisions=1)
    checkpoint = _checkpoint(task, profile, provenance, usage)

    missing = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            missing,
            live_revalidator=_AllowLiveRevalidator(),
        ).revalidate_resume(
            checkpoint,
            now=_NOW,
        )
        is False
    )

    wrong_budget = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    wrong_budget.restore_run(
        task,
        lease.request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
    )
    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            wrong_budget,
            live_revalidator=_AllowLiveRevalidator(),
        ).revalidate_resume(
            checkpoint,
            now=_NOW,
        )
        is False
    )

    restored = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    restored.restore_run(
        task,
        lease.request,
        provenance=provenance,
        budget_usage=usage,
    )
    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            restored,
            live_revalidator=_AllowLiveRevalidator(),
        ).revalidate_resume(
            checkpoint,
            now=_NOW,
        )
        is True
    )
    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            restored,
            live_revalidator=_DenyContextLiveRevalidator(),
        ).revalidate_resume(
            checkpoint,
            now=_NOW,
        )
        is False
    )

    restored.release_run(lease.request.run_id)
    wrong_budget.release_run(lease.request.run_id)
    await lease.release()
