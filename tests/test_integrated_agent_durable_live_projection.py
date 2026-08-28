from __future__ import annotations

from dataclasses import replace
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
    IntegratedAgentRunBinding,
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
    NormalizedPlan,
    PlanRevision,
)
from phoenix_os.integrated_agent.data_flow import integrated_provenance_union
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    integrated_data_flow_context_digest,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryResumeGate,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 8, 28, 22, 30, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=901))
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=902))
_STEP_ID = AgentStepId(UUID(int=903))
_ROOT_ID = CheckpointId(UUID(int=904))
_NEXT_ID = CheckpointId(UUID(int=905))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


class _AlwaysCurrentLiveRevalidator:
    def __init__(self) -> None:
        self.run_calls = 0
        self.context_calls = 0

    async def revalidate_run(
        self,
        checkpoint: CheckpointEnvelope,
        binding: IntegratedAgentRunBinding,
        request: AgentRunRequest,
        *,
        now: datetime,
    ) -> bool:
        del checkpoint, binding, request, now
        self.run_calls += 1
        return True

    async def revalidate_context(
        self,
        checkpoint: CheckpointEnvelope,
        provenance: IntegratedDataProvenance,
        *,
        now: datetime,
    ) -> bool:
        del checkpoint, provenance, now
        self.context_calls += 1
        return True


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(5),
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
        budget_extension=IntegratedBudgetExtension(
            max_integrated_steps=4,
            max_plan_revisions=4,
        ),
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
        task_id=IntegratedTaskId(UUID(int=906)),
        objective="Recover exact live integrated projection state.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_RUN_ID,
        created_at=_NOW - timedelta(minutes=2),
        deadline=_NOW + timedelta(minutes=18),
    )


def _initial_provenance(
    profile: IntegratedExecutionProfile,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
) -> IntegratedDataProvenance:
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    guard.begin_run(task, request)
    provenance = guard.current_provenance(request.run_id)
    assert provenance is not None
    guard.release_run(request.run_id)
    return provenance


def _enriched_provenance(base: IntegratedDataProvenance) -> IntegratedDataProvenance:
    return integrated_provenance_union(
        base,
        derived_atom=IntegratedDataProvenanceAtom(
            source_kind=IntegratedDataSourceKind.MEMORY,
            source_binding="agent-memory:research/scope:agent",
            freshness_bindings=("memory-snapshot:1",),
        ),
    )


def _checkpoint(
    task: IntegratedTaskRequest,
    profile: IntegratedExecutionProfile,
    provenance: IntegratedDataProvenance,
) -> CheckpointEnvelope:
    projection = IntegratedOrchestrationCheckpointProjection(
        task_id=task.task_id,
        task_digest=task.digest,
        execution_profile_id=profile.profile_id,
        execution_profile_generation=profile.generation,
        budget_extension_usage=IntegratedBudgetUsage(),
        data_flow_context_digest=integrated_data_flow_context_digest(provenance),
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        current_agent_step_id=_STEP_ID,
        last_safe_boundary=_ROOT_ID,
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_ROOT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
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
                metadata=merge_integrated_durable_projection(
                    {"tenant": "demo"},
                    projection,
                ),
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


@pytest.mark.asyncio
async def test_projector_snapshots_live_budget_plan_and_reviewed_context() -> None:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    base = _initial_provenance(profile, task, lease.request)
    live = _enriched_provenance(base)
    usage = IntegratedBudgetUsage(integrated_steps=1, plan_revisions=1)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    guard.restore_run(task, lease.request, provenance=live, budget_usage=usage)
    plan = NormalizedPlan.create(
        task_id=task.task_id,
        revision=PlanRevision(1),
        statements=("continue from reviewed context",),
        provenance=live,
    )
    planner = IntegratedPlanner(profile)
    planner.restore_run(lease.binding, plan=plan)
    projector = IntegratedDurableCheckpointMetadataProjector(
        execution_guard=guard,
        planner=planner,
    )
    current = _checkpoint(task, profile, base)

    metadata = projector.project_metadata(
        current,
        checkpoint_id=_NEXT_ID,
        status=DurableRunStatus.ACTIVE,
        step_id=_STEP_ID,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        metadata=current.metadata.metadata,
    )
    projected_checkpoint = seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=_NEXT_ID,
            sequence=CheckpointSequence(2),
            previous_digest=current.digest,
            run_version=DurableRunVersion(2),
            metadata=replace(current.metadata, metadata=metadata),
            digest=_digest("0"),
        )
    )
    projected = decode_integrated_durable_projection(projected_checkpoint)
    assert projected is not None
    assert projected.budget_extension_usage == usage
    assert projected.plan_revision == plan.revision
    assert projected.plan_digest == plan.digest
    assert projected.data_flow_context_digest == (integrated_data_flow_context_digest(live))
    assert projected.last_safe_boundary == _NEXT_ID

    planner.release_run(_RUN_ID)
    guard.release_run(_RUN_ID)
    await lease.release()


@pytest.mark.asyncio
async def test_projector_fails_closed_on_partial_live_state() -> None:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    provenance = _initial_provenance(profile, task, lease.request)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    guard.restore_run(
        task,
        lease.request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
    )
    planner = IntegratedPlanner(profile)
    projector = IntegratedDurableCheckpointMetadataProjector(
        execution_guard=guard,
        planner=planner,
    )
    current = _checkpoint(task, profile, provenance)

    with pytest.raises(
        IntegratedAgentCodecError,
        match="live durable projection state",
    ):
        projector.project_metadata(
            current,
            checkpoint_id=_NEXT_ID,
            status=DurableRunStatus.ACTIVE,
            step_id=_STEP_ID,
            next_operation=CheckpointNextOperation.MODEL_TURN,
            active_attempt=None,
            metadata=current.metadata.metadata,
        )

    guard.release_run(_RUN_ID)
    await lease.release()


@pytest.mark.asyncio
async def test_planner_restore_rehydrates_only_exact_reviewed_plan() -> None:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    provenance = _initial_provenance(profile, task, lease.request)
    plan = NormalizedPlan.create(
        task_id=task.task_id,
        revision=PlanRevision(2),
        statements=("reviewed one", "reviewed two"),
        provenance=provenance,
    )
    planner = IntegratedPlanner(profile)

    planner.restore_run(lease.binding, plan=plan)

    assert planner.current_revision(_RUN_ID) == 2
    assert planner.current_plan(_RUN_ID) == plan
    planner.release_run(_RUN_ID)
    await lease.release()


@pytest.mark.asyncio
async def test_resume_gate_requires_exact_live_plan_when_checkpoint_has_plan() -> None:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    provenance = _initial_provenance(profile, task, lease.request)
    usage = IntegratedBudgetUsage(integrated_steps=1, plan_revisions=1)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    guard.restore_run(task, lease.request, provenance=provenance, budget_usage=usage)
    plan = NormalizedPlan.create(
        task_id=task.task_id,
        revision=PlanRevision(1),
        statements=("reviewed continuation",),
        provenance=provenance,
    )
    planner = IntegratedPlanner(profile)
    planner.restore_run(lease.binding, plan=plan)
    base = _checkpoint(task, profile, provenance)
    projection = decode_integrated_durable_projection(base)
    assert projection is not None
    checkpoint = seal_checkpoint_envelope(
        replace(
            base,
            metadata=replace(
                base.metadata,
                metadata=merge_integrated_durable_projection(
                    {"tenant": "demo"},
                    replace(
                        projection,
                        budget_extension_usage=usage,
                        plan_revision=plan.revision,
                        plan_digest=plan.digest,
                    ),
                ),
            ),
            digest=_digest("0"),
        )
    )

    live_revalidator = _AlwaysCurrentLiveRevalidator()

    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            guard,
            planner=planner,
            live_revalidator=live_revalidator,
        ).revalidate_resume(checkpoint, now=_NOW)
        is True
    )
    assert live_revalidator.run_calls == 1
    assert live_revalidator.context_calls == 1
    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            guard,
            live_revalidator=live_revalidator,
        ).revalidate_resume(checkpoint, now=_NOW)
        is False
    )

    planner.release_run(_RUN_ID)
    assert (
        await IntegratedDurableRecoveryResumeGate(
            admission,
            guard,
            planner=planner,
            live_revalidator=live_revalidator,
        ).revalidate_resume(checkpoint, now=_NOW)
        is False
    )

    guard.release_run(_RUN_ID)
    await lease.release()
