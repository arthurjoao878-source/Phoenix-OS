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
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
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
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedAgentAdmissionLease,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedBudgetUsage,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
    IntegratedTaskRequest,
    IntegratedWaitingReason,
)
from phoenix_os.integrated_agent.durable_context_resupply import (
    IntegratedDurableContextResupplyCoordinator,
)
from phoenix_os.integrated_agent.durable_projection import decode_integrated_durable_projection
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryResumeGate,
    IntegratedDurableResumeState,
)
from phoenix_os.integrated_agent.durable_root import create_integrated_durable_root
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 9, 8, 21, 30, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=2001))
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=2002))
_STEP_ID = AgentStepId(UUID(int=2003))
_ROOT_ID = CheckpointId(UUID(int=2004))
_PAUSE_ID = CheckpointId(UUID(int=2005))


class _AllowLiveRevalidator:
    async def revalidate_run(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True

    async def revalidate_context(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _compatibility_validator() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=AgentId("assistant"),
                current=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(6),
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


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=2006)),
        objective="Resume only after explicit reviewed context resupply.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_RUN_ID,
        created_at=_NOW - timedelta(minutes=5),
        deadline=_NOW + timedelta(minutes=15),
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


def _root(request: AgentRunRequest) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_ROOT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
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
                    started_at=request.created_at,
                    deadline=request.deadline,
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
            ),
            created_at=_NOW - timedelta(minutes=4),
            digest=_digest("0"),
        )
    )


async def _setup_post_restart() -> tuple[
    IntegratedExecutionProfile,
    IntegratedTaskRequest,
    IntegratedAgentAdmission,
    IntegratedAgentAdmissionLease,
    IntegratedDataProvenance,
    IntegratedAgentExecutionGuard,
    IntegratedPlanner,
    IntegratedDurableRecoveryResumeGate,
    InMemoryDurableRunStore,
    CheckpointEnvelope,
    IntegratedDurableContextResupplyCoordinator,
]:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    admission_lease = await admission.admit(task, _request())

    seed_guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    seed_guard.begin_run(task, admission_lease.request)
    provenance = seed_guard.current_provenance(_RUN_ID)
    assert provenance is not None
    seed_guard.release_run(_RUN_ID)

    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile)
    gate = IntegratedDurableRecoveryResumeGate(
        admission,
        guard,
        planner=planner,
        live_revalidator=_AllowLiveRevalidator(),
    )
    store = InMemoryDurableRunStore()
    root = await create_integrated_durable_root(
        store,
        _root(admission_lease.request),
        admission_lease.binding,
        provenance=provenance,
    )
    coordinator = IntegratedDurableContextResupplyCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        resume_gate=gate,
        checkpoint_id_factory=lambda: _PAUSE_ID,
    )
    return (
        profile,
        task,
        admission,
        admission_lease,
        provenance,
        guard,
        planner,
        gate,
        store,
        root,
        coordinator,
    )


@pytest.mark.asyncio
async def test_post_restart_context_loss_pauses_with_caller_owned_lease() -> None:
    (
        _profile_value,
        _task_value,
        admission,
        admission_lease,
        _provenance,
        _guard,
        _planner,
        gate,
        store,
        root,
        coordinator,
    ) = await _setup_post_restart()

    await admission_lease.release()
    assert await admission.binding_for_run(_RUN_ID) is None
    assert await admission.request_for_run(_RUN_ID) is None
    assert (
        await gate.assess_resume_state(root, now=_NOW)
        is IntegratedDurableResumeState.CONTEXT_RESUPPLY
    )

    durable_lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="operator-resume",
        now=_NOW,
    )
    try:
        paused = await coordinator.pause_candidate_with_lease(
            _DURABLE_RUN_ID,
            lease=durable_lease,
            now=_NOW,
        )
        authoritative_lease = await store.lease_manager.require_current(
            durable_lease,
            now=_NOW,
        )
        assert authoritative_lease == durable_lease

        projection = decode_integrated_durable_projection(paused)
        assert projection is not None
        assert paused.sequence == CheckpointSequence(2)
        assert paused.previous_digest == root.digest
        assert paused.run_version == DurableRunVersion(2)
        assert paused.status is DurableRunStatus.PAUSED_OPERATOR
        assert projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
        assert projection.waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
        assert projection.last_safe_boundary == root.checkpoint_id
    finally:
        await store.lease_manager.release(durable_lease, now=_NOW)
        await coordinator.close()


@pytest.mark.asyncio
async def test_post_restart_partial_live_restore_remains_denied() -> None:
    (
        _profile_value,
        task,
        admission,
        admission_lease,
        provenance,
        guard,
        _planner,
        gate,
        _store,
        root,
        coordinator,
    ) = await _setup_post_restart()

    request = admission_lease.request
    await admission_lease.release()
    guard.restore_run(
        task,
        request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
    )
    try:
        assert await admission.binding_for_run(_RUN_ID) is None
        assert await admission.request_for_run(_RUN_ID) is None
        assert await gate.assess_resume_state(root, now=_NOW) is IntegratedDurableResumeState.DENIED
    finally:
        guard.release_run(_RUN_ID)
        await coordinator.close()
