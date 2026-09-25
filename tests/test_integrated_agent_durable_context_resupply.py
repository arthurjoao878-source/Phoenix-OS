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
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
from phoenix_os.agent.errors import AgentStateConflictError
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
from phoenix_os.integrated_agent.durable_projection import (
    RFC0036_DURABLE_METADATA_PREFIX,
    decode_integrated_durable_projection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
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

_NOW = datetime(2026, 8, 28, 23, 30, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=1001))
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=1002))
_STEP_ID = AgentStepId(UUID(int=1003))
_ROOT_ID = CheckpointId(UUID(int=1004))
_PAUSE_ID = CheckpointId(UUID(int=1005))
_RECOVERING_ID = CheckpointId(UUID(int=1006))
_NORMALIZED_ID = CheckpointId(UUID(int=1007))
_INVALID_RECOVERING_ID = CheckpointId(UUID(int=1008))


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
        task_id=IntegratedTaskId(UUID(int=1006)),
        objective="Resume only after exact reviewed context is supplied.",
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


async def _setup() -> tuple[
    IntegratedExecutionProfile,
    IntegratedTaskRequest,
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
    lease = await admission.admit(task, _request())

    seed_guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    seed_guard.begin_run(task, lease.request)
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
        _root(lease.request),
        lease.binding,
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
        lease,
        provenance,
        guard,
        planner,
        gate,
        store,
        root,
        coordinator,
    )


def _recovering_from_pause(
    paused: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId,
    step_id: AgentStepId | None = None,
) -> CheckpointEnvelope:
    projection = decode_integrated_durable_projection(paused)
    assert projection is not None
    recovering_projection = replace(
        projection,
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        waiting_reason=None,
        current_agent_step_id=None,
        current_attempt_id=None,
    )
    unreserved = {
        key: value
        for key, value in paused.metadata.metadata.items()
        if not key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
    }
    return seal_checkpoint_envelope(
        replace(
            paused,
            checkpoint_id=checkpoint_id,
            sequence=paused.sequence.next(),
            previous_digest=paused.digest,
            run_version=paused.run_version.next(),
            status=DurableRunStatus.RECOVERING,
            step_id=step_id,
            metadata=replace(
                paused.metadata,
                next_operation=CheckpointNextOperation.MODEL_TURN,
                active_attempt=None,
                metadata=merge_integrated_durable_projection(
                    unreserved,
                    recovering_projection,
                ),
            ),
            created_at=_NOW + timedelta(seconds=1),
        )
    )


@pytest.mark.asyncio
async def test_exact_rfc0039_recovering_orphan_normalizes_to_context_resupply() -> None:
    (
        _profile_value,
        _task_value,
        _admission_lease,
        _provenance,
        _guard,
        _planner,
        gate,
        store,
        _root,
        coordinator,
    ) = await _setup()
    paused = await coordinator.pause_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-pause",
        now=_NOW,
    )
    recovering = _recovering_from_pause(
        paused,
        checkpoint_id=_RECOVERING_ID,
    )
    writer = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="recovering-writer",
        now=_NOW + timedelta(seconds=1),
    )
    try:
        await store.append(
            recovering,
            expected_version=paused.run_version,
            lease=writer,
            now=_NOW + timedelta(seconds=1),
        )
    finally:
        await store.lease_manager.release(
            writer,
            now=_NOW + timedelta(seconds=1),
        )

    normalizer = IntegratedDurableContextResupplyCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        resume_gate=gate,
        checkpoint_id_factory=lambda: _NORMALIZED_ID,
    )
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="recovering-normalizer",
        now=_NOW + timedelta(seconds=2),
    )
    try:
        normalized = await normalizer.pause_candidate_with_lease(
            _DURABLE_RUN_ID,
            lease=lease,
            now=_NOW + timedelta(seconds=2),
        )
    finally:
        await store.lease_manager.release(
            lease,
            now=_NOW + timedelta(seconds=2),
        )

    projection = decode_integrated_durable_projection(normalized)
    assert projection is not None
    assert normalized.status is DurableRunStatus.PAUSED_OPERATOR
    assert normalized.previous_digest == recovering.digest
    assert normalized.sequence == recovering.sequence.next()
    assert normalized.step_id == paused.step_id
    assert normalized.metadata.active_attempt is None
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
    assert projection.waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
    paused_projection = decode_integrated_durable_projection(paused)
    assert paused_projection is not None
    assert projection.last_safe_boundary == paused_projection.last_safe_boundary


@pytest.mark.asyncio
async def test_non_exact_recovering_checkpoint_is_rejected() -> None:
    (
        _profile_value,
        _task_value,
        _admission_lease,
        _provenance,
        _guard,
        _planner,
        gate,
        store,
        _root,
        coordinator,
    ) = await _setup()
    paused = await coordinator.pause_candidate(
        _DURABLE_RUN_ID,
        owner_id="invalid-recovery-pause",
        now=_NOW,
    )
    invalid = _recovering_from_pause(
        paused,
        checkpoint_id=_INVALID_RECOVERING_ID,
        step_id=_STEP_ID,
    )
    writer = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="invalid-recovering-writer",
        now=_NOW + timedelta(seconds=1),
    )
    try:
        await store.append(
            invalid,
            expected_version=paused.run_version,
            lease=writer,
            now=_NOW + timedelta(seconds=1),
        )
    finally:
        await store.lease_manager.release(
            writer,
            now=_NOW + timedelta(seconds=1),
        )

    normalizer = IntegratedDurableContextResupplyCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        resume_gate=gate,
        checkpoint_id_factory=lambda: _NORMALIZED_ID,
    )
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="invalid-recovering-normalizer",
        now=_NOW + timedelta(seconds=2),
    )
    try:
        with pytest.raises(AgentStateConflictError):
            await normalizer.pause_candidate_with_lease(
                _DURABLE_RUN_ID,
                lease=lease,
                now=_NOW + timedelta(seconds=2),
            )
    finally:
        await store.lease_manager.release(
            lease,
            now=_NOW + timedelta(seconds=2),
        )


@pytest.mark.asyncio
async def test_missing_metadata_only_context_persists_explicit_resupply_pause() -> None:
    (
        _profile_value,
        task,
        lease,
        provenance,
        guard,
        planner,
        gate,
        store,
        root,
        coordinator,
    ) = await _setup()

    assert (
        await gate.assess_resume_state(root, now=_NOW)
        is IntegratedDurableResumeState.CONTEXT_RESUPPLY
    )
    assert await gate.revalidate_resume(root, now=_NOW) is False

    paused = await coordinator.pause_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW,
    )
    projection = decode_integrated_durable_projection(paused)
    assert projection is not None
    assert paused.sequence == CheckpointSequence(2)
    assert paused.previous_digest == root.digest
    assert paused.run_version == DurableRunVersion(2)
    assert paused.status is DurableRunStatus.PAUSED_OPERATOR
    assert paused.metadata.actor_id == root.metadata.actor_id
    assert paused.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
    assert paused.metadata.active_attempt is None
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
    assert projection.waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
    assert projection.last_safe_boundary == root.checkpoint_id
    assert classify_recovery_checkpoint(paused, now=_NOW) == (
        RecoveryPoint.OPERATOR_PAUSE,
        RecoveryDisposition.PAUSE_OPERATOR,
    )
    history = await store.list_history(_DURABLE_RUN_ID, limit=2)
    IntegratedDurableRecoveryHistoryValidator().validate_history(paused, history)

    assert (
        await coordinator.pause_candidate(
            _DURABLE_RUN_ID,
            owner_id="recovery-worker",
            now=_NOW,
        )
        == paused
    )

    guard.restore_run(
        task,
        lease.request,
        provenance=provenance,
        budget_usage=projection.budget_extension_usage,
    )
    planner.restore_run(lease.binding, plan=None)
    assert await gate.assess_resume_state(paused, now=_NOW) is IntegratedDurableResumeState.READY
    assert await gate.revalidate_resume(paused, now=_NOW) is True
    assert classify_recovery_checkpoint(paused, now=_NOW) == (
        RecoveryPoint.OPERATOR_PAUSE,
        RecoveryDisposition.PAUSE_OPERATOR,
    )

    planner.release_run(_RUN_ID)
    guard.release_run(_RUN_ID)
    await coordinator.close()
    await lease.release()


@pytest.mark.asyncio
async def test_partial_live_restore_is_denied_not_mislabeled_as_context_resupply() -> None:
    (
        _profile_value,
        task,
        lease,
        provenance,
        guard,
        _planner,
        gate,
        store,
        root,
        coordinator,
    ) = await _setup()
    guard.restore_run(
        task,
        lease.request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
    )

    assert await gate.assess_resume_state(root, now=_NOW) is IntegratedDurableResumeState.DENIED
    with pytest.raises(AgentStateConflictError):
        await coordinator.pause_candidate(
            _DURABLE_RUN_ID,
            owner_id="recovery-worker",
            now=_NOW,
        )
    assert await store.list_history(_DURABLE_RUN_ID, limit=2) == (root,)

    guard.release_run(_RUN_ID)
    await coordinator.close()
    await lease.release()


@pytest.mark.asyncio
async def test_exact_restored_context_is_ready_and_never_forced_into_resupply_wait() -> None:
    (
        _profile_value,
        task,
        lease,
        provenance,
        guard,
        planner,
        gate,
        store,
        root,
        coordinator,
    ) = await _setup()
    guard.restore_run(
        task,
        lease.request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(),
    )
    planner.restore_run(lease.binding, plan=None)

    assert await gate.assess_resume_state(root, now=_NOW) is IntegratedDurableResumeState.READY
    with pytest.raises(AgentStateConflictError):
        await coordinator.pause_candidate(
            _DURABLE_RUN_ID,
            owner_id="recovery-worker",
            now=_NOW,
        )
    assert await store.list_history(_DURABLE_RUN_ID, limit=2) == (root,)

    planner.release_run(_RUN_ID)
    guard.release_run(_RUN_ID)
    await coordinator.close()
    await lease.release()
