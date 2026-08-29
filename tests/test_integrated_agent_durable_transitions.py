from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_attempts import StoreBackedDurableExecutionAttemptRecorder
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
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    IndeterminateReason,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_metadata import DurableCheckpointMetadataProjector
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
    IntegratedWaitingReason,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)

_NOW = datetime(2026, 8, 28, 18, 0, tzinfo=UTC)
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=201))
_AGENT_RUN_ID = AgentRunId(UUID(int=202))
_STEP_ID = AgentStepId(UUID(int=203))
_INITIAL_CHECKPOINT_ID = CheckpointId(UUID(int=204))
_PREPARED_CHECKPOINT_ID = CheckpointId(UUID(int=205))
_STARTED_CHECKPOINT_ID = CheckpointId(UUID(int=206))
_TERMINAL_CHECKPOINT_ID = CheckpointId(UUID(int=207))
_ATTEMPT_ID = ExecutionAttemptId(UUID(int=208))


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


def _projection() -> IntegratedOrchestrationCheckpointProjection:
    return IntegratedOrchestrationCheckpointProjection(
        task_id=IntegratedTaskId(UUID(int=1)),
        task_digest=IntegratedTaskDigest("sha256:" + "1" * 64),
        execution_profile_id=IntegratedExecutionProfileId("default"),
        execution_profile_generation=IntegratedExecutionProfileGeneration(1),
        budget_extension_usage=IntegratedBudgetUsage(integrated_steps=1),
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        current_agent_step_id=_STEP_ID,
        last_safe_boundary=_INITIAL_CHECKPOINT_ID,
    )


def _checkpoint(*, integrated: bool) -> CheckpointEnvelope:
    extension = {"tenant": "demo"}
    if integrated:
        extension = dict(merge_integrated_durable_projection(extension, _projection()))
    budget = AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=_NOW - timedelta(minutes=1),
        deadline=_NOW + timedelta(hours=1),
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_INITIAL_CHECKPOINT_ID,
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
                budget=budget,
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata=extension,
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


def _recorder(
    store: InMemoryDurableRunStore,
    projector: IntegratedDurableCheckpointMetadataProjector,
) -> StoreBackedDurableExecutionAttemptRecorder:
    checkpoints = iter(
        (
            _PREPARED_CHECKPOINT_ID,
            _STARTED_CHECKPOINT_ID,
            _TERMINAL_CHECKPOINT_ID,
        )
    )
    return StoreBackedDurableExecutionAttemptRecorder(
        store=store,
        attempt_id_factory=lambda: _ATTEMPT_ID,
        checkpoint_id_factory=lambda: next(checkpoints),
        metadata_projector=projector,
    )


async def _started_integrated_attempt() -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
    CheckpointEnvelope,
]:
    current = _checkpoint(integrated=True)
    store = InMemoryDurableRunStore()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=_NOW + timedelta(seconds=1),
    )
    recorder = _recorder(store, IntegratedDurableCheckpointMetadataProjector())
    prepared = await recorder.prepare_model_attempt(
        _DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=_NOW + timedelta(seconds=2),
    )
    started = await recorder.mark_started(
        _DURABLE_RUN_ID,
        _ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=_NOW + timedelta(seconds=3),
    )
    return store, lease, recorder, started


def test_integrated_projector_implements_generic_rfc0028_projection_seam() -> None:
    assert isinstance(
        IntegratedDurableCheckpointMetadataProjector(),
        DurableCheckpointMetadataProjector,
    )


@pytest.mark.asyncio
async def test_installed_projector_leaves_generic_rfc0028_metadata_unchanged() -> None:
    current = _checkpoint(integrated=False)
    store = InMemoryDurableRunStore()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=_NOW + timedelta(seconds=1),
    )
    recorder = _recorder(store, IntegratedDurableCheckpointMetadataProjector())

    prepared = await recorder.prepare_model_attempt(
        _DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=_NOW + timedelta(seconds=2),
    )

    assert dict(prepared.metadata.metadata) == {"tenant": "demo"}
    assert decode_integrated_durable_projection(prepared) is None


@pytest.mark.asyncio
async def test_attempt_transitions_keep_integrated_projection_exact_and_safe_boundary_current() -> (
    None
):
    store, lease, recorder, started = await _started_integrated_attempt()
    history = await store.list_history(_DURABLE_RUN_ID, limit=3)
    prepared = history[-2]

    prepared_projection = decode_integrated_durable_projection(prepared)
    assert prepared_projection is not None
    assert prepared_projection.current_attempt_id == _ATTEMPT_ID
    assert prepared_projection.last_safe_boundary == _PREPARED_CHECKPOINT_ID
    assert prepared_projection.orchestration_phase is IntegratedOrchestrationPhase.EXECUTING

    started_projection = decode_integrated_durable_projection(started)
    assert started_projection is not None
    assert started_projection.current_attempt_id == _ATTEMPT_ID
    assert started_projection.last_safe_boundary == _PREPARED_CHECKPOINT_ID

    completed = await recorder.mark_terminal(
        _DURABLE_RUN_ID,
        _ATTEMPT_ID,
        expected_version=started.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.SUCCEEDED,
        now=_NOW + timedelta(seconds=4),
        next_operation=CheckpointNextOperation.COMPLETE,
    )
    completed_projection = decode_integrated_durable_projection(completed)
    assert completed_projection is not None
    assert completed_projection.current_attempt_id == _ATTEMPT_ID
    assert completed_projection.last_safe_boundary == _TERMINAL_CHECKPOINT_ID
    assert completed_projection.orchestration_phase is IntegratedOrchestrationPhase.EXECUTING


@pytest.mark.asyncio
async def test_recovery_indeterminate_transition_updates_projection_before_validation() -> None:
    store, lease, _recorder_instance, started = await _started_integrated_attempt()
    await store.lease_manager.release(
        lease,
        now=_NOW + timedelta(seconds=4),
    )
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
    )

    assessment = await coordinator.persist_indeterminate_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        reason=IndeterminateReason.PROCESS_LOSS,
        now=_NOW + timedelta(seconds=5),
    )

    assert assessment.point is RecoveryPoint.ACTIVE_MODEL_ATTEMPT
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    current = await store.get_current(_DURABLE_RUN_ID)
    assert current is not None
    assert current.sequence == started.sequence.next()
    assert current.status is DurableRunStatus.INDETERMINATE_MODEL
    assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    projection = decode_integrated_durable_projection(current)
    assert projection is not None
    assert projection.current_attempt_id == _ATTEMPT_ID
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
    assert projection.waiting_reason is IntegratedWaitingReason.RECONCILIATION
    assert projection.last_safe_boundary == _PREPARED_CHECKPOINT_ID
