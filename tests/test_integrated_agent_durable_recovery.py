from __future__ import annotations

from dataclasses import dataclass, field, replace
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
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_metadata import DurableCheckpointHistoryValidator
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.errors import AgentCodecError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
    PlanDigest,
    PlanRevision,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError

_NOW = datetime(2026, 8, 28, 19, 0, tzinfo=UTC)
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=301))
_AGENT_RUN_ID = AgentRunId(UUID(int=302))
_STEP_ID = AgentStepId(UUID(int=303))
_ATTEMPT_ID = ExecutionAttemptId(UUID(int=304))
_IDS = tuple(CheckpointId(UUID(int=400 + index)) for index in range(1, 8))


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


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
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


def _projection(
    *,
    last_safe_boundary: CheckpointId,
    usage: IntegratedBudgetUsage | None = None,
    task_id: IntegratedTaskId | None = None,
    task_digest: IntegratedTaskDigest | None = None,
    profile_id: IntegratedExecutionProfileId | None = None,
    profile_generation: IntegratedExecutionProfileGeneration | None = None,
    plan_revision: PlanRevision | None = None,
    plan_digest: PlanDigest | None = None,
    data_flow_context_digest: str | None = None,
    attempt_id: ExecutionAttemptId | None = None,
) -> IntegratedOrchestrationCheckpointProjection:
    return IntegratedOrchestrationCheckpointProjection(
        task_id=task_id or IntegratedTaskId(UUID(int=1)),
        task_digest=task_digest or IntegratedTaskDigest("sha256:" + "1" * 64),
        execution_profile_id=profile_id or IntegratedExecutionProfileId("default"),
        execution_profile_generation=(
            profile_generation or IntegratedExecutionProfileGeneration(1)
        ),
        plan_revision=plan_revision,
        plan_digest=plan_digest,
        budget_extension_usage=usage or IntegratedBudgetUsage(),
        data_flow_context_digest=data_flow_context_digest,
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        current_agent_step_id=_STEP_ID,
        current_attempt_id=attempt_id,
        last_safe_boundary=last_safe_boundary,
    )


def _attempt(status: ExecutionAttemptStatus) -> ExecutionAttempt:
    prepared_at = _NOW + timedelta(seconds=1)
    started_at = None
    completed_at = None
    if status is not ExecutionAttemptStatus.PREPARED:
        started_at = prepared_at + timedelta(seconds=1)
    if status.terminal:
        completed_at = prepared_at + timedelta(seconds=2)
    return ExecutionAttempt(
        attempt_id=_ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=status,
        agent_run_id=_AGENT_RUN_ID,
        step_id=_STEP_ID,
        prepared_at=prepared_at,
        started_at=started_at,
        completed_at=completed_at,
        external_request_digest=_digest("e"),
    )


def _checkpoint(
    sequence: int,
    checkpoint_id: CheckpointId,
    *,
    previous_digest: CheckpointDigest | None,
    projection: IntegratedOrchestrationCheckpointProjection | None,
    active_attempt: ExecutionAttempt | None = None,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
) -> CheckpointEnvelope:
    extension = {"tenant": "demo"}
    if projection is not None:
        extension = dict(merge_integrated_durable_projection(extension, projection))
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=checkpoint_id,
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=next_operation,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                active_attempt=active_attempt,
                metadata=extension,
            ),
            created_at=_NOW + timedelta(seconds=sequence),
            digest=_digest("0"),
        )
    )


def _valid_history() -> tuple[CheckpointEnvelope, ...]:
    first = _checkpoint(
        1,
        _IDS[0],
        previous_digest=None,
        projection=_projection(last_safe_boundary=_IDS[0]),
    )
    prepared = _attempt(ExecutionAttemptStatus.PREPARED)
    second = _checkpoint(
        2,
        _IDS[1],
        previous_digest=first.digest,
        projection=_projection(
            last_safe_boundary=_IDS[1],
            attempt_id=_ATTEMPT_ID,
        ),
        active_attempt=prepared,
    )
    started = _attempt(ExecutionAttemptStatus.STARTED)
    third = _checkpoint(
        3,
        _IDS[2],
        previous_digest=second.digest,
        projection=_projection(
            last_safe_boundary=_IDS[1],
            attempt_id=_ATTEMPT_ID,
        ),
        active_attempt=started,
    )
    return first, second, third


def _replace_projection(
    checkpoint: CheckpointEnvelope,
    projection: IntegratedOrchestrationCheckpointProjection | None,
) -> CheckpointEnvelope:
    extension = {"tenant": "demo"}
    if projection is not None:
        extension = dict(merge_integrated_durable_projection(extension, projection))
    return seal_checkpoint_envelope(
        replace(
            checkpoint,
            metadata=replace(checkpoint.metadata, metadata=extension),
            digest=_digest("0"),
        )
    )


def test_validator_implements_generic_rfc0028_history_seam() -> None:
    assert isinstance(
        IntegratedDurableRecoveryHistoryValidator(),
        DurableCheckpointHistoryValidator,
    )


def test_generic_history_without_rfc0036_projection_remains_valid() -> None:
    checkpoint = _checkpoint(
        1,
        _IDS[0],
        previous_digest=None,
        projection=None,
    )
    IntegratedDurableRecoveryHistoryValidator().validate_history(
        checkpoint,
        (checkpoint,),
    )


def test_valid_integrated_history_accepts_safe_boundary_and_started_attempt() -> None:
    history = _valid_history()
    IntegratedDurableRecoveryHistoryValidator().validate_history(history[-1], history)


def test_projection_cannot_appear_or_disappear_mid_history() -> None:
    history = _valid_history()
    generic_root = _replace_projection(history[0], None)
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            history[-1],
            (generic_root, history[1], history[2]),
        )

    missing_middle = _replace_projection(history[1], None)
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            history[-1],
            (history[0], missing_middle, history[2]),
        )


@pytest.mark.parametrize("field_name", ["task", "task_digest", "profile", "generation"])
def test_immutable_task_and_profile_binding_cannot_change(field_name: str) -> None:
    history = _valid_history()
    original = _projection(
        last_safe_boundary=_IDS[1],
        attempt_id=_ATTEMPT_ID,
    )
    if field_name == "task":
        mutated = replace(original, task_id=IntegratedTaskId(UUID(int=99)))
    elif field_name == "task_digest":
        mutated = replace(
            original,
            task_digest=IntegratedTaskDigest("sha256:" + "9" * 64),
        )
    elif field_name == "profile":
        mutated = replace(
            original,
            execution_profile_id=IntegratedExecutionProfileId("alternate"),
        )
    else:
        mutated = replace(
            original,
            execution_profile_generation=IntegratedExecutionProfileGeneration(2),
        )
    corrupt = _replace_projection(history[2], mutated)

    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            corrupt,
            (history[0], history[1], corrupt),
        )


def test_budget_usage_cannot_decrease() -> None:
    history = _valid_history()
    second_projection = _projection(
        last_safe_boundary=_IDS[1],
        usage=IntegratedBudgetUsage(integrated_steps=2, network_operations=1),
        attempt_id=_ATTEMPT_ID,
    )
    second = _replace_projection(history[1], second_projection)
    third_projection = _projection(
        last_safe_boundary=_IDS[1],
        usage=IntegratedBudgetUsage(integrated_steps=2, network_operations=0),
        attempt_id=_ATTEMPT_ID,
    )
    third = _replace_projection(history[2], third_projection)

    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            third,
            (history[0], second, third),
        )


def test_plan_cannot_regress_disappear_or_rewrite_same_revision() -> None:
    history = _valid_history()
    revision_one = _projection(
        last_safe_boundary=_IDS[1],
        usage=IntegratedBudgetUsage(plan_revisions=1, integrated_steps=1),
        plan_revision=PlanRevision(1),
        plan_digest=PlanDigest("sha256:" + "a" * 64),
        attempt_id=_ATTEMPT_ID,
    )
    second = _replace_projection(history[1], revision_one)

    removed = _replace_projection(
        history[2],
        _projection(
            last_safe_boundary=_IDS[1],
            usage=IntegratedBudgetUsage(plan_revisions=1, integrated_steps=1),
            attempt_id=_ATTEMPT_ID,
        ),
    )
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            removed,
            (history[0], second, removed),
        )

    rewritten = _replace_projection(
        history[2],
        replace(
            revision_one,
            plan_digest=PlanDigest("sha256:" + "b" * 64),
        ),
    )
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            rewritten,
            (history[0], second, rewritten),
        )

    revision_two = _replace_projection(
        history[1],
        replace(
            revision_one,
            plan_revision=PlanRevision(2),
            plan_digest=PlanDigest("sha256:" + "c" * 64),
            budget_extension_usage=IntegratedBudgetUsage(
                plan_revisions=2,
                integrated_steps=2,
            ),
        ),
    )
    regressed = _replace_projection(history[2], revision_one)
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            regressed,
            (history[0], revision_two, regressed),
        )


def test_plan_revision_cannot_exceed_consumed_plan_budget() -> None:
    history = _valid_history()
    corrupt_projection = _projection(
        last_safe_boundary=_IDS[1],
        usage=IntegratedBudgetUsage(plan_revisions=1, integrated_steps=2),
        plan_revision=PlanRevision(2),
        plan_digest=PlanDigest("sha256:" + "a" * 64),
        attempt_id=_ATTEMPT_ID,
    )
    corrupt = _replace_projection(history[2], corrupt_projection)

    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            corrupt,
            (history[0], history[1], corrupt),
        )


def test_data_flow_context_digest_cannot_disappear() -> None:
    history = _valid_history()
    second = _replace_projection(
        history[1],
        _projection(
            last_safe_boundary=_IDS[1],
            data_flow_context_digest="sha256:" + "c" * 64,
            attempt_id=_ATTEMPT_ID,
        ),
    )
    third = _replace_projection(
        history[2],
        _projection(
            last_safe_boundary=_IDS[1],
            attempt_id=_ATTEMPT_ID,
        ),
    )

    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            third,
            (history[0], second, third),
        )


def test_last_safe_boundary_must_reference_established_safe_checkpoint() -> None:
    history = _valid_history()
    unknown = _replace_projection(
        history[2],
        _projection(
            last_safe_boundary=CheckpointId(UUID(int=999)),
            attempt_id=_ATTEMPT_ID,
        ),
    )
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            unknown,
            (history[0], history[1], unknown),
        )

    started_as_safe = _replace_projection(
        history[2],
        _projection(
            last_safe_boundary=_IDS[2],
            attempt_id=_ATTEMPT_ID,
        ),
    )
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            started_as_safe,
            (history[0], history[1], started_as_safe),
        )


def test_last_safe_boundary_cannot_move_backwards() -> None:
    history = _valid_history()
    regressed = _replace_projection(
        history[2],
        _projection(
            last_safe_boundary=_IDS[0],
            attempt_id=_ATTEMPT_ID,
        ),
    )
    with pytest.raises(IntegratedAgentCodecError):
        IntegratedDurableRecoveryHistoryValidator().validate_history(
            regressed,
            (history[0], history[1], regressed),
        )


@pytest.mark.asyncio
async def test_coordinator_wraps_extension_corruption_and_releases_lease() -> None:
    corrupt_projection = _projection(
        last_safe_boundary=CheckpointId(UUID(int=999)),
    )
    checkpoint = _checkpoint(
        1,
        _IDS[0],
        previous_digest=None,
        projection=corrupt_projection,
    )
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        history_validator=IntegratedDurableRecoveryHistoryValidator(),
    )

    with pytest.raises(AgentCodecError, match="extension history"):
        await coordinator.assess_candidate(
            _DURABLE_RUN_ID,
            owner_id="recovery-worker",
            now=_NOW + timedelta(minutes=10),
        )

    assert (
        await store.lease_manager.get_current(
            _DURABLE_RUN_ID,
            now=_NOW + timedelta(minutes=10),
        )
        is None
    )


@dataclass
class _CountingIntegratedHistoryValidator:
    calls: list[int] = field(default_factory=list)
    delegate: IntegratedDurableRecoveryHistoryValidator = field(
        default_factory=IntegratedDurableRecoveryHistoryValidator
    )

    def validate_history(
        self,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None:
        self.calls.append(current.sequence.value)
        self.delegate.validate_history(current, history)


@pytest.mark.asyncio
async def test_indeterminate_persistence_revalidates_post_append_history() -> None:
    initial = _checkpoint(
        1,
        _IDS[0],
        previous_digest=None,
        projection=_projection(last_safe_boundary=_IDS[0]),
    )
    store = InMemoryDurableRunStore()
    await store.create(initial)
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=_NOW + timedelta(seconds=1),
    )
    checkpoint_ids = iter((_IDS[1], _IDS[2], _IDS[3]))
    recorder = StoreBackedDurableExecutionAttemptRecorder(
        store=store,
        attempt_id_factory=lambda: _ATTEMPT_ID,
        checkpoint_id_factory=lambda: next(checkpoint_ids),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
    )
    prepared = await recorder.prepare_model_attempt(
        _DURABLE_RUN_ID,
        expected_version=initial.run_version,
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
    await store.lease_manager.release(lease, now=_NOW + timedelta(seconds=4))

    validator = _CountingIntegratedHistoryValidator()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=validator,
    )
    assessment = await coordinator.persist_indeterminate_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        reason=IndeterminateReason.PROCESS_LOSS,
        now=_NOW + timedelta(seconds=5),
    )

    assert assessment.sequence == started.sequence.next()
    assert validator.calls == [3, 4]
