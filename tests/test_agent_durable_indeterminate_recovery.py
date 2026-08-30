from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.agent import (
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
    DurableExecutionAttemptRecorder,
    DurableIndeterminateRecoveryCoordinator,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    RecoveryDisposition,
    RecoveryPoint,
    StartupDurableRecoveryCoordinator,
    StoreBackedDurableExecutionAttemptRecorder,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 1, 1, tzinfo=UTC)
RECOVERY_TIME = NOW + timedelta(seconds=10)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000004"))
ATTEMPT_ID = ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000005"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _validator() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=AgentId("assistant"),
                current=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )


def _budget(*, deadline: datetime | None = None) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=deadline or NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind,
    *,
    status: ExecutionAttemptStatus = ExecutionAttemptStatus.STARTED,
    reason: IndeterminateReason | None = None,
) -> ExecutionAttempt:
    prepared_at = NOW + timedelta(seconds=1)
    started_at = NOW + timedelta(seconds=2)
    completed_at = RECOVERY_TIME if status.terminal else None
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=prepared_at,
        tool_call_id=CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None,
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=(None if status is ExecutionAttemptStatus.PREPARED else started_at),
        completed_at=completed_at,
        external_request_digest=_digest("e"),
        indeterminate_reason=reason,
        error_code=(
            "attempt-failed"
            if status
            in {
                ExecutionAttemptStatus.FAILED,
                ExecutionAttemptStatus.TIMED_OUT,
            }
            else None
        ),
    )


def _checkpoint(
    *,
    durable_run_id: DurableAgentRunId = DURABLE_RUN_ID,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
    budget_deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
    created_at: datetime = NOW + timedelta(seconds=3),
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=durable_run_id,
            checkpoint_id=CheckpointId(
                UUID(int=0x60000000000000000000000000000000 + durable_run_id.value.int)
            ),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=next_operation,
                budget=_budget(deadline=budget_deadline),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=retention_deadline or NOW + timedelta(days=7),
                active_attempt=active_attempt,
                metadata={"tenant": "demo"},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _started_checkpoint(
    kind: ExecutionAttemptKind,
    *,
    budget_deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
) -> CheckpointEnvelope:
    operation = (
        CheckpointNextOperation.MODEL_TURN
        if kind is ExecutionAttemptKind.MODEL_TURN
        else CheckpointNextOperation.TOOL_INVOCATION
    )
    return _checkpoint(
        next_operation=operation,
        active_attempt=_attempt(kind),
        budget_deadline=budget_deadline,
        retention_deadline=retention_deadline,
    )


async def _created(
    checkpoint: CheckpointEnvelope,
) -> tuple[InMemoryDurableRunStore, StartupDurableRecoveryCoordinator]:
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )
    return store, coordinator


def _assert_exact_indeterminate(
    before: CheckpointEnvelope,
    after: CheckpointEnvelope,
    *,
    reason: IndeterminateReason,
) -> None:
    before_attempt = before.metadata.active_attempt
    after_attempt = after.metadata.active_attempt
    assert before_attempt is not None
    assert after_attempt is not None
    expected_status = (
        DurableRunStatus.INDETERMINATE_MODEL
        if before_attempt.kind is ExecutionAttemptKind.MODEL_TURN
        else DurableRunStatus.INDETERMINATE_TOOL
    )
    assert after.status is expected_status
    assert after.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert after.sequence == before.sequence.next()
    assert after.run_version == before.run_version.next()
    assert after.previous_digest == before.digest
    assert after.checkpoint_id != before.checkpoint_id
    assert after.created_at == RECOVERY_TIME
    assert after_attempt.attempt_id == before_attempt.attempt_id
    assert after_attempt.kind is before_attempt.kind
    assert after_attempt.agent_run_id == before_attempt.agent_run_id
    assert after_attempt.step_id == before_attempt.step_id
    assert after_attempt.tool_call_id == before_attempt.tool_call_id
    assert after_attempt.tool_effect is before_attempt.tool_effect
    assert after_attempt.prepared_at == before_attempt.prepared_at
    assert after_attempt.started_at == before_attempt.started_at
    assert after_attempt.external_request_digest == before_attempt.external_request_digest
    assert after_attempt.status is ExecutionAttemptStatus.INDETERMINATE
    assert after_attempt.completed_at == RECOVERY_TIME
    assert after_attempt.indeterminate_reason is reason
    assert after_attempt.error_code is None


def test_startup_coordinator_implements_indeterminate_protocol() -> None:
    store = InMemoryDurableRunStore()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )

    assert isinstance(coordinator, DurableIndeterminateRecoveryCoordinator)


@pytest.mark.parametrize(
    ("kind", "expected_status"),
    (
        (ExecutionAttemptKind.MODEL_TURN, DurableRunStatus.INDETERMINATE_MODEL),
        (ExecutionAttemptKind.TOOL_INVOCATION, DurableRunStatus.INDETERMINATE_TOOL),
    ),
)
async def test_persist_indeterminate_candidate_records_exact_transition(
    kind: ExecutionAttemptKind,
    expected_status: DurableRunStatus,
) -> None:
    before = _started_checkpoint(kind)
    store, coordinator = await _created(before)

    assessment = await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    after = await store.get_current(DURABLE_RUN_ID)

    assert after is not None
    _assert_exact_indeterminate(before, after, reason=IndeterminateReason.PROCESS_LOSS)
    assert assessment.status is expected_status
    assert assessment.point is (
        RecoveryPoint.ACTIVE_MODEL_ATTEMPT
        if kind is ExecutionAttemptKind.MODEL_TURN
        else RecoveryPoint.ACTIVE_TOOL_ATTEMPT
    )
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert assessment.sequence == CheckpointSequence(2)
    assert assessment.run_version == DurableRunVersion(2)
    assert assessment.checkpoint_id == after.checkpoint_id
    assert assessment.checkpoint_digest == after.digest
    assert await store.lease_manager.get_current(DURABLE_RUN_ID, now=RECOVERY_TIME) is None


@pytest.mark.parametrize("reason", tuple(IndeterminateReason))
async def test_persist_indeterminate_candidate_accepts_reviewed_reason(
    reason: IndeterminateReason,
) -> None:
    before = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store, coordinator = await _created(before)

    await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
        reason=reason,
    )
    after = await store.get_current(DURABLE_RUN_ID)

    assert after is not None
    _assert_exact_indeterminate(before, after, reason=reason)


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_repeated_recovery_is_idempotent(kind: ExecutionAttemptKind) -> None:
    before = _started_checkpoint(kind)
    store, coordinator = await _created(before)

    first = await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    second = await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME + timedelta(seconds=1),
    )
    current = await store.get_current(DURABLE_RUN_ID)
    history = await store.list_history(DURABLE_RUN_ID, limit=2)

    assert current is not None
    assert len(history) == 2
    assert current.sequence == CheckpointSequence(2)
    assert first.checkpoint_id == current.checkpoint_id
    assert second.checkpoint_id == current.checkpoint_id
    assert second.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert second.generation.value == first.generation.value + 1


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_read_only_assessment_still_does_not_mutate_started_attempt(
    kind: ExecutionAttemptKind,
) -> None:
    before = _started_checkpoint(kind)
    store, coordinator = await _created(before)

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    current = await store.get_current(DURABLE_RUN_ID)

    assert current == before
    assert assessment.disposition is (
        RecoveryDisposition.MARK_INDETERMINATE_MODEL
        if kind is ExecutionAttemptKind.MODEL_TURN
        else RecoveryDisposition.MARK_INDETERMINATE_TOOL
    )


async def test_started_attempt_is_marked_before_budget_expiry_disposition() -> None:
    before = _started_checkpoint(
        ExecutionAttemptKind.TOOL_INVOCATION,
        budget_deadline=NOW + timedelta(seconds=5),
    )
    store, coordinator = await _created(before)

    assessment = await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    current = await store.get_current(DURABLE_RUN_ID)

    assert current is not None
    assert current.status is DurableRunStatus.INDETERMINATE_TOOL
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR


@pytest.mark.parametrize(
    ("checkpoint", "expected"),
    (
        (
            _checkpoint(
                budget_deadline=NOW + timedelta(seconds=5),
            ),
            RecoveryDisposition.TERMINATE_EXPIRED,
        ),
        (
            _checkpoint(
                retention_deadline=NOW + timedelta(seconds=5),
            ),
            RecoveryDisposition.TERMINATE_EXPIRED,
        ),
        (
            _checkpoint(
                active_attempt=_attempt(
                    ExecutionAttemptKind.MODEL_TURN,
                    status=ExecutionAttemptStatus.PREPARED,
                )
            ),
            RecoveryDisposition.PAUSE_OPERATOR,
        ),
        (
            _checkpoint(
                next_operation=CheckpointNextOperation.VALIDATE_PROPOSAL,
                active_attempt=_attempt(
                    ExecutionAttemptKind.MODEL_TURN,
                    status=ExecutionAttemptStatus.SUCCEEDED,
                ),
            ),
            RecoveryDisposition.PAUSE_OPERATOR,
        ),
    ),
)
async def test_non_started_candidates_are_not_rewritten(
    checkpoint: CheckpointEnvelope,
    expected: RecoveryDisposition,
) -> None:
    store, coordinator = await _created(checkpoint)

    assessment = await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    current = await store.get_current(DURABLE_RUN_ID)

    assert current == checkpoint
    assert assessment.disposition is expected
    assert len(await store.list_history(DURABLE_RUN_ID, limit=1)) == 1


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_existing_indeterminate_checkpoint_is_not_rewritten(
    kind: ExecutionAttemptKind,
) -> None:
    status = (
        DurableRunStatus.INDETERMINATE_MODEL
        if kind is ExecutionAttemptKind.MODEL_TURN
        else DurableRunStatus.INDETERMINATE_TOOL
    )
    checkpoint = _checkpoint(
        status=status,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            kind,
            status=ExecutionAttemptStatus.INDETERMINATE,
            reason=IndeterminateReason.PROCESS_LOSS,
        ),
    )
    store, coordinator = await _created(checkpoint)

    assessment = await coordinator.persist_indeterminate_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME + timedelta(seconds=1),
    )
    current = await store.get_current(DURABLE_RUN_ID)

    assert current == checkpoint
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert len(await store.list_history(DURABLE_RUN_ID, limit=1)) == 1


async def test_direct_recorder_marks_model_attempt_indeterminate() -> None:
    before = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store = InMemoryDurableRunStore()
    await store.create(before)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=RECOVERY_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    after = await recorder.mark_indeterminate(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=before.run_version,
        lease=lease,
        reason=IndeterminateReason.PROCESS_LOSS,
        now=RECOVERY_TIME,
    )

    _assert_exact_indeterminate(before, after, reason=IndeterminateReason.PROCESS_LOSS)


async def test_direct_recorder_marks_tool_attempt_indeterminate() -> None:
    before = _started_checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    store = InMemoryDurableRunStore()
    await store.create(before)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=RECOVERY_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    after = await recorder.mark_indeterminate(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=before.run_version,
        lease=lease,
        reason=IndeterminateReason.TOOL_STATUS_UNKNOWN,
        now=RECOVERY_TIME,
    )

    _assert_exact_indeterminate(before, after, reason=IndeterminateReason.TOOL_STATUS_UNKNOWN)


async def test_direct_recorder_rejects_prepared_attempt() -> None:
    checkpoint = _checkpoint(
        active_attempt=_attempt(
            ExecutionAttemptKind.MODEL_TURN,
            status=ExecutionAttemptStatus.PREPARED,
        )
    )
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=RECOVERY_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_indeterminate(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=checkpoint.run_version,
            lease=lease,
            reason=IndeterminateReason.PROCESS_LOSS,
            now=RECOVERY_TIME,
        )


async def test_direct_recorder_rejects_wrong_attempt_identity() -> None:
    checkpoint = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=RECOVERY_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    other_attempt = ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000006"))

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_indeterminate(
            DURABLE_RUN_ID,
            other_attempt,
            expected_version=checkpoint.run_version,
            lease=lease,
            reason=IndeterminateReason.PROCESS_LOSS,
            now=RECOVERY_TIME,
        )


async def test_direct_recorder_rejects_stale_version() -> None:
    checkpoint = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=RECOVERY_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_indeterminate(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=DurableRunVersion(2),
            lease=lease,
            reason=IndeterminateReason.PROCESS_LOSS,
            now=RECOVERY_TIME,
        )


async def test_direct_recorder_rejects_expired_lease() -> None:
    checkpoint = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=RECOVERY_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_indeterminate(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=checkpoint.run_version,
            lease=lease,
            reason=IndeterminateReason.PROCESS_LOSS,
            now=RECOVERY_TIME + timedelta(seconds=31),
        )


async def test_direct_recorder_rejects_time_before_attempt_start() -> None:
    checkpoint = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=NOW + timedelta(seconds=1),
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_indeterminate(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=checkpoint.run_version,
            lease=lease,
            reason=IndeterminateReason.PROCESS_LOSS,
            now=NOW + timedelta(seconds=1),
        )


async def test_persist_rejects_unknown_run_and_releases_no_authority() -> None:
    store = InMemoryDurableRunStore()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentStateConflictError):
        await coordinator.persist_indeterminate_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=RECOVERY_TIME,
        )


async def test_persist_rejects_terminal_run() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
        active_attempt=None,
    )
    _store, coordinator = await _created(checkpoint)

    with pytest.raises(AgentStateConflictError):
        await coordinator.persist_indeterminate_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=RECOVERY_TIME,
        )


async def test_persist_releases_lease_after_validation_failure() -> None:
    before = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    store, coordinator = await _created(before)

    with pytest.raises(TypeError):
        await coordinator.persist_indeterminate_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=RECOVERY_TIME,
            reason=cast(Any, "process_loss"),
        )

    assert await store.lease_manager.get_current(DURABLE_RUN_ID, now=RECOVERY_TIME) is None


async def test_closed_coordinator_rejects_persistence() -> None:
    before = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    _store, coordinator = await _created(before)
    await coordinator.close()

    with pytest.raises(RuntimeError, match="closed"):
        await coordinator.persist_indeterminate_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=RECOVERY_TIME,
        )


def test_constructor_rejects_non_recorder() -> None:
    store = InMemoryDurableRunStore()

    with pytest.raises(TypeError, match="attempt_recorder"):
        StartupDurableRecoveryCoordinator(
            store=store,
            lease_manager=store.lease_manager,
            compatibility_validator=_validator(),
            attempt_recorder=cast(Any, object()),
        )


async def test_persist_rejects_invalid_owner_id() -> None:
    before = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    _store, coordinator = await _created(before)

    with pytest.raises(ValueError, match="owner_id"):
        await coordinator.persist_indeterminate_candidate(
            DURABLE_RUN_ID,
            owner_id="INVALID OWNER",
            now=RECOVERY_TIME,
        )


async def test_persist_rejects_naive_time() -> None:
    before = _started_checkpoint(ExecutionAttemptKind.MODEL_TURN)
    _store, coordinator = await _created(before)

    with pytest.raises(ValueError, match="timezone-aware"):
        await coordinator.persist_indeterminate_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=datetime(2026, 8, 1, 1),
        )


async def test_recorder_protocol_includes_indeterminate_transition() -> None:
    store = InMemoryDurableRunStore()
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    assert isinstance(recorder, DurableExecutionAttemptRecorder)
