from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityCategory,
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryCoordinator,
    StartupDurableRecoveryCoordinator,
    classify_recovery_checkpoint,
)
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 7, 31, 6, tzinfo=UTC)
RECOVERY_TIME = NOW + timedelta(minutes=10)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))


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


def _budget(*, deadline: datetime | None = None) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=deadline or NOW + timedelta(hours=1),
    )


def _metadata(
    *,
    next_operation: CheckpointNextOperation,
    active_attempt: ExecutionAttempt | None = None,
    budget_deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=AgentId("assistant"),
        actor_id="worker-1",
        next_operation=next_operation,
        budget=_budget(deadline=budget_deadline),
        compatibility=_compatibility(),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
        retention_deadline=retention_deadline or NOW + timedelta(days=7),
        active_attempt=active_attempt,
        metadata={"tenant": "demo"},
    )


def _checkpoint(
    sequence: int = 1,
    *,
    durable_run_id: DurableAgentRunId = DURABLE_RUN_ID,
    agent_run_id: AgentRunId = AGENT_RUN_ID,
    previous_digest: CheckpointDigest | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
    budget_deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=durable_run_id,
            checkpoint_id=CheckpointId(
                UUID(int=sequence * 1_000 + (durable_run_id.value.int & 0xFF))
            ),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=agent_run_id,
            step_id=STEP_ID,
            metadata=_metadata(
                next_operation=next_operation,
                active_attempt=active_attempt,
                budget_deadline=budget_deadline,
                retention_deadline=retention_deadline,
            ),
            created_at=NOW + timedelta(seconds=10 + sequence),
            digest=_digest("0"),
        )
    )


def _next(
    current: CheckpointEnvelope,
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
) -> CheckpointEnvelope:
    return _checkpoint(
        current.sequence.value + 1,
        durable_run_id=current.durable_run_id,
        agent_run_id=current.agent_run_id,
        previous_digest=current.digest,
        status=status,
        next_operation=next_operation,
    )


def _model_attempt(status: ExecutionAttemptStatus) -> ExecutionAttempt:
    started_at = NOW + timedelta(seconds=2)
    completed_at = (
        NOW + timedelta(seconds=3)
        if status not in {ExecutionAttemptStatus.PREPARED, ExecutionAttemptStatus.STARTED}
        else None
    )
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004")),
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW + timedelta(seconds=1),
        started_at=(started_at if status is not ExecutionAttemptStatus.PREPARED else None),
        completed_at=completed_at,
        indeterminate_reason=(
            IndeterminateReason.PROCESS_LOSS
            if status is ExecutionAttemptStatus.INDETERMINATE
            else None
        ),
        error_code=(
            "provider-failed"
            if status
            in {
                ExecutionAttemptStatus.FAILED,
                ExecutionAttemptStatus.TIMED_OUT,
            }
            else None
        ),
    )


def _tool_attempt(status: ExecutionAttemptStatus) -> ExecutionAttempt:
    started_at = NOW + timedelta(seconds=2)
    completed_at = (
        NOW + timedelta(seconds=3)
        if status not in {ExecutionAttemptStatus.PREPARED, ExecutionAttemptStatus.STARTED}
        else None
    )
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000005")),
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW + timedelta(seconds=1),
        tool_call_id=ToolCallId(UUID("60000000-0000-0000-0000-000000000006")),
        tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
        started_at=(started_at if status is not ExecutionAttemptStatus.PREPARED else None),
        completed_at=completed_at,
        indeterminate_reason=(
            IndeterminateReason.PROCESS_LOSS
            if status is ExecutionAttemptStatus.INDETERMINATE
            else None
        ),
        error_code=(
            "tool-failed"
            if status
            in {
                ExecutionAttemptStatus.FAILED,
                ExecutionAttemptStatus.TIMED_OUT,
            }
            else None
        ),
    )


class _AppendOnAcquireLeaseManager(InMemoryDurableLeaseManager):
    def __init__(self) -> None:
        super().__init__()
        self.store: InMemoryDurableRunStore | None = None
        self.checkpoint: CheckpointEnvelope | None = None
        self.appended = False

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        lease = await super().acquire(run_id, owner_id=owner_id, now=now)
        if not self.appended:
            if self.store is None or self.checkpoint is None:
                raise AssertionError("append-on-acquire manager is not configured")
            await self.store.append(
                self.checkpoint,
                expected_version=DurableRunVersion(self.checkpoint.run_version.value - 1),
                lease=lease,
                now=now,
            )
            self.appended = True
        return lease


class _TruncatedHistoryStore(InMemoryDurableRunStore):
    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        history = await super().list_history(run_id, limit=limit)
        return history[-1:]


def test_classification_resumes_only_reviewed_safe_boundaries() -> None:
    active = _checkpoint()
    shutdown = _checkpoint(status=DurableRunStatus.PAUSED_SHUTDOWN)

    assert classify_recovery_checkpoint(active, now=RECOVERY_TIME) == (
        RecoveryPoint.SAFE_BOUNDARY,
        RecoveryDisposition.RESUME,
    )
    assert classify_recovery_checkpoint(shutdown, now=RECOVERY_TIME) == (
        RecoveryPoint.SHUTDOWN_PAUSE,
        RecoveryDisposition.RESUME,
    )


def test_classification_pauses_approval_operator_and_internal_states() -> None:
    approval = _checkpoint(
        status=DurableRunStatus.PAUSED_APPROVAL,
        next_operation=CheckpointNextOperation.WAIT_APPROVAL,
    )
    operator = _checkpoint(
        status=DurableRunStatus.PAUSED_OPERATOR,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
    )
    recovering = _checkpoint(status=DurableRunStatus.RECOVERING)

    assert classify_recovery_checkpoint(approval, now=RECOVERY_TIME) == (
        RecoveryPoint.AWAITING_APPROVAL,
        RecoveryDisposition.PAUSE_OPERATOR,
    )
    assert classify_recovery_checkpoint(operator, now=RECOVERY_TIME) == (
        RecoveryPoint.OPERATOR_PAUSE,
        RecoveryDisposition.PAUSE_OPERATOR,
    )
    assert classify_recovery_checkpoint(recovering, now=RECOVERY_TIME) == (
        RecoveryPoint.UNSAFE_STATE,
        RecoveryDisposition.PAUSE_OPERATOR,
    )


def test_classification_marks_started_external_attempts_indeterminate() -> None:
    model = _checkpoint(active_attempt=_model_attempt(ExecutionAttemptStatus.STARTED))
    tool = _checkpoint(
        next_operation=CheckpointNextOperation.TOOL_INVOCATION,
        active_attempt=_tool_attempt(ExecutionAttemptStatus.STARTED),
    )

    assert classify_recovery_checkpoint(model, now=RECOVERY_TIME) == (
        RecoveryPoint.ACTIVE_MODEL_ATTEMPT,
        RecoveryDisposition.MARK_INDETERMINATE_MODEL,
    )
    assert classify_recovery_checkpoint(tool, now=RECOVERY_TIME) == (
        RecoveryPoint.ACTIVE_TOOL_ATTEMPT,
        RecoveryDisposition.MARK_INDETERMINATE_TOOL,
    )


def test_classification_preserves_existing_indeterminate_for_operator() -> None:
    model = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_model_attempt(ExecutionAttemptStatus.INDETERMINATE),
    )
    tool = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_TOOL,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_tool_attempt(ExecutionAttemptStatus.INDETERMINATE),
    )

    assert classify_recovery_checkpoint(model, now=RECOVERY_TIME) == (
        RecoveryPoint.ACTIVE_MODEL_ATTEMPT,
        RecoveryDisposition.PAUSE_OPERATOR,
    )
    assert classify_recovery_checkpoint(tool, now=RECOVERY_TIME) == (
        RecoveryPoint.ACTIVE_TOOL_ATTEMPT,
        RecoveryDisposition.PAUSE_OPERATOR,
    )


def test_classification_expires_retention_or_original_budget_deadline() -> None:
    retention_expired = _checkpoint(
        retention_deadline=NOW + timedelta(minutes=1),
    )
    budget_expired = _checkpoint(
        budget_deadline=NOW + timedelta(minutes=1),
    )

    assert classify_recovery_checkpoint(retention_expired, now=RECOVERY_TIME) == (
        RecoveryPoint.EXPIRED,
        RecoveryDisposition.TERMINATE_EXPIRED,
    )
    assert classify_recovery_checkpoint(budget_expired, now=RECOVERY_TIME) == (
        RecoveryPoint.EXPIRED,
        RecoveryDisposition.TERMINATE_EXPIRED,
    )


def test_classification_fails_closed_for_invalid_or_future_state() -> None:
    no_operation = _checkpoint(next_operation=CheckpointNextOperation.NONE)

    assert classify_recovery_checkpoint(no_operation, now=RECOVERY_TIME) == (
        RecoveryPoint.UNSAFE_STATE,
        RecoveryDisposition.TERMINATE_FAILED,
    )
    with pytest.raises(AgentStateConflictError):
        classify_recovery_checkpoint(no_operation, now=NOW)


async def test_coordinator_assesses_bounded_sorted_page_and_releases_leases() -> None:
    store = InMemoryDurableRunStore()
    first_run = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
    last_run = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000003"))
    await store.create(_checkpoint(durable_run_id=last_run))
    await store.create(_checkpoint(durable_run_id=first_run))

    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
    )
    assessments = await coordinator.assess_page(
        owner_id="startup-worker",
        now=RECOVERY_TIME,
        limit=2,
    )

    assert isinstance(coordinator, DurableRecoveryCoordinator)
    assert tuple(item.run_id for item in assessments) == (first_run, last_run)
    assert all(item.point is RecoveryPoint.SAFE_BOUNDARY for item in assessments)
    assert all(
        item.compatibility.category is DurableCompatibilityCategory.EXACT for item in assessments
    )
    assert all(item.generation.value == 1 for item in assessments)
    assert await store.lease_manager.get_current(first_run, now=RECOVERY_TIME) is None
    assert await store.lease_manager.get_current(last_run, now=RECOVERY_TIME) is None


async def test_coordinator_uses_authoritative_post_acquisition_checkpoint() -> None:
    manager = _AppendOnAcquireLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    first = _checkpoint()
    second = _next(
        first,
        status=DurableRunStatus.PAUSED_SHUTDOWN,
    )
    await store.create(first)
    manager.store = store
    manager.checkpoint = second

    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_compatibility_validator(),
    )
    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )

    assert assessment.checkpoint_id == second.checkpoint_id
    assert assessment.sequence == CheckpointSequence(2)
    assert assessment.run_version == DurableRunVersion(2)
    assert assessment.point is RecoveryPoint.SHUTDOWN_PAUSE
    assert manager.appended is True
    assert await manager.get_current(DURABLE_RUN_ID, now=RECOVERY_TIME) is None


async def test_coordinator_rejects_incomplete_history_and_releases_lease() -> None:
    store = _TruncatedHistoryStore()
    first = _checkpoint()
    second = _next(first)
    await store.create(first)
    initial_lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="writer",
        now=NOW + timedelta(seconds=30),
    )
    await store.append(
        second,
        expected_version=DurableRunVersion(1),
        lease=initial_lease,
        now=NOW + timedelta(seconds=30),
    )
    await store.lease_manager.release(
        initial_lease,
        now=NOW + timedelta(seconds=30),
    )

    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
    )
    with pytest.raises(AgentCodecError, match="incomplete"):
        await coordinator.assess_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=RECOVERY_TIME,
        )

    assert await store.lease_manager.get_current(DURABLE_RUN_ID, now=RECOVERY_TIME) is None


async def test_closed_coordinator_rejects_new_assessments() -> None:
    store = InMemoryDurableRunStore()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
    )

    await coordinator.close()

    assert coordinator.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        await coordinator.assess_page(
            owner_id="startup-worker",
            now=RECOVERY_TIME,
            limit=1,
        )
