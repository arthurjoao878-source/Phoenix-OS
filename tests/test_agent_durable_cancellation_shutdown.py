from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_attempts import StoreBackedDurableExecutionAttemptRecorder
from phoenix_os.agent.durable_authorization import DurableReconciliationAuthorizer
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    ReconciliationDecision,
    ReconciliationRequest,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_reconciliation import (
    StoreBackedDurableReconciliationDispositionApplier,
    reconciliation_disposition_record,
)
from phoenix_os.agent.durable_recovery import (
    StartupDurableRecoveryCoordinator,
    classify_recovery_checkpoint,
)
from phoenix_os.agent.durable_state import DurableCheckpointBoundary, DurableRunStateMachine
from phoenix_os.agent.errors import AgentAuthorizationRejectedError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 1, 4, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=10)
SHUTDOWN_TIME = NOW + timedelta(seconds=20)
RECONCILE_TIME = NOW + timedelta(seconds=30)

DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000005"))


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


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind,
    *,
    status: ExecutionAttemptStatus,
    reason: IndeterminateReason | None = None,
) -> ExecutionAttempt:
    prepared_at = NOW + timedelta(seconds=1)
    started_at = None
    completed_at = None
    if status is not ExecutionAttemptStatus.PREPARED:
        started_at = NOW + timedelta(seconds=2)
    if status not in {
        ExecutionAttemptStatus.PREPARED,
        ExecutionAttemptStatus.STARTED,
    }:
        completed_at = NOW + timedelta(seconds=3)
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=prepared_at,
        tool_call_id=(TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None),
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=started_at,
        completed_at=completed_at,
        external_request_digest=_digest("e"),
        indeterminate_reason=reason,
    )


def _operation(kind: ExecutionAttemptKind) -> CheckpointNextOperation:
    return (
        CheckpointNextOperation.MODEL_TURN
        if kind is ExecutionAttemptKind.MODEL_TURN
        else CheckpointNextOperation.TOOL_INVOCATION
    )


def _checkpoint(
    *,
    run_id: DurableAgentRunId = DURABLE_RUN_ID,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
    sequence: int = 1,
    previous_digest: CheckpointDigest | None = None,
    created_at: datetime = NOW + timedelta(seconds=5),
) -> CheckpointEnvelope:
    if status.terminal:
        next_operation = CheckpointNextOperation.NONE
        active_attempt = None
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=run_id,
            checkpoint_id=CheckpointId(
                UUID(int=0x60000000000000000000000000000000 + sequence + run_id.value.int)
            ),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=next_operation,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=7),
                active_attempt=active_attempt,
                metadata={"tenant": "demo"},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _next_checkpoint(
    current: CheckpointEnvelope,
    *,
    status: DurableRunStatus,
    next_operation: CheckpointNextOperation,
    active_attempt: ExecutionAttempt | None = None,
    created_at: datetime = SHUTDOWN_TIME,
) -> CheckpointEnvelope:
    if status.terminal:
        next_operation = CheckpointNextOperation.NONE
        active_attempt = None
    return seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=CheckpointId(
                UUID(int=0x70000000000000000000000000000000 + current.sequence.value + 1)
            ),
            sequence=current.sequence.next(),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            status=status,
            metadata=replace(
                current.metadata,
                next_operation=next_operation,
                active_attempt=active_attempt,
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        attributes={"durable_actor_id": "operator-1"},
    )


class _RecordingLeaseManager(InMemoryDurableLeaseManager):
    def __init__(self) -> None:
        super().__init__()
        self.acquire_calls = 0
        self.on_acquire: Callable[[], Awaitable[None]] | None = None

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        self.acquire_calls += 1
        lease = await super().acquire(run_id, owner_id=owner_id, now=now)
        if self.on_acquire is not None:
            await self.on_acquire()
        return lease


class _RecordingAuthorizer:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del request, checkpoint, lease, context
        self.calls += 1
        if self.error is not None:
            raise self.error


async def _store_with_checkpoint(
    checkpoint: CheckpointEnvelope,
    *,
    manager: InMemoryDurableLeaseManager | None = None,
) -> tuple[InMemoryDurableRunStore, InMemoryDurableLeaseManager]:
    selected_manager = manager or InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=selected_manager)
    await store.create(checkpoint)
    return store, selected_manager


async def _recovery_harness(
    checkpoint: CheckpointEnvelope,
    *,
    manager: InMemoryDurableLeaseManager | None = None,
) -> tuple[
    InMemoryDurableRunStore,
    InMemoryDurableLeaseManager,
    StartupDurableRecoveryCoordinator,
]:
    store, selected_manager = await _store_with_checkpoint(checkpoint, manager=manager)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=selected_manager,
        compatibility_validator=_validator(),
    )
    return store, selected_manager, coordinator


async def _cancel_reconciliation_harness(
    kind: ExecutionAttemptKind,
    *,
    authorizer: _RecordingAuthorizer | None = None,
) -> tuple[
    InMemoryDurableRunStore,
    InMemoryDurableLeaseManager,
    DurableLease,
    _RecordingAuthorizer,
    StoreBackedDurableReconciliationDispositionApplier,
    ReconciliationRequest,
]:
    checkpoint = _checkpoint(
        status=(
            DurableRunStatus.INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        ),
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            kind,
            status=ExecutionAttemptStatus.INDETERMINATE,
            reason=IndeterminateReason.PROCESS_LOSS,
        ),
    )
    store, manager = await _store_with_checkpoint(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="reconcile-worker",
        now=LEASE_TIME,
    )
    selected_authorizer = authorizer or _RecordingAuthorizer()
    applier = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=selected_authorizer,
    )
    request = ReconciliationRequest(
        run_id=checkpoint.durable_run_id,
        attempt_id=ATTEMPT_ID,
        actor_id="operator-1",
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        decision=ReconciliationDecision.CANCEL_RUN,
        requested_at=RECONCILE_TIME - timedelta(seconds=1),
    )
    return store, manager, lease, selected_authorizer, applier, request


def test_recording_authorizer_matches_reconciliation_protocol() -> None:
    assert isinstance(_RecordingAuthorizer(), DurableReconciliationAuthorizer)


def test_cancelled_status_is_terminal() -> None:
    assert DurableRunStatus.CANCELLED.terminal


async def test_cancelled_checkpoint_is_not_a_recovery_candidate() -> None:
    store = InMemoryDurableRunStore()
    cancelled = _checkpoint(status=DurableRunStatus.CANCELLED)
    active = _checkpoint(run_id=OTHER_RUN_ID)
    await store.create(cancelled)
    await store.create(active)

    assert await store.list_recovery_candidates(limit=2) == (OTHER_RUN_ID,)


def test_cancelled_checkpoint_cannot_be_classified_for_resume() -> None:
    checkpoint = _checkpoint(status=DurableRunStatus.CANCELLED)

    with pytest.raises(AgentStateConflictError):
        classify_recovery_checkpoint(checkpoint, now=SHUTDOWN_TIME)


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_cancelled_checkpoint_blocks_new_external_attempts(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.CANCELLED,
        next_operation=_operation(kind),
    )
    store, manager = await _store_with_checkpoint(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        if kind is ExecutionAttemptKind.MODEL_TURN:
            await recorder.prepare_model_attempt(
                checkpoint.durable_run_id,
                expected_version=checkpoint.run_version,
                lease=lease,
                external_request_digest=_digest("f"),
                now=SHUTDOWN_TIME,
            )
        else:
            await recorder.prepare_tool_attempt(
                checkpoint.durable_run_id,
                expected_version=checkpoint.run_version,
                lease=lease,
                tool_call_id=TOOL_CALL_ID,
                tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
                external_request_digest=_digest("f"),
                now=SHUTDOWN_TIME,
            )

    assert await store.get_current(checkpoint.durable_run_id) == checkpoint
    assert len(await store.list_history(checkpoint.durable_run_id, limit=1)) == 1


async def test_store_rejects_work_after_terminal_cancelled_checkpoint() -> None:
    cancelled = _checkpoint(status=DurableRunStatus.CANCELLED)
    store, manager = await _store_with_checkpoint(cancelled)
    lease = await manager.acquire(
        cancelled.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )
    candidate = _next_checkpoint(
        cancelled,
        status=DurableRunStatus.ACTIVE,
        next_operation=CheckpointNextOperation.MODEL_TURN,
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(
            candidate,
            expected_version=cancelled.run_version,
            lease=lease,
            now=SHUTDOWN_TIME,
        )

    assert await store.get_current(cancelled.durable_run_id) == cancelled


def test_state_machine_terminal_cancellation_cannot_resume() -> None:
    machine = DurableRunStateMachine(DURABLE_RUN_ID, created_at=NOW)
    machine.transition(DurableRunStatus.ACTIVE, now=NOW + timedelta(seconds=1))
    machine.transition(
        DurableRunStatus.CHECKPOINTING,
        now=NOW + timedelta(seconds=2),
        boundary=DurableCheckpointBoundary(CheckpointNextOperation.NONE),
    )
    machine.transition(
        DurableRunStatus.CANCELLED,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.terminal
    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.RECOVERING,
            now=NOW + timedelta(seconds=4),
        )


@pytest.mark.parametrize(
    "next_operation",
    tuple(
        operation
        for operation in CheckpointNextOperation
        if operation is not CheckpointNextOperation.NONE
    ),
)
def test_controlled_shutdown_accepts_only_safe_checkpoint_boundary(
    next_operation: CheckpointNextOperation,
) -> None:
    machine = DurableRunStateMachine(DURABLE_RUN_ID, created_at=NOW)
    machine.transition(DurableRunStatus.ACTIVE, now=NOW + timedelta(seconds=1))
    machine.transition(
        DurableRunStatus.CHECKPOINTING,
        now=NOW + timedelta(seconds=2),
        boundary=DurableCheckpointBoundary(next_operation),
    )
    machine.transition(
        DurableRunStatus.PAUSED_SHUTDOWN,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is DurableRunStatus.PAUSED_SHUTDOWN


@pytest.mark.parametrize(
    "unsafe_boundary",
    (
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            model_call_active=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.TOOL_INVOCATION,
            tool_call_active=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.VALIDATE_RESULT,
            result_stream_open=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.WAIT_APPROVAL,
            approval_consumption_active=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            transition_complete=False,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            budgets_known=False,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            continuation_available=False,
        ),
    ),
)
def test_controlled_shutdown_rejects_unsafe_checkpoint_boundary(
    unsafe_boundary: DurableCheckpointBoundary,
) -> None:
    machine = DurableRunStateMachine(DURABLE_RUN_ID, created_at=NOW)
    machine.transition(DurableRunStatus.ACTIVE, now=NOW + timedelta(seconds=1))

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.CHECKPOINTING,
            now=NOW + timedelta(seconds=2),
            boundary=unsafe_boundary,
        )

    assert machine.status is DurableRunStatus.ACTIVE


@pytest.mark.parametrize(
    "next_operation",
    tuple(
        operation
        for operation in CheckpointNextOperation
        if operation is not CheckpointNextOperation.NONE
    ),
)
def test_shutdown_pause_recovers_only_with_deterministic_continuation(
    next_operation: CheckpointNextOperation,
) -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_SHUTDOWN,
        next_operation=next_operation,
    )

    assert classify_recovery_checkpoint(checkpoint, now=SHUTDOWN_TIME) == (
        RecoveryPoint.SHUTDOWN_PAUSE,
        RecoveryDisposition.RESUME,
    )


def test_shutdown_pause_without_continuation_fails_closed() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_SHUTDOWN,
        next_operation=CheckpointNextOperation.NONE,
    )

    assert classify_recovery_checkpoint(checkpoint, now=SHUTDOWN_TIME) == (
        RecoveryPoint.UNSAFE_STATE,
        RecoveryDisposition.TERMINATE_FAILED,
    )


async def test_shutdown_pause_remains_a_recovery_candidate() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_SHUTDOWN,
        next_operation=CheckpointNextOperation.MODEL_TURN,
    )
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)

    assert await store.list_recovery_candidates(limit=1) == (checkpoint.durable_run_id,)


async def test_shutdown_recovery_assessment_releases_its_lease() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_SHUTDOWN,
        next_operation=CheckpointNextOperation.MODEL_TURN,
    )
    store, manager, coordinator = await _recovery_harness(checkpoint)

    assessment = await coordinator.assess_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=SHUTDOWN_TIME,
    )

    assert assessment.point is RecoveryPoint.SHUTDOWN_PAUSE
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert manager.active_count == 0
    assert await manager.get_current(checkpoint.durable_run_id, now=SHUTDOWN_TIME) is None
    assert await store.get_current(checkpoint.durable_run_id) == checkpoint


async def test_closed_recovery_coordinator_stops_new_lease_acquisition() -> None:
    manager = _RecordingLeaseManager()
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_SHUTDOWN,
        next_operation=CheckpointNextOperation.MODEL_TURN,
    )
    store, _, coordinator = await _recovery_harness(checkpoint, manager=manager)
    await coordinator.close()

    with pytest.raises(RuntimeError, match="closed"):
        await coordinator.assess_candidate(
            checkpoint.durable_run_id,
            owner_id="startup-worker",
            now=SHUTDOWN_TIME,
        )

    assert manager.acquire_calls == 0
    assert manager.active_count == 0
    assert not manager.closed
    assert not store.closed


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_closed_recovery_coordinator_stops_indeterminate_persistence_before_lease(
    kind: ExecutionAttemptKind,
) -> None:
    manager = _RecordingLeaseManager()
    checkpoint = _checkpoint(
        next_operation=_operation(kind),
        active_attempt=_attempt(kind, status=ExecutionAttemptStatus.STARTED),
    )
    _, _, coordinator = await _recovery_harness(checkpoint, manager=manager)
    await coordinator.close()

    with pytest.raises(RuntimeError, match="closed"):
        await coordinator.persist_indeterminate_candidate(
            checkpoint.durable_run_id,
            owner_id="startup-worker",
            now=SHUTDOWN_TIME,
            reason=IndeterminateReason.SHUTDOWN_TIMEOUT,
        )

    assert manager.acquire_calls == 0
    assert manager.active_count == 0


async def test_recovery_coordinator_close_is_idempotent_and_preserves_dependencies() -> None:
    manager = _RecordingLeaseManager()
    checkpoint = _checkpoint()
    store, _, coordinator = await _recovery_harness(checkpoint, manager=manager)

    await coordinator.close()
    await coordinator.close()

    assert coordinator.closed
    assert not manager.closed
    assert not store.closed
    assert manager.active_count == 0


async def test_close_after_recovery_lease_acquisition_releases_the_lease() -> None:
    manager = _RecordingLeaseManager()
    checkpoint = _checkpoint()
    _, _, coordinator = await _recovery_harness(checkpoint, manager=manager)
    manager.on_acquire = coordinator.close

    with pytest.raises(RuntimeError, match="closed"):
        await coordinator.assess_candidate(
            checkpoint.durable_run_id,
            owner_id="startup-worker",
            now=SHUTDOWN_TIME,
        )

    assert coordinator.closed
    assert manager.acquire_calls == 1
    assert manager.active_count == 0
    assert not manager.closed


async def test_lease_manager_close_invalidates_active_leases_and_blocks_new_work() -> None:
    manager = InMemoryDurableLeaseManager()
    await manager.acquire(
        DURABLE_RUN_ID,
        owner_id="worker-1",
        now=LEASE_TIME,
    )

    await manager.close()

    assert manager.closed
    assert manager.active_count == 0
    with pytest.raises(RuntimeError, match="closed"):
        await manager.acquire(
            OTHER_RUN_ID,
            owner_id="worker-2",
            now=SHUTDOWN_TIME,
        )


async def test_lease_manager_close_waits_for_guarded_mutation_then_invalidates_leases() -> None:
    manager = InMemoryDurableLeaseManager()
    lease = await manager.acquire(
        DURABLE_RUN_ID,
        owner_id="worker-1",
        now=LEASE_TIME,
    )
    entered = asyncio.Event()
    release_guard = asyncio.Event()

    async def hold_guard() -> None:
        async with manager.guard_current(
            lease,
            now=LEASE_TIME + timedelta(seconds=1),
        ):
            entered.set()
            await release_guard.wait()

    guard_task = asyncio.create_task(hold_guard())
    await entered.wait()
    close_task = asyncio.create_task(manager.close())
    await asyncio.sleep(0)

    assert not close_task.done()
    assert manager.active_count == 1

    release_guard.set()
    await asyncio.wait_for(guard_task, timeout=1)
    await asyncio.wait_for(close_task, timeout=1)

    assert manager.closed
    assert manager.active_count == 0


async def test_store_close_invalidates_owned_lease_manager() -> None:
    store = InMemoryDurableRunStore()
    manager = cast(InMemoryDurableLeaseManager, store.lease_manager)
    checkpoint = _checkpoint()
    await store.create(checkpoint)
    await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )

    await store.close()

    assert store.closed
    assert manager.closed
    assert manager.active_count == 0


async def test_store_close_preserves_injected_lease_manager_ownership() -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    checkpoint = _checkpoint()
    await store.create(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )

    await store.close()

    assert store.closed
    assert not manager.closed
    assert manager.active_count == 1
    await manager.release(lease, now=SHUTDOWN_TIME)
    assert manager.active_count == 0
    await manager.close()


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_paused_shutdown_blocks_new_attempt_preparation(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_SHUTDOWN,
        next_operation=_operation(kind),
    )
    store, manager = await _store_with_checkpoint(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        if kind is ExecutionAttemptKind.MODEL_TURN:
            await recorder.prepare_model_attempt(
                checkpoint.durable_run_id,
                expected_version=checkpoint.run_version,
                lease=lease,
                external_request_digest=_digest("f"),
                now=SHUTDOWN_TIME,
            )
        else:
            await recorder.prepare_tool_attempt(
                checkpoint.durable_run_id,
                expected_version=checkpoint.run_version,
                lease=lease,
                tool_call_id=TOOL_CALL_ID,
                tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
                external_request_digest=_digest("f"),
                now=SHUTDOWN_TIME,
            )

    assert await store.get_current(checkpoint.durable_run_id) == checkpoint


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_shutdown_timeout_preserves_unknown_external_completion_as_indeterminate(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        next_operation=_operation(kind),
        active_attempt=_attempt(kind, status=ExecutionAttemptStatus.STARTED),
    )
    store, manager, coordinator = await _recovery_harness(checkpoint)

    assessment = await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=SHUTDOWN_TIME,
        reason=IndeterminateReason.SHUTDOWN_TIMEOUT,
    )
    current = await store.get_current(checkpoint.durable_run_id)

    assert current is not None
    assert current.status is (
        DurableRunStatus.INDETERMINATE_MODEL
        if kind is ExecutionAttemptKind.MODEL_TURN
        else DurableRunStatus.INDETERMINATE_TOOL
    )
    assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert current.metadata.active_attempt is not None
    assert current.metadata.active_attempt.status is ExecutionAttemptStatus.INDETERMINATE
    assert (
        current.metadata.active_attempt.indeterminate_reason is IndeterminateReason.SHUTDOWN_TIMEOUT
    )
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert manager.active_count == 0


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_repeated_shutdown_timeout_recovery_does_not_rewrite_indeterminate_state(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        next_operation=_operation(kind),
        active_attempt=_attempt(kind, status=ExecutionAttemptStatus.STARTED),
    )
    store, _, coordinator = await _recovery_harness(checkpoint)

    first = await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=SHUTDOWN_TIME,
        reason=IndeterminateReason.SHUTDOWN_TIMEOUT,
    )
    second = await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=SHUTDOWN_TIME + timedelta(seconds=1),
        reason=IndeterminateReason.SHUTDOWN_TIMEOUT,
    )
    history = await store.list_history(checkpoint.durable_run_id, limit=2)

    assert first.checkpoint_id == second.checkpoint_id
    assert len(history) == 2
    assert history[-1].metadata.active_attempt is not None
    assert (
        history[-1].metadata.active_attempt.indeterminate_reason
        is IndeterminateReason.SHUTDOWN_TIMEOUT
    )


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_shutdown_does_not_overwrite_existing_indeterminate_reason(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        status=(
            DurableRunStatus.INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        ),
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            kind,
            status=ExecutionAttemptStatus.INDETERMINATE,
            reason=IndeterminateReason.PROCESS_LOSS,
        ),
    )
    store, _, coordinator = await _recovery_harness(checkpoint)

    assessment = await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=SHUTDOWN_TIME,
        reason=IndeterminateReason.SHUTDOWN_TIMEOUT,
    )
    current = await store.get_current(checkpoint.durable_run_id)

    assert current == checkpoint
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert current is not None
    assert current.metadata.active_attempt is not None
    assert current.metadata.active_attempt.indeterminate_reason is IndeterminateReason.PROCESS_LOSS
    assert len(await store.list_history(checkpoint.durable_run_id, limit=1)) == 1


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_prepared_attempt_can_be_cancelled_without_claiming_run_cancelled(
    kind: ExecutionAttemptKind,
) -> None:
    attempt = _attempt(kind, status=ExecutionAttemptStatus.PREPARED)
    checkpoint = _checkpoint(
        next_operation=_operation(kind),
        active_attempt=attempt,
    )
    store, manager = await _store_with_checkpoint(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    after = await recorder.mark_terminal(
        checkpoint.durable_run_id,
        ATTEMPT_ID,
        expected_version=checkpoint.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.CANCELLED,
        now=SHUTDOWN_TIME,
    )

    assert after.status is DurableRunStatus.PAUSED_OPERATOR
    assert after.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert after.metadata.active_attempt is not None
    assert after.metadata.active_attempt.status is ExecutionAttemptStatus.CANCELLED


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_indeterminate_attempt_cannot_be_locally_cancelled_without_reconciliation(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        status=(
            DurableRunStatus.INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        ),
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            kind,
            status=ExecutionAttemptStatus.INDETERMINATE,
            reason=IndeterminateReason.PROCESS_LOSS,
        ),
    )
    store, manager = await _store_with_checkpoint(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="worker-1",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            checkpoint.durable_run_id,
            ATTEMPT_ID,
            expected_version=checkpoint.run_version,
            lease=lease,
            status=ExecutionAttemptStatus.CANCELLED,
            now=SHUTDOWN_TIME,
        )

    assert await store.get_current(checkpoint.durable_run_id) == checkpoint


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_explicit_reconciliation_can_terminally_cancel_indeterminate_run(
    kind: ExecutionAttemptKind,
) -> None:
    store, manager, lease, authorizer, applier, request = await _cancel_reconciliation_harness(kind)

    after = await applier.apply(
        request,
        lease=lease,
        context=_context(),
        now=RECONCILE_TIME,
    )

    assert authorizer.calls == 1
    assert after.status is DurableRunStatus.CANCELLED
    assert after.metadata.next_operation is CheckpointNextOperation.NONE
    assert after.metadata.active_attempt is None
    record = reconciliation_disposition_record(after)
    assert record.decision is ReconciliationDecision.CANCEL_RUN
    assert record.result_status is DurableRunStatus.CANCELLED
    assert record.result_attempt_status is None
    assert len(await store.list_history(request.run_id, limit=2)) == 2
    assert await manager.require_current(lease, now=RECONCILE_TIME) == lease


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_rejected_cancel_reconciliation_does_not_mutate_run(
    kind: ExecutionAttemptKind,
) -> None:
    rejected = _RecordingAuthorizer(AgentAuthorizationRejectedError())
    store, _, lease, authorizer, applier, request = await _cancel_reconciliation_harness(
        kind,
        authorizer=rejected,
    )
    before = await store.get_current(request.run_id)

    with pytest.raises(AgentAuthorizationRejectedError):
        await applier.apply(
            request,
            lease=lease,
            context=_context(),
            now=RECONCILE_TIME,
        )

    assert authorizer.calls == 1
    assert await store.get_current(request.run_id) == before
    assert len(await store.list_history(request.run_id, limit=1)) == 1


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_cancel_reconciliation_requires_current_fenced_lease(
    kind: ExecutionAttemptKind,
) -> None:
    store, manager, lease, authorizer, applier, request = await _cancel_reconciliation_harness(kind)
    replacement = await manager.acquire(
        request.run_id,
        owner_id="replacement-worker",
        now=lease.expires_at,
    )

    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            request,
            lease=lease,
            context=_context(),
            now=replacement.acquired_at,
        )

    assert authorizer.calls == 0
    current = await store.get_current(request.run_id)
    assert current is not None
    assert current.status.indeterminate
    assert len(await store.list_history(request.run_id, limit=1)) == 1


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_cancellation_recorded_by_new_owner_blocks_stale_worker(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(next_operation=_operation(kind))
    store, manager = await _store_with_checkpoint(checkpoint)

    stale = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="stale-worker",
        now=LEASE_TIME,
    )
    takeover_time = stale.expires_at
    replacement = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="cancelling-worker",
        now=takeover_time,
    )

    cancelled = seal_checkpoint_envelope(
        replace(
            _next_checkpoint(
                checkpoint,
                status=DurableRunStatus.CANCELLED,
                next_operation=CheckpointNextOperation.NONE,
                created_at=takeover_time,
            ),
            checkpoint_id=CheckpointId(UUID("80000000-0000-0000-0000-000000000001")),
            digest=_digest("0"),
        )
    )
    persisted = await store.append(
        cancelled,
        expected_version=checkpoint.run_version,
        lease=replacement,
        now=takeover_time,
    )
    assert persisted.status is DurableRunStatus.CANCELLED

    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    stale_time = takeover_time + timedelta(seconds=1)

    with pytest.raises(AgentStateConflictError):
        if kind is ExecutionAttemptKind.MODEL_TURN:
            await recorder.prepare_model_attempt(
                checkpoint.durable_run_id,
                expected_version=checkpoint.run_version,
                lease=stale,
                external_request_digest=_digest("f"),
                now=stale_time,
            )
        else:
            await recorder.prepare_tool_attempt(
                checkpoint.durable_run_id,
                expected_version=checkpoint.run_version,
                lease=stale,
                tool_call_id=TOOL_CALL_ID,
                tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
                external_request_digest=_digest("f"),
                now=stale_time,
            )

    assert await store.get_current(checkpoint.durable_run_id) == cancelled
    assert await store.list_recovery_candidates(limit=1) == ()
