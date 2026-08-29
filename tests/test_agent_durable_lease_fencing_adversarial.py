from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
    RetentionPolicy,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_reconciliation import (
    StoreBackedDurableReconciliationDispositionApplier,
)
from phoenix_os.agent.durable_reliability import (
    DurableMutationOutcome,
    ReliabilityFaultPoint,
)
from phoenix_os.agent.durable_reliability_fake import (
    DeterministicReliabilityFaultInjector,
    InjectedReliabilityFault,
    ReliabilityFaultTrigger,
)
from phoenix_os.agent.durable_sqlite import SQLiteDurableLeaseManager
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 29, 23, tzinfo=UTC)
RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000031"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000032"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000033"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000034"))
CHECKPOINT_ID_1 = CheckpointId(UUID("50000000-0000-0000-0000-000000000035"))
CHECKPOINT_ID_2 = CheckpointId(UUID("50000000-0000-0000-0000-000000000036"))
TOOL_CALL_ID = ToolCallId(UUID("60000000-0000-0000-0000-000000000037"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget(created_at: datetime) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=created_at - timedelta(minutes=1),
        deadline=created_at + timedelta(hours=2),
    )


def _attempt(
    status: ExecutionAttemptStatus,
    *,
    kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN,
    created_at: datetime = NOW,
) -> ExecutionAttempt:
    started = created_at - timedelta(seconds=1)
    completed = (
        created_at
        if status
        not in {
            ExecutionAttemptStatus.PREPARED,
            ExecutionAttemptStatus.STARTED,
        }
        else None
    )
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=created_at - timedelta(seconds=2),
        tool_call_id=(TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None),
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=(started if status is not ExecutionAttemptStatus.PREPARED else None),
        completed_at=completed,
        external_request_digest=_digest("e"),
        indeterminate_reason=(
            IndeterminateReason.PROCESS_LOSS
            if status is ExecutionAttemptStatus.INDETERMINATE
            else None
        ),
    )


def _checkpoint(
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    attempt: ExecutionAttempt | None = None,
    created_at: datetime = NOW,
    checkpoint_id: CheckpointId = CHECKPOINT_ID_1,
    sequence: int = 1,
    previous_digest: CheckpointDigest | None = None,
) -> CheckpointEnvelope:
    if status.terminal:
        next_operation = CheckpointNextOperation.NONE
        attempt = None
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=RUN_ID,
            checkpoint_id=checkpoint_id,
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-origin",
                next_operation=next_operation,
                budget=_budget(created_at),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=created_at + timedelta(days=120),
                active_attempt=attempt,
                metadata={},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _successor(current: CheckpointEnvelope, *, now: datetime) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=CHECKPOINT_ID_2,
            sequence=current.sequence.next(),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            created_at=now,
            digest=_digest("0"),
        )
    )


def _revive_stale_identity(
    stale: DurableLease,
    current: DurableLease,
    *,
    now: datetime,
) -> DurableLease:
    return replace(
        stale,
        acquired_at=now,
        expires_at=current.expires_at,
    )


async def _take_over(
    manager: InMemoryDurableLeaseManager,
) -> tuple[DurableLease, DurableLease, DurableLease, datetime]:
    first = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW + timedelta(seconds=1),
    )
    takeover_at = first.expires_at
    second = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=takeover_at,
    )
    stale_active = _revive_stale_identity(first, second, now=takeover_at)
    assert stale_active.active_at(takeover_at)
    assert stale_active.generation.value + 1 == second.generation.value
    return first, second, stale_active, takeover_at


class _AllowReconciliationAuthorizer:
    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("point", "committed"),
    (
        (ReliabilityFaultPoint.LEASE_BEFORE_ACQUIRE, False),
        (ReliabilityFaultPoint.LEASE_AFTER_ACQUIRE, True),
    ),
)
async def test_inmemory_acquire_fault_boundary_is_exact(
    point: ReliabilityFaultPoint,
    committed: bool,
) -> None:
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(point=point),),
        max_total_hits=8,
    )
    manager = InMemoryDurableLeaseManager(fault_injector=injector)

    with pytest.raises(InjectedReliabilityFault):
        await manager.acquire(RUN_ID, owner_id="fault-worker", now=NOW)

    current = await manager.get_current(RUN_ID, now=NOW)
    assert (current is not None) is committed
    if current is not None:
        assert current.generation.value == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("point", "renewed"),
    (
        (ReliabilityFaultPoint.LEASE_BEFORE_RENEW, False),
        (ReliabilityFaultPoint.LEASE_AFTER_RENEW, True),
    ),
)
async def test_inmemory_renew_fault_boundary_is_exact(
    point: ReliabilityFaultPoint,
    renewed: bool,
) -> None:
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(point=point),),
        max_total_hits=16,
    )
    manager = InMemoryDurableLeaseManager(fault_injector=injector)
    original = await manager.acquire(RUN_ID, owner_id="fault-worker", now=NOW)
    renewal_at = NOW + timedelta(seconds=1)

    with pytest.raises(InjectedReliabilityFault):
        await manager.renew(original, now=renewal_at)

    current = await manager.get_current(RUN_ID, now=renewal_at)
    assert current is not None
    assert current.generation == original.generation
    assert current.acquired_at == (renewal_at if renewed else original.acquired_at)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("point", "committed"),
    (
        (ReliabilityFaultPoint.LEASE_BEFORE_ACQUIRE, False),
        (ReliabilityFaultPoint.LEASE_AFTER_ACQUIRE, True),
    ),
)
async def test_sqlite_acquire_fault_boundary_survives_reopen(
    tmp_path: Path,
    point: ReliabilityFaultPoint,
    committed: bool,
) -> None:
    path = tmp_path / f"{point.name.lower()}.sqlite3"
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(point=point),),
        max_total_hits=8,
    )
    manager = SQLiteDurableLeaseManager(path, fault_injector=injector)

    with pytest.raises(InjectedReliabilityFault):
        await manager.acquire(RUN_ID, owner_id="sqlite-worker", now=NOW)
    await manager.close()

    reopened = SQLiteDurableLeaseManager(path)
    current = await reopened.get_current(RUN_ID, now=NOW)
    assert (current is not None) is committed
    if current is not None:
        assert current.generation.value == 1
    await reopened.close()


async def _exercise_repeated_takeover(
    manager: InMemoryDurableLeaseManager | SQLiteDurableLeaseManager,
) -> None:
    current = await manager.acquire(RUN_ID, owner_id="worker-1", now=NOW)
    assert current.generation.value == 1

    for expected_generation in range(2, 33):
        takeover_at = current.expires_at
        stale = current
        current = await manager.acquire(
            RUN_ID,
            owner_id=f"worker-{expected_generation}",
            now=takeover_at,
        )
        assert current.generation.value == expected_generation
        forged_stale = _revive_stale_identity(stale, current, now=takeover_at)
        with pytest.raises(AgentStateConflictError):
            await manager.require_current(forged_stale, now=takeover_at)
        with pytest.raises(AgentStateConflictError):
            await manager.renew(forged_stale, now=takeover_at)


@pytest.mark.asyncio
async def test_repeated_takeover_is_bounded_and_monotonic_in_memory() -> None:
    await _exercise_repeated_takeover(InMemoryDurableLeaseManager())


@pytest.mark.asyncio
async def test_repeated_takeover_is_bounded_and_monotonic_in_sqlite(
    tmp_path: Path,
) -> None:
    manager = SQLiteDurableLeaseManager(tmp_path / "takeover.sqlite3")
    await _exercise_repeated_takeover(manager)
    await manager.close()


@pytest.mark.asyncio
async def test_stale_generation_cannot_append_checkpoint() -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    current = _checkpoint()
    await store.create(current)
    _first, _second, stale, takeover_at = await _take_over(manager)
    candidate = _successor(current, now=takeover_at)

    with pytest.raises(AgentStateConflictError):
        await store.append(
            candidate,
            expected_version=current.run_version,
            lease=stale,
            now=takeover_at,
        )

    assert await store.get_current(RUN_ID) == current


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_status",
    (
        ExecutionAttemptStatus.SUCCEEDED,
        ExecutionAttemptStatus.CANCELLED,
    ),
)
async def test_stale_generation_cannot_record_attempt_completion(
    terminal_status: ExecutionAttemptStatus,
) -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    current = _checkpoint(
        attempt=_attempt(ExecutionAttemptStatus.STARTED),
    )
    await store.create(current)
    _first, _second, stale, takeover_at = await _take_over(manager)
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            RUN_ID,
            ATTEMPT_ID,
            expected_version=current.run_version,
            lease=stale,
            status=terminal_status,
            now=takeover_at,
        )

    assert await store.get_current(RUN_ID) == current


@pytest.mark.asyncio
async def test_stale_generation_cannot_record_indeterminate_status() -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    current = _checkpoint(
        attempt=_attempt(ExecutionAttemptStatus.STARTED),
    )
    await store.create(current)
    _first, _second, stale, takeover_at = await _take_over(manager)
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_indeterminate(
            RUN_ID,
            ATTEMPT_ID,
            expected_version=current.run_version,
            lease=stale,
            reason=IndeterminateReason.PROCESS_LOSS,
            now=takeover_at,
        )

    assert await store.get_current(RUN_ID) == current


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "decision",
    (
        ReconciliationDecision.REMAIN_INDETERMINATE,
        ReconciliationDecision.CANCEL_RUN,
        ReconciliationDecision.FAIL_RUN,
    ),
)
async def test_stale_generation_cannot_reconcile_cancel_or_terminalize(
    decision: ReconciliationDecision,
) -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    current = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        attempt=_attempt(ExecutionAttemptStatus.INDETERMINATE),
    )
    await store.create(current)
    _first, _second, stale, takeover_at = await _take_over(manager)
    applier = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=_AllowReconciliationAuthorizer(),
    )
    request = ReconciliationRequest(
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        actor_id="operator-1",
        expected_version=current.run_version,
        generation=stale.generation,
        decision=decision,
        requested_at=takeover_at,
    )
    context = SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        attributes={"durable_actor_id": "operator-1"},
    )

    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            request,
            lease=stale,
            context=context,
            now=takeover_at,
        )

    assert await store.get_current(RUN_ID) == current


@pytest.mark.asyncio
async def test_stale_generation_cannot_cleanup_payload_or_terminal_metadata() -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    terminal_at = NOW - timedelta(days=40)
    current = _checkpoint(
        status=DurableRunStatus.COMPLETED,
        created_at=terminal_at,
    )
    await store.create(current)
    first = await manager.acquire(RUN_ID, owner_id="cleanup-a", now=NOW)
    takeover_at = first.expires_at
    second = await manager.acquire(RUN_ID, owner_id="cleanup-b", now=takeover_at)
    stale = _revive_stale_identity(first, second, now=takeover_at)
    policy = RetentionPolicy()

    with pytest.raises(AgentStateConflictError):
        await store.delete_expired_protected_payloads(
            RUN_ID,
            policy=policy,
            lease=stale,
            now=takeover_at,
        )
    with pytest.raises(AgentStateConflictError):
        await store.tombstone_terminal_run(
            RUN_ID,
            policy=policy,
            lease=stale,
            now=takeover_at,
        )

    assert await store.get_current(RUN_ID) == current
    assert await store.get_tombstone(RUN_ID) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    (
        CheckpointNextOperation.MODEL_TURN,
        CheckpointNextOperation.TOOL_INVOCATION,
    ),
)
async def test_lost_renewal_stops_new_protected_external_work(
    operation: CheckpointNextOperation,
) -> None:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    current = _checkpoint(next_operation=operation)
    await store.create(current)
    first, _second, stale, takeover_at = await _take_over(manager)

    with pytest.raises(AgentStateConflictError):
        await manager.renew(stale, now=takeover_at)

    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    with pytest.raises(AgentStateConflictError):
        if operation is CheckpointNextOperation.MODEL_TURN:
            await recorder.prepare_model_attempt(
                RUN_ID,
                expected_version=current.run_version,
                lease=stale,
                external_request_digest=_digest("9"),
                now=takeover_at,
            )
        else:
            await recorder.prepare_tool_attempt(
                RUN_ID,
                expected_version=current.run_version,
                lease=stale,
                tool_call_id=TOOL_CALL_ID,
                tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
                external_request_digest=_digest("9"),
                now=takeover_at,
            )

    assert first.generation.value == 1
    assert await store.get_current(RUN_ID) == current


def test_mutation_outcome_enum_remains_separate_from_fencing() -> None:
    assert {item.value for item in DurableMutationOutcome} == {
        "CONFIRMED_COMMITTED",
        "CONFIRMED_NOT_COMMITTED",
        "COMMIT_OUTCOME_UNKNOWN",
    }
