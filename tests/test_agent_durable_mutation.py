from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
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
    ExecutionAttemptId,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_mutation import (
    append_durable_checkpoint_confirmed,
    classify_durable_checkpoint_mutation,
    resolve_durable_checkpoint_append,
)
from phoenix_os.agent.durable_reliability import DurableMutationOutcome, ReliabilityFaultPoint
from phoenix_os.agent.durable_reliability_fake import (
    DeterministicReliabilityFaultInjector,
    ReliabilityFaultTrigger,
)
from phoenix_os.agent.durable_sqlite import SQLiteDurableRunStore
from phoenix_os.agent.errors import AgentServiceUnavailableError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 29, 12, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
MUTATION_TIME = NOW + timedelta(seconds=2)

RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
FIRST_CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-0000-0000-000000000004"))
SECOND_CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-0000-0000-000000000005"))
THIRD_CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-0000-0000-000000000006"))
ATTEMPT_ID = ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000005"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=16,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _initial_checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=RUN_ID,
            checkpoint_id=FIRST_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=7),
                active_attempt=None,
                metadata={},
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


def _successor(
    current: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId = SECOND_CHECKPOINT_ID,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=checkpoint_id,
            sequence=current.sequence.next(),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            created_at=MUTATION_TIME,
            digest=_digest("0"),
        )
    )


async def _seed(
    store: InMemoryDurableRunStore,
) -> tuple[CheckpointEnvelope, DurableLease]:
    current = _initial_checkpoint()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="mutation-test",
        now=LEASE_TIME,
    )
    return current, lease


class _BeforeMutationFailureStore(InMemoryDurableRunStore):
    def __init__(self) -> None:
        super().__init__()
        self.append_calls = 0

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        self.append_calls += 1
        raise RuntimeError("synthetic pre-commit failure")


class _AfterCommitFailureStore(InMemoryDurableRunStore):
    def __init__(self) -> None:
        super().__init__()
        self.append_calls = 0

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        self.append_calls += 1
        await super().append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
        )
        raise RuntimeError("synthetic post-commit acknowledgement failure")


class _AcknowledgedWithoutCommitStore(InMemoryDurableRunStore):
    def __init__(self) -> None:
        super().__init__()
        self.append_calls = 0

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        self.append_calls += 1
        return checkpoint


class _ReadUnavailableStore(_BeforeMutationFailureStore):
    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        raise RuntimeError("synthetic authoritative reread failure")


class _FaultInjectingSQLiteStore(SQLiteDurableRunStore):
    def __init__(
        self,
        path: Path,
        injector: DeterministicReliabilityFaultInjector,
    ) -> None:
        super().__init__(path)
        self._test_injector = injector

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        self._test_injector.inject(ReliabilityFaultPoint.CHECKPOINT_BEFORE_STORE_MUTATION)
        committed = await super().append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
        )
        self._test_injector.inject(ReliabilityFaultPoint.CHECKPOINT_AFTER_STORE_COMMIT_BEFORE_ACK)
        return committed


@pytest.mark.asyncio
async def test_precommit_failure_is_confirmed_not_committed_without_retry() -> None:
    store = _BeforeMutationFailureStore()
    current, lease = await _seed(store)
    intended = _successor(current)

    resolution = await resolve_durable_checkpoint_append(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=MUTATION_TIME,
    )

    assert resolution.outcome is DurableMutationOutcome.CONFIRMED_NOT_COMMITTED
    assert resolution.authoritative == current
    assert resolution.append_acknowledged is False
    assert store.append_calls == 1


@pytest.mark.asyncio
async def test_postcommit_ack_failure_is_proven_committed_by_exact_reread() -> None:
    store = _AfterCommitFailureStore()
    current, lease = await _seed(store)
    intended = _successor(current)

    confirmed = await append_durable_checkpoint_confirmed(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=MUTATION_TIME,
    )

    assert confirmed == intended
    assert await store.get_current(RUN_ID) == intended
    assert store.append_calls == 1


@pytest.mark.asyncio
async def test_ambiguous_postcommit_write_preserves_monotonic_budget_state() -> None:
    store = _AfterCommitFailureStore()
    current, lease = await _seed(store)
    intended = seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=SECOND_CHECKPOINT_ID,
            sequence=current.sequence.next(),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            metadata=replace(
                current.metadata,
                budget=replace(
                    current.metadata.budget,
                    steps=current.metadata.budget.steps + 1,
                ),
            ),
            created_at=MUTATION_TIME,
            digest=_digest("0"),
        )
    )

    confirmed = await append_durable_checkpoint_confirmed(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=MUTATION_TIME,
    )

    assert confirmed == intended
    assert confirmed.sequence.value == current.sequence.value + 1
    assert confirmed.run_version.value == current.run_version.value + 1
    assert confirmed.metadata.budget.steps == current.metadata.budget.steps + 1
    assert await store.get_current(RUN_ID) == intended
    assert store.append_calls == 1


@pytest.mark.asyncio
async def test_successful_local_return_is_not_sufficient_commit_evidence() -> None:
    store = _AcknowledgedWithoutCommitStore()
    current, lease = await _seed(store)
    intended = _successor(current)

    resolution = await resolve_durable_checkpoint_append(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=MUTATION_TIME,
    )

    assert resolution.append_acknowledged is True
    assert resolution.outcome is DurableMutationOutcome.CONFIRMED_NOT_COMMITTED
    assert resolution.authoritative == current
    assert store.append_calls == 1


@pytest.mark.asyncio
async def test_unavailable_reread_keeps_commit_outcome_unknown() -> None:
    store = _ReadUnavailableStore()
    current, lease = await _seed(store)
    intended = _successor(current)

    resolution = await resolve_durable_checkpoint_append(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=MUTATION_TIME,
    )

    assert resolution.outcome is DurableMutationOutcome.COMMIT_OUTCOME_UNKNOWN
    assert resolution.authoritative is None
    assert resolution.append_acknowledged is False
    with pytest.raises(AgentServiceUnavailableError):
        await append_durable_checkpoint_confirmed(
            store,
            current=current,
            intended=intended,
            lease=lease,
            now=MUTATION_TIME,
        )


def test_conflicting_authoritative_successor_remains_unknown() -> None:
    current = _initial_checkpoint()
    intended = _successor(current)
    conflicting = _successor(current, checkpoint_id=THIRD_CHECKPOINT_ID)

    assert (
        classify_durable_checkpoint_mutation(current, intended, conflicting)
        is DurableMutationOutcome.COMMIT_OUTCOME_UNKNOWN
    )


@pytest.mark.asyncio
async def test_confirmed_not_committed_fails_closed_instead_of_retrying() -> None:
    store = _BeforeMutationFailureStore()
    current, lease = await _seed(store)
    intended = _successor(current)

    with pytest.raises(AgentStateConflictError):
        await append_durable_checkpoint_confirmed(
            store,
            current=current,
            intended=intended,
            lease=lease,
            now=MUTATION_TIME,
        )

    assert store.append_calls == 1
    assert await store.get_current(RUN_ID) == current


@pytest.mark.asyncio
async def test_attempt_recorder_accepts_postcommit_ack_failure_only_after_reread() -> None:
    store = _AfterCommitFailureStore()
    current, lease = await _seed(store)
    recorder = StoreBackedDurableExecutionAttemptRecorder(
        store=store,
        attempt_id_factory=lambda: ATTEMPT_ID,
        checkpoint_id_factory=lambda: SECOND_CHECKPOINT_ID,
    )

    prepared = await recorder.prepare_model_attempt(
        RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=MUTATION_TIME,
    )

    assert prepared.sequence == CheckpointSequence(2)
    assert prepared.metadata.active_attempt is not None
    assert prepared.metadata.active_attempt.attempt_id == ATTEMPT_ID
    assert await store.get_current(RUN_ID) == prepared
    assert store.append_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("point", "expected_outcome"),
    (
        (
            ReliabilityFaultPoint.CHECKPOINT_BEFORE_STORE_MUTATION,
            DurableMutationOutcome.CONFIRMED_NOT_COMMITTED,
        ),
        (
            ReliabilityFaultPoint.CHECKPOINT_AFTER_STORE_COMMIT_BEFORE_ACK,
            DurableMutationOutcome.CONFIRMED_COMMITTED,
        ),
    ),
)
async def test_sqlite_reopen_proves_exact_transaction_boundary_outcome(
    tmp_path: Path,
    point: ReliabilityFaultPoint,
    expected_outcome: DurableMutationOutcome,
) -> None:
    path = tmp_path / f"{point.name.lower()}.sqlite3"
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(point=point),),
        max_total_hits=4,
    )
    store = _FaultInjectingSQLiteStore(path, injector)
    current = _initial_checkpoint()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="sqlite-boundary",
        now=LEASE_TIME,
    )
    intended = _successor(current)

    resolution = await resolve_durable_checkpoint_append(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=MUTATION_TIME,
    )
    expected = (
        intended if expected_outcome is DurableMutationOutcome.CONFIRMED_COMMITTED else current
    )

    assert resolution.outcome is expected_outcome
    assert resolution.authoritative == expected
    assert resolution.append_acknowledged is False
    await store.close()

    reopened = SQLiteDurableRunStore(path)
    assert await reopened.get_current(RUN_ID) == expected
    await reopened.close()
