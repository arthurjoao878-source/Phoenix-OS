from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
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
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryAssessment,
    StartupDurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_reliability import ReliabilityFaultPoint
from phoenix_os.agent.durable_reliability_fake import (
    DeterministicReliabilityFaultInjector,
    InjectedReliabilityFault,
    ReliabilityFaultTrigger,
)
from phoenix_os.agent.durable_worker import (
    BoundedDurableRecoveryWorker,
    DurableRecoveryWorkerConfiguration,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 29, 23, 30, tzinfo=UTC)
RECOVERY_TIME = NOW + timedelta(minutes=5)
RUN_ID = DurableAgentRunId(UUID("11000000-0000-0000-0000-000000000031"))
AGENT_RUN_ID = AgentRunId(UUID("22000000-0000-0000-0000-000000000032"))
STEP_ID = AgentStepId(UUID("33000000-0000-0000-0000-000000000033"))
ATTEMPT_ID = ExecutionAttemptId(UUID("44000000-0000-0000-0000-000000000034"))


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
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _started_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW + timedelta(seconds=1),
        started_at=NOW + timedelta(seconds=2),
        external_request_digest=_digest("e"),
    )


def _checkpoint(*, started: bool) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=RUN_ID,
            checkpoint_id=CheckpointId(UUID("55000000-0000-0000-0000-000000000035")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=7),
                active_attempt=(_started_attempt() if started else None),
                metadata={},
            ),
            created_at=NOW + timedelta(seconds=3),
            digest=_digest("0"),
        )
    )


def _points(
    injector: DeterministicReliabilityFaultInjector,
) -> tuple[ReliabilityFaultPoint, ...]:
    return tuple(observation.point for observation in injector.observations)


@pytest.mark.asyncio
async def test_assess_page_fault_points_encode_required_recovery_order() -> None:
    injector = DeterministicReliabilityFaultInjector(max_total_hits=32)
    manager = InMemoryDurableLeaseManager(fault_injector=injector)
    store = InMemoryDurableRunStore(lease_manager=manager)
    await store.create(_checkpoint(started=False))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_compatibility_validator(),
        fault_injector=injector,
    )

    assessments = await coordinator.assess_page(
        owner_id="recoverer-a",
        now=RECOVERY_TIME,
        limit=1,
    )

    assert len(assessments) == 1
    assert _points(injector) == (
        ReliabilityFaultPoint.RECOVERY_AFTER_CANDIDATE_READ,
        ReliabilityFaultPoint.LEASE_BEFORE_ACQUIRE,
        ReliabilityFaultPoint.LEASE_AFTER_ACQUIRE,
        ReliabilityFaultPoint.RECOVERY_AFTER_LEASE_ACQUIRE,
        ReliabilityFaultPoint.RECOVERY_AFTER_REREAD,
        ReliabilityFaultPoint.RECOVERY_AFTER_LIVE_REVALIDATION,
    )


@pytest.mark.asyncio
async def test_indeterminate_transition_fault_points_are_exact_and_ordered() -> None:
    injector = DeterministicReliabilityFaultInjector(max_total_hits=32)
    manager = InMemoryDurableLeaseManager(fault_injector=injector)
    store = InMemoryDurableRunStore(lease_manager=manager)
    await store.create(_checkpoint(started=True))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_compatibility_validator(),
        fault_injector=injector,
    )

    assessment = await coordinator.persist_indeterminate_candidate(
        RUN_ID,
        owner_id="recoverer-a",
        now=RECOVERY_TIME,
    )

    assert assessment.status is DurableRunStatus.INDETERMINATE_MODEL
    assert _points(injector) == (
        ReliabilityFaultPoint.LEASE_BEFORE_ACQUIRE,
        ReliabilityFaultPoint.LEASE_AFTER_ACQUIRE,
        ReliabilityFaultPoint.RECOVERY_AFTER_LEASE_ACQUIRE,
        ReliabilityFaultPoint.RECOVERY_AFTER_REREAD,
        ReliabilityFaultPoint.RECOVERY_AFTER_LIVE_REVALIDATION,
        ReliabilityFaultPoint.RECOVERY_BEFORE_TRANSITION,
        ReliabilityFaultPoint.RECOVERY_AFTER_TRANSITION_COMMIT,
    )


@pytest.mark.asyncio
async def test_fault_after_transition_commit_cannot_repeat_transition() -> None:
    injector = DeterministicReliabilityFaultInjector(
        (
            ReliabilityFaultTrigger(
                point=ReliabilityFaultPoint.RECOVERY_AFTER_TRANSITION_COMMIT,
            ),
        ),
        max_total_hits=32,
    )
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    await store.create(_checkpoint(started=True))
    crashing = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_compatibility_validator(),
        fault_injector=injector,
    )

    with pytest.raises(InjectedReliabilityFault):
        await crashing.persist_indeterminate_candidate(
            RUN_ID,
            owner_id="recoverer-a",
            now=RECOVERY_TIME,
        )

    history_after_crash = await store.list_history(RUN_ID, limit=8)
    assert len(history_after_crash) == 2
    assert history_after_crash[-1].status is DurableRunStatus.INDETERMINATE_MODEL

    successor = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_compatibility_validator(),
    )
    assessment = await successor.persist_indeterminate_candidate(
        RUN_ID,
        owner_id="recoverer-b",
        now=RECOVERY_TIME,
    )

    assert assessment.status is DurableRunStatus.INDETERMINATE_MODEL
    assert len(await store.list_history(RUN_ID, limit=8)) == 2


class _TwoReaderBarrierStore(InMemoryDurableRunStore):
    def __init__(self, *, lease_manager: InMemoryDurableLeaseManager) -> None:
        super().__init__(lease_manager=lease_manager)
        self._nonempty_candidate_reads = 0
        self._both_read = asyncio.Event()
        self._read_lock = asyncio.Lock()

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        candidates = await super().list_recovery_candidates(
            limit=limit,
            after=after,
        )
        if not candidates:
            return candidates

        async with self._read_lock:
            self._nonempty_candidate_reads += 1
            if self._nonempty_candidate_reads == 2:
                self._both_read.set()

        await self._both_read.wait()
        return candidates


class _PersistingRecoveryCoordinator:
    """Test-only worker adapter over the real indeterminate transition path."""

    def __init__(self, delegate: StartupDurableRecoveryCoordinator) -> None:
        self._delegate = delegate

    @property
    def closed(self) -> bool:
        return self._delegate.closed

    async def assess_candidate(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableRecoveryAssessment:
        return await self._delegate.persist_indeterminate_candidate(
            run_id,
            owner_id=owner_id,
            now=now,
        )

    async def assess_page(
        self,
        *,
        owner_id: str,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableRecoveryAssessment, ...]:
        return await self._delegate.assess_page(
            owner_id=owner_id,
            now=now,
            limit=limit,
            after=after,
        )

    async def close(self) -> None:
        await self._delegate.close()


@pytest.mark.asyncio
async def test_two_recoverers_share_advisory_candidate_but_only_one_transition() -> None:
    manager = InMemoryDurableLeaseManager()
    store = _TwoReaderBarrierStore(lease_manager=manager)
    await store.create(_checkpoint(started=True))

    coordinator_injectors = (
        DeterministicReliabilityFaultInjector(max_total_hits=32),
        DeterministicReliabilityFaultInjector(max_total_hits=32),
    )
    worker_injectors = (
        DeterministicReliabilityFaultInjector(max_total_hits=8),
        DeterministicReliabilityFaultInjector(max_total_hits=8),
    )
    coordinators = tuple(
        StartupDurableRecoveryCoordinator(
            store=store,
            lease_manager=manager,
            compatibility_validator=_compatibility_validator(),
            fault_injector=coordinator_injectors[index],
        )
        for index in range(2)
    )
    persisting_coordinators = tuple(
        _PersistingRecoveryCoordinator(coordinator) for coordinator in coordinators
    )
    workers = tuple(
        BoundedDurableRecoveryWorker(
            store=store,
            coordinator=persisting_coordinators[index],
            configuration=DurableRecoveryWorkerConfiguration(
                owner_id=f"recoverer-{index + 1}",
                page_size=1,
                max_candidates=1,
                concurrency=1,
            ),
            clock=lambda: RECOVERY_TIME,
            fault_injector=worker_injectors[index],
        )
        for index in range(2)
    )
    await asyncio.gather(*(worker.start() for worker in workers))

    reports = await asyncio.gather(*(worker.run_once() for worker in workers))

    assert all(report.admitted == 1 for report in reports)
    assert all(
        _points(injector)
        and _points(injector)[0] is ReliabilityFaultPoint.RECOVERY_AFTER_CANDIDATE_READ
        for injector in worker_injectors
    )
    history = await store.list_history(RUN_ID, limit=8)
    assert len(history) == 2
    assert history[-1].status is DurableRunStatus.INDETERMINATE_MODEL

    transition_counts = tuple(
        _points(injector).count(ReliabilityFaultPoint.RECOVERY_AFTER_TRANSITION_COMMIT)
        for injector in coordinator_injectors
    )
    assert sorted(transition_counts) == [0, 1]

    loser_index = transition_counts.index(0)
    loser_points = _points(coordinator_injectors[loser_index])
    assert (
        reports[loser_index].conflicts == 1
        or ReliabilityFaultPoint.RECOVERY_AFTER_REREAD in loser_points
    )

    await asyncio.gather(*(worker.close() for worker in workers))
