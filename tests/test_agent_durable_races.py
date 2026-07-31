import asyncio
from dataclasses import replace
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
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    FencingGeneration,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 7, 31, 20, tzinfo=UTC)
RECOVERY_TIME = NOW + timedelta(minutes=5)
RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
AGENT_ID = AgentId("assistant")
BUDGET_DEADLINE = NOW + timedelta(hours=1)
RETENTION_DEADLINE = NOW + timedelta(days=7)


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


COMPATIBILITY = CompatibilityDigests(
    configuration=_digest("a"),
    tool_registry=_digest("b"),
    model_provider=_digest("c"),
    checkpoint_codec=_digest("d"),
)


def _budget(
    *,
    steps: int = 0,
    model_turns: int = 0,
    tool_calls: int = 0,
    model_output_bytes: int = 0,
    tool_result_bytes: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    started_at: datetime = NOW,
    deadline: datetime = BUDGET_DEADLINE,
) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=steps,
        model_turns=model_turns,
        tool_calls=tool_calls,
        model_output_bytes=model_output_bytes,
        tool_result_bytes=tool_result_bytes,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        started_at=started_at,
        deadline=deadline,
    )


def _metadata(
    *,
    agent_id: AgentId = AGENT_ID,
    actor_id: str = "worker-1",
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    budget: AgentBudgetSnapshot | None = None,
    compatibility: CompatibilityDigests = COMPATIBILITY,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.METADATA_ONLY,
    retention_deadline: datetime = RETENTION_DEADLINE,
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=agent_id,
        actor_id=actor_id,
        next_operation=next_operation,
        budget=budget or _budget(),
        compatibility=compatibility,
        payload_profile=payload_profile,
        retention_deadline=retention_deadline,
        metadata={"tenant": "demo"},
    )


def _checkpoint(
    sequence: int,
    *,
    previous_digest: CheckpointDigest | None = None,
    checkpoint_id: CheckpointId | None = None,
    metadata: CheckpointMetadata | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    created_at: datetime | None = None,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=RUN_ID,
            checkpoint_id=checkpoint_id or CheckpointId(UUID(int=sequence * 100 + 1)),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=metadata or _metadata(),
            created_at=created_at or NOW + timedelta(seconds=sequence * 10),
            digest=_digest("0"),
        )
    )


def _next(
    current: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId | None = None,
    metadata: CheckpointMetadata | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    created_at: datetime | None = None,
) -> CheckpointEnvelope:
    return _checkpoint(
        current.sequence.value + 1,
        previous_digest=current.digest,
        checkpoint_id=checkpoint_id,
        metadata=metadata or current.metadata,
        status=status,
        created_at=created_at,
    )


def _validator() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=AGENT_ID,
                current=COMPATIBILITY,
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )


async def _append_first_and_acquire(
    store: InMemoryDurableRunStore,
    first: CheckpointEnvelope,
) -> DurableLease:
    await store.create(first)
    return await store.lease_manager.acquire(
        RUN_ID,
        owner_id="writer",
        now=RECOVERY_TIME,
    )


class _UntrustedHistoryStore:
    def __init__(
        self,
        *,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None:
        self._current = current
        self._history = history
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def create(self, checkpoint: CheckpointEnvelope) -> None:
        raise AssertionError("untrusted history store is read-only")

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        return self._current if run_id == self._current.durable_run_id else None

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        if run_id != self._current.durable_run_id:
            return ()
        return self._history

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        if limit <= 0:
            return ()
        if after is not None and self._current.durable_run_id <= after:
            return ()
        return (self._current.durable_run_id,)

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        raise AssertionError("untrusted history store is read-only")

    async def close(self) -> None:
        self._closed = True


class _BlockingCurrentStore(InMemoryDurableRunStore):
    def __init__(self) -> None:
        super().__init__()
        self.read_entered = asyncio.Event()
        self.allow_read = asyncio.Event()

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        self.read_entered.set()
        await self.allow_read.wait()
        return await super().get_current(run_id)


class _ReplaceLeaseDuringHistoryStore(InMemoryDurableRunStore):
    def __init__(self) -> None:
        super().__init__()
        self.replacement: DurableLease | None = None

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        history = await super().list_history(run_id, limit=limit)
        current = await self.lease_manager.get_current(run_id, now=RECOVERY_TIME)
        if current is None:
            raise AssertionError("coordinator lease was not active")
        self.replacement = await self.lease_manager.acquire(
            run_id,
            owner_id="replacement-worker",
            now=current.expires_at,
        )
        return history


def _changed_metadata(
    current: CheckpointMetadata,
    change: str,
) -> CheckpointMetadata:
    if change == "agent":
        return replace(current, agent_id=AgentId("other-agent"))
    if change == "actor":
        return replace(current, actor_id="other-worker")
    if change == "payload_profile":
        return replace(
            current,
            compatibility=replace(COMPATIBILITY, payload_codec=_digest("e")),
            payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
        )
    if change == "budget_started_at":
        return replace(
            current,
            budget=replace(current.budget, started_at=NOW + timedelta(seconds=1)),
        )
    if change == "budget_deadline":
        return replace(
            current,
            budget=replace(current.budget, deadline=NOW + timedelta(hours=2)),
        )
    if change == "retention":
        return replace(
            current,
            retention_deadline=NOW + timedelta(days=6),
        )
    raise AssertionError(f"unknown metadata change: {change}")


COUNTER_FIELDS = (
    "steps",
    "model_turns",
    "tool_calls",
    "model_output_bytes",
    "tool_result_bytes",
    "input_tokens",
    "output_tokens",
)


def _counter_budget() -> AgentBudgetSnapshot:
    return _budget(
        steps=4,
        model_turns=3,
        tool_calls=2,
        model_output_bytes=10,
        tool_result_bytes=10,
        input_tokens=10,
        output_tokens=10,
    )


def _decrement_counter(
    budget: AgentBudgetSnapshot,
    counter_field: str,
) -> AgentBudgetSnapshot:
    if counter_field == "steps":
        return replace(budget, steps=budget.steps - 1)
    if counter_field == "model_turns":
        return replace(budget, model_turns=budget.model_turns - 1)
    if counter_field == "tool_calls":
        return replace(budget, tool_calls=budget.tool_calls - 1)
    if counter_field == "model_output_bytes":
        return replace(
            budget,
            model_output_bytes=budget.model_output_bytes - 1,
        )
    if counter_field == "tool_result_bytes":
        return replace(
            budget,
            tool_result_bytes=budget.tool_result_bytes - 1,
        )
    if counter_field == "input_tokens":
        return replace(budget, input_tokens=budget.input_tokens - 1)
    if counter_field == "output_tokens":
        return replace(budget, output_tokens=budget.output_tokens - 1)
    raise AssertionError(f"unknown budget counter: {counter_field}")


@pytest.mark.parametrize(
    "change",
    (
        "agent",
        "actor",
        "payload_profile",
        "budget_started_at",
        "budget_deadline",
        "retention",
    ),
)
async def test_store_rejects_immutable_run_metadata_changes_atomically(change: str) -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    lease = await _append_first_and_acquire(store, first)
    candidate = _next(first, metadata=_changed_metadata(first.metadata, change))

    with pytest.raises(AgentStateConflictError):
        await store.append(
            candidate,
            expected_version=DurableRunVersion(1),
            lease=lease,
            now=RECOVERY_TIME,
        )

    assert await store.get_current(RUN_ID) == first
    assert await store.list_history(RUN_ID, limit=2) == (first,)


@pytest.mark.parametrize("counter_field", COUNTER_FIELDS)
async def test_store_rejects_accumulated_budget_counter_rollback(counter_field: str) -> None:
    store = InMemoryDurableRunStore()
    first_budget = _counter_budget()
    first = _checkpoint(1, metadata=_metadata(budget=first_budget))
    lease = await _append_first_and_acquire(store, first)
    candidate_budget = _decrement_counter(first_budget, counter_field)
    candidate = _next(
        first,
        metadata=replace(first.metadata, budget=candidate_budget),
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(
            candidate,
            expected_version=DurableRunVersion(1),
            lease=lease,
            now=RECOVERY_TIME,
        )

    assert await store.get_current(RUN_ID) == first


@pytest.mark.parametrize(
    "change",
    (
        "agent",
        "actor",
        "payload_profile",
        "budget_started_at",
        "budget_deadline",
        "retention",
    ),
)
async def test_recovery_rejects_history_that_changes_immutable_run_metadata(
    change: str,
) -> None:
    first = _checkpoint(1)
    second = _next(first, metadata=_changed_metadata(first.metadata, change))
    store = _UntrustedHistoryStore(current=second, history=(first, second))
    manager = InMemoryDurableLeaseManager()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentCodecError):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker",
            now=RECOVERY_TIME,
        )

    assert await manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


@pytest.mark.parametrize("counter_field", COUNTER_FIELDS)
async def test_recovery_rejects_history_budget_counter_rollback(counter_field: str) -> None:
    first_budget = _counter_budget()
    first = _checkpoint(1, metadata=_metadata(budget=first_budget))
    second_budget = _decrement_counter(first_budget, counter_field)
    second = _next(
        first,
        metadata=replace(first.metadata, budget=second_budget),
    )
    store = _UntrustedHistoryStore(current=second, history=(first, second))
    manager = InMemoryDurableLeaseManager()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentCodecError, match="budget counters"):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker",
            now=RECOVERY_TIME,
        )

    assert await manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


async def test_recovery_rejects_duplicate_checkpoint_identity() -> None:
    first = _checkpoint(1)
    second = _next(first, checkpoint_id=first.checkpoint_id)
    store = _UntrustedHistoryStore(current=second, history=(first, second))
    manager = InMemoryDurableLeaseManager()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentCodecError, match="checkpoint id"):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker",
            now=RECOVERY_TIME,
        )

    assert await manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


async def test_recovery_rejects_history_after_terminal_checkpoint() -> None:
    terminal_metadata = _metadata(next_operation=CheckpointNextOperation.NONE)
    terminal = _checkpoint(
        1,
        metadata=terminal_metadata,
        status=DurableRunStatus.COMPLETED,
    )
    second = _next(
        terminal,
        metadata=_metadata(),
        status=DurableRunStatus.ACTIVE,
    )
    store = _UntrustedHistoryStore(current=second, history=(terminal, second))
    manager = InMemoryDurableLeaseManager()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentCodecError, match="terminal checkpoint"):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker",
            now=RECOVERY_TIME,
        )

    assert await manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


async def test_recovery_rejects_checkpoint_time_rollback() -> None:
    first = _checkpoint(1, created_at=NOW + timedelta(seconds=20))
    second = _next(first, created_at=NOW + timedelta(seconds=10))
    store = _UntrustedHistoryStore(current=second, history=(first, second))
    manager = InMemoryDurableLeaseManager()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentCodecError, match="time backwards"):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker",
            now=RECOVERY_TIME,
        )

    assert await manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


async def test_recovery_rejects_rolled_back_current_against_newer_history() -> None:
    first = _checkpoint(1)
    second = _next(first)
    store = _UntrustedHistoryStore(current=first, history=(second,))
    manager = InMemoryDurableLeaseManager()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentCodecError, match="changed during validation"):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker",
            now=RECOVERY_TIME,
        )

    assert await manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


async def test_overlapping_recovery_coordinators_have_one_lease_holder() -> None:
    store = _BlockingCurrentStore()
    await store.create(_checkpoint(1))
    first = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )
    second = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )

    first_task = asyncio.create_task(
        first.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker-a",
            now=RECOVERY_TIME,
        )
    )
    await store.read_entered.wait()

    with pytest.raises(AgentStateConflictError):
        await second.assess_candidate(
            RUN_ID,
            owner_id="recovery-worker-b",
            now=RECOVERY_TIME + timedelta(seconds=1),
        )

    store.allow_read.set()
    assessment = await first_task

    assert assessment.generation == FencingGeneration(1)
    assert await store.lease_manager.get_current(RUN_ID, now=RECOVERY_TIME) is None


async def test_replaced_lease_prevents_stale_recovery_assessment() -> None:
    store = _ReplaceLeaseDuringHistoryStore()
    await store.create(_checkpoint(1))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )

    with pytest.raises(AgentStateConflictError):
        await coordinator.assess_candidate(
            RUN_ID,
            owner_id="stale-recovery-worker",
            now=RECOVERY_TIME,
        )

    replacement = store.replacement
    assert replacement is not None
    assert replacement.generation == FencingGeneration(2)
    assert (
        await store.lease_manager.get_current(
            RUN_ID,
            now=replacement.acquired_at,
        )
        == replacement
    )
    await store.lease_manager.release(
        replacement,
        now=replacement.acquired_at,
    )
