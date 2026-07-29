import asyncio
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_codec import (
    CanonicalCheckpointCodec,
    seal_checkpoint_envelope,
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
    DurableRunLimits,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentStateConflictError,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 7, 29, 16, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _checkpoint_id(sequence: int, *, variant: int = 0) -> CheckpointId:
    return CheckpointId(UUID(int=sequence * 100 + variant + 1))


def _budget(*, steps: int = 0) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=steps,
        model_turns=steps,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _metadata(
    *,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    steps: int = 0,
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=AgentId("assistant"),
        actor_id="worker-1",
        next_operation=next_operation,
        budget=_budget(steps=steps),
        compatibility=CompatibilityDigests(
            configuration=_digest("a"),
            tool_registry=_digest("b"),
            model_provider=_digest("c"),
            checkpoint_codec=_digest("d"),
        ),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
        retention_deadline=NOW + timedelta(days=7),
        metadata={"tenant": "demo"},
    )


def _checkpoint(
    sequence: int,
    *,
    previous_digest: CheckpointDigest | None = None,
    checkpoint_id: CheckpointId | None = None,
    durable_run_id: DurableAgentRunId = DURABLE_RUN_ID,
    agent_run_id: AgentRunId = AGENT_RUN_ID,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    created_offset: int | None = None,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=durable_run_id,
            checkpoint_id=checkpoint_id or _checkpoint_id(sequence),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=agent_run_id,
            step_id=STEP_ID,
            metadata=_metadata(next_operation=next_operation, steps=sequence - 1),
            created_at=NOW + timedelta(seconds=created_offset or sequence),
            digest=_digest("0"),
        )
    )


def _next(
    current: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
) -> CheckpointEnvelope:
    return _checkpoint(
        current.sequence.value + 1,
        previous_digest=current.digest,
        checkpoint_id=checkpoint_id,
        status=status,
        next_operation=next_operation,
    )


async def test_store_implements_protocol_and_round_trips_canonical_history() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    second = _next(first)
    third = _next(second)

    assert isinstance(store, DurableRunStore)
    assert store.closed is False
    assert store.run_count == 0
    assert await store.get_current(DURABLE_RUN_ID) is None

    await store.create(first)
    assert await store.append(second, expected_version=DurableRunVersion(1)) == second
    assert await store.append(third, expected_version=DurableRunVersion(2)) == third

    assert store.run_count == 1
    assert await store.get_current(DURABLE_RUN_ID) == third
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (second, third)
    assert await store.list_history(DURABLE_RUN_ID, limit=3) == (first, second, third)


async def test_create_rejects_duplicate_or_noninitial_checkpoint_without_mutation() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)

    with pytest.raises(AgentStateConflictError):
        await store.create(first)

    second = _next(first)
    other_store = InMemoryDurableRunStore()
    with pytest.raises(AgentStateConflictError):
        await other_store.create(second)

    assert await store.get_current(DURABLE_RUN_ID) == first
    assert await other_store.get_current(DURABLE_RUN_ID) is None


async def test_create_rejects_unsealed_checkpoint_without_mutation() -> None:
    store = InMemoryDurableRunStore()
    sealed = _checkpoint(1)
    unsealed = replace(sealed, digest=_digest("9"))

    with pytest.raises(AgentCodecError, match="digest"):
        await store.create(unsealed)

    assert store.run_count == 0


@pytest.mark.parametrize(
    "candidate_factory",
    [
        lambda current: replace(_next(current), sequence=CheckpointSequence(3)),
        lambda current: replace(_next(current), run_version=DurableRunVersion(3)),
        lambda current: replace(_next(current), previous_digest=_digest("8")),
        lambda current: _next(current, checkpoint_id=current.checkpoint_id),
    ],
)
async def test_append_rejects_sequence_version_chain_and_id_conflicts_atomically(
    candidate_factory: Callable[[CheckpointEnvelope], CheckpointEnvelope],
) -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)
    candidate = candidate_factory(first)
    candidate = seal_checkpoint_envelope(candidate)

    with pytest.raises(AgentStateConflictError):
        await store.append(candidate, expected_version=DurableRunVersion(1))

    assert await store.get_current(DURABLE_RUN_ID) == first
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first,)


async def test_append_rejects_stale_expected_version_and_terminal_history() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)

    second = _next(first)
    with pytest.raises(AgentStateConflictError):
        await store.append(second, expected_version=DurableRunVersion(2))
    assert await store.get_current(DURABLE_RUN_ID) == first

    terminal = _next(
        first,
        status=DurableRunStatus.COMPLETED,
        next_operation=CheckpointNextOperation.NONE,
    )
    await store.append(terminal, expected_version=DurableRunVersion(1))

    with pytest.raises(AgentStateConflictError):
        await store.append(_next(terminal), expected_version=DurableRunVersion(2))
    assert await store.get_current(DURABLE_RUN_ID) == terminal


async def test_append_rejects_run_identity_changes() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)
    different_agent_run = AgentRunId(UUID("20000000-0000-0000-0000-000000000099"))
    candidate = _checkpoint(
        2,
        previous_digest=first.digest,
        agent_run_id=different_agent_run,
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(candidate, expected_version=DurableRunVersion(1))

    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_max_checkpoint_limit_fails_before_mutating_history() -> None:
    limits = replace(DurableRunLimits(), max_checkpoints=2)
    store = InMemoryDurableRunStore(limits=limits)
    first = _checkpoint(1)
    second = _next(first)
    third = _next(second)

    await store.create(first)
    await store.append(second, expected_version=DurableRunVersion(1))

    with pytest.raises(AgentLimitExceededError):
        await store.append(third, expected_version=DurableRunVersion(2))

    assert await store.get_current(DURABLE_RUN_ID) == second
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first, second)


async def test_history_byte_limit_rolls_back_failed_append() -> None:
    codec = CanonicalCheckpointCodec()
    first = _checkpoint(1)
    second = _next(first)
    first_size = len(codec.encode(first))
    second_size = len(codec.encode(second))
    limits = replace(
        DurableRunLimits(),
        max_checkpoint_history_bytes=first_size + second_size - 1,
    )
    store = InMemoryDurableRunStore(codec=codec, limits=limits)

    await store.create(first)
    with pytest.raises(AgentLimitExceededError):
        await store.append(second, expected_version=DurableRunVersion(1))

    assert await store.get_current(DURABLE_RUN_ID) == first
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first,)


async def test_concurrent_appends_allow_only_one_writer_for_the_same_version() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)
    left = _next(first, checkpoint_id=_checkpoint_id(2, variant=1))
    right = _next(first, checkpoint_id=_checkpoint_id(2, variant=2))

    results = await asyncio.gather(
        store.append(left, expected_version=DurableRunVersion(1)),
        store.append(right, expected_version=DurableRunVersion(1)),
        return_exceptions=True,
    )

    successes = [result for result in results if isinstance(result, CheckpointEnvelope)]
    conflicts = [result for result in results if isinstance(result, AgentStateConflictError)]
    assert len(successes) == 1
    assert len(conflicts) == 1
    assert await store.get_current(DURABLE_RUN_ID) == successes[0]
    assert len(await store.list_history(DURABLE_RUN_ID, limit=2)) == 2


async def test_corrupted_stored_bytes_fail_closed() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)
    stored = store._runs[DURABLE_RUN_ID]
    store._runs[DURABLE_RUN_ID] = replace(stored, payloads=(b"not-json",))

    with pytest.raises(AgentCodecError):
        await store.get_current(DURABLE_RUN_ID)


@pytest.mark.parametrize("limit", [0, -1])
async def test_history_limit_must_be_positive(limit: int) -> None:
    store = InMemoryDurableRunStore()

    with pytest.raises(ValueError, match="greater than zero"):
        await store.list_history(DURABLE_RUN_ID, limit=limit)


async def test_close_is_idempotent_and_all_operations_fail_closed() -> None:
    store = InMemoryDurableRunStore()
    first = _checkpoint(1)
    await store.create(first)
    await store.close()
    await store.close()

    assert store.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        await store.get_current(DURABLE_RUN_ID)
    with pytest.raises(RuntimeError, match="closed"):
        await store.list_history(DURABLE_RUN_ID, limit=1)
    with pytest.raises(RuntimeError, match="closed"):
        await store.create(
            _checkpoint(
                1,
                durable_run_id=DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000099")),
            )
        )
    with pytest.raises(RuntimeError, match="closed"):
        await store.append(_next(first), expected_version=DurableRunVersion(1))
