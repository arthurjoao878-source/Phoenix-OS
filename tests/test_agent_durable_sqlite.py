import asyncio
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_codec import CanonicalCheckpointCodec, seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    MAX_RECOVERY_CANDIDATE_PAGE,
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
    DurableLeaseId,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    FencingGeneration,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_sqlite import (
    DURABLE_SQLITE_SCHEMA_VERSION,
    SQLiteDurableLeaseManager,
    SQLiteDurableRunStore,
)
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentStateConflictError,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 1, 15, tzinfo=UTC)
WRITE_TIME = NOW + timedelta(seconds=10)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))


def _path(tmp_path: Path, name: str = "durable.sqlite3") -> Path:
    return tmp_path / name


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
    actor_id: str = "worker-1",
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=AgentId("assistant"),
        actor_id=actor_id,
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
    steps: int | None = None,
    actor_id: str = "worker-1",
    created_offset: int | None = None,
) -> CheckpointEnvelope:
    selected_steps = sequence - 1 if steps is None else steps
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
            metadata=_metadata(
                next_operation=next_operation,
                steps=selected_steps,
                actor_id=actor_id,
            ),
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
    steps: int | None = None,
    actor_id: str | None = None,
) -> CheckpointEnvelope:
    sequence = current.sequence.value + 1
    return _checkpoint(
        sequence,
        previous_digest=current.digest,
        checkpoint_id=checkpoint_id,
        durable_run_id=current.durable_run_id,
        agent_run_id=current.agent_run_id,
        status=status,
        next_operation=next_operation,
        steps=current.metadata.budget.steps + 1 if steps is None else steps,
        actor_id=current.metadata.actor_id if actor_id is None else actor_id,
    )


async def _lease(
    store: SQLiteDurableRunStore,
    *,
    run_id: DurableAgentRunId = DURABLE_RUN_ID,
    owner_id: str = "worker-1",
    now: datetime = NOW,
) -> DurableLease:
    return await store.lease_manager.acquire(
        run_id,
        owner_id=owner_id,
        now=now,
    )


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def test_reference_adapter_matches_public_protocols_and_rejects_memory_path(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    assert isinstance(store, DurableRunStore)
    assert isinstance(store.lease_manager, DurableLeaseManager)
    assert store.path == _path(tmp_path).resolve()
    assert store.limits == DurableRunLimits()
    assert not store.closed
    assert not store.lease_manager.closed

    with pytest.raises(ValueError, match="durable file"):
        SQLiteDurableRunStore(":memory:")
    with pytest.raises(ValueError, match="durable file"):
        SQLiteDurableLeaseManager(":memory:")


@pytest.mark.parametrize("busy_timeout_ms", [True, 1.5, "5"])
def test_reference_adapter_rejects_invalid_busy_timeout_type(
    tmp_path: Path,
    busy_timeout_ms: object,
) -> None:
    with pytest.raises(TypeError, match="busy_timeout_ms"):
        SQLiteDurableRunStore(
            _path(tmp_path),
            busy_timeout_ms=cast(int, busy_timeout_ms),
        )


def test_reference_adapter_validates_path_and_parent_policy(tmp_path: Path) -> None:
    directory = tmp_path / "db-dir"
    directory.mkdir()
    with pytest.raises(ValueError, match="directory"):
        SQLiteDurableRunStore(directory)

    missing = tmp_path / "missing" / "durable.sqlite3"
    with pytest.raises(ValueError, match="parent"):
        SQLiteDurableRunStore(missing, create_parent=False)

    created = SQLiteDurableRunStore(missing, create_parent=True)
    assert created.path.parent == missing.parent.resolve()


async def test_create_reopen_and_current_checkpoint_are_durable(tmp_path: Path) -> None:
    path = _path(tmp_path)
    first = _checkpoint(1)
    store = SQLiteDurableRunStore(path)

    await store.create(first)
    assert await store.get_current(DURABLE_RUN_ID) == first
    connection = _connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == DURABLE_SQLITE_SCHEMA_VERSION
    connection.close()
    await store.close()

    reopened = SQLiteDurableRunStore(path)
    assert await reopened.get_current(DURABLE_RUN_ID) == first
    assert await reopened.list_history(DURABLE_RUN_ID, limit=1) == (first,)
    await reopened.close()


async def test_create_is_atomic_and_duplicate_run_fails_closed(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)
    await store.create(first)

    with pytest.raises(AgentStateConflictError):
        await store.create(first)

    assert await store.get_current(DURABLE_RUN_ID) == first
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first,)


async def test_unknown_run_reads_are_empty(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    assert await store.get_current(DURABLE_RUN_ID) is None
    assert await store.list_history(DURABLE_RUN_ID, limit=1) == ()


async def test_append_persists_fenced_checkpoint_and_bounded_history(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)
    second = _next(first)
    third = _next(second)
    await store.create(first)
    lease = await _lease(store)

    assert (
        await store.append(
            second,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        )
        == second
    )
    assert (
        await store.append(
            third,
            expected_version=second.run_version,
            lease=lease,
            now=WRITE_TIME + timedelta(seconds=1),
        )
        == third
    )

    assert await store.get_current(DURABLE_RUN_ID) == third
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (second, third)
    assert await store.list_history(DURABLE_RUN_ID, limit=3) == (first, second, third)


async def test_append_requires_current_persisted_lease(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)
    second = _next(first)
    await store.create(first)

    forged = DurableLease(
        run_id=DURABLE_RUN_ID,
        lease_id=DurableLeaseId(),
        owner_id="worker-1",
        generation=FencingGeneration(1),
        acquired_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    with pytest.raises(AgentStateConflictError):
        await store.append(
            second,
            expected_version=first.run_version,
            lease=forged,
            now=WRITE_TIME,
        )

    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_append_rejects_stale_version_without_mutation(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)
    second = _next(first)
    await store.create(first)
    lease = await _lease(store)

    with pytest.raises(AgentStateConflictError):
        await store.append(
            second,
            expected_version=DurableRunVersion(2),
            lease=lease,
            now=WRITE_TIME,
        )

    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_append_rejects_lease_for_different_run(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)
    second = _next(first)
    await store.create(first)
    other_run = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000099"))
    wrong = await _lease(store, run_id=other_run, owner_id="worker-other")

    with pytest.raises(AgentStateConflictError):
        await store.append(
            second,
            expected_version=first.run_version,
            lease=wrong,
            now=WRITE_TIME,
        )

    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_expired_replaced_lease_fences_stale_writer(tmp_path: Path) -> None:
    limits = replace(
        DurableRunLimits(),
        lease_duration=timedelta(seconds=2),
        lease_renewal_interval=timedelta(seconds=1),
    )
    store = SQLiteDurableRunStore(_path(tmp_path), limits=limits)
    first = _checkpoint(1)
    second = _next(first)
    await store.create(first)
    stale = await _lease(store)
    current = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="worker-2",
        now=stale.expires_at,
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(
            second,
            expected_version=first.run_version,
            lease=stale,
            now=current.acquired_at,
        )

    assert (
        await store.append(
            second,
            expected_version=first.run_version,
            lease=current,
            now=current.acquired_at,
        )
        == second
    )


async def test_duplicate_checkpoint_identity_rolls_back_entire_append(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)
    duplicate = _next(first, checkpoint_id=first.checkpoint_id)
    await store.create(first)
    lease = await _lease(store)

    with pytest.raises(AgentStateConflictError):
        await store.append(
            duplicate,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        )

    assert await store.get_current(DURABLE_RUN_ID) == first
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first,)


@pytest.mark.parametrize("mutation", ["actor", "budget"])
async def test_append_rejects_immutable_or_regressed_state(
    tmp_path: Path,
    mutation: str,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1, steps=1)
    await store.create(first)
    lease = await _lease(store)
    if mutation == "actor":
        candidate = _next(first, actor_id="worker-2")
    else:
        candidate = _next(first, steps=0)

    with pytest.raises(AgentStateConflictError):
        await store.append(
            candidate,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        )

    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_terminal_checkpoint_is_not_recoverable_or_appendable(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    terminal = _checkpoint(
        1,
        status=DurableRunStatus.CANCELLED,
        next_operation=CheckpointNextOperation.NONE,
    )
    await store.create(terminal)
    lease = await _lease(store)
    later = _next(terminal)

    assert await store.list_recovery_candidates(limit=10) == ()
    with pytest.raises(AgentStateConflictError):
        await store.append(
            later,
            expected_version=terminal.run_version,
            lease=lease,
            now=WRITE_TIME,
        )


async def test_recovery_candidates_are_bounded_sorted_and_persisted(tmp_path: Path) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first_run = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
    terminal_run = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
    last_run = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000003"))
    await store.create(_checkpoint(1, durable_run_id=last_run))
    await store.create(
        _checkpoint(
            1,
            durable_run_id=terminal_run,
            status=DurableRunStatus.COMPLETED,
            next_operation=CheckpointNextOperation.NONE,
        )
    )
    await store.create(_checkpoint(1, durable_run_id=first_run))

    assert await store.list_recovery_candidates(limit=1) == (first_run,)
    assert await store.list_recovery_candidates(limit=3, after=first_run) == (last_run,)
    await store.close()

    reopened = SQLiteDurableRunStore(path)
    assert await reopened.list_recovery_candidates(limit=3) == (first_run, last_run)


@pytest.mark.parametrize("limit", [True, 0, -1])
async def test_recovery_candidate_limit_validation(tmp_path: Path, limit: int) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    if isinstance(limit, bool):
        with pytest.raises(TypeError, match="integer"):
            await store.list_recovery_candidates(limit=limit)
    else:
        with pytest.raises(ValueError, match="greater than zero"):
            await store.list_recovery_candidates(limit=limit)

    with pytest.raises(AgentLimitExceededError):
        await store.list_recovery_candidates(limit=MAX_RECOVERY_CANDIDATE_PAGE + 1)


async def test_checkpoint_count_limit_fails_without_partial_write(tmp_path: Path) -> None:
    limits = replace(DurableRunLimits(), max_checkpoints=2)
    store = SQLiteDurableRunStore(_path(tmp_path), limits=limits)
    first = _checkpoint(1)
    second = _next(first)
    third = _next(second)
    await store.create(first)
    lease = await _lease(store)
    await store.append(
        second,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
    )

    with pytest.raises(AgentLimitExceededError):
        await store.append(
            third,
            expected_version=second.run_version,
            lease=lease,
            now=WRITE_TIME + timedelta(seconds=1),
        )

    assert await store.get_current(DURABLE_RUN_ID) == second
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first, second)


async def test_history_byte_limit_fails_without_partial_write(tmp_path: Path) -> None:
    codec = CanonicalCheckpointCodec()
    first = _checkpoint(1)
    second = _next(first)
    first_size = len(codec.encode(first))
    second_size = len(codec.encode(second))
    limits = replace(
        DurableRunLimits(),
        max_checkpoint_history_bytes=first_size + second_size - 1,
    )
    store = SQLiteDurableRunStore(_path(tmp_path), codec=codec, limits=limits)
    await store.create(first)
    lease = await _lease(store)

    with pytest.raises(AgentLimitExceededError):
        await store.append(
            second,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        )

    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_concurrent_store_instances_allow_one_append_for_same_version(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    left_store = SQLiteDurableRunStore(path)
    right_store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    await left_store.create(first)
    lease = await _lease(left_store)
    left = _next(first, checkpoint_id=_checkpoint_id(2, variant=1))
    right = _next(first, checkpoint_id=_checkpoint_id(2, variant=2))

    results = await asyncio.gather(
        left_store.append(
            left,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        ),
        right_store.append(
            right,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        ),
        return_exceptions=True,
    )

    successes = [item for item in results if isinstance(item, CheckpointEnvelope)]
    conflicts = [item for item in results if isinstance(item, AgentStateConflictError)]
    assert len(successes) == 1
    assert len(conflicts) == 1
    assert await left_store.get_current(DURABLE_RUN_ID) == successes[0]


async def test_corrupted_checkpoint_payload_fails_closed_after_reopen(tmp_path: Path) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    await store.create(first)
    await store.close()

    connection = _connect(path)
    connection.execute(
        "UPDATE durable_checkpoints SET payload = ? WHERE run_id = ? AND sequence = 1",
        (sqlite3.Binary(b"not-json"), str(DURABLE_RUN_ID)),
    )
    connection.close()

    reopened = SQLiteDurableRunStore(path)
    with pytest.raises(AgentCodecError):
        await reopened.get_current(DURABLE_RUN_ID)


async def test_corrupted_run_head_metadata_fails_closed_after_reopen(tmp_path: Path) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    await store.create(first)
    await store.close()

    connection = _connect(path)
    connection.execute(
        "UPDATE durable_runs SET current_digest = ? WHERE run_id = ?",
        ("f" * 64, str(DURABLE_RUN_ID)),
    )
    connection.close()

    reopened = SQLiteDurableRunStore(path)
    with pytest.raises(AgentCodecError, match="head metadata"):
        await reopened.get_current(DURABLE_RUN_ID)


async def test_missing_history_sequence_fails_closed_after_reopen(tmp_path: Path) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    second = _next(first)
    third = _next(second)
    await store.create(first)
    lease = await _lease(store)
    await store.append(
        second,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
    )
    await store.append(
        third,
        expected_version=second.run_version,
        lease=lease,
        now=WRITE_TIME + timedelta(seconds=1),
    )
    await store.close()

    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(
        "DELETE FROM durable_checkpoints WHERE run_id = ? AND sequence = 2",
        (str(DURABLE_RUN_ID),),
    )
    connection.close()

    reopened = SQLiteDurableRunStore(path)
    with pytest.raises(AgentCodecError, match="incomplete"):
        await reopened.list_history(DURABLE_RUN_ID, limit=3)


async def test_schema_version_mismatch_fails_closed(tmp_path: Path) -> None:
    path = _path(tmp_path)
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA user_version = 99")
    connection.close()

    store = SQLiteDurableRunStore(path)
    with pytest.raises(AgentCodecError, match="schema version"):
        await store.get_current(DURABLE_RUN_ID)


async def test_lease_generation_survives_manager_restart(tmp_path: Path) -> None:
    path = _path(tmp_path)
    first_manager = SQLiteDurableLeaseManager(path)
    first = await first_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="worker-1",
        now=NOW,
    )
    await first_manager.close()

    second_manager = SQLiteDurableLeaseManager(path)
    with pytest.raises(AgentStateConflictError):
        await second_manager.acquire(
            DURABLE_RUN_ID,
            owner_id="worker-2",
            now=NOW + timedelta(seconds=1),
        )
    second = await second_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="worker-2",
        now=first.expires_at,
    )

    assert first.generation == FencingGeneration(1)
    assert second.generation == FencingGeneration(2)
    assert second.lease_id != first.lease_id


async def test_release_and_reacquire_preserve_monotonic_generation(tmp_path: Path) -> None:
    manager = SQLiteDurableLeaseManager(_path(tmp_path))
    first = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)

    await manager.release(first, now=NOW + timedelta(seconds=1))
    assert await manager.get_current(DURABLE_RUN_ID, now=NOW + timedelta(seconds=1)) is None
    second = await manager.acquire(
        DURABLE_RUN_ID,
        owner_id="worker-2",
        now=NOW + timedelta(seconds=2),
    )

    assert second.generation == FencingGeneration(2)
    with pytest.raises(AgentStateConflictError):
        await manager.require_current(first, now=NOW + timedelta(seconds=2))


async def test_renew_preserves_stable_lease_identity_and_generation(tmp_path: Path) -> None:
    manager = SQLiteDurableLeaseManager(_path(tmp_path))
    original = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)

    renewed = await manager.renew(original, now=NOW + timedelta(seconds=5))

    assert renewed.run_id == original.run_id
    assert renewed.lease_id == original.lease_id
    assert renewed.owner_id == original.owner_id
    assert renewed.generation == original.generation
    assert renewed.acquired_at == NOW + timedelta(seconds=5)
    assert (
        await manager.require_current(
            original,
            now=NOW + timedelta(seconds=6),
        )
        == renewed
    )


async def test_active_lease_blocks_second_manager_for_same_run(tmp_path: Path) -> None:
    path = _path(tmp_path)
    first_manager = SQLiteDurableLeaseManager(path)
    second_manager = SQLiteDurableLeaseManager(path)
    current = await first_manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)

    with pytest.raises(AgentStateConflictError):
        await second_manager.acquire(
            DURABLE_RUN_ID,
            owner_id="worker-2",
            now=NOW + timedelta(seconds=1),
        )

    assert (
        await second_manager.get_current(
            DURABLE_RUN_ID,
            now=NOW + timedelta(seconds=1),
        )
        == current
    )


async def test_concurrent_lease_acquisition_has_exactly_one_winner(tmp_path: Path) -> None:
    path = _path(tmp_path)
    first_manager = SQLiteDurableLeaseManager(path)
    second_manager = SQLiteDurableLeaseManager(path)

    async def acquire(manager: SQLiteDurableLeaseManager, owner: str) -> DurableLease | None:
        try:
            return await manager.acquire(DURABLE_RUN_ID, owner_id=owner, now=NOW)
        except AgentStateConflictError:
            return None

    results = await asyncio.gather(
        acquire(first_manager, "worker-1"),
        acquire(second_manager, "worker-2"),
    )
    winners = [item for item in results if item is not None]

    assert len(winners) == 1
    assert winners[0].generation == FencingGeneration(1)


async def test_invalid_owner_does_not_consume_persisted_generation(tmp_path: Path) -> None:
    manager = SQLiteDurableLeaseManager(_path(tmp_path))

    with pytest.raises(ValueError):
        await manager.acquire(DURABLE_RUN_ID, owner_id="Worker Invalid", now=NOW)

    lease = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)
    assert lease.generation == FencingGeneration(1)


async def test_clock_rollback_fails_closed_without_replacing_lease(tmp_path: Path) -> None:
    manager = SQLiteDurableLeaseManager(_path(tmp_path))
    current = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)

    with pytest.raises(AgentStateConflictError):
        await manager.acquire(
            DURABLE_RUN_ID,
            owner_id="worker-2",
            now=NOW - timedelta(seconds=1),
        )

    assert await manager.get_current(DURABLE_RUN_ID, now=NOW) == current


async def test_guard_current_serializes_same_manager_lease_mutations(tmp_path: Path) -> None:
    manager = SQLiteDurableLeaseManager(_path(tmp_path))
    lease = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)
    entered = asyncio.Event()
    release_guard = asyncio.Event()

    async def hold_guard() -> None:
        async with manager.guard_current(lease, now=NOW + timedelta(seconds=1)):
            entered.set()
            await release_guard.wait()

    guard_task = asyncio.create_task(hold_guard())
    await entered.wait()
    renewal = asyncio.create_task(manager.renew(lease, now=NOW + timedelta(seconds=2)))
    await asyncio.sleep(0)
    assert not renewal.done()

    release_guard.set()
    await guard_task
    renewed = await renewal
    assert renewed.generation == lease.generation


async def test_generation_overflow_fails_closed(tmp_path: Path) -> None:
    path = _path(tmp_path)
    manager = SQLiteDurableLeaseManager(path)
    lease = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)
    await manager.release(lease, now=NOW + timedelta(seconds=1))
    await manager.close()

    connection = _connect(path)
    connection.execute(
        "UPDATE durable_leases SET generation = ? WHERE run_id = ?",
        (2_147_483_647, str(DURABLE_RUN_ID)),
    )
    connection.close()

    reopened = SQLiteDurableLeaseManager(path)
    with pytest.raises(AgentLimitExceededError):
        await reopened.acquire(
            DURABLE_RUN_ID,
            owner_id="worker-2",
            now=NOW + timedelta(seconds=2),
        )


async def test_store_closes_owned_manager_but_not_injected_manager(tmp_path: Path) -> None:
    owned_store = SQLiteDurableRunStore(_path(tmp_path, "owned.sqlite3"))
    owned_manager = owned_store.lease_manager
    await owned_store.close()
    await owned_store.close()
    assert owned_store.closed
    assert owned_manager.closed

    path = _path(tmp_path, "injected.sqlite3")
    manager = SQLiteDurableLeaseManager(path)
    injected_store = SQLiteDurableRunStore(path, lease_manager=manager)
    await injected_store.close()
    assert injected_store.closed
    assert not manager.closed
    lease = await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)
    assert lease.run_id == DURABLE_RUN_ID
    await manager.close()


async def test_injected_manager_must_share_path_and_limits(tmp_path: Path) -> None:
    manager = SQLiteDurableLeaseManager(_path(tmp_path, "one.sqlite3"))

    with pytest.raises(ValueError, match="same SQLite"):
        SQLiteDurableRunStore(
            _path(tmp_path, "two.sqlite3"),
            lease_manager=manager,
        )

    custom = replace(DurableRunLimits(), max_checkpoints=32)
    with pytest.raises(ValueError, match="limits"):
        SQLiteDurableRunStore(
            _path(tmp_path, "one.sqlite3"),
            limits=custom,
            lease_manager=manager,
        )


async def test_closed_store_and_manager_fail_closed(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    manager = store.lease_manager
    await store.close()

    with pytest.raises(RuntimeError, match="closed"):
        await store.get_current(DURABLE_RUN_ID)
    with pytest.raises(RuntimeError, match="closed"):
        await store.list_recovery_candidates(limit=1)
    with pytest.raises(RuntimeError, match="closed"):
        await manager.acquire(DURABLE_RUN_ID, owner_id="worker-1", now=NOW)
