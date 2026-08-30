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
    RetentionPolicy,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_reliability import (
    DurableRecoveryAttemptStore,
    DurableStoreFreshnessCategory,
)
from phoenix_os.agent.durable_retention import DurableRetentionStore
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
RETENTION_POLICY = RetentionPolicy(
    payload_retention=timedelta(seconds=10),
    metadata_retention=timedelta(seconds=20),
    tombstone_retention=timedelta(seconds=30),
)


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
    assert isinstance(store, DurableRecoveryAttemptStore)
    assert isinstance(store, DurableRetentionStore)
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
    lease = await _lease(store)

    with pytest.raises(AgentStateConflictError):
        await store.create(first)

    assert await store.lease_manager.require_current(lease, now=NOW) == lease
    assert await store.get_current(DURABLE_RUN_ID) == first
    assert await store.list_history(DURABLE_RUN_ID, limit=2) == (first,)


async def test_sqlite_successful_create_fences_preexisting_lease_authority(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    prebirth = await _lease(
        store,
        owner_id="prebirth-worker",
        now=NOW,
    )
    first = _checkpoint(1)

    await store.create(first)

    with pytest.raises(AgentStateConflictError):
        await store.lease_manager.require_current(prebirth, now=NOW)

    fresh = await _lease(
        store,
        owner_id="newborn-worker",
        now=NOW,
    )
    assert fresh.generation.value == prebirth.generation.value + 1
    assert await store.get_current(DURABLE_RUN_ID) == first


async def test_sqlite_failed_birth_fence_rolls_back_run_and_preserves_lease(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    prebirth = await _lease(
        store,
        owner_id="prebirth-worker",
        now=NOW,
    )
    first = _checkpoint(1)

    connection = _connect(path)
    connection.execute(
        "CREATE TRIGGER fail_birth_fence "
        "BEFORE UPDATE OF active ON durable_leases "
        f"WHEN NEW.run_id = '{DURABLE_RUN_ID}' AND NEW.active = 0 "
        "BEGIN SELECT RAISE(ABORT, 'injected birth fence failure'); END"
    )
    connection.close()

    with pytest.raises(AgentStateConflictError):
        await store.create(first)

    assert await store.get_current(DURABLE_RUN_ID) is None
    assert await store.lease_manager.require_current(prebirth, now=NOW) == prebirth


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


async def _sqlite_terminal_retention_run(
    store: SQLiteDurableRunStore,
) -> tuple[CheckpointEnvelope, CheckpointEnvelope, DurableLease]:
    first = _checkpoint(1)
    await store.create(first)
    lease = await _lease(store)
    terminal = _next(
        first,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
    )
    await store.append(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
    )
    return first, terminal, lease


async def test_sqlite_terminal_tombstone_persists_across_reopen(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    _, terminal, lease = await _sqlite_terminal_retention_run(store)
    due = terminal.created_at + RETENTION_POLICY.metadata_retention

    tombstone = await store.tombstone_terminal_run(
        DURABLE_RUN_ID,
        policy=RETENTION_POLICY,
        lease=lease,
        now=due,
    )

    assert tombstone.run_id == DURABLE_RUN_ID
    assert tombstone.terminal_status == terminal.status
    assert tombstone.terminal_version == terminal.run_version
    assert tombstone.final_checkpoint_digest == terminal.digest
    assert tombstone.deletion_generation == lease.generation
    assert tombstone.terminal_at == terminal.created_at
    assert tombstone.retain_until == terminal.created_at + RETENTION_POLICY.tombstone_retention

    assert await store.get_current(DURABLE_RUN_ID) is None
    assert await store.list_history(DURABLE_RUN_ID, limit=10) == ()
    await store.close()

    reopened = SQLiteDurableRunStore(path)
    assert await reopened.get_tombstone(DURABLE_RUN_ID) == tombstone
    assert await reopened.get_current(DURABLE_RUN_ID) is None
    assert await reopened.list_history(DURABLE_RUN_ID, limit=10) == ()
    await reopened.close()


async def test_sqlite_retained_tombstone_blocks_run_recreation_after_reopen(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first, terminal, lease = await _sqlite_terminal_retention_run(store)

    await store.tombstone_terminal_run(
        DURABLE_RUN_ID,
        policy=RETENTION_POLICY,
        lease=lease,
        now=terminal.created_at + RETENTION_POLICY.metadata_retention,
    )
    await store.close()

    reopened = SQLiteDurableRunStore(path)

    with pytest.raises(AgentStateConflictError):
        await reopened.create(first)

    assert await reopened.get_current(DURABLE_RUN_ID) is None
    assert await reopened.get_tombstone(DURABLE_RUN_ID) is not None
    await reopened.close()


async def test_sqlite_cleanup_candidates_require_terminal_due_and_unleased(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))
    first = _checkpoint(1)

    await store.create(first)

    assert (
        await store.list_cleanup_candidates(
            policy=RETENTION_POLICY,
            now=NOW + timedelta(minutes=1),
            limit=10,
        )
        == ()
    )

    lease = await _lease(store)

    terminal = _next(
        first,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
    )

    await store.append(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
    )

    payload_due = terminal.created_at + RETENTION_POLICY.payload_retention

    assert (
        await store.list_cleanup_candidates(
            policy=RETENTION_POLICY,
            now=payload_due,
            limit=10,
        )
        == ()
    )

    await store.lease_manager.release(
        lease,
        now=WRITE_TIME,
    )

    assert await store.list_cleanup_candidates(
        policy=RETENTION_POLICY,
        now=payload_due,
        limit=10,
    ) == (DURABLE_RUN_ID,)


async def test_sqlite_metadata_only_payload_cleanup_is_idempotent_noop(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    _, terminal, lease = await _sqlite_terminal_retention_run(store)

    payload_due = terminal.created_at + RETENTION_POLICY.payload_retention

    assert (
        await store.delete_expired_protected_payloads(
            DURABLE_RUN_ID,
            policy=RETENTION_POLICY,
            lease=lease,
            now=payload_due,
        )
        is False
    )

    assert (
        await store.delete_expired_protected_payloads(
            DURABLE_RUN_ID,
            policy=RETENTION_POLICY,
            lease=lease,
            now=payload_due,
        )
        is False
    )

    assert await store.get_current(DURABLE_RUN_ID) == terminal


async def test_sqlite_tombstone_purge_boundary_is_idempotent_and_releases_id(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    first, terminal, lease = await _sqlite_terminal_retention_run(store)

    tombstone = await store.tombstone_terminal_run(
        DURABLE_RUN_ID,
        policy=RETENTION_POLICY,
        lease=lease,
        now=(terminal.created_at + RETENTION_POLICY.metadata_retention),
    )

    await store.lease_manager.release(
        lease,
        now=(terminal.created_at + RETENTION_POLICY.metadata_retention),
    )

    purge_lease = await _lease(
        store,
        now=(tombstone.retain_until - timedelta(seconds=1)),
    )

    with pytest.raises(AgentStateConflictError):
        await store.create(first)
    assert (
        await store.lease_manager.require_current(
            purge_lease,
            now=(tombstone.retain_until - timedelta(seconds=1)),
        )
        == purge_lease
    )

    with pytest.raises(AgentStateConflictError):
        await store.purge_expired_tombstone(
            DURABLE_RUN_ID,
            lease=purge_lease,
            now=(tombstone.retain_until - timedelta(microseconds=1)),
        )

    assert (
        await store.purge_expired_tombstone(
            DURABLE_RUN_ID,
            lease=purge_lease,
            now=tombstone.retain_until,
        )
        is True
    )

    assert (
        await store.purge_expired_tombstone(
            DURABLE_RUN_ID,
            lease=purge_lease,
            now=tombstone.retain_until,
        )
        is False
    )

    assert await store.get_tombstone(DURABLE_RUN_ID) is None

    await store.create(first)

    assert await store.get_current(DURABLE_RUN_ID) == first
    with pytest.raises(AgentStateConflictError):
        await store.lease_manager.require_current(
            purge_lease,
            now=tombstone.retain_until,
        )

    second = _next(first)
    with pytest.raises(AgentStateConflictError):
        await store.append(
            second,
            expected_version=first.run_version,
            lease=purge_lease,
            now=tombstone.retain_until,
        )

    reborn_lease = await _lease(
        store,
        owner_id="reborn-worker",
        now=tombstone.retain_until,
    )
    assert reborn_lease.generation.value == purge_lease.generation.value + 1
    assert (
        await store.append(
            second,
            expected_version=first.run_version,
            lease=reborn_lease,
            now=tombstone.retain_until,
        )
        == second
    )


async def test_sqlite_stale_cleanup_lease_cannot_tombstone_terminal_run(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    _, terminal, stale_lease = await _sqlite_terminal_retention_run(store)

    await store.lease_manager.release(
        stale_lease,
        now=WRITE_TIME + timedelta(seconds=1),
    )

    current_lease = await _lease(
        store,
        now=WRITE_TIME + timedelta(seconds=2),
    )

    due = terminal.created_at + RETENTION_POLICY.metadata_retention

    with pytest.raises(AgentStateConflictError):
        await store.tombstone_terminal_run(
            DURABLE_RUN_ID,
            policy=RETENTION_POLICY,
            lease=stale_lease,
            now=due,
        )

    assert await store.get_current(DURABLE_RUN_ID) == terminal
    assert await store.get_tombstone(DURABLE_RUN_ID) is None

    tombstone = await store.tombstone_terminal_run(
        DURABLE_RUN_ID,
        policy=RETENTION_POLICY,
        lease=current_lease,
        now=due,
    )

    assert tombstone.deletion_generation == current_lease.generation
    assert await store.get_current(DURABLE_RUN_ID) is None
    assert await store.get_tombstone(DURABLE_RUN_ID) == tombstone


async def test_sqlite_cleanup_candidate_pagination_is_deterministic_and_bounded(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(_path(tmp_path))

    run_ids = (
        DurableAgentRunId(UUID(int=3)),
        DurableAgentRunId(UUID(int=1)),
        DurableAgentRunId(UUID(int=2)),
    )

    for index, run_id in enumerate(run_ids, start=1):
        first = _checkpoint(
            1,
            durable_run_id=run_id,
            agent_run_id=AgentRunId(UUID(int=1_000 + index)),
        )

        await store.create(first)

        lease = await _lease(
            store,
            run_id=run_id,
            now=NOW,
        )

        terminal = _next(
            first,
            status=DurableRunStatus.FAILED,
            next_operation=CheckpointNextOperation.NONE,
        )

        await store.append(
            terminal,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
        )

        await store.lease_manager.release(
            lease,
            now=WRITE_TIME + timedelta(seconds=1),
        )

    expected = tuple(sorted(run_ids, key=str))
    cleanup_time = NOW + timedelta(minutes=1)

    first_page = await store.list_cleanup_candidates(
        policy=RETENTION_POLICY,
        now=cleanup_time,
        limit=2,
    )

    second_page = await store.list_cleanup_candidates(
        policy=RETENTION_POLICY,
        now=cleanup_time,
        limit=2,
        after=first_page[-1],
    )

    assert first_page == expected[:2]
    assert second_page == expected[2:]
    assert first_page + second_page == expected


async def test_sqlite_recovery_attempts_persist_and_exhaust_candidates(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    limits = replace(DurableRunLimits(), max_recovery_attempts=2)
    store = SQLiteDurableRunStore(path, limits=limits)
    first = _checkpoint(1)
    await store.create(first)

    first_lease = await _lease(store, now=NOW)
    assert (
        await store.claim_recovery_attempt(
            DURABLE_RUN_ID,
            lease=first_lease,
            now=NOW,
        )
        == 1
    )
    await store.lease_manager.release(first_lease, now=NOW + timedelta(seconds=1))
    await store.close()

    reopened = SQLiteDurableRunStore(path, limits=limits)
    assert await reopened.get_recovery_attempt_count(DURABLE_RUN_ID) == 1
    assert await reopened.list_recovery_candidates(limit=1) == (DURABLE_RUN_ID,)

    second_lease = await _lease(
        reopened,
        owner_id="recovery-worker",
        now=NOW + timedelta(seconds=2),
    )
    assert (
        await reopened.claim_recovery_attempt(
            DURABLE_RUN_ID,
            lease=second_lease,
            now=NOW + timedelta(seconds=2),
        )
        == 2
    )
    await reopened.lease_manager.release(
        second_lease,
        now=NOW + timedelta(seconds=3),
    )

    assert await reopened.get_recovery_attempt_count(DURABLE_RUN_ID) == 2
    assert await reopened.list_recovery_candidates(limit=1) == ()
    await reopened.close()

    final = SQLiteDurableRunStore(path, limits=limits)
    assert await final.get_recovery_attempt_count(DURABLE_RUN_ID) == 2
    assert await final.list_recovery_candidates(limit=1) == ()
    await final.close()


async def test_sqlite_stale_lease_cannot_claim_recovery_attempt(
    tmp_path: Path,
) -> None:
    limits = replace(
        DurableRunLimits(),
        lease_duration=timedelta(seconds=2),
        lease_renewal_interval=timedelta(seconds=1),
    )
    store = SQLiteDurableRunStore(_path(tmp_path), limits=limits)
    await store.create(_checkpoint(1))
    stale = await _lease(store, owner_id="stale-worker", now=NOW)
    current = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="current-worker",
        now=stale.expires_at,
    )

    with pytest.raises(AgentStateConflictError):
        await store.claim_recovery_attempt(
            DURABLE_RUN_ID,
            lease=stale,
            now=current.acquired_at,
        )

    assert await store.get_recovery_attempt_count(DURABLE_RUN_ID) == 0
    assert (
        await store.claim_recovery_attempt(
            DURABLE_RUN_ID,
            lease=current,
            now=current.acquired_at,
        )
        == 1
    )


async def test_sqlite_schema_three_migrates_recovery_attempts_to_zero(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    connection = _connect(path)
    connection.execute(
        """
        CREATE TABLE durable_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO durable_meta (
            singleton, schema_version, created_at, updated_at
        ) VALUES (1, 3, ?, ?)
        """,
        (NOW.isoformat(), NOW.isoformat()),
    )
    connection.execute(
        """
        CREATE TABLE durable_runs (
            run_id TEXT PRIMARY KEY,
            current_sequence INTEGER NOT NULL CHECK (current_sequence > 0),
            current_version INTEGER NOT NULL CHECK (current_version > 0),
            current_checkpoint_id TEXT NOT NULL,
            current_digest TEXT NOT NULL CHECK (length(current_digest) = 64),
            history_bytes INTEGER NOT NULL CHECK (history_bytes >= 0),
            terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute("PRAGMA user_version = 3")
    connection.close()

    store = SQLiteDurableRunStore(path)
    assert await store.list_recovery_candidates(limit=1) == ()
    await store.close()

    migrated = _connect(path)
    try:
        assert (
            migrated.execute("PRAGMA user_version").fetchone()[0] == DURABLE_SQLITE_SCHEMA_VERSION
        )
        assert (
            migrated.execute(
                "SELECT schema_version FROM durable_meta WHERE singleton = 1"
            ).fetchone()[0]
            == DURABLE_SQLITE_SCHEMA_VERSION
        )
        columns = {row[1] for row in migrated.execute("PRAGMA table_info(durable_runs)").fetchall()}
        assert "recovery_attempts" in columns
    finally:
        migrated.close()


def _backup_sqlite_database(source: Path, destination: Path) -> None:
    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


async def test_sqlite_restored_stale_active_backup_blocks_automatic_recovery(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    stale_backup = _path(tmp_path, "stale-active.sqlite3")

    store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    await store.create(first)

    initial_freshness = await store.get_store_freshness()
    assert initial_freshness.category is DurableStoreFreshnessCategory.CURRENT
    assert initial_freshness.store_generation == 0
    assert initial_freshness.witness_generation == 0

    await store.close()
    _backup_sqlite_database(path, stale_backup)

    current_store = SQLiteDurableRunStore(path)
    assert await current_store.get_current(DURABLE_RUN_ID) == first
    lease = await _lease(current_store)
    terminal = _next(
        first,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
    )
    await current_store.append(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
    )
    await current_store.tombstone_terminal_run(
        DURABLE_RUN_ID,
        policy=RETENTION_POLICY,
        lease=lease,
        now=terminal.created_at + RETENTION_POLICY.metadata_retention,
    )

    terminal_freshness = await current_store.get_store_freshness()
    assert terminal_freshness.category is DurableStoreFreshnessCategory.CURRENT
    assert terminal_freshness.store_generation == 2
    assert terminal_freshness.witness_generation == 2
    await current_store.close()

    _backup_sqlite_database(stale_backup, path)

    restored = SQLiteDurableRunStore(path)
    freshness = await restored.get_store_freshness()
    assert freshness.category is DurableStoreFreshnessCategory.ROLLBACK_DETECTED
    assert freshness.store_generation == 0
    assert freshness.witness_generation == 2

    assert await restored.get_current(DURABLE_RUN_ID) == first
    assert await restored.list_recovery_candidates(limit=10) == ()

    recovery_lease = await restored.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="restore-review",
        now=NOW + timedelta(minutes=1),
    )
    with pytest.raises(AgentStateConflictError):
        await restored.claim_recovery_attempt(
            DURABLE_RUN_ID,
            lease=recovery_lease,
            now=NOW + timedelta(minutes=1),
        )
    assert await restored.get_recovery_attempt_count(DURABLE_RUN_ID) == 0
    await restored.close()


async def test_sqlite_missing_initialized_freshness_witness_pauses_automatic_recovery(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    await store.create(first)

    freshness = await store.get_store_freshness()
    assert freshness.category is DurableStoreFreshnessCategory.CURRENT
    witness_path = store.freshness_witness_path
    assert witness_path.is_file()
    await store.close()

    witness_path.unlink()

    reopened = SQLiteDurableRunStore(path)
    missing = await reopened.get_store_freshness()
    assert missing.category is DurableStoreFreshnessCategory.WITNESS_UNAVAILABLE
    assert missing.store_generation == 0
    assert missing.witness_generation is None
    assert await reopened.get_current(DURABLE_RUN_ID) == first
    assert await reopened.list_recovery_candidates(limit=10) == ()

    lease = await reopened.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="restore-review",
        now=NOW + timedelta(minutes=1),
    )
    with pytest.raises(AgentStateConflictError):
        await reopened.claim_recovery_attempt(
            DURABLE_RUN_ID,
            lease=lease,
            now=NOW + timedelta(minutes=1),
        )
    await reopened.close()


async def test_sqlite_database_ahead_of_witness_repairs_commit_before_witness_crash(
    tmp_path: Path,
) -> None:
    path = _path(tmp_path)
    store = SQLiteDurableRunStore(path)
    first = _checkpoint(1)
    await store.create(first)

    initial = await store.get_store_freshness()
    assert initial.category is DurableStoreFreshnessCategory.CURRENT
    witness_path = store.freshness_witness_path
    old_witness = witness_path.read_bytes()

    lease = await _lease(store)
    terminal = _next(
        first,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
    )
    await store.append(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
    )
    committed = await store.get_store_freshness()
    assert committed.store_generation == 1
    assert committed.witness_generation == 1
    await store.close()

    witness_path.write_bytes(old_witness)

    reopened = SQLiteDurableRunStore(path)
    repaired = await reopened.get_store_freshness()
    assert repaired.category is DurableStoreFreshnessCategory.CURRENT
    assert repaired.store_generation == 1
    assert repaired.witness_generation == 1
    assert witness_path.read_bytes() != old_witness
    assert await reopened.get_current(DURABLE_RUN_ID) == terminal
    await reopened.close()


@pytest.mark.parametrize(
    "counter",
    (
        "steps",
        "model_turns",
        "tool_calls",
        "model_output_bytes",
        "tool_result_bytes",
        "input_tokens",
        "output_tokens",
    ),
)
async def test_sqlite_repeated_restart_preserves_all_budget_dimensions(
    tmp_path: Path,
    counter: str,
) -> None:
    path = _path(tmp_path)
    base = _checkpoint(1)
    budget = replace(
        base.metadata.budget,
        steps=6,
        model_turns=4,
        tool_calls=2,
        model_output_bytes=101,
        tool_result_bytes=202,
        input_tokens=303,
        output_tokens=404,
    )
    first = seal_checkpoint_envelope(
        replace(
            base,
            metadata=replace(base.metadata, budget=budget),
            digest=_digest("0"),
        )
    )

    store = SQLiteDurableRunStore(path)
    await store.create(first)
    await store.close()

    for _restart in range(2):
        reopened = SQLiteDurableRunStore(path)
        current = await reopened.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.metadata.budget == budget
        await reopened.close()

    final = SQLiteDurableRunStore(path)
    current = await final.get_current(DURABLE_RUN_ID)
    assert current is not None
    lease = await _lease(final, now=WRITE_TIME)

    current_value = getattr(current.metadata.budget, counter)
    assert current_value > 0
    regressed_budget = replace(
        current.metadata.budget,
        **{counter: current_value - 1},
    )
    candidate = seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=_checkpoint_id(2, variant=90),
            sequence=current.sequence.next(),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            metadata=replace(current.metadata, budget=regressed_budget),
            created_at=WRITE_TIME,
            digest=_digest("0"),
        )
    )

    with pytest.raises(AgentStateConflictError):
        await final.append(
            candidate,
            expected_version=current.run_version,
            lease=lease,
            now=WRITE_TIME,
        )

    assert await final.get_current(DURABLE_RUN_ID) == current
    await final.close()


async def test_sqlite_repeated_restart_preserves_original_deadline_and_expiry_boundary(
    tmp_path: Path,
) -> None:
    from phoenix_os.agent.durable_contracts import RecoveryDisposition, RecoveryPoint
    from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint

    path = _path(tmp_path)
    first = _checkpoint(1)
    original_deadline = first.metadata.budget.deadline

    store = SQLiteDurableRunStore(path)
    await store.create(first)
    await store.close()

    current = first
    for _restart in range(3):
        reopened = SQLiteDurableRunStore(path)
        restored = await reopened.get_current(DURABLE_RUN_ID)
        assert restored is not None
        assert restored.metadata.budget.deadline == original_deadline
        current = restored
        await reopened.close()

    assert classify_recovery_checkpoint(
        current,
        now=original_deadline,
    ) == (
        RecoveryPoint.EXPIRED,
        RecoveryDisposition.TERMINATE_EXPIRED,
    )

    final = SQLiteDurableRunStore(path)
    final_current = await final.get_current(DURABLE_RUN_ID)
    assert final_current is not None
    lease = await _lease(final, now=WRITE_TIME)
    extended = seal_checkpoint_envelope(
        replace(
            final_current,
            checkpoint_id=_checkpoint_id(2, variant=91),
            sequence=final_current.sequence.next(),
            previous_digest=final_current.digest,
            run_version=final_current.run_version.next(),
            metadata=replace(
                final_current.metadata,
                budget=replace(
                    final_current.metadata.budget,
                    deadline=original_deadline + timedelta(minutes=1),
                ),
            ),
            created_at=WRITE_TIME,
            digest=_digest("0"),
        )
    )

    with pytest.raises(AgentStateConflictError):
        await final.append(
            extended,
            expected_version=final_current.run_version,
            lease=lease,
            now=WRITE_TIME,
        )

    authoritative = await final.get_current(DURABLE_RUN_ID)
    assert authoritative is not None
    assert authoritative.metadata.budget.deadline == original_deadline
    await final.close()
