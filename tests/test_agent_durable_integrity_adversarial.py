from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_codec import CanonicalCheckpointCodec, seal_checkpoint_envelope
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
)
from phoenix_os.agent.durable_sqlite import SQLiteDurableRunStore
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 29, 13, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
MUTATION_TIME = NOW + timedelta(seconds=2)

RUN_ID = DurableAgentRunId(UUID("11000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("11000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("22000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("33000000-0000-0000-0000-000000000003"))
FIRST_CHECKPOINT_ID = CheckpointId(UUID("44000000-0000-0000-0000-000000000004"))
SECOND_CHECKPOINT_ID = CheckpointId(UUID("44000000-0000-0000-0000-000000000005"))
OTHER_CHECKPOINT_ID = CheckpointId(UUID("44000000-0000-0000-0000-000000000006"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
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


def _checkpoint(
    *,
    run_id: DurableAgentRunId = RUN_ID,
    checkpoint_id: CheckpointId = FIRST_CHECKPOINT_ID,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=run_id,
            checkpoint_id=checkpoint_id,
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


def _successor(current: CheckpointEnvelope) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=SECOND_CHECKPOINT_ID,
            sequence=current.sequence.next(),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            created_at=MUTATION_TIME,
            digest=_digest("0"),
        )
    )


@pytest.mark.parametrize("fraction", (1, 4, 2, 3))
def test_canonical_checkpoint_rejects_truncation_at_multiple_boundaries(
    fraction: int,
) -> None:
    codec = CanonicalCheckpointCodec()
    encoded = codec.encode(_checkpoint())
    cut = max(1, min(len(encoded) - 1, len(encoded) // fraction))

    with pytest.raises(AgentCodecError):
        codec.decode(encoded[:cut])


def test_canonical_checkpoint_rejects_extra_trailing_bytes() -> None:
    codec = CanonicalCheckpointCodec()
    encoded = codec.encode(_checkpoint())

    with pytest.raises(AgentCodecError):
        codec.decode(encoded + b"\n")


def test_canonical_checkpoint_rejects_one_byte_content_corruption() -> None:
    codec = CanonicalCheckpointCodec()
    encoded = codec.encode(_checkpoint())
    marker = b"worker-1"
    offset = encoded.index(marker)
    corrupted = bytearray(encoded)
    corrupted[offset + len(marker) - 1] = ord("2")

    with pytest.raises(AgentCodecError):
        codec.decode(bytes(corrupted))


def test_canonical_checkpoint_rejects_persisted_digest_substitution() -> None:
    codec = CanonicalCheckpointCodec()
    checkpoint = _checkpoint()
    encoded = codec.encode(checkpoint)
    marker = checkpoint.digest.value.encode("ascii")
    offset = encoded.index(marker)
    corrupted = bytearray(encoded)
    corrupted[offset] = ord("f") if marker[0] != ord("f") else ord("e")

    with pytest.raises(AgentCodecError):
        codec.decode(bytes(corrupted))


@pytest.mark.asyncio
async def test_sqlite_rejects_skipped_sequence_without_partial_commit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "skipped-sequence.sqlite3"
    store = SQLiteDurableRunStore(path)
    current = _checkpoint()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="sequence-test",
        now=LEASE_TIME,
    )
    skipped = seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=SECOND_CHECKPOINT_ID,
            sequence=CheckpointSequence(3),
            previous_digest=current.digest,
            run_version=current.run_version.next(),
            created_at=MUTATION_TIME,
            digest=_digest("0"),
        )
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(
            skipped,
            expected_version=current.run_version,
            lease=lease,
            now=MUTATION_TIME,
        )

    await store.close()
    reopened = SQLiteDurableRunStore(path)
    assert await reopened.get_current(RUN_ID) == current
    await reopened.close()


@pytest.mark.asyncio
async def test_sqlite_rejects_duplicate_sequence_without_partial_commit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate-sequence.sqlite3"
    store = SQLiteDurableRunStore(path)
    current = _checkpoint()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="duplicate-sequence-test",
        now=LEASE_TIME,
    )
    duplicate_sequence = seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=SECOND_CHECKPOINT_ID,
            created_at=MUTATION_TIME,
            digest=_digest("0"),
        )
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(
            duplicate_sequence,
            expected_version=current.run_version,
            lease=lease,
            now=MUTATION_TIME,
        )

    assert await store.get_current(RUN_ID) == current
    await store.close()


@pytest.mark.asyncio
async def test_sqlite_rejects_wrong_previous_digest_without_partial_commit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "wrong-previous-digest.sqlite3"
    store = SQLiteDurableRunStore(path)
    current = _checkpoint()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="wrong-previous-test",
        now=LEASE_TIME,
    )
    wrong_previous = seal_checkpoint_envelope(
        replace(
            current,
            checkpoint_id=SECOND_CHECKPOINT_ID,
            sequence=current.sequence.next(),
            previous_digest=_digest("f"),
            run_version=current.run_version.next(),
            created_at=MUTATION_TIME,
            digest=_digest("0"),
        )
    )

    with pytest.raises(AgentStateConflictError):
        await store.append(
            wrong_previous,
            expected_version=current.run_version,
            lease=lease,
            now=MUTATION_TIME,
        )

    assert await store.get_current(RUN_ID) == current
    await store.close()


@pytest.mark.asyncio
async def test_sqlite_rejects_valid_cross_run_checkpoint_substitution_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cross-run-substitution.sqlite3"
    codec = CanonicalCheckpointCodec()
    store = SQLiteDurableRunStore(path)
    current = _checkpoint()
    other = _checkpoint(
        run_id=OTHER_RUN_ID,
        checkpoint_id=OTHER_CHECKPOINT_ID,
    )
    await store.create(current)
    await store.create(other)
    substituted_payload = codec.encode(other)
    await store.close()

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            UPDATE durable_checkpoints
            SET payload = ?, payload_bytes = ?
            WHERE run_id = ? AND sequence = 1
            """,
            (
                sqlite3.Binary(substituted_payload),
                len(substituted_payload),
                str(RUN_ID),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    reopened = SQLiteDurableRunStore(path)
    with pytest.raises(AgentCodecError):
        await reopened.get_current(RUN_ID)
    await reopened.close()


@pytest.mark.asyncio
async def test_sqlite_rejects_rollback_to_older_valid_head_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "rollback.sqlite3"
    codec = CanonicalCheckpointCodec()
    store = SQLiteDurableRunStore(path)
    first = _checkpoint()
    await store.create(first)
    lease = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="rollback-test",
        now=LEASE_TIME,
    )
    second = _successor(first)
    await store.append(
        second,
        expected_version=first.run_version,
        lease=lease,
        now=MUTATION_TIME,
    )
    first_bytes = len(codec.encode(first))
    await store.close()

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            UPDATE durable_runs
            SET current_sequence = ?,
                current_version = ?,
                current_checkpoint_id = ?,
                current_digest = ?,
                history_bytes = ?,
                terminal = ?,
                updated_at = ?
            WHERE run_id = ?
            """,
            (
                first.sequence.value,
                first.run_version.value,
                str(first.checkpoint_id),
                first.digest.value,
                first_bytes,
                int(first.status.terminal),
                first.created_at.isoformat(),
                str(RUN_ID),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    reopened = SQLiteDurableRunStore(path)
    with pytest.raises(AgentCodecError):
        await reopened.get_current(RUN_ID)
    await reopened.close()
