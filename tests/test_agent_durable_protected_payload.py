from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
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
    DurableRunLimits,
    DurableRunStatus,
    DurableRunVersion,
    ProtectedPayloadReference,
    RetentionPolicy,
)
from phoenix_os.agent.durable_fake import DeterministicCheckpointProtector
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_payload import (
    DURABLE_PROTECTED_PAYLOAD_CONTEXT_VERSION,
    DurableProtectedPayloadStore,
    protected_payload_associated_data,
)
from phoenix_os.agent.durable_retention_worker import BoundedDurableRetentionWorker
from phoenix_os.agent.durable_sqlite import (
    DURABLE_SQLITE_SCHEMA_VERSION,
    SQLiteDurableRunStore,
)
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentStateConflictError,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)
WRITE_TIME = NOW + timedelta(seconds=10)
RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
SECRET = b"0123456789abcdef0123456789abcdef"
RETENTION_POLICY = RetentionPolicy(
    payload_retention=timedelta(seconds=10),
    metadata_retention=timedelta(seconds=20),
    tombstone_retention=timedelta(seconds=30),
)


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


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


def _compatibility(*, payload_codec: bool = True) -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
        payload_codec=_digest("e") if payload_codec else None,
    )


def _protector() -> DeterministicCheckpointProtector:
    return DeterministicCheckpointProtector(
        SECRET,
        protector_id="deterministic-checkpoint-protector",
        key_version="payload-key-v1",
        clock=lambda: NOW,
    )


def _unsealed(
    sequence: int,
    *,
    previous_digest: CheckpointDigest | None = None,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.PROTECTED_CONTENT,
    payload_codec: bool = True,
    payload_reference: ProtectedPayloadReference | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    created_offset: int | None = None,
) -> CheckpointEnvelope:
    return CheckpointEnvelope(
        schema_version=CheckpointSchemaVersion(),
        durable_run_id=RUN_ID,
        checkpoint_id=CheckpointId(UUID(int=10_000 + sequence)),
        sequence=CheckpointSequence(sequence),
        previous_digest=previous_digest,
        run_version=DurableRunVersion(sequence),
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        metadata=CheckpointMetadata(
            agent_id=AgentId("assistant"),
            actor_id="worker-1",
            next_operation=next_operation,
            budget=_budget(steps=sequence - 1),
            compatibility=_compatibility(payload_codec=payload_codec),
            payload_profile=payload_profile,
            retention_deadline=NOW + timedelta(days=7),
            payload_reference=payload_reference,
            metadata={"tenant": "demo"},
        ),
        created_at=NOW + timedelta(seconds=created_offset or sequence),
        digest=_digest("0"),
    )


def _protected_checkpoint(
    sequence: int,
    plaintext: bytes,
    *,
    previous_digest: CheckpointDigest | None = None,
    reference_override: ProtectedPayloadReference | None = None,
    payload_codec: bool = True,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
) -> tuple[CheckpointEnvelope, bytes]:
    protector = _protector()
    envelope = _unsealed(
        sequence,
        previous_digest=previous_digest,
        payload_codec=payload_codec,
        status=status,
        next_operation=next_operation,
    )
    reference, ciphertext = protector.protect(
        run_id=envelope.durable_run_id,
        checkpoint_id=envelope.checkpoint_id,
        sequence=envelope.sequence,
        schema_version=envelope.schema_version,
        profile=envelope.metadata.payload_profile,
        plaintext=plaintext,
    )
    selected_reference = reference if reference_override is None else reference_override
    checkpoint = seal_checkpoint_envelope(
        replace(
            envelope,
            metadata=replace(
                envelope.metadata,
                payload_reference=selected_reference,
            ),
        )
    )
    return checkpoint, ciphertext


def _metadata_checkpoint(sequence: int = 1) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        _unsealed(
            sequence,
            payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            payload_codec=False,
        )
    )


async def _lease(
    store: InMemoryDurableRunStore | SQLiteDurableRunStore,
    *,
    now: datetime = NOW,
) -> DurableLease:
    return await store.lease_manager.acquire(
        RUN_ID,
        owner_id="worker-1",
        now=now,
    )


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def test_associated_data_is_canonical_and_binds_required_context() -> None:
    data = protected_payload_associated_data(
        run_id=RUN_ID,
        checkpoint_id=CheckpointId(UUID(int=10_001)),
        sequence=CheckpointSequence(1),
        schema_version=CheckpointSchemaVersion(1),
        profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
    )
    decoded = json.loads(data)

    assert decoded == {
        "checkpoint_id": "00000000-0000-0000-0000-000000002711",
        "kind": "phoenix.agent.durable-protected-payload",
        "profile": "protected_content",
        "run_id": str(RUN_ID),
        "schema_version": 1,
        "sequence": 1,
        "version": DURABLE_PROTECTED_PAYLOAD_CONTEXT_VERSION,
    }
    assert data == protected_payload_associated_data(
        run_id=RUN_ID,
        checkpoint_id=CheckpointId(UUID(int=10_001)),
        sequence=CheckpointSequence(1),
        schema_version=CheckpointSchemaVersion(1),
        profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
    )


@pytest.mark.parametrize(
    ("argument", "value", "error_type"),
    [
        ("run_id", "run", TypeError),
        ("checkpoint_id", "checkpoint", TypeError),
        ("sequence", 1, TypeError),
        ("profile", CheckpointPayloadProfile.METADATA_ONLY, ValueError),
    ],
)
def test_associated_data_rejects_invalid_context(
    argument: str,
    value: object,
    error_type: type[Exception],
) -> None:
    arguments: dict[str, object] = {
        "run_id": RUN_ID,
        "checkpoint_id": CheckpointId(UUID(int=10_001)),
        "sequence": CheckpointSequence(1),
        "schema_version": CheckpointSchemaVersion(),
        "profile": CheckpointPayloadProfile.PROTECTED_CONTENT,
    }
    arguments[argument] = value

    with pytest.raises(error_type):
        protected_payload_associated_data(**arguments)  # type: ignore[arg-type]


def test_protector_fails_closed_when_schema_context_is_substituted() -> None:
    protector = _protector()
    checkpoint = _unsealed(1)
    reference, ciphertext = protector.protect(
        run_id=checkpoint.durable_run_id,
        checkpoint_id=checkpoint.checkpoint_id,
        sequence=checkpoint.sequence,
        schema_version=checkpoint.schema_version,
        profile=checkpoint.metadata.payload_profile,
        plaintext=b"schema-bound",
    )

    with pytest.raises(AgentCodecError):
        protector.unprotect(
            run_id=checkpoint.durable_run_id,
            checkpoint_id=checkpoint.checkpoint_id,
            sequence=checkpoint.sequence,
            schema_version=CheckpointSchemaVersion(2),
            profile=checkpoint.metadata.payload_profile,
            reference=reference,
            ciphertext=ciphertext,
        )


async def test_memory_protected_birth_fences_preexisting_lease_authority() -> None:
    store = InMemoryDurableRunStore()
    prebirth = await _lease(store)
    checkpoint, ciphertext = _protected_checkpoint(1, b"memory rebirth")

    await store.create_protected(
        checkpoint,
        protected_payload=ciphertext,
    )

    with pytest.raises(AgentStateConflictError):
        await store.lease_manager.require_current(prebirth, now=NOW)

    fresh = await _lease(store, now=NOW)
    assert fresh.generation.value == prebirth.generation.value + 1
    assert (
        await store.get_protected_payload(
            checkpoint,
            lease=fresh,
            now=WRITE_TIME,
        )
        == ciphertext
    )


async def test_sqlite_protected_birth_fences_preexisting_lease_authority(
    tmp_path: Path,
) -> None:
    store = SQLiteDurableRunStore(tmp_path / "protected-rebirth.sqlite3")
    prebirth = await _lease(store)
    checkpoint, ciphertext = _protected_checkpoint(1, b"sqlite rebirth")

    await store.create_protected(
        checkpoint,
        protected_payload=ciphertext,
    )

    with pytest.raises(AgentStateConflictError):
        await store.lease_manager.require_current(prebirth, now=NOW)

    fresh = await _lease(store, now=NOW)
    assert fresh.generation.value == prebirth.generation.value + 1
    assert (
        await store.get_protected_payload(
            checkpoint,
            lease=fresh,
            now=WRITE_TIME,
        )
        == ciphertext
    )


async def test_memory_store_round_trips_current_protected_ciphertext() -> None:
    store = InMemoryDurableRunStore()
    assert isinstance(store, DurableProtectedPayloadStore)
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected continuation")
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    lease = await _lease(store)

    restored = await store.get_protected_payload(
        checkpoint,
        lease=lease,
        now=WRITE_TIME,
    )

    assert restored == ciphertext
    assert restored != b"protected continuation"


@pytest.mark.parametrize(
    "case",
    ["payload_without_reference", "reference_without_payload", "missing_payload_codec"],
)
async def test_memory_store_rejects_incomplete_payload_binding(case: str) -> None:
    store = InMemoryDurableRunStore()
    payload: bytes | None
    if case == "payload_without_reference":
        checkpoint = _metadata_checkpoint()
        payload = b"ciphertext"
    else:
        checkpoint, ciphertext = _protected_checkpoint(
            1,
            b"protected",
            payload_codec=case != "missing_payload_codec",
        )
        payload = None if case == "reference_without_payload" else ciphertext

    with pytest.raises(AgentStateConflictError):
        if case == "reference_without_payload":
            await store.create(checkpoint)
        else:
            assert payload is not None
            await store.create_protected(checkpoint, protected_payload=payload)

    assert await store.get_current(RUN_ID) is None


async def test_memory_store_rejects_tampered_ciphertext_atomically() -> None:
    store = InMemoryDurableRunStore()
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(AgentCodecError, match="digest"):
        await store.create_protected(checkpoint, protected_payload=tampered)

    assert await store.get_current(RUN_ID) is None


async def test_memory_store_read_requires_current_lease() -> None:
    store = InMemoryDurableRunStore()
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected")
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    current = await _lease(store)
    await store.lease_manager.release(current, now=NOW + timedelta(seconds=1))

    with pytest.raises(AgentStateConflictError):
        await store.get_protected_payload(
            checkpoint,
            lease=current,
            now=NOW + timedelta(seconds=2),
        )


async def test_memory_store_read_rejects_stale_checkpoint_after_append() -> None:
    store = InMemoryDurableRunStore()
    first, first_ciphertext = _protected_checkpoint(1, b"first")
    second, second_ciphertext = _protected_checkpoint(
        2,
        b"second",
        previous_digest=first.digest,
    )
    await store.create_protected(first, protected_payload=first_ciphertext)
    lease = await _lease(store)
    await store.append_protected(
        second,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
        protected_payload=second_ciphertext,
    )

    with pytest.raises(AgentStateConflictError):
        await store.get_protected_payload(first, lease=lease, now=WRITE_TIME)

    assert (
        await store.get_protected_payload(second, lease=lease, now=WRITE_TIME) == second_ciphertext
    )


async def test_memory_store_enforces_configured_plaintext_limit() -> None:
    checkpoint, ciphertext = _protected_checkpoint(1, b"12345")
    limits = replace(DurableRunLimits(), max_protected_payload_bytes=4)
    store = InMemoryDurableRunStore(limits=limits)

    with pytest.raises(AgentLimitExceededError):
        await store.create_protected(checkpoint, protected_payload=ciphertext)


def _create_v1_database(path: Path) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA user_version = 1")
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
        INSERT INTO durable_meta(singleton, schema_version, created_at, updated_at)
        VALUES(1, 1, ?, ?)
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
    connection.execute(
        """
        CREATE TABLE durable_checkpoints (
            run_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            checkpoint_id TEXT NOT NULL,
            run_version INTEGER NOT NULL CHECK (run_version > 0),
            digest TEXT NOT NULL CHECK (length(digest) = 64),
            previous_digest TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload BLOB NOT NULL,
            payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
            PRIMARY KEY (run_id, sequence),
            UNIQUE (run_id, checkpoint_id),
            FOREIGN KEY (run_id) REFERENCES durable_runs(run_id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE durable_leases (
            run_id TEXT PRIMARY KEY,
            generation INTEGER NOT NULL CHECK (generation > 0),
            active INTEGER NOT NULL CHECK (active IN (0, 1)),
            lease_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            acquired_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
    connection.close()


async def test_sqlite_schema_migrates_v1_database_to_current_schema(
    tmp_path: Path,
) -> None:
    path = tmp_path / "durable.sqlite3"
    _create_v1_database(path)
    store = SQLiteDurableRunStore(path)

    assert await store.get_current(RUN_ID) is None

    connection = _connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == DURABLE_SQLITE_SCHEMA_VERSION
    assert DURABLE_SQLITE_SCHEMA_VERSION == 5
    row = connection.execute(
        "SELECT schema_version FROM durable_meta WHERE singleton = 1"
    ).fetchone()
    assert row is not None
    assert row["schema_version"] == DURABLE_SQLITE_SCHEMA_VERSION
    table = connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name = 'durable_protected_payloads'
        """
    ).fetchone()
    assert table is not None
    connection.close()


async def test_sqlite_create_reopen_and_read_protected_ciphertext(tmp_path: Path) -> None:
    path = tmp_path / "durable.sqlite3"
    checkpoint, ciphertext = _protected_checkpoint(1, b"persisted protected continuation")
    store = SQLiteDurableRunStore(path)
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    lease = await _lease(store)
    assert await store.get_protected_payload(checkpoint, lease=lease, now=WRITE_TIME) == ciphertext
    await store.lease_manager.release(lease, now=WRITE_TIME)
    await store.close()

    reopened = SQLiteDurableRunStore(path)
    reopened_lease = await _lease(reopened, now=WRITE_TIME + timedelta(seconds=1))
    assert (
        await reopened.get_protected_payload(
            checkpoint,
            lease=reopened_lease,
            now=WRITE_TIME + timedelta(seconds=1),
        )
        == ciphertext
    )


async def test_sqlite_persists_ciphertext_and_content_free_metadata_only(tmp_path: Path) -> None:
    path = tmp_path / "durable.sqlite3"
    plaintext = b"plaintext-must-not-enter-sqlite"
    checkpoint, ciphertext = _protected_checkpoint(1, plaintext)
    store = SQLiteDurableRunStore(path)
    await store.create_protected(checkpoint, protected_payload=ciphertext)

    connection = _connect(path)
    row = connection.execute(
        """
        SELECT reference, key_version, plaintext_bytes, ciphertext_bytes,
               ciphertext_digest, ciphertext
        FROM durable_protected_payloads
        WHERE run_id = ? AND sequence = 1
        """,
        (str(RUN_ID),),
    ).fetchone()
    assert row is not None
    reference = checkpoint.metadata.payload_reference
    assert reference is not None
    stored_ciphertext = bytes(row["ciphertext"])
    assert stored_ciphertext == ciphertext
    assert plaintext not in stored_ciphertext
    assert row["reference"] == reference.reference
    assert row["key_version"] == reference.key_version
    assert row["plaintext_bytes"] == len(plaintext)
    assert row["ciphertext_bytes"] == len(ciphertext)
    assert row["ciphertext_digest"] == hashlib.sha256(ciphertext).hexdigest()
    connection.close()


async def test_sqlite_append_persists_checkpoint_and_payload_atomically(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(tmp_path / "durable.sqlite3")
    first, first_ciphertext = _protected_checkpoint(1, b"first")
    second, second_ciphertext = _protected_checkpoint(
        2,
        b"second",
        previous_digest=first.digest,
    )
    await store.create_protected(first, protected_payload=first_ciphertext)
    lease = await _lease(store)

    assert (
        await store.append_protected(
            second,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
            protected_payload=second_ciphertext,
        )
        == second
    )
    assert (
        await store.get_protected_payload(second, lease=lease, now=WRITE_TIME) == second_ciphertext
    )


async def test_sqlite_duplicate_opaque_reference_rolls_back_append(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(tmp_path / "durable.sqlite3")
    first, first_ciphertext = _protected_checkpoint(1, b"same bytes")
    second, _ = _protected_checkpoint(
        2,
        b"same bytes",
        previous_digest=first.digest,
        reference_override=first.metadata.payload_reference,
    )
    second_ciphertext = first_ciphertext
    await store.create_protected(first, protected_payload=first_ciphertext)
    lease = await _lease(store)

    with pytest.raises(AgentStateConflictError):
        await store.append_protected(
            second,
            expected_version=first.run_version,
            lease=lease,
            now=WRITE_TIME,
            protected_payload=second_ciphertext,
        )

    assert await store.get_current(RUN_ID) == first


async def test_sqlite_missing_referenced_payload_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "durable.sqlite3"
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected")
    store = SQLiteDurableRunStore(path)
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    lease = await _lease(store)

    connection = _connect(path)
    connection.execute(
        "DELETE FROM durable_protected_payloads WHERE run_id = ? AND sequence = 1",
        (str(RUN_ID),),
    )
    connection.close()

    with pytest.raises(AgentCodecError, match="missing"):
        await store.get_protected_payload(checkpoint, lease=lease, now=WRITE_TIME)


@pytest.mark.parametrize(
    "field",
    ["ciphertext", "ciphertext_digest", "key_version", "schema_version", "profile"],
)
async def test_sqlite_tampered_payload_record_fails_closed(
    tmp_path: Path,
    field: str,
) -> None:
    path = tmp_path / f"{field}.sqlite3"
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected")
    store = SQLiteDurableRunStore(path)
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    lease = await _lease(store)

    connection = _connect(path)
    if field == "ciphertext":
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        connection.execute(
            "UPDATE durable_protected_payloads SET ciphertext = ? WHERE run_id = ?",
            (sqlite3.Binary(tampered), str(RUN_ID)),
        )
    elif field == "ciphertext_digest":
        connection.execute(
            "UPDATE durable_protected_payloads SET ciphertext_digest = ? WHERE run_id = ?",
            ("f" * 64, str(RUN_ID)),
        )
    elif field == "key_version":
        connection.execute(
            "UPDATE durable_protected_payloads SET key_version = ? WHERE run_id = ?",
            ("payload-key-v2", str(RUN_ID)),
        )
    elif field == "schema_version":
        connection.execute(
            "UPDATE durable_protected_payloads SET schema_version = ? WHERE run_id = ?",
            (2, str(RUN_ID)),
        )
    else:
        connection.execute(
            "UPDATE durable_protected_payloads SET profile = ? WHERE run_id = ?",
            ("metadata_only", str(RUN_ID)),
        )
    connection.close()

    with pytest.raises(AgentCodecError):
        await store.get_protected_payload(checkpoint, lease=lease, now=WRITE_TIME)


async def test_sqlite_protected_payload_read_requires_current_lease(tmp_path: Path) -> None:
    store = SQLiteDurableRunStore(tmp_path / "durable.sqlite3")
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected")
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    lease = await _lease(store)
    await store.lease_manager.release(lease, now=NOW + timedelta(seconds=1))

    with pytest.raises(AgentStateConflictError):
        await store.get_protected_payload(
            checkpoint,
            lease=lease,
            now=NOW + timedelta(seconds=2),
        )


async def test_sqlite_stale_lease_cannot_read_after_reacquisition(tmp_path: Path) -> None:
    limits = replace(
        DurableRunLimits(),
        lease_duration=timedelta(seconds=2),
        lease_renewal_interval=timedelta(seconds=1),
    )
    store = SQLiteDurableRunStore(tmp_path / "durable.sqlite3", limits=limits)
    checkpoint, ciphertext = _protected_checkpoint(1, b"protected")
    await store.create_protected(checkpoint, protected_payload=ciphertext)
    stale = await _lease(store)
    current = await store.lease_manager.acquire(
        RUN_ID,
        owner_id="worker-2",
        now=stale.expires_at,
    )

    with pytest.raises(AgentStateConflictError):
        await store.get_protected_payload(
            checkpoint,
            lease=stale,
            now=current.acquired_at,
        )

    assert (
        await store.get_protected_payload(
            checkpoint,
            lease=current,
            now=current.acquired_at,
        )
        == ciphertext
    )


async def test_sqlite_metadata_only_checkpoint_creates_no_payload_record(tmp_path: Path) -> None:
    path = tmp_path / "durable.sqlite3"
    store = SQLiteDurableRunStore(path)
    checkpoint = _metadata_checkpoint()

    await store.create(checkpoint)

    connection = _connect(path)
    assert connection.execute("SELECT COUNT(*) FROM durable_protected_payloads").fetchone()[0] == 0
    connection.close()


async def _sqlite_terminal_protected_retention_run(
    store: SQLiteDurableRunStore,
) -> tuple[
    CheckpointEnvelope,
    CheckpointEnvelope,
    DurableLease,
    bytes,
    bytes,
]:
    first, first_ciphertext = _protected_checkpoint(
        1,
        b"first retained secret",
    )

    terminal, terminal_ciphertext = _protected_checkpoint(
        2,
        b"terminal retained secret",
        previous_digest=first.digest,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
    )

    await store.create_protected(
        first,
        protected_payload=first_ciphertext,
    )

    lease = await _lease(store)

    await store.append_protected(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=WRITE_TIME,
        protected_payload=terminal_ciphertext,
    )

    return (
        first,
        terminal,
        lease,
        first_ciphertext,
        terminal_ciphertext,
    )


async def test_sqlite_retention_physically_deletes_ciphertext_but_keeps_history(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retention-payload.sqlite3"
    store = SQLiteDurableRunStore(path)

    (
        first,
        terminal,
        lease,
        _,
        _,
    ) = await _sqlite_terminal_protected_retention_run(store)

    connection = _connect(path)

    before = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_protected_payloads
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    assert before is not None
    assert before["count"] == 2
    connection.close()

    due = terminal.created_at + RETENTION_POLICY.payload_retention

    assert (
        await store.delete_expired_protected_payloads(
            RUN_ID,
            policy=RETENTION_POLICY,
            lease=lease,
            now=due,
        )
        is True
    )

    assert (
        await store.delete_expired_protected_payloads(
            RUN_ID,
            policy=RETENTION_POLICY,
            lease=lease,
            now=due,
        )
        is False
    )

    assert await store.get_current(RUN_ID) == terminal
    assert await store.list_history(RUN_ID, limit=10) == (
        first,
        terminal,
    )

    connection = _connect(path)

    payload_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_protected_payloads
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    run_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_runs
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    checkpoint_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_checkpoints
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    assert payload_count is not None
    assert run_count is not None
    assert checkpoint_count is not None

    assert payload_count["count"] == 0
    assert run_count["count"] == 1
    assert checkpoint_count["count"] == 2

    connection.close()

    with pytest.raises(
        AgentCodecError,
        match="missing",
    ):
        await store.get_protected_payload(
            terminal,
            lease=lease,
            now=due,
        )


async def test_sqlite_tombstone_atomically_removes_run_history_and_ciphertext(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retention-tombstone.sqlite3"
    store = SQLiteDurableRunStore(path)

    (
        _,
        terminal,
        lease,
        _,
        _,
    ) = await _sqlite_terminal_protected_retention_run(store)

    due = terminal.created_at + RETENTION_POLICY.metadata_retention

    tombstone = await store.tombstone_terminal_run(
        RUN_ID,
        policy=RETENTION_POLICY,
        lease=lease,
        now=due,
    )

    connection = _connect(path)

    run_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_runs
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    checkpoint_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_checkpoints
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    payload_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_protected_payloads
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    tombstone_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM durable_tombstones
        WHERE run_id = ?
        """,
        (str(RUN_ID),),
    ).fetchone()

    assert run_count is not None
    assert checkpoint_count is not None
    assert payload_count is not None
    assert tombstone_count is not None

    assert run_count["count"] == 0
    assert checkpoint_count["count"] == 0
    assert payload_count["count"] == 0
    assert tombstone_count["count"] == 1

    connection.close()

    assert await store.get_current(RUN_ID) is None
    assert await store.list_history(RUN_ID, limit=10) == ()
    assert await store.get_tombstone(RUN_ID) == tombstone


async def test_retention_worker_runs_real_sqlite_cleanup_end_to_end(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retention-worker-e2e.sqlite3"
    store = SQLiteDurableRunStore(path)

    (
        _,
        terminal,
        setup_lease,
        _,
        _,
    ) = await _sqlite_terminal_protected_retention_run(store)

    await store.lease_manager.release(
        setup_lease,
        now=WRITE_TIME,
    )

    cleanup_now = terminal.created_at + RETENTION_POLICY.metadata_retention

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: cleanup_now,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 1
        assert report.payloads_deleted == 1
        assert report.tombstoned == 1
        assert report.purged == 0
        assert report.conflicts == 0
        assert report.failed == 0
        assert report.timed_out is False

        tombstone = await store.get_tombstone(RUN_ID)

        assert tombstone is not None
        assert tombstone.run_id == RUN_ID
        assert tombstone.terminal_status is DurableRunStatus.FAILED
        assert tombstone.terminal_version == terminal.run_version
        assert tombstone.final_checkpoint_digest == terminal.digest
        assert tombstone.terminal_at == terminal.created_at
        assert tombstone.retain_until == (
            terminal.created_at + RETENTION_POLICY.tombstone_retention
        )

        assert await store.get_current(RUN_ID) is None

        assert (
            await store.list_history(
                RUN_ID,
                limit=10,
            )
            == ()
        )

        assert (
            await store.lease_manager.get_current(
                RUN_ID,
                now=cleanup_now,
            )
            is None
        )

        connection = _connect(path)

        try:
            payload_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM durable_protected_payloads
                WHERE run_id = ?
                """,
                (str(RUN_ID),),
            ).fetchone()[0]
        finally:
            connection.close()

        assert payload_count == 0
    finally:
        await worker.close()
        await store.close()

    reopened = SQLiteDurableRunStore(path)

    try:
        assert await reopened.get_tombstone(RUN_ID) == tombstone

        assert await reopened.get_current(RUN_ID) is None

        assert (
            await reopened.list_history(
                RUN_ID,
                limit=10,
            )
            == ()
        )

        assert (
            await reopened.lease_manager.get_current(
                RUN_ID,
                now=cleanup_now,
            )
            is None
        )
    finally:
        await reopened.close()
