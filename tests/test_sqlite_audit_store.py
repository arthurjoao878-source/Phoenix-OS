import asyncio
import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phoenix_os import (
    AUDIT_GENESIS_DIGEST,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditPersistenceError,
    AuditQuery,
    AuditRecoveryError,
    AuditSchemaError,
    AuditStoreClosedError,
    KeyRef,
    SQLiteAuditStore,
)


class DeterministicSigner:
    def sign(self, digest: bytes, *, key: KeyRef) -> bytes:
        return hashlib.sha256(digest + key.canonical.encode()).digest()

    async def verify(self, digest: bytes, signature: bytes, *, key: KeyRef) -> bool:
        return signature == self.sign(digest, key=key)


def fact(
    index: int,
    *,
    outcome: AuditOutcome = AuditOutcome.SUCCEEDED,
    actor: str = "tester",
) -> AuditEvent:
    return AuditEvent(
        name="security.changed",
        source="phoenix.test",
        category=AuditCategory.SYSTEM,
        action="security.change",
        resource=f"system:item/{index}",
        actor=actor,
        outcome=outcome,
        details={"index": index, "password": "never-store-this"},
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index),
        correlation_id=f"corr-{index}",
    )


@pytest.mark.asyncio
async def test_sqlite_store_persists_chain_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "ledger.sqlite3"
    first_store = SQLiteAuditStore(path)
    first = await first_store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = await first_store.append(
        fact(2), recorded_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)
    )
    await first_store.close()

    reopened = SQLiteAuditStore(path)
    records = await reopened.read(AuditQuery(limit=1000))
    verification = await reopened.verify()

    assert [record.sequence for record in records] == [1, 2]
    assert records[0].digest == first.digest
    assert records[1].previous_digest == first.digest
    assert records[1].digest == second.digest
    assert records[0].event.details["password"] == "***"
    assert verification.valid
    assert verification.head_digest == second.digest


@pytest.mark.asyncio
async def test_sqlite_store_resumes_sequence_after_reopen(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    first = await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    reopened = SQLiteAuditStore(path)
    await reopened.start(object())
    second = await reopened.append(fact(2), recorded_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC))

    assert second.sequence == 2
    assert second.previous_digest == first.digest
    assert (await reopened.verify()).valid


@pytest.mark.asyncio
async def test_sqlite_store_filters_in_persisted_sequence_order(tmp_path: Path) -> None:
    store = SQLiteAuditStore(tmp_path / "ledger.sqlite3")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await store.append(fact(1), recorded_at=now)
    await store.append(fact(2, outcome=AuditOutcome.DENIED, actor="arthur"), recorded_at=now)
    await store.append(fact(3, outcome=AuditOutcome.DENIED, actor="arthur"), recorded_at=now)

    records = await store.read(
        AuditQuery(
            start_sequence=2,
            outcomes=frozenset({AuditOutcome.DENIED}),
            actors=frozenset({"arthur"}),
            actions=frozenset({"security.change"}),
            limit=1,
        )
    )

    assert [record.sequence for record in records] == [2]


@pytest.mark.asyncio
async def test_sqlite_store_serializes_appends_from_multiple_instances(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    first_store = SQLiteAuditStore(path)
    second_store = SQLiteAuditStore(path)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    records = await asyncio.gather(
        first_store.append(fact(1), recorded_at=now),
        second_store.append(fact(2), recorded_at=now + timedelta(seconds=1)),
    )

    assert sorted(record.sequence for record in records) == [1, 2]
    assert (await first_store.verify()).valid
    assert [record.sequence for record in await second_store.read(AuditQuery())] == [1, 2]


@pytest.mark.asyncio
async def test_sqlite_guards_reject_direct_updates_and_deletes(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE audit_records SET actor = 'intruder' WHERE sequence = 1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM audit_records WHERE sequence = 1")
    connection.close()


@pytest.mark.asyncio
async def test_verify_detects_persisted_record_corruption(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER audit_records_no_update")
    connection.execute("UPDATE audit_records SET resource = 'system:tampered' WHERE sequence = 1")
    connection.commit()
    connection.close()

    reopened = SQLiteAuditStore(path)
    result = await reopened.verify()

    assert not result.valid
    assert result.failure_sequence == 1
    assert result.reason == "record digest mismatch"


@pytest.mark.asyncio
async def test_recovery_refuses_append_to_corrupted_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER audit_records_no_update")
    connection.execute("UPDATE audit_records SET actor = 'intruder' WHERE sequence = 1")
    connection.commit()
    connection.close()

    reopened = SQLiteAuditStore(path)
    with pytest.raises(AuditRecoveryError, match="recovery verification failed"):
        await reopened.append(fact(2), recorded_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC))


@pytest.mark.asyncio
async def test_verify_detects_metadata_head_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    record = await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE audit_meta SET head_digest = ? WHERE singleton = 1",
        (AUDIT_GENESIS_DIGEST,),
    )
    connection.commit()
    connection.close()

    result = await SQLiteAuditStore(path).verify()
    assert not result.valid
    assert result.failure_sequence == record.sequence
    assert result.reason == "audit metadata does not match the persisted chain head"


@pytest.mark.asyncio
async def test_external_signatures_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    signer = DeterministicSigner()
    key = KeyRef("audit", "test-kms", 1)
    store = SQLiteAuditStore(
        path,
        signer=signer,
        signing_key=key,
        signing_algorithm="test-sha256",
    )
    record = await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    reopened = SQLiteAuditStore(path, signer=signer, signing_key=key)
    loaded = (await reopened.read(AuditQuery()))[0]
    result = await reopened.verify()

    assert record.seal is not None
    assert loaded.seal is not None
    assert loaded.seal.signature == record.seal.signature
    assert result.valid
    assert result.signatures_checked == 1


@pytest.mark.asyncio
async def test_signed_database_requires_verifier_for_validation(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    signer = DeterministicSigner()
    key = KeyRef("audit")
    store = SQLiteAuditStore(path, signer=signer, signing_key=key)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    result = await SQLiteAuditStore(path).verify()
    assert not result.valid
    assert result.reason == "signature verifier unavailable"


@pytest.mark.asyncio
async def test_close_blocks_append_but_preserves_forensic_reads(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    assert store.closed
    assert len(await store.read(AuditQuery())) == 1
    assert (await store.verify()).valid
    assert (await store.snapshot()).closed
    with pytest.raises(AuditStoreClosedError):
        await store.append(fact(2), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))


@pytest.mark.asyncio
async def test_duplicate_event_id_is_rejected_transactionally(tmp_path: Path) -> None:
    store = SQLiteAuditStore(tmp_path / "ledger.sqlite3")
    event = fact(1)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await store.append(event, recorded_at=now)

    with pytest.raises(AuditPersistenceError, match="rejected"):
        await store.append(event, recorded_at=now + timedelta(seconds=1))

    snapshot = await store.snapshot()
    assert snapshot.records == 1
    assert (await store.verify()).valid


def test_sqlite_store_validates_durable_path_and_signing_configuration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="durable file"):
        SQLiteAuditStore(":memory:")
    with pytest.raises(ValueError, match="directory"):
        SQLiteAuditStore(tmp_path)
    with pytest.raises(ValueError, match="together"):
        SQLiteAuditStore(tmp_path / "ledger.sqlite3", signer=DeterministicSigner())
    with pytest.raises(ValueError, match="negative"):
        SQLiteAuditStore(tmp_path / "ledger.sqlite3", busy_timeout_ms=-1)


@pytest.mark.asyncio
async def test_unsupported_schema_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()

    store = SQLiteAuditStore(path)
    with pytest.raises(AuditSchemaError, match="unsupported"):
        await store.snapshot()


@pytest.mark.asyncio
async def test_sqlite_guards_reject_sequence_gaps_and_broken_links(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = SQLiteAuditStore(path)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    columns = """
        sequence, event_id, name, source, category, action, resource, actor, outcome, severity,
        details_json, occurred_at, correlation_id, causation_id, recorded_at, previous_digest,
        digest, seal_key_name, seal_key_provider, seal_key_version, seal_algorithm, seal_signature
    """
    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="contiguous"):
        connection.execute(
            f"""
            INSERT INTO audit_records ({columns})
            SELECT
                3, '00000000-0000-0000-0000-000000000003', name, source, category, action,
                resource, actor, outcome, severity, details_json, occurred_at, correlation_id,
                causation_id, recorded_at, digest, ?, NULL, NULL, NULL, NULL, NULL
            FROM audit_records WHERE sequence = 1
            """,
            ("3" * 64,),
        )
    connection.rollback()

    with pytest.raises(sqlite3.IntegrityError, match="previous digest"):
        connection.execute(
            f"""
            INSERT INTO audit_records ({columns})
            SELECT
                2, '00000000-0000-0000-0000-000000000002', name, source, category, action,
                resource, actor, outcome, severity, details_json, occurred_at, correlation_id,
                causation_id, recorded_at, ?, ?, NULL, NULL, NULL, NULL, NULL
            FROM audit_records WHERE sequence = 1
            """,
            (AUDIT_GENESIS_DIGEST, "2" * 64),
        )
    connection.close()
