import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os import (
    AUDIT_GENESIS_DIGEST,
    AuditArchiveCompression,
    AuditArchiveError,
    AuditArchiveExistsError,
    AuditArchiveManager,
    AuditCategory,
    AuditEvent,
    AuditRetentionConfirmationError,
    AuditRetentionPlan,
    AuditRetentionPolicy,
    InMemoryAuditStore,
    KeyRef,
)


class DeterministicSigner:
    def sign(self, digest: bytes, *, key: KeyRef) -> bytes:
        return hashlib.sha256(digest + key.canonical.encode()).digest()

    async def verify(self, digest: bytes, signature: bytes, *, key: KeyRef) -> bool:
        return signature == self.sign(digest, key=key)


def fact(index: int) -> AuditEvent:
    return AuditEvent(
        id=UUID(int=index),
        name="security.changed",
        source="phoenix.test",
        category=AuditCategory.SYSTEM,
        action="security.change",
        resource=f"system:item/{index}",
        actor="tester",
        details={"index": index, "password": "never-store-this"},
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index),
        correlation_id=f"corr-{index}",
    )


def manifest_paths(directory: Path) -> tuple[Path, ...]:
    return tuple(sorted(directory.glob("*.manifest.json")))


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def append_bytes(path: Path, value: bytes) -> None:
    path.write_bytes(path.read_bytes() + value)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


async def populated_store(count: int) -> InMemoryAuditStore:
    store = InMemoryAuditStore()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(1, count + 1):
        await store.append(fact(index), recorded_at=now + timedelta(seconds=index))
    return store


@pytest.mark.asyncio
async def test_export_segment_is_canonical_redacted_and_verifiable(tmp_path: Path) -> None:
    store = await populated_store(3)
    manager = AuditArchiveManager(tmp_path / "archives")

    result = await manager.export_segment(
        store,
        start_sequence=1,
        end_sequence=3,
        compression=AuditArchiveCompression.NONE,
        created_at=datetime(2026, 2, 1, tzinfo=UTC),
    )
    verification = await manager.verify_archive(result.manifest_path)
    payload = read_text(result.artifact_path)

    assert verification.valid
    assert verification.checked_records == 3
    assert result.manifest.anchor_digest == AUDIT_GENESIS_DIGEST
    assert result.manifest.head_digest == verification.head_digest
    assert '"password":"***"' in payload
    assert "never-store-this" not in payload


@pytest.mark.asyncio
async def test_gzip_archive_bytes_are_deterministic_for_same_records(tmp_path: Path) -> None:
    first_store = await populated_store(2)
    second_store = await populated_store(2)
    first = AuditArchiveManager(tmp_path / "first")
    second = AuditArchiveManager(tmp_path / "second")
    created_at = datetime(2026, 2, 1, tzinfo=UTC)

    first_result = await first.export_segment(
        first_store,
        start_sequence=1,
        end_sequence=2,
        created_at=created_at,
    )
    second_result = await second.export_segment(
        second_store,
        start_sequence=1,
        end_sequence=2,
        created_at=created_at,
    )

    assert read_bytes(first_result.artifact_path) == read_bytes(second_result.artifact_path)
    assert first_result.manifest.payload_digest == second_result.manifest.payload_digest
    assert first_result.manifest.artifact_digest == second_result.manifest.artifact_digest


@pytest.mark.asyncio
async def test_rotate_exports_full_segments_and_optional_partial(tmp_path: Path) -> None:
    store = await populated_store(5)
    manager = AuditArchiveManager(tmp_path)

    full = await manager.rotate(store, segment_records=2)
    partial = await manager.rotate(store, segment_records=2, include_partial=True)

    assert [(item.manifest.first_sequence, item.manifest.last_sequence) for item in full] == [
        (1, 2),
        (3, 4),
    ]
    assert [(item.manifest.first_sequence, item.manifest.last_sequence) for item in partial] == [
        (5, 5)
    ]
    chain = await manager.verify_chain()
    assert chain.valid
    assert chain.checked_archives == 3
    assert chain.checked_records == 5


@pytest.mark.asyncio
async def test_second_segment_requires_sequence_and_hash_continuity(tmp_path: Path) -> None:
    store = await populated_store(4)
    manager = AuditArchiveManager(tmp_path)
    await manager.export_segment(store, start_sequence=1, end_sequence=2)

    with pytest.raises(AuditArchiveError, match="immediately"):
        await manager.export_segment(store, start_sequence=4, end_sequence=4)


@pytest.mark.asyncio
async def test_export_rejects_incomplete_range(tmp_path: Path) -> None:
    store = await populated_store(2)
    manager = AuditArchiveManager(tmp_path)

    with pytest.raises(AuditArchiveError, match="incomplete"):
        await manager.export_segment(store, start_sequence=1, end_sequence=3)


@pytest.mark.asyncio
async def test_export_never_overwrites_existing_bundle(tmp_path: Path) -> None:
    store = await populated_store(1)
    manager = AuditArchiveManager(tmp_path)
    await manager.export_segment(store, start_sequence=1, end_sequence=1)

    with pytest.raises(AuditArchiveExistsError):
        await manager.export_segment(store, start_sequence=1, end_sequence=1)


@pytest.mark.asyncio
async def test_verification_detects_artifact_tampering(tmp_path: Path) -> None:
    store = await populated_store(1)
    manager = AuditArchiveManager(tmp_path)
    result = await manager.export_segment(store, start_sequence=1, end_sequence=1)
    append_bytes(result.artifact_path, b"tampered")

    verification = await manager.verify_archive(result.manifest_path)

    assert not verification.valid
    assert verification.reason == "archive artifact digest mismatch"


@pytest.mark.asyncio
async def test_verification_detects_manifest_tampering(tmp_path: Path) -> None:
    store = await populated_store(1)
    manager = AuditArchiveManager(tmp_path)
    result = await manager.export_segment(store, start_sequence=1, end_sequence=1)
    document = read_json(result.manifest_path)
    document["head_digest"] = "f" * 64
    write_json(result.manifest_path, document)

    verification = await manager.verify_archive(result.manifest_path)

    assert not verification.valid
    assert verification.reason == "manifest digest mismatch"


@pytest.mark.asyncio
async def test_chain_verification_detects_manifest_link_break(tmp_path: Path) -> None:
    store = await populated_store(2)
    manager = AuditArchiveManager(tmp_path)
    await manager.rotate(store, segment_records=1, include_partial=True)
    second_path = manifest_paths(tmp_path)[1]
    document = read_json(second_path)
    document["previous_manifest_digest"] = AUDIT_GENESIS_DIGEST
    write_json(second_path, document)

    verification = await manager.verify_chain()

    assert not verification.valid
    assert verification.reason == "manifest chain continuity mismatch"


@pytest.mark.asyncio
async def test_signed_archive_requires_and_uses_external_verifier(tmp_path: Path) -> None:
    signer = DeterministicSigner()
    key = KeyRef("audit", "test-kms", 1)
    store = InMemoryAuditStore(signer=signer, signing_key=key)
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    manager = AuditArchiveManager(tmp_path)
    result = await manager.export_segment(store, start_sequence=1, end_sequence=1)

    unavailable = await manager.verify_archive(result.manifest_path)
    verified = await manager.verify_archive(result.manifest_path, signer=signer)

    assert not unavailable.valid
    assert unavailable.reason == "signature verifier unavailable"
    assert verified.valid
    assert verified.signatures_checked == 1


@pytest.mark.asyncio
async def test_retention_plan_is_non_destructive_until_exact_confirmation(tmp_path: Path) -> None:
    store = await populated_store(3)
    manager = AuditArchiveManager(tmp_path)
    await manager.rotate(store, segment_records=1, include_partial=True)
    plan = manager.plan_retention(
        AuditRetentionPolicy(keep_last=1),
        now=datetime(2026, 3, 1, tzinfo=UTC),
    )

    assert len(plan.delete_archive_ids) == 2
    assert len(manifest_paths(tmp_path)) == 3
    with pytest.raises(AuditRetentionConfirmationError, match="does not match"):
        await manager.apply_retention(plan, confirmation_digest=AUDIT_GENESIS_DIGEST)
    assert len(manifest_paths(tmp_path)) == 3


@pytest.mark.asyncio
async def test_confirmed_retention_deletes_only_oldest_prefix(tmp_path: Path) -> None:
    store = await populated_store(3)
    manager = AuditArchiveManager(tmp_path)
    await manager.rotate(store, segment_records=1, include_partial=True)
    plan = manager.plan_retention(
        AuditRetentionPolicy(keep_last=1),
        now=datetime(2026, 3, 1, tzinfo=UTC),
    )

    result = await manager.apply_retention(plan, confirmation_digest=plan.digest)
    verification = await manager.verify_chain()

    assert result.deleted_archive_ids == plan.delete_archive_ids
    assert len(manifest_paths(tmp_path)) == 1
    assert verification.valid
    assert verification.checked_records == 1


@pytest.mark.asyncio
async def test_protected_archive_stops_prefix_retention(tmp_path: Path) -> None:
    store = await populated_store(4)
    manager = AuditArchiveManager(tmp_path)
    archives = await manager.rotate(store, segment_records=1, include_partial=True)
    protected = archives[1].manifest.archive_id

    plan = manager.plan_retention(
        AuditRetentionPolicy(keep_last=1, protected_archive_ids=frozenset({protected})),
        now=datetime(2026, 3, 1, tzinfo=UTC),
    )

    assert plan.delete_archive_ids == (archives[0].manifest.archive_id,)
    assert protected in plan.retain_archive_ids
    assert archives[2].manifest.archive_id in plan.retain_archive_ids


@pytest.mark.asyncio
async def test_max_age_prevents_new_archive_deletion(tmp_path: Path) -> None:
    store = await populated_store(2)
    manager = AuditArchiveManager(tmp_path)
    await manager.export_segment(
        store,
        start_sequence=1,
        end_sequence=1,
        created_at=datetime(2026, 2, 20, tzinfo=UTC),
    )
    await manager.export_segment(
        store,
        start_sequence=2,
        end_sequence=2,
        created_at=datetime(2026, 2, 28, tzinfo=UTC),
    )

    plan = manager.plan_retention(
        AuditRetentionPolicy(keep_last=0, max_age=timedelta(days=5)),
        now=datetime(2026, 3, 1, tzinfo=UTC),
    )

    assert len(plan.delete_archive_ids) == 1
    assert len(plan.retain_archive_ids) == 1


def test_archive_contracts_validate_policy_and_plan_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="negative"):
        AuditRetentionPolicy(keep_last=-1)
    with pytest.raises(ValueError, match="positive"):
        AuditRetentionPolicy(max_age=timedelta(0))
    with pytest.raises(ValueError, match="timezone-aware"):
        AuditRetentionPlan(datetime(2026, 1, 1), (), (), 0, AUDIT_GENESIS_DIGEST)
    with pytest.raises(ValueError, match="directory"):
        file_path = tmp_path / "file"
        file_path.write_text("x", encoding="utf-8")
        AuditArchiveManager(file_path)
