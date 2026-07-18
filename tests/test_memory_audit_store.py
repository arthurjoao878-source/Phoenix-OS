import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os import (
    AUDIT_GENESIS_DIGEST,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditStoreClosedError,
    InMemoryAuditStore,
    KeyRef,
)


class DeterministicSigner:
    def sign(self, digest: bytes, *, key: KeyRef) -> bytes:
        return hashlib.sha256(digest + key.canonical.encode()).digest()

    async def verify(self, digest: bytes, signature: bytes, *, key: KeyRef) -> bool:
        return signature == self.sign(digest, key=key)


def fact(index: int, *, outcome: AuditOutcome = AuditOutcome.SUCCEEDED) -> AuditEvent:
    return AuditEvent(
        name="security.changed",
        source="phoenix.test",
        category=AuditCategory.SYSTEM,
        action="security.change",
        resource=f"system:item/{index}",
        actor="tester",
        outcome=outcome,
        details={"index": index},
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index),
    )


@pytest.mark.asyncio
async def test_append_allocates_deterministic_sequence_and_links() -> None:
    store = InMemoryAuditStore()
    first = await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = await store.append(fact(2), recorded_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC))

    assert first.sequence == 1
    assert first.previous_digest == AUDIT_GENESIS_DIGEST
    assert second.sequence == 2
    assert second.previous_digest == first.digest
    assert second.digest != first.digest
    assert (await store.verify()).valid


@pytest.mark.asyncio
async def test_concurrent_appends_remain_contiguous() -> None:
    store = InMemoryAuditStore()
    records = await asyncio.gather(
        *(
            store.append(
                fact(index),
                recorded_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index),
            )
            for index in range(1, 31)
        )
    )
    assert sorted(record.sequence for record in records) == list(range(1, 31))
    stored = await store.read(AuditQuery(limit=1000))
    assert [record.sequence for record in stored] == list(range(1, 31))
    assert (await store.verify()).valid


@pytest.mark.asyncio
async def test_read_applies_filters_and_limit_in_sequence_order() -> None:
    store = InMemoryAuditStore()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await store.append(fact(1), recorded_at=now)
    await store.append(fact(2, outcome=AuditOutcome.DENIED), recorded_at=now)
    await store.append(fact(3, outcome=AuditOutcome.DENIED), recorded_at=now)

    records = await store.read(
        AuditQuery(
            start_sequence=2,
            outcomes=frozenset({AuditOutcome.DENIED}),
            limit=1,
        )
    )
    assert [record.sequence for record in records] == [2]


@pytest.mark.asyncio
async def test_verify_detects_changed_event_content() -> None:
    store = InMemoryAuditStore()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    original = await store.append(fact(1), recorded_at=now)
    store._records[0] = replace(
        original,
        event=replace(original.event, resource="system:tampered"),
    )

    result = await store.verify()
    assert not result.valid
    assert result.failure_sequence == 1
    assert result.checked_records == 1
    assert result.reason == "record digest mismatch"


@pytest.mark.asyncio
async def test_verify_detects_sequence_gap_and_broken_link() -> None:
    store = InMemoryAuditStore()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await store.append(fact(1), recorded_at=now)
    second = await store.append(fact(2), recorded_at=now)
    store._records[1] = replace(second, sequence=4)
    result = await store.verify()
    assert not result.valid
    assert "sequence mismatch" in (result.reason or "")

    store._records[1] = replace(second, previous_digest=AUDIT_GENESIS_DIGEST)
    result = await store.verify()
    assert not result.valid
    assert result.reason == "previous digest link mismatch"


@pytest.mark.asyncio
async def test_optional_external_signatures_are_created_and_verified() -> None:
    signer = DeterministicSigner()
    store = InMemoryAuditStore(
        signer=signer,
        signing_key=KeyRef("audit", "test-kms", 1),
        signing_algorithm="test-sha256",
    )
    record = await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    result = await store.verify()

    assert record.seal is not None
    assert record.seal.algorithm == "test-sha256"
    assert result.valid
    assert result.signatures_checked == 1
    assert (await store.snapshot()).signed_records == 1


@pytest.mark.asyncio
async def test_verify_detects_invalid_external_signature() -> None:
    store = InMemoryAuditStore(
        signer=DeterministicSigner(),
        signing_key=KeyRef("audit"),
    )
    record = await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    assert record.seal is not None
    store._records[0] = replace(
        record,
        seal=replace(record.seal, signature=b"wrong"),
    )
    result = await store.verify()
    assert not result.valid
    assert result.reason == "external signature mismatch"


def test_signer_and_key_must_be_configured_together() -> None:
    with pytest.raises(ValueError, match="together"):
        InMemoryAuditStore(signer=DeterministicSigner())
    with pytest.raises(ValueError, match="together"):
        InMemoryAuditStore(signing_key=KeyRef("audit"))


@pytest.mark.asyncio
async def test_close_blocks_append_but_preserves_read_and_verification() -> None:
    store = InMemoryAuditStore()
    await store.append(fact(1), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
    await store.close()

    assert store.closed
    assert len(await store.read(AuditQuery())) == 1
    assert (await store.verify()).valid
    assert (await store.snapshot()).closed
    with pytest.raises(AuditStoreClosedError):
        await store.append(fact(2), recorded_at=datetime(2026, 1, 1, tzinfo=UTC))
