from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    InMemoryAgentMemoryStore,
    MemoryDeleteRequest,
    MemoryId,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordIncarnation,
    MemoryRecordStatus,
    MemoryRecordVersion,
    MemoryRetentionPolicy,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemoryWriteRequest,
    StateStoreMemoryStore,
    memory_content_digest,
)
from phoenix_os.state import MemoryStateStore, StateKey

_NOW = datetime(2026, 8, 12, 3, tzinfo=UTC)


class FakeClock:
    def __init__(self, now: datetime = _NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _scope(scope_id: str = "agent-alpha") -> MemoryScope:
    return MemoryScope(
        namespace=MemoryNamespace("assistant"),
        kind=MemoryScopeKind.AGENT,
        scope_id=MemoryScopeId(scope_id),
    )


def _memory_id(value: int = 1) -> MemoryId:
    return MemoryId(UUID(int=value))


def _request(
    content: str,
    *,
    scope: MemoryScope | None = None,
    memory_id: MemoryId | None = None,
    expected_version: MemoryRecordVersion | None = None,
    expected_incarnation: MemoryRecordIncarnation | None = None,
    created_at: datetime = _NOW,
) -> MemoryWriteRequest:
    digest = memory_content_digest(content)
    return MemoryWriteRequest(
        scope=_scope() if scope is None else scope,
        memory_id=_memory_id() if memory_id is None else memory_id,
        content=content,
        provenance=MemoryProvenance(
            origin=MemoryOriginKind.USER_INPUT,
            content_digest=digest,
            created_at=created_at,
            attributes={"source": "test"},
        ),
        metadata={"kind": "note"},
        expected_version=expected_version,
        expected_incarnation=expected_incarnation,
        created_at=created_at,
    )


def _read(
    *,
    scope: MemoryScope | None = None,
    memory_id: MemoryId | None = None,
    expected_version: MemoryRecordVersion | None = None,
    expected_incarnation: MemoryRecordIncarnation | None = None,
) -> MemoryReadRequest:
    return MemoryReadRequest(
        scope=_scope() if scope is None else scope,
        memory_id=_memory_id() if memory_id is None else memory_id,
        expected_version=expected_version,
        expected_incarnation=expected_incarnation,
        created_at=_NOW,
    )


@pytest.mark.asyncio
async def test_authoritative_store_creates_and_reads_exact_record() -> None:
    clock = FakeClock()
    store = InMemoryAgentMemoryStore(clock=clock)

    created = await store.write(_request("remember the blue folder"))
    loaded = await store.read(_read())

    assert loaded == created
    assert created.incarnation.value.version == 4
    assert created.version == MemoryRecordVersion(1)
    assert created.status is MemoryRecordStatus.ACTIVE
    assert created.content_digest == memory_content_digest("remember the blue folder")
    assert created.created_at == _NOW
    assert created.updated_at == _NOW
    assert created.expires_at == _NOW + store.limits.retention.record_ttl
    assert created.metadata == {"kind": "note"}


@pytest.mark.asyncio
async def test_exact_version_read_rejects_stale_or_missing_record() -> None:
    store = InMemoryAgentMemoryStore(clock=FakeClock())
    created = await store.write(_request("version-bound"))

    assert (
        await store.read(
            _read(
                expected_version=created.version,
                expected_incarnation=created.incarnation,
            )
        )
        == created
    )

    with pytest.raises(AgentStateConflictError):
        await store.read(
            _read(
                expected_version=created.version.next(),
                expected_incarnation=created.incarnation,
            )
        )
    with pytest.raises(AgentStateConflictError):
        await store.read(
            _read(
                memory_id=_memory_id(2),
                expected_version=MemoryRecordVersion(),
                expected_incarnation=MemoryRecordIncarnation(UUID(int=99)),
            )
        )


@pytest.mark.asyncio
async def test_cross_scope_substitution_returns_no_record() -> None:
    store = InMemoryAgentMemoryStore(clock=FakeClock())
    memory_id = _memory_id()
    await store.write(_request("isolated", memory_id=memory_id))

    assert (
        await store.read(
            _read(
                scope=_scope("agent-beta"),
                memory_id=memory_id,
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_update_requires_exact_logical_version_and_preserves_identity() -> None:
    clock = FakeClock()
    store = InMemoryAgentMemoryStore(clock=clock)
    created = await store.write(_request("first"))

    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _request(
            "second",
            memory_id=created.memory_id,
            expected_version=created.version,
            expected_incarnation=created.incarnation,
            created_at=clock(),
        )
    )

    assert updated.memory_id == created.memory_id
    assert updated.scope == created.scope
    assert updated.incarnation == created.incarnation
    assert updated.version == created.version.next()
    assert updated.created_at == created.created_at
    assert updated.updated_at == clock()
    assert updated.content == "second"

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _request(
                "stale",
                memory_id=created.memory_id,
                expected_version=created.version,
                expected_incarnation=created.incarnation,
                created_at=clock(),
            )
        )


@pytest.mark.asyncio
async def test_duplicate_create_fails_closed() -> None:
    store = InMemoryAgentMemoryStore(clock=FakeClock())
    request = _request("first")
    await store.write(request)

    with pytest.raises(AgentStateConflictError):
        await store.write(_request("replacement", memory_id=request.memory_id))


@pytest.mark.asyncio
async def test_concurrent_updates_allow_only_one_winner() -> None:
    clock = FakeClock()
    store = InMemoryAgentMemoryStore(clock=clock)
    created = await store.write(_request("base"))
    clock.advance(timedelta(seconds=1))

    results = await asyncio.gather(
        store.write(
            _request(
                "left",
                memory_id=created.memory_id,
                expected_version=created.version,
                expected_incarnation=created.incarnation,
                created_at=clock(),
            )
        ),
        store.write(
            _request(
                "right",
                memory_id=created.memory_id,
                expected_version=created.version,
                expected_incarnation=created.incarnation,
                created_at=clock(),
            )
        ),
        return_exceptions=True,
    )

    winners = [item for item in results if isinstance(item, MemoryRecord)]
    conflicts = [item for item in results if isinstance(item, AgentStateConflictError)]
    assert len(winners) == 1
    assert len(conflicts) == 1


@pytest.mark.asyncio
async def test_configured_record_byte_limit_is_enforced() -> None:
    limits = MemoryLimits(
        max_record_bytes=4,
        max_total_bytes_per_scope=16,
    )
    store = InMemoryAgentMemoryStore(limits=limits, clock=FakeClock())

    with pytest.raises(AgentLimitExceededError):
        await store.write(_request("12345"))


@pytest.mark.asyncio
async def test_scope_record_count_limit_is_atomic() -> None:
    limits = MemoryLimits(
        max_records_per_scope=1,
        max_context_items=1,
    )
    store = InMemoryAgentMemoryStore(limits=limits, clock=FakeClock())
    await store.write(_request("one", memory_id=_memory_id(1)))

    with pytest.raises(AgentLimitExceededError):
        await store.write(_request("two", memory_id=_memory_id(2)))

    assert len(await store.list_scope(_scope())) == 1


@pytest.mark.asyncio
async def test_scope_total_byte_limit_is_enforced() -> None:
    limits = MemoryLimits(
        max_record_bytes=8,
        max_total_bytes_per_scope=8,
    )
    store = InMemoryAgentMemoryStore(limits=limits, clock=FakeClock())
    await store.write(_request("1234", memory_id=_memory_id(1)))

    with pytest.raises(AgentLimitExceededError):
        await store.write(_request("56789", memory_id=_memory_id(2)))


@pytest.mark.asyncio
async def test_expired_record_is_absent_from_read_and_listing() -> None:
    clock = FakeClock()
    limits = MemoryLimits(
        retention=MemoryRetentionPolicy(
            record_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    store = InMemoryAgentMemoryStore(limits=limits, clock=clock)
    created = await store.write(_request("short lived"))

    clock.advance(timedelta(seconds=11))

    assert await store.read(_read()) is None
    with pytest.raises(AgentStateConflictError):
        await store.read(
            _read(
                expected_version=created.version,
                expected_incarnation=created.incarnation,
            )
        )
    assert await store.list_scope(_scope()) == ()


@pytest.mark.asyncio
async def test_expired_identity_cannot_be_recreated_during_retention_window() -> None:
    clock = FakeClock()
    limits = MemoryLimits(
        retention=MemoryRetentionPolicy(
            record_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    store = InMemoryAgentMemoryStore(limits=limits, clock=clock)
    created = await store.write(_request("short lived"))
    clock.advance(timedelta(seconds=11))

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _request(
                "resurrect",
                memory_id=created.memory_id,
                created_at=clock(),
            )
        )


@pytest.mark.asyncio
async def test_purge_turns_expired_content_into_content_free_tombstone() -> None:
    clock = FakeClock()
    limits = MemoryLimits(
        retention=MemoryRetentionPolicy(
            record_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, limits=limits, clock=clock)
    await store.write(_request("delete this after ttl"))
    clock.advance(timedelta(seconds=11))

    assert await store.purge_expired(_scope()) == 1
    assert await store.read(_read()) is None

    raw = await backing.list(namespace="agent-memory")
    assert len(raw) == 1
    assert isinstance(raw[0].value, dict)
    document = raw[0].value
    assert document["status"] == "tombstoned"
    assert document["content"] is None
    assert document["metadata"] == {}
    assert document["provenance"] is None
    assert document["content_digest"] == memory_content_digest("delete this after ttl")


@pytest.mark.asyncio
async def test_explicit_delete_is_versioned_and_prevents_stale_resurrection() -> None:
    clock = FakeClock()
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, clock=clock)
    created = await store.write(_request("erase me"))

    clock.advance(timedelta(seconds=1))
    await store.delete(
        MemoryDeleteRequest(
            scope=created.scope,
            memory_id=created.memory_id,
            expected_version=created.version,
            expected_incarnation=created.incarnation,
            created_at=clock(),
        )
    )

    assert await store.read(_read(memory_id=created.memory_id)) is None
    with pytest.raises(AgentStateConflictError):
        await store.read(
            _read(
                memory_id=created.memory_id,
                expected_version=created.version,
                expected_incarnation=created.incarnation,
            )
        )

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _request(
                "stale resurrection",
                memory_id=created.memory_id,
                expected_version=created.version,
                expected_incarnation=created.incarnation,
                created_at=clock(),
            )
        )

    raw = await backing.list(namespace="agent-memory")
    assert len(raw) == 1
    assert isinstance(raw[0].value, dict)
    document = raw[0].value
    assert document["version"] == created.version.next().value
    assert document["status"] == "tombstoned"
    assert document["content"] is None


@pytest.mark.asyncio
async def test_delete_with_stale_version_fails_without_mutation() -> None:
    store = InMemoryAgentMemoryStore(clock=FakeClock())
    created = await store.write(_request("keep me"))

    with pytest.raises(AgentStateConflictError):
        await store.delete(
            MemoryDeleteRequest(
                scope=created.scope,
                memory_id=created.memory_id,
                expected_version=created.version.next(),
                expected_incarnation=created.incarnation,
                created_at=_NOW,
            )
        )

    assert await store.read(_read()) == created


@pytest.mark.asyncio
async def test_tombstone_retention_is_finite_in_backing_state_store() -> None:
    clock = FakeClock()
    limits = MemoryLimits(
        retention=MemoryRetentionPolicy(
            record_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, limits=limits, clock=clock)
    created = await store.write(_request("erase me"))
    await store.delete(
        MemoryDeleteRequest(
            scope=created.scope,
            memory_id=created.memory_id,
            expected_version=created.version,
            expected_incarnation=created.incarnation,
            created_at=clock(),
        )
    )

    clock.advance(timedelta(seconds=31))

    assert await backing.list(namespace="agent-memory") == ()
    assert await store.read(_read(memory_id=created.memory_id)) is None


@pytest.mark.asyncio
async def test_snapshot_restore_does_not_resurrect_tombstoned_memory() -> None:
    clock = FakeClock()
    source = MemoryStateStore(clock=clock)
    source_store = StateStoreMemoryStore(source, clock=clock)
    created = await source_store.write(_request("erase me"))
    await source_store.delete(
        MemoryDeleteRequest(
            scope=created.scope,
            memory_id=created.memory_id,
            expected_version=created.version,
            expected_incarnation=created.incarnation,
            created_at=clock(),
        )
    )
    snapshot = await source.snapshot()

    restored_backing = MemoryStateStore(clock=clock)
    await restored_backing.restore(snapshot)
    restored = StateStoreMemoryStore(restored_backing, clock=clock)

    assert await restored.read(_read(memory_id=created.memory_id)) is None
    with pytest.raises(AgentStateConflictError):
        await restored.write(
            _request(
                "stale resurrection",
                memory_id=created.memory_id,
                created_at=clock(),
            )
        )


@pytest.mark.asyncio
async def test_state_store_backed_wrapper_survives_wrapper_restart() -> None:
    clock = FakeClock()
    backing = MemoryStateStore(clock=clock)
    first = StateStoreMemoryStore(backing, clock=clock)
    created = await first.write(_request("persisted"))
    await first.close()

    assert not backing.closed

    second = StateStoreMemoryStore(backing, clock=clock)
    assert await second.read(_read(memory_id=created.memory_id)) == created


@pytest.mark.asyncio
async def test_persisted_unknown_schema_fails_closed() -> None:
    clock = FakeClock()
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, clock=clock)
    await store.write(_request("persisted"))

    stored = (await backing.list(namespace="agent-memory"))[0]
    assert isinstance(stored.value, dict)
    corrupt = dict(stored.value)
    corrupt["schema_version"] = 999
    key = StateKey(stored.key.namespace, stored.key.name, dict)
    await backing.put(key, corrupt, expected_version=stored.version)

    with pytest.raises(AgentCodecError, match="memory document"):
        await store.read(_read())


@pytest.mark.asyncio
async def test_persisted_scope_substitution_fails_closed() -> None:
    clock = FakeClock()
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, clock=clock)
    await store.write(_request("persisted"))

    stored = (await backing.list(namespace="agent-memory"))[0]
    assert isinstance(stored.value, dict)
    corrupt = dict(stored.value)
    corrupt["scope_id"] = "agent-beta"
    key = StateKey(stored.key.namespace, stored.key.name, dict)
    await backing.put(key, corrupt, expected_version=stored.version)

    with pytest.raises(AgentCodecError, match="memory document"):
        await store.read(_read())


@pytest.mark.asyncio
async def test_state_keys_are_content_free_scope_digests() -> None:
    backing = MemoryStateStore(clock=FakeClock())
    store = StateStoreMemoryStore(backing, clock=FakeClock())
    await store.write(_request("highly sensitive remembered text"))

    stored = (await backing.list(namespace="agent-memory"))[0]
    assert "highly" not in stored.key.canonical
    assert "assistant" not in stored.key.canonical
    assert "agent-alpha" not in stored.key.canonical
    assert stored.key.name.startswith("record.")
    assert len(stored.key.name.split(".")[1]) == 64


@pytest.mark.asyncio
async def test_list_scope_is_deterministic_and_bounded() -> None:
    store = InMemoryAgentMemoryStore(clock=FakeClock())
    await store.write(_request("three", memory_id=_memory_id(3)))
    await store.write(_request("one", memory_id=_memory_id(1)))
    await store.write(_request("two", memory_id=_memory_id(2)))

    listed = await store.list_scope(_scope(), limit=2)

    assert [record.memory_id for record in listed] == [_memory_id(1), _memory_id(2)]
    with pytest.raises(ValueError, match="configured memory bounds"):
        await store.list_scope(_scope(), limit=store.limits.max_records_per_scope + 1)


@pytest.mark.asyncio
async def test_owned_in_memory_store_closes_fail_closed() -> None:
    store = InMemoryAgentMemoryStore(clock=FakeClock())
    await store.close()
    assert store.closed

    with pytest.raises(AgentServiceUnavailableError):
        await store.read(_read())


def test_active_memory_record_validates_digest_and_is_frozen() -> None:
    content = "immutable"
    digest = memory_content_digest(content)
    record = MemoryRecord(
        scope=_scope(),
        memory_id=_memory_id(),
        incarnation=MemoryRecordIncarnation(),
        version=MemoryRecordVersion(),
        status=MemoryRecordStatus.ACTIVE,
        content_digest=digest,
        created_at=_NOW,
        updated_at=_NOW,
        expires_at=_NOW + timedelta(days=1),
        content=content,
        provenance=MemoryProvenance(
            origin=MemoryOriginKind.USER_INPUT,
            content_digest=digest,
            created_at=_NOW,
        ),
        metadata={"kind": "note"},
    )

    assert record.content_bytes == len(content.encode("utf-8"))
    assert not record.expired(now=_NOW)

    with pytest.raises(FrozenInstanceError):
        record.content = "changed"  # type: ignore[misc]


def test_tombstone_contract_rejects_retained_content() -> None:
    with pytest.raises(ValueError, match="cannot retain content"):
        MemoryRecord(
            scope=_scope(),
            memory_id=_memory_id(),
            incarnation=MemoryRecordIncarnation(),
            version=MemoryRecordVersion(2),
            status=MemoryRecordStatus.TOMBSTONED,
            content_digest=memory_content_digest("former"),
            created_at=_NOW,
            updated_at=_NOW + timedelta(seconds=1),
            expires_at=_NOW + timedelta(days=1),
            content="former",
            deleted_at=_NOW + timedelta(seconds=1),
        )


@pytest.mark.asyncio
async def test_legacy_v1_record_gets_stable_synthetic_incarnation_and_upgrades_on_write() -> None:
    clock = FakeClock()
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, clock=clock)
    created = await store.write(_request("legacy"))
    stored = (await backing.list(namespace="agent-memory"))[0]
    assert isinstance(stored.value, dict)

    legacy_document = dict(stored.value)
    legacy_document["schema_version"] = 1
    legacy_document.pop("incarnation")
    key = StateKey(stored.key.namespace, stored.key.name, dict)
    await backing.put(key, legacy_document, expected_version=stored.version)

    first_read = await store.read(_read(memory_id=created.memory_id))
    second_read = await store.read(_read(memory_id=created.memory_id))
    assert first_read is not None
    assert second_read is not None
    assert first_read.incarnation == second_read.incarnation
    assert first_read.incarnation.value.version == 5

    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _request(
            "legacy updated",
            memory_id=first_read.memory_id,
            expected_version=first_read.version,
            expected_incarnation=first_read.incarnation,
            created_at=clock(),
        )
    )
    assert updated.incarnation == first_read.incarnation

    upgraded = (await backing.list(namespace="agent-memory"))[0]
    assert isinstance(upgraded.value, dict)
    assert upgraded.value["schema_version"] == 2
    assert upgraded.value["incarnation"] == str(first_read.incarnation)


@pytest.mark.asyncio
async def test_rebirth_gets_new_incarnation_and_rejects_predecessor_bindings() -> None:
    clock = FakeClock()
    limits = MemoryLimits(
        retention=MemoryRetentionPolicy(
            record_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=10),
        )
    )
    backing = MemoryStateStore(clock=clock)
    store = StateStoreMemoryStore(backing, limits=limits, clock=clock)
    first = await store.write(_request("same bytes"))

    await store.delete(
        MemoryDeleteRequest(
            scope=first.scope,
            memory_id=first.memory_id,
            expected_version=first.version,
            expected_incarnation=first.incarnation,
            created_at=clock(),
        )
    )
    clock.advance(timedelta(seconds=11))
    assert await backing.list(namespace="agent-memory") == ()

    reborn = await store.write(
        _request(
            "same bytes",
            memory_id=first.memory_id,
            created_at=clock(),
        )
    )
    assert reborn.memory_id == first.memory_id
    assert reborn.version == first.version
    assert reborn.content_digest == first.content_digest
    assert reborn.incarnation != first.incarnation

    stale_read = MemoryReadRequest(
        scope=first.scope,
        memory_id=first.memory_id,
        expected_version=first.version,
        expected_incarnation=first.incarnation,
        created_at=clock(),
    )
    with pytest.raises(AgentStateConflictError):
        await store.read(stale_read)

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _request(
                "predecessor update",
                memory_id=first.memory_id,
                expected_version=first.version,
                expected_incarnation=first.incarnation,
                created_at=clock(),
            )
        )

    with pytest.raises(AgentStateConflictError):
        await store.delete(
            MemoryDeleteRequest(
                scope=first.scope,
                memory_id=first.memory_id,
                expected_version=first.version,
                expected_incarnation=first.incarnation,
                created_at=clock(),
            )
        )

    assert (
        await store.read(
            _read(
                memory_id=reborn.memory_id,
                expected_version=reborn.version,
                expected_incarnation=reborn.incarnation,
            )
        )
        == reborn
    )
