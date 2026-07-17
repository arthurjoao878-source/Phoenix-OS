import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os import (
    ABSENT_VERSION,
    BusClosedError,
    Event,
    EventBus,
    InMemorySink,
    MemoryStateStore,
    ObservabilityHub,
    RestoreMode,
    StateConflictError,
    StateKey,
    StateOperationContext,
    StateStoreClosedError,
    StateTypeError,
    TransactionState,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.mark.asyncio
async def test_put_get_update_and_stats() -> None:
    store = MemoryStateStore()
    key = StateKey("profile", "arthur", dict)

    created = await store.put(key, {"level": 1}, expected_version=ABSENT_VERSION)
    loaded = await store.get(key)
    updated = await store.put(key, {"level": 2}, expected_version=created.version)

    assert loaded == created
    assert loaded is not None
    assert loaded.value == {"level": 1}
    assert updated.version > created.version
    assert updated.created_at == created.created_at
    assert updated.value == {"level": 2}
    stats = await store.stats()
    assert stats.records == 1
    assert stats.reads == 1
    assert stats.writes == 2


@pytest.mark.asyncio
async def test_typed_key_rejects_mismatched_value_on_read() -> None:
    store = MemoryStateStore()
    untyped = StateKey[object]("profile", "arthur")
    await store.put(untyped, "text")

    with pytest.raises(StateTypeError, match="expected dict"):
        await store.get(StateKey("profile", "arthur", dict))


@pytest.mark.asyncio
async def test_values_are_isolated_by_serialization() -> None:
    store = MemoryStateStore()
    source = {"nested": [1, 2]}
    key = StateKey("cache", "value", dict)
    await store.put(key, source)
    source["nested"].append(3)

    first = await store.get(key)
    second = await store.get(key)
    assert first is not None and second is not None
    assert first.value == {"nested": [1, 2]}
    assert first.value is not second.value


@pytest.mark.asyncio
async def test_optimistic_concurrency_conflicts_are_explicit() -> None:
    store = MemoryStateStore()
    key = StateKey("profile", "arthur", int)
    created = await store.put(key, 1)

    with pytest.raises(StateConflictError) as captured:
        await store.put(key, 2, expected_version=ABSENT_VERSION)
    assert captured.value.actual_version == created.version

    with pytest.raises(StateConflictError):
        await store.put(key, 2, expected_version=created.version + 1)

    stats = await store.stats()
    assert stats.conflicts == 2
    assert (await store.get(key)).value == 1  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_delete_supports_version_checks_and_missing_keys() -> None:
    store = MemoryStateStore()
    key = StateKey[object]("profile", "arthur")
    created = await store.put(key, {"level": 1})

    with pytest.raises(StateConflictError):
        await store.delete(key, expected_version=created.version + 1)
    assert await store.delete(key, expected_version=created.version)
    assert not await store.delete(key)
    assert not await store.delete(key, expected_version=ABSENT_VERSION)
    with pytest.raises(StateConflictError):
        await store.delete(key, expected_version=created.version)


@pytest.mark.asyncio
async def test_list_is_sorted_and_filterable() -> None:
    store = MemoryStateStore()
    await store.put(StateKey("session", "zeta", int), 1)
    await store.put(StateKey("cache", "alpha", int), 2)
    await store.put(StateKey("session", "alpha", int), 3)

    all_records = await store.list()
    session_records = await store.list(namespace="SESSION")
    prefix_records = await store.list(namespace="session", prefix="a")

    assert [record.key.canonical for record in all_records] == [
        "cache:alpha",
        "session:alpha",
        "session:zeta",
    ]
    assert [record.key.name for record in session_records] == ["alpha", "zeta"]
    assert [record.value for record in prefix_records] == [3]


@pytest.mark.asyncio
async def test_ttl_is_enforced_lazily_and_by_purge() -> None:
    clock = FakeClock()
    store = MemoryStateStore(clock=clock)
    first = StateKey("cache", "first", str)
    second = StateKey("cache", "second", str)
    await store.put(first, "a", ttl=timedelta(seconds=10))
    await store.put(second, "b", ttl=timedelta(seconds=20))

    clock.advance(timedelta(seconds=11))
    assert await store.get(first) is None
    assert await store.get(second) is not None
    assert await store.purge_expired() == 0

    clock.advance(timedelta(seconds=10))
    assert await store.purge_expired() == 1
    stats = await store.stats()
    assert stats.expirations == 2
    assert stats.records == 0


@pytest.mark.asyncio
async def test_invalid_ttl_and_expected_version_are_rejected() -> None:
    store = MemoryStateStore()
    key = StateKey("cache", "value", int)

    with pytest.raises(ValueError, match="ttl"):
        await store.put(key, 1, ttl=timedelta(0))
    with pytest.raises(ValueError, match="expected_version"):
        await store.put(key, 1, expected_version=-1)


@pytest.mark.asyncio
async def test_transaction_commits_atomically() -> None:
    store = MemoryStateStore()
    first = StateKey("profile", "first", int)
    second = StateKey("profile", "second", int)

    transaction = store.transaction()
    async with transaction as tx:
        await tx.put(first, 1)
        await tx.put(second, 2)
        assert (await tx.get(first)).value == 1  # type: ignore[union-attr]

    assert transaction.state is TransactionState.COMMITTED
    assert (await store.get(first)).value == 1  # type: ignore[union-attr]
    assert (await store.get(second)).value == 2  # type: ignore[union-attr]
    assert (await store.stats()).transactions == 1


@pytest.mark.asyncio
async def test_transaction_rolls_back_on_failure() -> None:
    store = MemoryStateStore()
    key = StateKey("profile", "arthur", int)
    await store.put(key, 1)
    transaction = store.transaction()

    with pytest.raises(RuntimeError, match="abort"):
        async with transaction as tx:
            await tx.put(key, 2)
            raise RuntimeError("abort")

    assert transaction.state is TransactionState.ROLLED_BACK
    assert (await store.get(key)).value == 1  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_transaction_delete_and_explicit_rollback() -> None:
    store = MemoryStateStore()
    key = StateKey[object]("profile", "arthur")
    await store.put(key, 1)
    tx = store.transaction()
    await tx.__aenter__()
    assert await tx.delete(key)
    await tx.rollback()

    assert tx.state is TransactionState.ROLLED_BACK
    assert await store.get(key) is not None
    with pytest.raises(Exception, match="not open"):
        await tx.commit()


@pytest.mark.asyncio
async def test_snapshot_restore_replace_and_merge_reversion_records() -> None:
    source = MemoryStateStore()
    key = StateKey("profile", "arthur", int)
    original = await source.put(key, 7)
    snapshot = await source.snapshot()

    target = MemoryStateStore()
    await target.put(StateKey("cache", "keep", int), 1)
    assert await target.restore(snapshot, mode=RestoreMode.MERGE) == 1
    assert len(await target.list()) == 2
    restored = await target.get(key)
    assert restored is not None
    assert restored.value == 7
    assert restored.version != original.version or (await target.stats()).revision >= 2

    assert await target.restore(snapshot, mode=RestoreMode.REPLACE) == 1
    assert [record.key.canonical for record in await target.list()] == ["profile:arthur"]


@pytest.mark.asyncio
async def test_events_observability_and_context_are_propagated() -> None:
    events = EventBus()
    observed_events: list[Event] = []
    await events.subscribe("*", observed_events.append)
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))
    store = MemoryStateStore(events=events, observability=hub)
    context = StateOperationContext(correlation_id="corr-7", metadata={"tenant": "acme"})

    await store.put(StateKey("profile", "arthur", int), 1, context=context)

    written = next(event for event in observed_events if event.name == "state.written")
    assert written.correlation_id == "corr-7"
    assert written.metadata == {"tenant": "acme"}
    observations = (await sink.snapshot()).records
    assert any(record.name == "state.put" for record in observations)
    assert any(record.name == "state.written" for record in observations)
    assert any(record.name == "state.operations.total" for record in observations)


@pytest.mark.asyncio
async def test_store_ignores_closed_diagnostic_channels() -> None:
    events = EventBus()
    hub = ObservabilityHub()
    await events.close()
    await hub.close()
    store = MemoryStateStore(events=events, observability=hub)

    record = await store.put(StateKey("profile", "arthur", int), 1)
    assert record.value == 1
    with pytest.raises(BusClosedError):
        await events.emit("test", source="test")


@pytest.mark.asyncio
async def test_close_is_idempotent_and_rejects_operations() -> None:
    store = MemoryStateStore()
    await store.put(StateKey("profile", "arthur", int), 1)
    await store.close()
    await store.close()

    assert store.closed
    assert (await store.stats()).records == 0
    with pytest.raises(StateStoreClosedError):
        await store.get(StateKey("profile", "arthur", int))
    with pytest.raises(StateStoreClosedError):
        store.transaction()


@pytest.mark.asyncio
async def test_transaction_serializes_competing_writer() -> None:
    store = MemoryStateStore()
    key = StateKey("profile", "arthur", int)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def transaction_worker() -> None:
        async with store.transaction() as tx:
            await tx.put(key, 1)
            entered.set()
            await release.wait()

    worker = asyncio.create_task(transaction_worker())
    await entered.wait()
    competing = asyncio.create_task(store.put(key, 2))
    await asyncio.sleep(0)
    assert not competing.done()
    release.set()
    await worker
    updated = await competing
    assert updated.value == 2
