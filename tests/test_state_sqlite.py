from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phoenix_os.agent.durable_sqlite import SQLiteDurableRunStore
from phoenix_os.state import ABSENT_VERSION, RestoreMode, StateKey
from phoenix_os.state.errors import StateConflictError
from phoenix_os.state.sqlite import SQLiteStateStore


@pytest.mark.asyncio
async def test_sqlite_state_store_persists_versions_and_values(tmp_path: Path) -> None:
    path = tmp_path / "durable.sqlite3"
    key: StateKey[dict[str, bool]] = StateKey("runtime", "operator")
    first_store = SQLiteStateStore(path)
    first = await first_store.put(key, {"ready": True}, expected_version=ABSENT_VERSION)
    await first_store.close()

    restarted = SQLiteStateStore(path)
    try:
        current = await restarted.get(key)
        assert current is not None
        assert current.value == {"ready": True}
        assert current.version == first.version
        updated = await restarted.put(key, {"ready": False}, expected_version=current.version)
        assert updated.version > current.version
    finally:
        await restarted.close()


@pytest.mark.asyncio
async def test_sqlite_state_store_rejects_stale_expected_version(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "durable.sqlite3")
    key: StateKey[int] = StateKey("runtime", "versioned")
    try:
        current = await store.put(key, 1, expected_version=ABSENT_VERSION)
        with pytest.raises(StateConflictError):
            await store.put(key, 2, expected_version=current.version + 1)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_state_store_transaction_is_atomic(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "durable.sqlite3")
    one: StateKey[str] = StateKey("tx", "one")
    two: StateKey[str] = StateKey("tx", "two")
    try:
        async with store.transaction() as transaction:
            await transaction.put(one, "a", expected_version=ABSENT_VERSION)
            await transaction.put(two, "b", expected_version=ABSENT_VERSION)
        assert (await store.get(one)).value == "a"  # type: ignore[union-attr]
        assert (await store.get(two)).value == "b"  # type: ignore[union-attr]

        with pytest.raises(RuntimeError):
            async with store.transaction() as transaction:
                await transaction.put(one, "rolled-back")
                raise RuntimeError("rollback")
        assert (await store.get(one)).value == "a"  # type: ignore[union-attr]
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_state_store_ttl_purge(tmp_path: Path) -> None:
    now = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
    clock_value = [now]
    store = SQLiteStateStore(
        tmp_path / "durable.sqlite3",
        clock=lambda: clock_value[0],
    )
    key: StateKey[str] = StateKey("ttl", "temporary")
    try:
        await store.put(key, "value", ttl=timedelta(seconds=5))
        clock_value[0] = now + timedelta(seconds=6)
        assert await store.get(key) is None
        stats = await store.stats()
        assert stats.expirations == 1
        assert stats.records == 0
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_state_store_snapshot_restore(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "durable.sqlite3")
    first: StateKey[dict[str, int]] = StateKey("snapshot", "first")
    second: StateKey[dict[str, int]] = StateKey("snapshot", "second")
    try:
        await store.put(first, {"value": 1})
        snapshot = await store.snapshot()
        await store.put(second, {"value": 2})
        restored = await store.restore(snapshot, mode=RestoreMode.REPLACE)
        assert restored == 1
        assert (await store.get(first)).value == {"value": 1}  # type: ignore[union-attr]
        assert await store.get(second) is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_generic_state_coexists_with_durable_agent_sqlite_without_user_version_ownership(
    tmp_path: Path,
) -> None:
    path = tmp_path / "durable.sqlite3"
    durable = SQLiteDurableRunStore(path)
    try:
        identity = await durable.resolve_checkout_registration_identity(
            registration_key="a" * 64,
            registration_digest="b" * 64,
        )
        assert identity.generation == 1
    finally:
        await durable.close()

    with sqlite3.connect(path) as connection:
        before = int(connection.execute("PRAGMA user_version").fetchone()[0])

    state = SQLiteStateStore(path)
    try:
        await state.put(StateKey("coexist", "value"), {"ok": True})
    finally:
        await state.close()

    with sqlite3.connect(path) as connection:
        after = int(connection.execute("PRAGMA user_version").fetchone()[0])
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert after == before
    assert "phoenix_state_meta" in tables
    assert "phoenix_state_records" in tables
    assert "durable_runs" in tables
