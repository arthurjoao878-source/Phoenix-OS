"""Persistent generic Phoenix StateStore backed by the explicit durable SQLite file."""

from __future__ import annotations

import asyncio
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import cast

from phoenix_os.events import EventBus
from phoenix_os.observability import ObservabilityHub
from phoenix_os.state.codec import JsonStateCodec
from phoenix_os.state.contracts import (
    ABSENT_VERSION,
    RestoreMode,
    StateCodec,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateSnapshot,
    StateStoreStats,
    TransactionState,
)
from phoenix_os.state.errors import (
    StateConflictError,
    StateSnapshotError,
    StateStoreClosedError,
    StateTransactionError,
    StateTypeError,
)

_STORE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
_DEFAULT_STORE_ID = "primary"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("state timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    decoded = datetime.fromisoformat(value)
    if decoded.tzinfo is None or decoded.utcoffset() is None:
        raise StateSnapshotError("persistent state timestamp is invalid")
    return decoded


class SQLiteStateStore:
    """StateStore implementation that coexists with the durable-agent SQLite schema."""

    def __init__(
        self,
        path: str | Path,
        *,
        store_id: str = _DEFAULT_STORE_ID,
        codec: StateCodec | None = None,
        events: EventBus | None = None,
        observability: ObservabilityHub | None = None,
        clock: Callable[[], datetime] = _utc_now,
        source: str = "phoenix.state.sqlite",
    ) -> None:
        selected_path = Path(path)
        selected_store_id = store_id.strip().lower()
        if not selected_store_id or _STORE_ID_PATTERN.fullmatch(selected_store_id) is None:
            raise ValueError("invalid SQLite state store id")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._path = selected_path
        self._store_id = selected_store_id
        self._codec = JsonStateCodec() if codec is None else codec
        self._events = events
        self._observability = observability
        self._clock = clock
        self._source = source
        self._closed = False
        self._lock = asyncio.Lock()
        self._reads = 0
        self._writes = 0
        self._deletes = 0
        self._expirations = 0
        self._conflicts = 0
        self._transactions = 0
        self._connection = self._open_connection()
        self._initialize_schema()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def store_id(self) -> str:
        return self._store_id

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(self, context: object = None) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object = None) -> None:
        del context
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()

    async def get[T](
        self,
        key: StateKey[T],
        *,
        context: StateOperationContext | None = None,
    ) -> StateRecord[T] | None:
        del context
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            now = self._now()
            self._purge_expired_locked(now)
            row = self._connection.execute(
                """
                SELECT namespace, name, payload, version, created_at, updated_at, expires_at
                FROM phoenix_state_records
                WHERE store_id = ? AND canonical_key = ?
                """,
                (self._store_id, key.canonical),
            ).fetchone()
            self._reads += 1
            if row is None:
                return None
            return cast(
                StateRecord[T],
                self._record_from_row(row, requested_key=cast(StateKey[object], key)),
            )

    async def put[T](
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
        context: StateOperationContext | None = None,
    ) -> StateRecord[T]:
        del context
        self._ensure_open()
        if ttl is not None and ttl <= timedelta(0):
            raise ValueError("state TTL must be positive")
        payload = self._codec.encode(value)
        async with self._lock:
            self._ensure_open()
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = self._now()
                self._purge_expired_locked(now)
                object_key = cast(StateKey[object], key)
                current = self._select_record_locked(object_key)
                self._require_expected_version(object_key, expected_version, current)
                revision = self._next_revision_locked()
                created_at = now if current is None else current.created_at
                expires_at = None if ttl is None else now + ttl
                connection.execute(
                    """
                    INSERT INTO phoenix_state_records (
                        store_id, canonical_key, namespace, name, payload, version,
                        created_at, updated_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(store_id, canonical_key) DO UPDATE SET
                        namespace = excluded.namespace,
                        name = excluded.name,
                        payload = excluded.payload,
                        version = excluded.version,
                        created_at = excluded.created_at,
                        updated_at = excluded.updated_at,
                        expires_at = excluded.expires_at
                    """,
                    (
                        self._store_id,
                        key.canonical,
                        key.namespace,
                        key.name,
                        payload,
                        revision,
                        _timestamp(created_at),
                        _timestamp(now),
                        None if expires_at is None else _timestamp(expires_at),
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            self._writes += 1
            return StateRecord(
                key=key,
                value=value,
                version=revision,
                created_at=created_at,
                updated_at=now,
                expires_at=expires_at,
            )

    async def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
        context: StateOperationContext | None = None,
    ) -> bool:
        del context
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = self._now()
                self._purge_expired_locked(now)
                current = self._select_record_locked(key)
                self._require_expected_version(key, expected_version, current)
                if current is None:
                    connection.execute("COMMIT")
                    return False
                connection.execute(
                    "DELETE FROM phoenix_state_records WHERE store_id = ? AND canonical_key = ?",
                    (self._store_id, key.canonical),
                )
                self._next_revision_locked()
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            self._deletes += 1
            return True

    async def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
        context: StateOperationContext | None = None,
    ) -> tuple[StateRecord[object], ...]:
        del context
        self._ensure_open()
        normalized_namespace = None if namespace is None else StateKey(namespace, "probe").namespace
        normalized_prefix = None if prefix is None else prefix.strip().lower()
        if normalized_prefix is not None and not normalized_prefix:
            raise ValueError("state prefix must not be blank")
        async with self._lock:
            self._ensure_open()
            self._purge_expired_locked(self._now())
            rows = self._connection.execute(
                """
                SELECT namespace, name, payload, version, created_at, updated_at, expires_at
                FROM phoenix_state_records
                WHERE store_id = ?
                ORDER BY canonical_key
                """,
                (self._store_id,),
            ).fetchall()
            records: list[StateRecord[object]] = []
            for row in rows:
                record = self._record_from_row(row)
                if (
                    normalized_namespace is not None
                    and record.key.namespace != normalized_namespace
                ):
                    continue
                if normalized_prefix is not None and not record.key.name.startswith(
                    normalized_prefix
                ):
                    continue
                records.append(record)
            self._reads += 1
            return tuple(records)

    def transaction(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> SQLiteStateTransaction:
        self._ensure_open()
        return SQLiteStateTransaction(self, context=context)

    async def snapshot(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> StateSnapshot:
        del context
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            self._purge_expired_locked(self._now())
            rows = self._connection.execute(
                """
                SELECT namespace, name, payload, version, created_at, updated_at, expires_at
                FROM phoenix_state_records
                WHERE store_id = ?
                ORDER BY canonical_key
                """,
                (self._store_id,),
            ).fetchall()
            return StateSnapshot(
                revision=self._revision_locked(),
                records=tuple(self._record_from_row(row) for row in rows),
                created_at=self._now(),
            )

    async def restore(
        self,
        snapshot: StateSnapshot,
        *,
        mode: RestoreMode = RestoreMode.REPLACE,
        context: StateOperationContext | None = None,
    ) -> int:
        del context
        self._ensure_open()
        if not isinstance(snapshot, StateSnapshot):
            raise TypeError("snapshot must be StateSnapshot")
        selected_mode = RestoreMode(mode)
        now = self._now()
        for record in snapshot.records:
            if record.expires_at is not None and record.expires_at <= now:
                raise StateSnapshotError("snapshot contains expired state")
        async with self._lock:
            self._ensure_open()
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._purge_expired_locked(now)
                if selected_mode is RestoreMode.REPLACE:
                    deleted = connection.execute(
                        "SELECT COUNT(*) FROM phoenix_state_records WHERE store_id = ?",
                        (self._store_id,),
                    ).fetchone()[0]
                    connection.execute(
                        "DELETE FROM phoenix_state_records WHERE store_id = ?",
                        (self._store_id,),
                    )
                    for _ in range(int(deleted)):
                        self._next_revision_locked()
                restored = 0
                for record in snapshot.records:
                    key: StateKey[object] = StateKey(record.key.namespace, record.key.name)
                    current = self._select_record_locked(key)
                    if (
                        selected_mode is RestoreMode.MERGE
                        and current is not None
                        and current.updated_at > record.updated_at
                    ):
                        continue
                    revision = self._next_revision_locked()
                    value = record.value
                    payload = self._codec.encode(value)
                    connection.execute(
                        """
                        INSERT INTO phoenix_state_records (
                            store_id, canonical_key, namespace, name, payload, version,
                            created_at, updated_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(store_id, canonical_key) DO UPDATE SET
                            namespace = excluded.namespace,
                            name = excluded.name,
                            payload = excluded.payload,
                            version = excluded.version,
                            created_at = excluded.created_at,
                            updated_at = excluded.updated_at,
                            expires_at = excluded.expires_at
                        """,
                        (
                            self._store_id,
                            key.canonical,
                            key.namespace,
                            key.name,
                            payload,
                            revision,
                            _timestamp(record.created_at),
                            _timestamp(record.updated_at),
                            None if record.expires_at is None else _timestamp(record.expires_at),
                        ),
                    )
                    restored += 1
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            return restored

    async def purge_expired(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> int:
        del context
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                removed = self._purge_expired_locked(self._now())
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            return removed

    async def stats(self) -> StateStoreStats:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            self._purge_expired_locked(self._now())
            records = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM phoenix_state_records WHERE store_id = ?",
                    (self._store_id,),
                ).fetchone()[0]
            )
            return StateStoreStats(
                closed=self._closed,
                revision=self._revision_locked(),
                records=records,
                reads=self._reads,
                writes=self._writes,
                deletes=self._deletes,
                expirations=self._expirations,
                conflicts=self._conflicts,
                transactions=self._transactions,
            )

    def _open_connection(self) -> sqlite3.Connection:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                self._path,
                isolation_level=None,
                check_same_thread=False,
                timeout=30.0,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            return connection
        except sqlite3.Error:
            raise

    def _initialize_schema(self) -> None:
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS phoenix_state_meta (
                    store_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL CHECK (revision >= 0)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS phoenix_state_records (
                    store_id TEXT NOT NULL,
                    canonical_key TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    name TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    version INTEGER NOT NULL CHECK (version > 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    PRIMARY KEY (store_id, canonical_key),
                    FOREIGN KEY (store_id)
                        REFERENCES phoenix_state_meta(store_id)
                        ON DELETE CASCADE
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS phoenix_state_records_namespace_name
                ON phoenix_state_records(store_id, namespace, name)
                """
            )
            connection.execute(
                """
                INSERT INTO phoenix_state_meta(store_id, revision)
                VALUES (?, 0)
                ON CONFLICT(store_id) DO NOTHING
                """,
                (self._store_id,),
            )
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise StateStoreClosedError()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("state clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("state clock must return a timezone-aware datetime")
        return value

    def _revision_locked(self) -> int:
        row = self._connection.execute(
            "SELECT revision FROM phoenix_state_meta WHERE store_id = ?",
            (self._store_id,),
        ).fetchone()
        if row is None:
            raise StateSnapshotError("state metadata is absent")
        return int(row[0])

    def _next_revision_locked(self) -> int:
        revision = self._revision_locked() + 1
        self._connection.execute(
            "UPDATE phoenix_state_meta SET revision = ? WHERE store_id = ?",
            (revision, self._store_id),
        )
        return revision

    def _select_record_locked(
        self,
        key: StateKey[object],
    ) -> StateRecord[object] | None:
        row = self._connection.execute(
            """
            SELECT namespace, name, payload, version, created_at, updated_at, expires_at
            FROM phoenix_state_records
            WHERE store_id = ? AND canonical_key = ?
            """,
            (self._store_id, key.canonical),
        ).fetchone()
        if row is None:
            return None
        return self._record_from_row(row, requested_key=key)

    def _record_from_row(
        self,
        row: sqlite3.Row,
        *,
        requested_key: StateKey[object] | None = None,
    ) -> StateRecord[object]:
        key = (
            StateKey(str(row["namespace"]), str(row["name"]))
            if requested_key is None
            else requested_key
        )
        payload = bytes(row["payload"])
        value = self._codec.decode(payload)
        expected_type = key.expected_type
        if expected_type is not None and not isinstance(value, expected_type):
            raise StateTypeError(
                f"decoded state value for {key.canonical} does not match expected type"
            )
        created_at = cast(datetime, _parse_timestamp(str(row["created_at"])))
        updated_at = cast(datetime, _parse_timestamp(str(row["updated_at"])))
        expires_raw = row["expires_at"]
        expires_at = _parse_timestamp(None if expires_raw is None else str(expires_raw))
        return StateRecord(
            key=key,
            value=value,
            version=int(row["version"]),
            created_at=created_at,
            updated_at=updated_at,
            expires_at=expires_at,
        )

    def _require_expected_version(
        self,
        key: StateKey[object],
        expected_version: int | None,
        current: StateRecord[object] | None,
    ) -> None:
        if expected_version is None:
            return
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise TypeError("expected_version must be an integer or None")
        if expected_version < ABSENT_VERSION:
            raise ValueError("expected_version cannot be negative")
        actual = ABSENT_VERSION if current is None else current.version
        if actual != expected_version:
            self._conflicts += 1
            raise StateConflictError(
                key,
                expected_version,
                None if current is None else current.version,
            )

    def _purge_expired_locked(self, now: datetime) -> int:
        rows = self._connection.execute(
            """
            SELECT canonical_key
            FROM phoenix_state_records
            WHERE store_id = ? AND expires_at IS NOT NULL AND expires_at <= ?
            ORDER BY canonical_key
            """,
            (self._store_id, _timestamp(now)),
        ).fetchall()
        if not rows:
            return 0
        for row in rows:
            self._connection.execute(
                "DELETE FROM phoenix_state_records WHERE store_id = ? AND canonical_key = ?",
                (self._store_id, str(row["canonical_key"])),
            )
            self._next_revision_locked()
        self._expirations += len(rows)
        return len(rows)


class SQLiteStateTransaction:
    """One BEGIN IMMEDIATE serializable transaction over SQLiteStateStore."""

    def __init__(
        self,
        store: SQLiteStateStore,
        *,
        context: StateOperationContext | None = None,
    ) -> None:
        self._store = store
        self._context = context
        self._state = TransactionState.NEW
        self._entered = False
        self._lock_held = False

    @property
    def state(self) -> TransactionState:
        return self._state

    async def __aenter__(self) -> SQLiteStateTransaction:
        if self._state is not TransactionState.NEW:
            raise StateTransactionError("state transaction cannot be entered twice")
        self._store._ensure_open()
        await self._store._lock.acquire()
        self._lock_held = True
        try:
            self._store._ensure_open()
            self._store._connection.execute("BEGIN IMMEDIATE")
            self._store._purge_expired_locked(self._store._now())
            self._state = TransactionState.OPEN
            self._entered = True
            return self
        except BaseException:
            self._release_lock()
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc, traceback
        if self._state is not TransactionState.OPEN:
            self._release_lock()
            return
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()

    async def get[T](self, key: StateKey[T]) -> StateRecord[T] | None:
        self._require_open()
        current = self._store._select_record_locked(cast(StateKey[object], key))
        self._store._reads += 1
        return cast(StateRecord[T] | None, current)

    async def put[T](
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
    ) -> StateRecord[T]:
        self._require_open()
        if ttl is not None and ttl <= timedelta(0):
            raise ValueError("state TTL must be positive")
        payload = self._store._codec.encode(value)
        object_key = cast(StateKey[object], key)
        current = self._store._select_record_locked(object_key)
        self._store._require_expected_version(object_key, expected_version, current)
        now = self._store._now()
        revision = self._store._next_revision_locked()
        created_at = now if current is None else current.created_at
        expires_at = None if ttl is None else now + ttl
        self._store._connection.execute(
            """
            INSERT INTO phoenix_state_records (
                store_id, canonical_key, namespace, name, payload, version,
                created_at, updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(store_id, canonical_key) DO UPDATE SET
                namespace = excluded.namespace,
                name = excluded.name,
                payload = excluded.payload,
                version = excluded.version,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
            """,
            (
                self._store._store_id,
                key.canonical,
                key.namespace,
                key.name,
                payload,
                revision,
                _timestamp(created_at),
                _timestamp(now),
                None if expires_at is None else _timestamp(expires_at),
            ),
        )
        self._store._writes += 1
        return StateRecord(
            key=key,
            value=value,
            version=revision,
            created_at=created_at,
            updated_at=now,
            expires_at=expires_at,
        )

    async def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
    ) -> bool:
        self._require_open()
        current = self._store._select_record_locked(key)
        self._store._require_expected_version(key, expected_version, current)
        if current is None:
            return False
        self._store._connection.execute(
            "DELETE FROM phoenix_state_records WHERE store_id = ? AND canonical_key = ?",
            (self._store._store_id, key.canonical),
        )
        self._store._next_revision_locked()
        self._store._deletes += 1
        return True

    async def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
    ) -> tuple[StateRecord[object], ...]:
        self._require_open()
        normalized_namespace = None if namespace is None else StateKey(namespace, "probe").namespace
        normalized_prefix = None if prefix is None else prefix.strip().lower()
        rows = self._store._connection.execute(
            """
            SELECT namespace, name, payload, version, created_at, updated_at, expires_at
            FROM phoenix_state_records
            WHERE store_id = ?
            ORDER BY canonical_key
            """,
            (self._store._store_id,),
        ).fetchall()
        records = tuple(self._store._record_from_row(row) for row in rows)
        self._store._reads += 1
        return tuple(
            record
            for record in records
            if (normalized_namespace is None or record.key.namespace == normalized_namespace)
            and (normalized_prefix is None or record.key.name.startswith(normalized_prefix))
        )

    async def commit(self) -> None:
        self._require_open()
        try:
            self._store._connection.execute("COMMIT")
            self._store._transactions += 1
            self._state = TransactionState.COMMITTED
        finally:
            self._release_lock()

    async def rollback(self) -> None:
        self._require_open()
        try:
            self._store._connection.execute("ROLLBACK")
            self._state = TransactionState.ROLLED_BACK
        finally:
            self._release_lock()

    def _require_open(self) -> None:
        if self._state is not TransactionState.OPEN or not self._entered:
            raise StateTransactionError("state transaction is not open")
        self._store._ensure_open()

    def _release_lock(self) -> None:
        if self._lock_held:
            self._lock_held = False
            self._store._lock.release()
