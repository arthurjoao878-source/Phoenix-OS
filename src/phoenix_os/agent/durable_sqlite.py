"""Durable SQLite reference storage for RFC-0028 agent runs and leases."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING, Final
from uuid import UUID

from phoenix_os.agent.durable_codec import CanonicalCheckpointCodec
from phoenix_os.agent.durable_contracts import (
    MAX_RECOVERY_CANDIDATE_PAGE,
    CheckpointCodec,
    CheckpointEnvelope,
    CheckpointPayloadProfile,
    DurableAgentRunId,
    DurableLease,
    DurableLeaseId,
    DurableRunLimits,
    DurableRunStore,
    DurableRunVersion,
    FencingGeneration,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_payload import validate_protected_payload_for_checkpoint
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)

if TYPE_CHECKING:
    from sqlite3 import Connection, Row

DURABLE_SQLITE_SCHEMA_VERSION: Final = 2
DEFAULT_DURABLE_SQLITE_BUSY_TIMEOUT_MS: Final = 5_000

_RUN_COLUMNS: Final = """
    run_id,
    current_sequence,
    current_version,
    current_checkpoint_id,
    current_digest,
    history_bytes,
    terminal,
    updated_at
"""

_CHECKPOINT_COLUMNS: Final = """
    run_id,
    sequence,
    checkpoint_id,
    run_version,
    digest,
    previous_digest,
    status,
    created_at,
    payload,
    payload_bytes
"""

_LEASE_COLUMNS: Final = """
    run_id,
    generation,
    active,
    lease_id,
    owner_id,
    acquired_at,
    expires_at
"""

_PROTECTED_PAYLOAD_COLUMNS: Final = """
    reference,
    run_id,
    sequence,
    checkpoint_id,
    schema_version,
    profile,
    key_version,
    plaintext_bytes,
    ciphertext_bytes,
    ciphertext_digest,
    created_at,
    ciphertext
"""


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_busy_timeout(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("busy_timeout_ms must be an integer")
    if value < 0:
        raise ValueError("busy_timeout_ms cannot be negative")


def _rollback(connection: Connection) -> None:
    try:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def _row_int(row: Row, key: str, *, positive: bool = False) -> int:
    value = row[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentCodecError("persisted durable SQLite metadata is invalid")
    if positive and value <= 0:
        raise AgentCodecError("persisted durable SQLite metadata is invalid")
    return value


def _row_text(row: Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str) or not value:
        raise AgentCodecError("persisted durable SQLite metadata is invalid")
    return value


def _row_optional_text(row: Row, key: str) -> str | None:
    value = row[key]
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise AgentCodecError("persisted durable SQLite metadata is invalid")
    return value


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise AgentCodecError("persisted durable SQLite timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exception:
        raise AgentCodecError("persisted durable SQLite timestamp is invalid") from exception
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentCodecError("persisted durable SQLite timestamp is invalid")
    return parsed


def _blob_bytes(value: object) -> bytes:
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytes):
        return value
    raise AgentCodecError("persisted durable checkpoint payload is invalid")


def _same_lease_identity(left: DurableLease, right: DurableLease) -> bool:
    return (
        left.run_id == right.run_id
        and left.lease_id == right.lease_id
        and left.owner_id == right.owner_id
        and left.generation == right.generation
    )


def _lease_from_row(row: Row) -> tuple[DurableLease, bool]:
    try:
        active_value = _row_int(row, "active")
        if active_value not in {0, 1}:
            raise AgentCodecError("persisted durable lease activity is invalid")
        lease = DurableLease(
            run_id=DurableAgentRunId(UUID(_row_text(row, "run_id"))),
            lease_id=DurableLeaseId(UUID(_row_text(row, "lease_id"))),
            owner_id=_row_text(row, "owner_id"),
            generation=FencingGeneration(_row_int(row, "generation", positive=True)),
            acquired_at=_parse_datetime(row["acquired_at"]),
            expires_at=_parse_datetime(row["expires_at"]),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("persisted durable lease is invalid") from exception
    return lease, bool(active_value)


def _require_current_lease(
    connection: Connection,
    lease: DurableLease,
    *,
    now: datetime,
) -> DurableLease:
    row = connection.execute(
        f"SELECT {_LEASE_COLUMNS} FROM durable_leases WHERE run_id = ?",
        (str(lease.run_id),),
    ).fetchone()
    if row is None:
        raise AgentStateConflictError()
    current, active = _lease_from_row(row)
    if (
        not active
        or not _same_lease_identity(current, lease)
        or now < current.acquired_at
        or now >= current.expires_at
    ):
        raise AgentStateConflictError()
    return current


class _SQLiteDurableDatabase:
    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int,
        create_parent: bool,
    ) -> None:
        _require_busy_timeout(busy_timeout_ms)
        database_path = Path(path).expanduser()
        if str(database_path).strip() in {"", ":memory:"}:
            raise ValueError("SQLite durable path must identify a durable file")
        if database_path.exists() and database_path.is_dir():
            raise ValueError("SQLite durable path must not be a directory")
        if create_parent:
            database_path.parent.mkdir(parents=True, exist_ok=True)
        elif not database_path.parent.exists():
            raise ValueError("SQLite durable parent directory does not exist")

        self.path = database_path.resolve()
        self.busy_timeout_ms = busy_timeout_ms
        self.connection: Connection | None = None
        self.initialized = False
        self.closed = False
        self.lock = asyncio.Lock()

    def ensure_open(self) -> None:
        if self.closed:
            raise RuntimeError("durable SQLite storage is closed")

    def writer_connection(self) -> Connection:
        self.ensure_open()
        if self.connection is None:
            connection = self._connect()
            try:
                self._initialize(connection)
            except BaseException:
                connection.close()
                raise
            self.connection = connection
            self.initialized = True
        elif not self.initialized:
            self._initialize(self.connection)
            self.initialized = True
        return self.connection

    async def close(self) -> None:
        async with self.lock:
            if self.closed:
                return
            self.closed = True
            connection = self.connection
            self.connection = None
            self.initialized = False
            if connection is not None:
                connection.close()

    def _connect(self) -> Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            connection.execute("PRAGMA trusted_schema = OFF")
            return connection
        except sqlite3.Error as exception:
            raise AgentServiceUnavailableError() from exception

    def _initialize(self, connection: Connection) -> None:
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, 1, DURABLE_SQLITE_SCHEMA_VERSION}:
                raise AgentCodecError("unsupported durable SQLite schema version")

            connection.execute("BEGIN IMMEDIATE")
            self._create_schema(connection)
            meta = connection.execute(
                "SELECT schema_version FROM durable_meta WHERE singleton = 1"
            ).fetchone()
            now = datetime.now(UTC).isoformat()

            if version == 0:
                if meta is None:
                    connection.execute(
                        """
                        INSERT INTO durable_meta (
                            singleton, schema_version, created_at, updated_at
                        ) VALUES (1, ?, ?, ?)
                        """,
                        (DURABLE_SQLITE_SCHEMA_VERSION, now, now),
                    )
                elif _row_int(meta, "schema_version", positive=True) != (
                    DURABLE_SQLITE_SCHEMA_VERSION
                ):
                    raise AgentCodecError(
                        "durable SQLite metadata is incompatible with an unversioned database"
                    )
                connection.execute(f"PRAGMA user_version = {DURABLE_SQLITE_SCHEMA_VERSION}")
            elif version == 1:
                if meta is None or _row_int(meta, "schema_version", positive=True) != 1:
                    raise AgentCodecError("durable SQLite v1 metadata is missing or incompatible")
                cursor = connection.execute(
                    """
                    UPDATE durable_meta
                    SET schema_version = ?, updated_at = ?
                    WHERE singleton = 1 AND schema_version = 1
                    """,
                    (DURABLE_SQLITE_SCHEMA_VERSION, now),
                )
                if cursor.rowcount != 1:
                    raise AgentCodecError("durable SQLite v1 migration did not update metadata")
                connection.execute(f"PRAGMA user_version = {DURABLE_SQLITE_SCHEMA_VERSION}")
            elif meta is None or _row_int(meta, "schema_version", positive=True) != (
                DURABLE_SQLITE_SCHEMA_VERSION
            ):
                raise AgentCodecError("durable SQLite metadata is missing or incompatible")

            connection.execute("COMMIT")
            self._validate_schema(connection)
        except AgentCodecError:
            _rollback(connection)
            raise
        except sqlite3.Error as exception:
            _rollback(connection)
            raise AgentServiceUnavailableError() from exception

    @staticmethod
    def _create_schema(connection: Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS durable_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS durable_runs (
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
            CREATE TABLE IF NOT EXISTS durable_checkpoints (
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
            CREATE TABLE IF NOT EXISTS durable_leases (
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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS durable_protected_payloads (
                reference TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                checkpoint_id TEXT NOT NULL,
                schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                profile TEXT NOT NULL,
                key_version TEXT NOT NULL,
                plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0),
                ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
                ciphertext_digest TEXT NOT NULL CHECK (length(ciphertext_digest) = 64),
                created_at TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                UNIQUE (run_id, sequence),
                UNIQUE (run_id, checkpoint_id),
                FOREIGN KEY (run_id, sequence)
                    REFERENCES durable_checkpoints(run_id, sequence)
                    ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS durable_runs_recovery
            ON durable_runs(terminal, run_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS durable_checkpoints_identity
            ON durable_checkpoints(run_id, checkpoint_id)
            """
        )

    @staticmethod
    def _validate_schema(connection: Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != DURABLE_SQLITE_SCHEMA_VERSION:
            raise AgentCodecError("unsupported durable SQLite schema version")
        row = connection.execute(
            "SELECT schema_version FROM durable_meta WHERE singleton = 1"
        ).fetchone()
        if row is None or _row_int(row, "schema_version", positive=True) != (
            DURABLE_SQLITE_SCHEMA_VERSION
        ):
            raise AgentCodecError("durable SQLite metadata is missing or incompatible")


class SQLiteDurableLeaseManager(DurableLeaseManager):
    """Persistent fenced lease manager backed by the RFC-0028 SQLite schema."""

    def __init__(
        self,
        path: str | Path,
        *,
        limits: DurableRunLimits | None = None,
        busy_timeout_ms: int = DEFAULT_DURABLE_SQLITE_BUSY_TIMEOUT_MS,
        create_parent: bool = True,
    ) -> None:
        selected_limits = DurableRunLimits() if limits is None else limits
        if not isinstance(selected_limits, DurableRunLimits):
            raise TypeError("limits must be DurableRunLimits")
        self._limits = selected_limits
        self._database = _SQLiteDurableDatabase(
            path,
            busy_timeout_ms=busy_timeout_ms,
            create_parent=create_parent,
        )
        self._closed = False

    @property
    def path(self) -> Path:
        return self._database.path

    @property
    def limits(self) -> DurableRunLimits:
        return self._limits

    @property
    def closed(self) -> bool:
        return self._closed or self._database.closed

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        self._ensure_open()
        self._require_run_id(run_id)
        _require_timezone_aware(now, label="now")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    f"SELECT {_LEASE_COLUMNS} FROM durable_leases WHERE run_id = ?",
                    (str(run_id),),
                ).fetchone()

                previous_generation = 0
                if row is not None:
                    previous, active = _lease_from_row(row)
                    if previous.run_id != run_id or now < previous.acquired_at:
                        raise AgentStateConflictError()
                    if active and now < previous.expires_at:
                        raise AgentStateConflictError()
                    previous_generation = previous.generation.value

                try:
                    generation = FencingGeneration(previous_generation + 1)
                except ValueError as exception:
                    raise AgentLimitExceededError() from exception

                lease = DurableLease(
                    run_id=run_id,
                    lease_id=DurableLeaseId(),
                    owner_id=owner_id,
                    generation=generation,
                    acquired_at=now,
                    expires_at=now + self._limits.lease_duration,
                )
                connection.execute(
                    """
                    INSERT INTO durable_leases (
                        run_id, generation, active, lease_id, owner_id, acquired_at, expires_at
                    ) VALUES (?, ?, 1, ?, ?, ?, ?)
                    ON CONFLICT(run_id) DO UPDATE SET
                        generation = excluded.generation,
                        active = 1,
                        lease_id = excluded.lease_id,
                        owner_id = excluded.owner_id,
                        acquired_at = excluded.acquired_at,
                        expires_at = excluded.expires_at
                    """,
                    (
                        str(run_id),
                        generation.value,
                        str(lease.lease_id),
                        lease.owner_id,
                        lease.acquired_at.isoformat(),
                        lease.expires_at.isoformat(),
                    ),
                )
                connection.execute("COMMIT")
                return lease
            except sqlite3.IntegrityError as exception:
                _rollback(connection)
                raise AgentStateConflictError() from exception
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def get_current(
        self,
        run_id: DurableAgentRunId,
        *,
        now: datetime,
    ) -> DurableLease | None:
        self._ensure_open()
        self._require_run_id(run_id)
        _require_timezone_aware(now, label="now")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                row = connection.execute(
                    f"SELECT {_LEASE_COLUMNS} FROM durable_leases WHERE run_id = ?",
                    (str(run_id),),
                ).fetchone()
            except sqlite3.Error as exception:
                raise AgentServiceUnavailableError() from exception
            if row is None:
                return None
            lease, active = _lease_from_row(row)
            if lease.run_id != run_id:
                raise AgentCodecError("persisted durable lease changed run identity")
            if not active:
                return None
            if now < lease.acquired_at:
                raise AgentStateConflictError()
            if now >= lease.expires_at:
                return None
            return lease

    async def renew(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> DurableLease:
        self._ensure_open()
        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = _require_current_lease(connection, lease, now=now)
                renewed = DurableLease(
                    run_id=current.run_id,
                    lease_id=current.lease_id,
                    owner_id=current.owner_id,
                    generation=current.generation,
                    acquired_at=now,
                    expires_at=now + self._limits.lease_duration,
                )
                cursor = connection.execute(
                    """
                    UPDATE durable_leases
                    SET acquired_at = ?, expires_at = ?
                    WHERE run_id = ? AND generation = ? AND lease_id = ? AND active = 1
                    """,
                    (
                        renewed.acquired_at.isoformat(),
                        renewed.expires_at.isoformat(),
                        str(renewed.run_id),
                        renewed.generation.value,
                        str(renewed.lease_id),
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgentStateConflictError()
                connection.execute("COMMIT")
                return renewed
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def require_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> DurableLease:
        self._ensure_open()
        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                return _require_current_lease(connection, lease, now=now)
            except sqlite3.Error as exception:
                raise AgentServiceUnavailableError() from exception

    @asynccontextmanager
    async def guard_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> AsyncIterator[DurableLease]:
        self._ensure_open()
        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = _require_current_lease(connection, lease, now=now)
                yield current
                connection.execute("COMMIT")
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> None:
        self._ensure_open()
        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = _require_current_lease(connection, lease, now=now)
                cursor = connection.execute(
                    """
                    UPDATE durable_leases
                    SET active = 0
                    WHERE run_id = ? AND generation = ? AND lease_id = ? AND active = 1
                    """,
                    (
                        str(current.run_id),
                        current.generation.value,
                        str(current.lease_id),
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgentStateConflictError()
                connection.execute("COMMIT")
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._database.close()

    @staticmethod
    def _require_run_id(run_id: DurableAgentRunId) -> None:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")

    @staticmethod
    def _require_lease(lease: DurableLease) -> None:
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")

    def _ensure_open(self) -> None:
        if self.closed:
            raise RuntimeError("durable SQLite lease manager is closed")


class SQLiteDurableRunStore(DurableRunStore):
    """File-backed durable run history with atomic fenced SQLite mutations."""

    def __init__(
        self,
        path: str | Path,
        *,
        codec: CheckpointCodec | None = None,
        limits: DurableRunLimits | None = None,
        lease_manager: SQLiteDurableLeaseManager | None = None,
        busy_timeout_ms: int = DEFAULT_DURABLE_SQLITE_BUSY_TIMEOUT_MS,
        create_parent: bool = True,
    ) -> None:
        selected_codec = CanonicalCheckpointCodec() if codec is None else codec
        selected_limits = DurableRunLimits() if limits is None else limits
        if not isinstance(selected_codec, CheckpointCodec):
            raise TypeError("codec must implement CheckpointCodec")
        if not isinstance(selected_limits, DurableRunLimits):
            raise TypeError("limits must be DurableRunLimits")

        self._codec = selected_codec
        self._limits = selected_limits
        self._database = _SQLiteDurableDatabase(
            path,
            busy_timeout_ms=busy_timeout_ms,
            create_parent=create_parent,
        )
        if lease_manager is None:
            self._lease_manager = SQLiteDurableLeaseManager(
                self._database.path,
                limits=selected_limits,
                busy_timeout_ms=busy_timeout_ms,
                create_parent=False,
            )
            self._owns_lease_manager = True
        else:
            if not isinstance(lease_manager, SQLiteDurableLeaseManager):
                raise TypeError("lease_manager must be SQLiteDurableLeaseManager")
            if lease_manager.path != self._database.path:
                raise ValueError("lease_manager must use the same SQLite durable path")
            if lease_manager.limits != selected_limits:
                raise ValueError("lease_manager limits must match store limits")
            self._lease_manager = lease_manager
            self._owns_lease_manager = False
        self._closed = False

    @property
    def path(self) -> Path:
        return self._database.path

    @property
    def limits(self) -> DurableRunLimits:
        return self._limits

    @property
    def lease_manager(self) -> SQLiteDurableLeaseManager:
        return self._lease_manager

    @property
    def closed(self) -> bool:
        return self._closed or self._database.closed

    async def create(self, checkpoint: CheckpointEnvelope) -> None:
        """Create one metadata-only durable run checkpoint."""

        await self._create(checkpoint, protected_payload=None)

    async def create_protected(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        protected_payload: bytes,
    ) -> None:
        """Atomically create one run checkpoint and its protected ciphertext."""

        await self._create(checkpoint, protected_payload=protected_payload)

    async def _create(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        protected_payload: bytes | None,
    ) -> None:
        self._ensure_open()
        encoded, decoded = self._prepare_checkpoint(checkpoint)
        protected = validate_protected_payload_for_checkpoint(
            decoded,
            protected_payload,
            limits=self._limits,
        )
        if (
            decoded.sequence.value != 1
            or decoded.run_version.value != 1
            or decoded.previous_digest is not None
        ):
            raise AgentStateConflictError()
        self._require_history_bounds(checkpoint_count=1, total_bytes=len(encoded))

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT 1 FROM durable_runs WHERE run_id = ?",
                    (str(decoded.durable_run_id),),
                ).fetchone()
                if existing is not None:
                    raise AgentStateConflictError()

                self._insert_run(connection, decoded, history_bytes=len(encoded))
                self._insert_checkpoint(connection, decoded, encoded)
                if protected is not None:
                    self._insert_protected_payload(connection, decoded, protected)
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exception:
                _rollback(connection)
                raise AgentStateConflictError() from exception
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        self._ensure_open()
        self._require_run_id(run_id)

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN")
                run_row = self._run_row(connection, run_id)
                if run_row is None:
                    connection.execute("COMMIT")
                    return None
                checkpoint = self._current_checkpoint(connection, run_row)
                connection.execute("COMMIT")
                return checkpoint
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        self._ensure_open()
        self._require_run_id(run_id)
        self._require_history_limit(limit)

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN")
                run_row = self._run_row(connection, run_id)
                if run_row is None:
                    connection.execute("COMMIT")
                    return ()
                current_sequence = _row_int(run_row, "current_sequence", positive=True)
                rows = connection.execute(
                    f"""
                    SELECT {_CHECKPOINT_COLUMNS}
                    FROM durable_checkpoints
                    WHERE run_id = ?
                    ORDER BY sequence DESC
                    LIMIT ?
                    """,
                    (str(run_id), limit),
                ).fetchall()
                checkpoints = tuple(
                    reversed(tuple(self._decode_checkpoint_row(row) for row in rows))
                )
                self._validate_history_segment(
                    checkpoints,
                    run_id=run_id,
                    current_sequence=current_sequence,
                    requested_limit=limit,
                )
                if checkpoints:
                    self._validate_run_row(run_row, checkpoints[-1])
                connection.execute("COMMIT")
                return checkpoints
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self._ensure_open()
        self._require_recovery_limit(limit)
        if after is not None:
            self._require_run_id(after)

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN")
                if after is None:
                    rows = connection.execute(
                        f"""
                        SELECT {_RUN_COLUMNS}
                        FROM durable_runs
                        WHERE terminal = 0
                        ORDER BY run_id ASC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                else:
                    rows = connection.execute(
                        f"""
                        SELECT {_RUN_COLUMNS}
                        FROM durable_runs
                        WHERE terminal = 0 AND run_id > ?
                        ORDER BY run_id ASC
                        LIMIT ?
                        """,
                        (str(after), limit),
                    ).fetchall()

                candidates: list[DurableAgentRunId] = []
                for row in rows:
                    try:
                        run_id = DurableAgentRunId(UUID(_row_text(row, "run_id")))
                    except (TypeError, ValueError) as exception:
                        raise AgentCodecError(
                            "persisted durable run identity is invalid"
                        ) from exception
                    checkpoint = self._current_checkpoint(connection, row)
                    if checkpoint.status.terminal:
                        raise AgentCodecError("persisted durable recovery index is inconsistent")
                    candidates.append(run_id)
                connection.execute("COMMIT")
                return tuple(candidates)
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Append one metadata-only checkpoint under a current persisted lease."""

        return await self._append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
            protected_payload=None,
        )

    async def append_protected(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
        protected_payload: bytes,
    ) -> CheckpointEnvelope:
        """Atomically append one checkpoint and its protected ciphertext."""

        return await self._append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
            protected_payload=protected_payload,
        )

    async def _append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
        protected_payload: bytes | None,
    ) -> CheckpointEnvelope:
        self._ensure_open()
        if not isinstance(expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        _require_timezone_aware(now, label="now")
        encoded, decoded = self._prepare_checkpoint(checkpoint)
        protected = validate_protected_payload_for_checkpoint(
            decoded,
            protected_payload,
            limits=self._limits,
        )
        if lease.run_id != decoded.durable_run_id:
            raise AgentStateConflictError()
        if self._lease_manager.closed:
            raise RuntimeError("durable SQLite lease manager is closed")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                _require_current_lease(connection, lease, now=now)
                run_row = self._run_row(connection, decoded.durable_run_id)
                if run_row is None:
                    raise AgentStateConflictError()
                current = self._current_checkpoint(connection, run_row)
                self._validate_history_aggregate(connection, run_row)
                self._validate_append(
                    current=current,
                    candidate=decoded,
                    expected_version=expected_version,
                )

                next_total_bytes = _row_int(run_row, "history_bytes") + len(encoded)
                self._require_history_bounds(
                    checkpoint_count=decoded.sequence.value,
                    total_bytes=next_total_bytes,
                )

                self._insert_checkpoint(connection, decoded, encoded)
                if protected is not None:
                    self._insert_protected_payload(connection, decoded, protected)
                cursor = connection.execute(
                    """
                    UPDATE durable_runs
                    SET
                        current_sequence = ?,
                        current_version = ?,
                        current_checkpoint_id = ?,
                        current_digest = ?,
                        history_bytes = ?,
                        terminal = ?,
                        updated_at = ?
                    WHERE run_id = ? AND current_version = ?
                    """,
                    (
                        decoded.sequence.value,
                        decoded.run_version.value,
                        str(decoded.checkpoint_id),
                        decoded.digest.value,
                        next_total_bytes,
                        int(decoded.status.terminal),
                        decoded.created_at.isoformat(),
                        str(decoded.durable_run_id),
                        expected_version.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgentStateConflictError()
                connection.execute("COMMIT")
                return decoded
            except sqlite3.IntegrityError as exception:
                _rollback(connection)
                raise AgentStateConflictError() from exception
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def get_protected_payload(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> bytes:
        """Read current ciphertext under the exact persisted lease and envelope."""

        self._ensure_open()
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        _require_timezone_aware(now, label="now")
        _, decoded = self._prepare_checkpoint(checkpoint)
        if lease.run_id != decoded.durable_run_id:
            raise AgentStateConflictError()
        if (
            decoded.metadata.payload_profile is not CheckpointPayloadProfile.PROTECTED_CONTENT
            or decoded.metadata.payload_reference is None
            or decoded.metadata.compatibility.payload_codec is None
        ):
            raise AgentStateConflictError()
        if self._lease_manager.closed:
            raise RuntimeError("durable SQLite lease manager is closed")

        async with self._database.lock:
            self._ensure_open()
            connection = self._database.writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                _require_current_lease(connection, lease, now=now)
                run_row = self._run_row(connection, decoded.durable_run_id)
                if run_row is None:
                    raise AgentStateConflictError()
                current = self._current_checkpoint(connection, run_row)
                if current != decoded:
                    raise AgentStateConflictError()
                row = connection.execute(
                    f"""
                    SELECT {_PROTECTED_PAYLOAD_COLUMNS}
                    FROM durable_protected_payloads
                    WHERE run_id = ? AND sequence = ?
                    """,
                    (str(decoded.durable_run_id), decoded.sequence.value),
                ).fetchone()
                if row is None:
                    raise AgentCodecError("persisted protected payload is missing")
                protected = self._decode_protected_payload_row(row, decoded)
                connection.execute("COMMIT")
                return protected
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception
            except BaseException:
                _rollback(connection)
                raise

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._database.close()
        if self._owns_lease_manager:
            await self._lease_manager.close()

    def _prepare_checkpoint(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> tuple[bytes, CheckpointEnvelope]:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        computed_digest = self._codec.digest(checkpoint)
        if computed_digest != checkpoint.digest:
            raise AgentCodecError("checkpoint digest does not match canonical content")
        encoded = self._codec.encode(checkpoint)
        if not isinstance(encoded, bytes):
            raise TypeError("checkpoint codec must return bytes")
        if not encoded or len(encoded) > self._limits.max_checkpoint_envelope_bytes:
            raise AgentLimitExceededError()
        decoded = self._codec.decode(encoded)
        if not isinstance(decoded, CheckpointEnvelope):
            raise TypeError("checkpoint codec must decode CheckpointEnvelope")
        if decoded != checkpoint:
            raise AgentCodecError("checkpoint codec round-trip changed the checkpoint")
        return encoded, decoded

    def _decode_checkpoint_row(self, row: Row) -> CheckpointEnvelope:
        payload = _blob_bytes(row["payload"])
        payload_bytes = _row_int(row, "payload_bytes", positive=True)
        if len(payload) != payload_bytes:
            raise AgentCodecError("persisted durable checkpoint size is inconsistent")
        if len(payload) > self._limits.max_checkpoint_envelope_bytes:
            raise AgentCodecError("persisted checkpoint exceeds the configured bound")
        try:
            decoded = self._codec.decode(payload)
        except (TypeError, ValueError, AgentCodecError) as exception:
            raise AgentCodecError("persisted durable checkpoint cannot be decoded") from exception
        if not isinstance(decoded, CheckpointEnvelope):
            raise AgentCodecError("persisted checkpoint decoded to an invalid type")
        if self._codec.digest(decoded) != decoded.digest:
            raise AgentCodecError("persisted checkpoint digest is invalid")

        previous_digest = _row_optional_text(row, "previous_digest")
        if (
            _row_text(row, "run_id") != str(decoded.durable_run_id)
            or _row_int(row, "sequence", positive=True) != decoded.sequence.value
            or _row_text(row, "checkpoint_id") != str(decoded.checkpoint_id)
            or _row_int(row, "run_version", positive=True) != decoded.run_version.value
            or _row_text(row, "digest") != decoded.digest.value
            or previous_digest
            != (None if decoded.previous_digest is None else decoded.previous_digest.value)
            or _row_text(row, "status") != decoded.status.value
            or _parse_datetime(row["created_at"]) != decoded.created_at
        ):
            raise AgentCodecError("persisted durable checkpoint metadata is inconsistent")
        return decoded

    def _current_checkpoint(
        self,
        connection: Connection,
        run_row: Row,
    ) -> CheckpointEnvelope:
        run_id = _row_text(run_row, "run_id")
        sequence = _row_int(run_row, "current_sequence", positive=True)
        row = connection.execute(
            f"""
            SELECT {_CHECKPOINT_COLUMNS}
            FROM durable_checkpoints
            WHERE run_id = ? AND sequence = ?
            """,
            (run_id, sequence),
        ).fetchone()
        if row is None:
            raise AgentCodecError("persisted durable run head is missing")
        checkpoint = self._decode_checkpoint_row(row)
        self._validate_run_row(run_row, checkpoint)
        return checkpoint

    @staticmethod
    def _validate_run_row(
        run_row: Row,
        checkpoint: CheckpointEnvelope,
    ) -> None:
        terminal = _row_int(run_row, "terminal")
        if terminal not in {0, 1}:
            raise AgentCodecError("persisted durable terminal marker is invalid")
        if (
            _row_text(run_row, "run_id") != str(checkpoint.durable_run_id)
            or _row_int(run_row, "current_sequence", positive=True) != checkpoint.sequence.value
            or _row_int(run_row, "current_version", positive=True) != checkpoint.run_version.value
            or _row_text(run_row, "current_checkpoint_id") != str(checkpoint.checkpoint_id)
            or _row_text(run_row, "current_digest") != checkpoint.digest.value
            or bool(terminal) != checkpoint.status.terminal
        ):
            raise AgentCodecError("persisted durable run head metadata is inconsistent")

    def _validate_history_aggregate(
        self,
        connection: Connection,
        run_row: Row,
    ) -> None:
        row = connection.execute(
            """
            SELECT COUNT(*) AS checkpoint_count,
                   COALESCE(SUM(payload_bytes), 0) AS history_bytes,
                   COALESCE(MAX(sequence), 0) AS max_sequence
            FROM durable_checkpoints
            WHERE run_id = ?
            """,
            (_row_text(run_row, "run_id"),),
        ).fetchone()
        if row is None:
            raise AgentCodecError("persisted durable history metadata is missing")
        current_sequence = _row_int(run_row, "current_sequence", positive=True)
        if (
            _row_int(row, "checkpoint_count") != current_sequence
            or _row_int(row, "max_sequence") != current_sequence
            or _row_int(row, "history_bytes") != _row_int(run_row, "history_bytes")
        ):
            raise AgentCodecError("persisted durable history aggregate is inconsistent")

    def _insert_run(
        self,
        connection: Connection,
        checkpoint: CheckpointEnvelope,
        *,
        history_bytes: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO durable_runs (
                run_id,
                current_sequence,
                current_version,
                current_checkpoint_id,
                current_digest,
                history_bytes,
                terminal,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(checkpoint.durable_run_id),
                checkpoint.sequence.value,
                checkpoint.run_version.value,
                str(checkpoint.checkpoint_id),
                checkpoint.digest.value,
                history_bytes,
                int(checkpoint.status.terminal),
                checkpoint.created_at.isoformat(),
            ),
        )

    @staticmethod
    def _insert_checkpoint(
        connection: Connection,
        checkpoint: CheckpointEnvelope,
        payload: bytes,
    ) -> None:
        connection.execute(
            """
            INSERT INTO durable_checkpoints (
                run_id,
                sequence,
                checkpoint_id,
                run_version,
                digest,
                previous_digest,
                status,
                created_at,
                payload,
                payload_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(checkpoint.durable_run_id),
                checkpoint.sequence.value,
                str(checkpoint.checkpoint_id),
                checkpoint.run_version.value,
                checkpoint.digest.value,
                None if checkpoint.previous_digest is None else checkpoint.previous_digest.value,
                checkpoint.status.value,
                checkpoint.created_at.isoformat(),
                sqlite3.Binary(payload),
                len(payload),
            ),
        )

    @staticmethod
    def _insert_protected_payload(
        connection: Connection,
        checkpoint: CheckpointEnvelope,
        protected_payload: bytes,
    ) -> None:
        reference = checkpoint.metadata.payload_reference
        if reference is None:
            raise AgentStateConflictError()
        connection.execute(
            """
            INSERT INTO durable_protected_payloads (
                reference,
                run_id,
                sequence,
                checkpoint_id,
                schema_version,
                profile,
                key_version,
                plaintext_bytes,
                ciphertext_bytes,
                ciphertext_digest,
                created_at,
                ciphertext
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reference.reference,
                str(checkpoint.durable_run_id),
                checkpoint.sequence.value,
                str(checkpoint.checkpoint_id),
                checkpoint.schema_version.value,
                checkpoint.metadata.payload_profile.value,
                reference.key_version,
                reference.plaintext_bytes,
                reference.ciphertext_bytes,
                reference.ciphertext_digest.value,
                reference.created_at.isoformat(),
                sqlite3.Binary(protected_payload),
            ),
        )

    def _decode_protected_payload_row(
        self,
        row: Row,
        checkpoint: CheckpointEnvelope,
    ) -> bytes:
        reference = checkpoint.metadata.payload_reference
        if reference is None:
            raise AgentStateConflictError()
        if (
            _row_text(row, "reference") != reference.reference
            or _row_text(row, "run_id") != str(checkpoint.durable_run_id)
            or _row_int(row, "sequence", positive=True) != checkpoint.sequence.value
            or _row_text(row, "checkpoint_id") != str(checkpoint.checkpoint_id)
            or _row_int(row, "schema_version", positive=True) != checkpoint.schema_version.value
            or _row_text(row, "profile") != checkpoint.metadata.payload_profile.value
            or _row_text(row, "key_version") != reference.key_version
            or _row_int(row, "plaintext_bytes") != reference.plaintext_bytes
            or _row_int(row, "ciphertext_bytes", positive=True) != reference.ciphertext_bytes
            or _row_text(row, "ciphertext_digest") != reference.ciphertext_digest.value
            or _parse_datetime(row["created_at"]) != reference.created_at
        ):
            raise AgentCodecError("persisted protected payload metadata is inconsistent")
        protected = validate_protected_payload_for_checkpoint(
            checkpoint,
            _blob_bytes(row["ciphertext"]),
            limits=self._limits,
        )
        if protected is None:
            raise AgentCodecError("persisted protected payload binding is invalid")
        return protected

    @staticmethod
    def _run_row(
        connection: Connection,
        run_id: DurableAgentRunId,
    ) -> Row | None:
        row = connection.execute(
            f"SELECT {_RUN_COLUMNS} FROM durable_runs WHERE run_id = ?",
            (str(run_id),),
        ).fetchone()
        if row is None:
            return None
        if not isinstance(row, sqlite3.Row):
            raise TypeError("SQLite durable run query returned an invalid row")
        return row

    def _validate_append(
        self,
        *,
        current: CheckpointEnvelope,
        candidate: CheckpointEnvelope,
        expected_version: DurableRunVersion,
    ) -> None:
        if current.status.terminal:
            raise AgentStateConflictError()
        if expected_version != current.run_version:
            raise AgentStateConflictError()
        if candidate.durable_run_id != current.durable_run_id:
            raise AgentStateConflictError()
        if candidate.agent_run_id != current.agent_run_id:
            raise AgentStateConflictError()
        if candidate.schema_version != current.schema_version:
            raise AgentStateConflictError()

        current_metadata = current.metadata
        candidate_metadata = candidate.metadata
        if (
            candidate_metadata.agent_id != current_metadata.agent_id
            or candidate_metadata.actor_id != current_metadata.actor_id
            or candidate_metadata.payload_profile is not current_metadata.payload_profile
            or candidate_metadata.budget.started_at != current_metadata.budget.started_at
            or candidate_metadata.budget.deadline != current_metadata.budget.deadline
            or candidate_metadata.retention_deadline != current_metadata.retention_deadline
        ):
            raise AgentStateConflictError()

        current_budget = current_metadata.budget
        candidate_budget = candidate_metadata.budget
        current_counters = (
            current_budget.steps,
            current_budget.model_turns,
            current_budget.tool_calls,
            current_budget.model_output_bytes,
            current_budget.tool_result_bytes,
            current_budget.input_tokens,
            current_budget.output_tokens,
        )
        candidate_counters = (
            candidate_budget.steps,
            candidate_budget.model_turns,
            candidate_budget.tool_calls,
            candidate_budget.model_output_bytes,
            candidate_budget.tool_result_bytes,
            candidate_budget.input_tokens,
            candidate_budget.output_tokens,
        )
        if any(
            candidate_value < current_value
            for current_value, candidate_value in zip(
                current_counters,
                candidate_counters,
                strict=True,
            )
        ):
            raise AgentStateConflictError()

        if candidate.sequence.value != current.sequence.value + 1:
            raise AgentStateConflictError()
        if candidate.run_version.value != current.run_version.value + 1:
            raise AgentStateConflictError()
        if candidate.previous_digest != current.digest:
            raise AgentStateConflictError()
        if candidate.created_at < current.created_at:
            raise AgentStateConflictError()

    @staticmethod
    def _validate_history_segment(
        checkpoints: tuple[CheckpointEnvelope, ...],
        *,
        run_id: DurableAgentRunId,
        current_sequence: int,
        requested_limit: int,
    ) -> None:
        expected_count = min(current_sequence, requested_limit)
        if len(checkpoints) != expected_count:
            raise AgentCodecError("persisted durable history is incomplete")
        if not checkpoints:
            return
        expected_first = current_sequence - expected_count + 1
        if checkpoints[0].sequence.value != expected_first:
            raise AgentCodecError("persisted durable history has a sequence gap")
        if checkpoints[-1].sequence.value != current_sequence:
            raise AgentCodecError("persisted durable history does not reach the run head")
        for checkpoint in checkpoints:
            if checkpoint.durable_run_id != run_id:
                raise AgentCodecError("persisted durable history changed run identity")
        for previous, current in pairwise(checkpoints):
            if (
                current.sequence.value != previous.sequence.value + 1
                or current.run_version.value != previous.run_version.value + 1
                or current.previous_digest != previous.digest
            ):
                raise AgentCodecError("persisted durable history chain is invalid")

    def _require_history_bounds(
        self,
        *,
        checkpoint_count: int,
        total_bytes: int,
    ) -> None:
        if checkpoint_count > self._limits.max_checkpoints:
            raise AgentLimitExceededError()
        if total_bytes > self._limits.max_checkpoint_history_bytes:
            raise AgentLimitExceededError()

    def _require_history_limit(self, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if limit > self._limits.max_checkpoints:
            raise AgentLimitExceededError()

    @staticmethod
    def _require_recovery_limit(limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if limit > MAX_RECOVERY_CANDIDATE_PAGE:
            raise AgentLimitExceededError()

    @staticmethod
    def _require_run_id(run_id: DurableAgentRunId) -> None:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")

    def _ensure_open(self) -> None:
        if self.closed:
            raise RuntimeError("durable SQLite run store is closed")
