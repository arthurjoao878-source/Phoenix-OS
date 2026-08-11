"""SQLite-backed durable delegation identity and recovery metadata."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final
from uuid import UUID

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.coordination_contracts import (
    CoordinationNamespace,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationStatus,
)
from phoenix_os.agent.coordination_durable_contracts import (
    DurableDelegationRecord,
    DurableDelegationRecoveryState,
    DurableDelegationStore,
    DurableDelegationVersion,
    require_recovery_page_limit,
)
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)

if TYPE_CHECKING:
    from sqlite3 import Connection, Row

COORDINATION_SQLITE_SCHEMA_VERSION: Final = 1
DEFAULT_COORDINATION_SQLITE_BUSY_TIMEOUT_MS: Final = 5_000

_RECORD_COLUMNS: Final = """
    delegation_id,
    namespace,
    parent_agent_id,
    parent_run_id,
    root_run_id,
    child_agent_id,
    child_run_id,
    depth,
    budget_model_turns,
    budget_tool_calls,
    budget_input_tokens,
    budget_output_tokens,
    budget_prompt_bytes,
    budget_result_bytes,
    budget_duration_us,
    status,
    request_digest,
    compatibility_digest,
    version,
    recovery_state,
    created_at,
    updated_at,
    deadline,
    error_code
"""


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


def _row_text(row: Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str) or not value:
        raise AgentCodecError("persisted coordination SQLite metadata is invalid")
    return value


def _row_optional_text(row: Row, key: str) -> str | None:
    value = row[key]
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise AgentCodecError("persisted coordination SQLite metadata is invalid")
    return value


def _row_int(row: Row, key: str, *, positive: bool = False) -> int:
    value = row[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentCodecError("persisted coordination SQLite metadata is invalid")
    if positive and value <= 0:
        raise AgentCodecError("persisted coordination SQLite metadata is invalid")
    return value


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise AgentCodecError("persisted coordination SQLite timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exception:
        raise AgentCodecError("persisted coordination SQLite timestamp is invalid") from exception
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentCodecError("persisted coordination SQLite timestamp is invalid")
    return parsed


def _record_from_row(row: Row) -> DurableDelegationRecord:
    try:
        return DurableDelegationRecord(
            delegation_id=DelegationId(UUID(_row_text(row, "delegation_id"))),
            namespace=CoordinationNamespace(_row_text(row, "namespace")),
            parent_agent_id=AgentId(_row_text(row, "parent_agent_id")),
            parent_run_id=AgentRunId(UUID(_row_text(row, "parent_run_id"))),
            root_run_id=AgentRunId(UUID(_row_text(row, "root_run_id"))),
            child_agent_id=AgentId(_row_text(row, "child_agent_id")),
            child_run_id=AgentRunId(UUID(_row_text(row, "child_run_id"))),
            depth=DelegationDepth(_row_int(row, "depth")),
            budget=DelegationBudget(
                max_model_turns=_row_int(row, "budget_model_turns", positive=True),
                max_tool_calls=_row_int(row, "budget_tool_calls", positive=True),
                max_input_tokens=_row_int(row, "budget_input_tokens", positive=True),
                max_output_tokens=_row_int(row, "budget_output_tokens", positive=True),
                max_prompt_bytes=_row_int(row, "budget_prompt_bytes", positive=True),
                max_result_bytes=_row_int(row, "budget_result_bytes", positive=True),
                duration=_microseconds_duration(_row_int(row, "budget_duration_us", positive=True)),
            ),
            status=DelegationStatus(_row_text(row, "status")),
            request_digest=_row_text(row, "request_digest"),
            compatibility_digest=_row_text(row, "compatibility_digest"),
            version=DurableDelegationVersion(_row_int(row, "version", positive=True)),
            recovery_state=DurableDelegationRecoveryState(_row_text(row, "recovery_state")),
            created_at=_parse_datetime(row["created_at"]),
            updated_at=_parse_datetime(row["updated_at"]),
            deadline=_parse_datetime(row["deadline"]),
            error_code=_row_optional_text(row, "error_code"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("persisted coordination SQLite record is invalid") from exception


class SQLiteDurableDelegationStore(DurableDelegationStore):
    """Dedicated-file SQLite reference store for content-free delegation recovery."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = DEFAULT_COORDINATION_SQLITE_BUSY_TIMEOUT_MS,
        create_parent: bool = False,
    ) -> None:
        _require_busy_timeout(busy_timeout_ms)
        database_path = Path(path).expanduser()
        if str(database_path).strip() in {"", ":memory:"}:
            raise ValueError("coordination SQLite path must identify a durable file")
        if database_path.exists() and database_path.is_dir():
            raise ValueError("coordination SQLite path must not be a directory")
        if create_parent:
            database_path.parent.mkdir(parents=True, exist_ok=True)
        elif not database_path.parent.exists():
            raise ValueError("coordination SQLite parent directory does not exist")

        self._path = database_path.resolve()
        self._busy_timeout_ms = busy_timeout_ms
        self._connection: Connection | None = None
        self._initialized = False
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def closed(self) -> bool:
        return self._closed

    async def create(
        self,
        record: DurableDelegationRecord,
        *,
        limits: DelegationLimits,
        root_budget_limit: DelegationBudget,
    ) -> None:
        if not isinstance(record, DurableDelegationRecord):
            raise TypeError("record must be DurableDelegationRecord")
        if not isinstance(limits, DelegationLimits):
            raise TypeError("limits must be DelegationLimits")
        if not isinstance(root_budget_limit, DelegationBudget):
            raise TypeError("root_budget_limit must be DelegationBudget")
        if record.version.value != 1:
            raise AgentStateConflictError()

        async with self._lock:
            connection = self._writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                _require_sqlite_durable_capacity(
                    connection,
                    record,
                    limits=limits,
                    root_budget_limit=root_budget_limit,
                )
                connection.execute(
                    """
                    INSERT INTO coordination_delegations (
                        delegation_id,
                        namespace,
                        parent_agent_id,
                        parent_run_id,
                        root_run_id,
                        child_agent_id,
                        child_run_id,
                        depth,
                        budget_model_turns,
                        budget_tool_calls,
                        budget_input_tokens,
                        budget_output_tokens,
                        budget_prompt_bytes,
                        budget_result_bytes,
                        budget_duration_us,
                        status,
                        request_digest,
                        compatibility_digest,
                        version,
                        recovery_state,
                        created_at,
                        updated_at,
                        deadline,
                        error_code
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    _record_values(record),
                )
                connection.execute("COMMIT")
            except AgentStateConflictError:
                _rollback(connection)
                raise
            except sqlite3.IntegrityError as exception:
                _rollback(connection)
                raise AgentStateConflictError() from exception
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception

    async def get(
        self,
        delegation_id: DelegationId,
    ) -> DurableDelegationRecord | None:
        if not isinstance(delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        async with self._lock:
            connection = self._writer_connection()
            try:
                row = connection.execute(
                    f"""
                    SELECT {_RECORD_COLUMNS}
                    FROM coordination_delegations
                    WHERE delegation_id = ?
                    """,
                    (str(delegation_id),),
                ).fetchone()
            except sqlite3.Error as exception:
                raise AgentServiceUnavailableError() from exception
            return None if row is None else _record_from_row(row)

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DelegationId | None = None,
    ) -> tuple[DelegationId, ...]:
        require_recovery_page_limit(limit)
        if after is not None and not isinstance(after, DelegationId):
            raise TypeError("after must be DelegationId or None")

        async with self._lock:
            connection = self._writer_connection()
            parameters: tuple[object, ...]
            if after is None:
                sql = """
                    SELECT delegation_id
                    FROM coordination_delegations
                    WHERE status NOT IN ('completed', 'failed', 'cancelled', 'expired')
                    ORDER BY delegation_id ASC
                    LIMIT ?
                """
                parameters = (limit,)
            else:
                sql = """
                    SELECT delegation_id
                    FROM coordination_delegations
                    WHERE status NOT IN ('completed', 'failed', 'cancelled', 'expired')
                      AND delegation_id > ?
                    ORDER BY delegation_id ASC
                    LIMIT ?
                """
                parameters = (str(after), limit)
            try:
                rows = connection.execute(sql, parameters).fetchall()
            except sqlite3.Error as exception:
                raise AgentServiceUnavailableError() from exception

            candidates: list[DelegationId] = []
            for row in rows:
                try:
                    candidates.append(DelegationId(UUID(_row_text(row, "delegation_id"))))
                except AgentCodecError:
                    raise
                except (TypeError, ValueError) as exception:
                    raise AgentCodecError(
                        "persisted coordination SQLite delegation id is invalid"
                    ) from exception
            return tuple(candidates)

    async def list_root_records(
        self,
        root_run_id: AgentRunId,
        *,
        limit: int = 1_024,
    ) -> tuple[DurableDelegationRecord, ...]:
        if not isinstance(root_run_id, AgentRunId):
            raise TypeError("root_run_id must be AgentRunId")
        require_recovery_page_limit(limit)
        async with self._lock:
            connection = self._writer_connection()
            try:
                rows = connection.execute(
                    f"""
                    SELECT {_RECORD_COLUMNS}
                    FROM coordination_delegations
                    WHERE root_run_id = ?
                    ORDER BY delegation_id ASC
                    LIMIT ?
                    """,
                    (str(root_run_id), limit),
                ).fetchall()
            except sqlite3.Error as exception:
                raise AgentServiceUnavailableError() from exception
            return tuple(_record_from_row(row) for row in rows)

    async def compare_and_swap(
        self,
        record: DurableDelegationRecord,
        *,
        expected_version: DurableDelegationVersion,
    ) -> DurableDelegationRecord:
        if not isinstance(record, DurableDelegationRecord):
            raise TypeError("record must be DurableDelegationRecord")
        if not isinstance(expected_version, DurableDelegationVersion):
            raise TypeError("expected_version must be DurableDelegationVersion")
        if record.version != expected_version.next():
            raise AgentStateConflictError()

        async with self._lock:
            connection = self._writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current_row = connection.execute(
                    f"""
                    SELECT {_RECORD_COLUMNS}
                    FROM coordination_delegations
                    WHERE delegation_id = ?
                    """,
                    (str(record.delegation_id),),
                ).fetchone()
                if current_row is None:
                    raise AgentStateConflictError()
                current = _record_from_row(current_row)
                if current.version != expected_version:
                    raise AgentStateConflictError()
                if current.terminal:
                    raise AgentStateConflictError()
                _require_same_identity(current, record)

                cursor = connection.execute(
                    """
                    UPDATE coordination_delegations
                    SET
                        status = ?,
                        version = ?,
                        recovery_state = ?,
                        updated_at = ?,
                        error_code = ?
                    WHERE delegation_id = ? AND version = ?
                    """,
                    (
                        record.status.value,
                        record.version.value,
                        record.recovery_state.value,
                        record.updated_at.isoformat(),
                        record.error_code,
                        str(record.delegation_id),
                        expected_version.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgentStateConflictError()
                connection.execute("COMMIT")
                return record
            except AgentStateConflictError:
                _rollback(connection)
                raise
            except sqlite3.IntegrityError as exception:
                _rollback(connection)
                raise AgentStateConflictError() from exception
            except sqlite3.Error as exception:
                _rollback(connection)
                raise AgentServiceUnavailableError() from exception

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            connection = self._connection
            self._connection = None
            self._initialized = False
            if connection is not None:
                connection.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("coordination SQLite storage is closed")

    def _writer_connection(self) -> Connection:
        self._ensure_open()
        if self._connection is None:
            connection = self._connect()
            try:
                self._initialize(connection)
            except BaseException:
                connection.close()
                raise
            self._connection = connection
            self._initialized = True
        elif not self._initialized:
            self._initialize(self._connection)
            self._initialized = True
        return self._connection

    def _connect(self) -> Connection:
        try:
            connection = sqlite3.connect(
                self._path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA trusted_schema = OFF")
            return connection
        except sqlite3.Error as exception:
            raise AgentServiceUnavailableError() from exception

    def _initialize(self, connection: Connection) -> None:
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, COORDINATION_SQLITE_SCHEMA_VERSION}:
                raise AgentCodecError("unsupported coordination SQLite schema version")

            connection.execute("BEGIN IMMEDIATE")
            self._create_schema(connection)
            meta = connection.execute(
                "SELECT schema_version FROM coordination_meta WHERE singleton = 1"
            ).fetchone()
            now = datetime.now(UTC).isoformat()
            if version == 0:
                if meta is None:
                    connection.execute(
                        """
                        INSERT INTO coordination_meta (
                            singleton, schema_version, created_at, updated_at
                        ) VALUES (1, ?, ?, ?)
                        """,
                        (COORDINATION_SQLITE_SCHEMA_VERSION, now, now),
                    )
                elif _row_int(meta, "schema_version", positive=True) != (
                    COORDINATION_SQLITE_SCHEMA_VERSION
                ):
                    raise AgentCodecError(
                        "coordination SQLite metadata is incompatible with an unversioned database"
                    )
                connection.execute(f"PRAGMA user_version = {COORDINATION_SQLITE_SCHEMA_VERSION}")
            elif meta is None or _row_int(meta, "schema_version", positive=True) != (
                COORDINATION_SQLITE_SCHEMA_VERSION
            ):
                raise AgentCodecError("coordination SQLite metadata is missing or incompatible")
            connection.execute("COMMIT")
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
            CREATE TABLE IF NOT EXISTS coordination_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS coordination_delegations (
                delegation_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                parent_agent_id TEXT NOT NULL,
                parent_run_id TEXT NOT NULL,
                root_run_id TEXT NOT NULL,
                child_agent_id TEXT NOT NULL,
                child_run_id TEXT NOT NULL UNIQUE,
                depth INTEGER NOT NULL CHECK (depth >= 0),
                budget_model_turns INTEGER NOT NULL CHECK (budget_model_turns > 0),
                budget_tool_calls INTEGER NOT NULL CHECK (budget_tool_calls > 0),
                budget_input_tokens INTEGER NOT NULL CHECK (budget_input_tokens > 0),
                budget_output_tokens INTEGER NOT NULL CHECK (budget_output_tokens > 0),
                budget_prompt_bytes INTEGER NOT NULL CHECK (budget_prompt_bytes > 0),
                budget_result_bytes INTEGER NOT NULL CHECK (budget_result_bytes > 0),
                budget_duration_us INTEGER NOT NULL CHECK (budget_duration_us > 0),
                status TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                compatibility_digest TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                recovery_state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deadline TEXT NOT NULL,
                error_code TEXT
            )
            """
        )


def _require_sqlite_durable_capacity(
    connection: Connection,
    record: DurableDelegationRecord,
    *,
    limits: DelegationLimits,
    root_budget_limit: DelegationBudget,
) -> None:
    root = connection.execute(
        """
        SELECT
            COUNT(*) AS child_count,
            COALESCE(SUM(budget_model_turns), 0) AS model_turns,
            COALESCE(SUM(budget_tool_calls), 0) AS tool_calls,
            COALESCE(SUM(budget_input_tokens), 0) AS input_tokens,
            COALESCE(SUM(budget_output_tokens), 0) AS output_tokens,
            COALESCE(SUM(budget_prompt_bytes), 0) AS prompt_bytes,
            COALESCE(SUM(budget_result_bytes), 0) AS result_bytes,
            COALESCE(SUM(budget_duration_us), 0) AS duration_us
        FROM coordination_delegations
        WHERE root_run_id = ?
        """,
        (str(record.root_run_id),),
    ).fetchone()
    if root is None:
        raise AgentServiceUnavailableError()

    parent = connection.execute(
        """
        SELECT COUNT(*) AS child_count
        FROM coordination_delegations
        WHERE root_run_id = ? AND parent_run_id = ?
        """,
        (str(record.root_run_id), str(record.parent_run_id)),
    ).fetchone()
    if parent is None:
        raise AgentServiceUnavailableError()

    if _row_int(root, "child_count") + 1 > limits.max_total_children:
        raise AgentStateConflictError()
    if _row_int(parent, "child_count") + 1 > limits.max_fan_out:
        raise AgentStateConflictError()

    totals = (
        (
            "model_turns",
            record.budget.max_model_turns,
            root_budget_limit.max_model_turns,
        ),
        (
            "tool_calls",
            record.budget.max_tool_calls,
            root_budget_limit.max_tool_calls,
        ),
        (
            "input_tokens",
            record.budget.max_input_tokens,
            root_budget_limit.max_input_tokens,
        ),
        (
            "output_tokens",
            record.budget.max_output_tokens,
            root_budget_limit.max_output_tokens,
        ),
        (
            "prompt_bytes",
            record.budget.max_prompt_bytes,
            root_budget_limit.max_prompt_bytes,
        ),
        (
            "result_bytes",
            record.budget.max_result_bytes,
            root_budget_limit.max_result_bytes,
        ),
        (
            "duration_us",
            _duration_microseconds(record.budget.duration),
            _duration_microseconds(root_budget_limit.duration),
        ),
    )
    for column, increment, maximum in totals:
        if _row_int(root, column) + increment > maximum:
            raise AgentStateConflictError()


def _duration_microseconds(value: timedelta) -> int:
    return ((value.days * 86_400 + value.seconds) * 1_000_000) + value.microseconds


def _microseconds_duration(value: int) -> timedelta:
    return timedelta(microseconds=value)


def _record_values(record: DurableDelegationRecord) -> tuple[object, ...]:
    return (
        str(record.delegation_id),
        str(record.namespace),
        str(record.parent_agent_id),
        str(record.parent_run_id),
        str(record.root_run_id),
        str(record.child_agent_id),
        str(record.child_run_id),
        record.depth.value,
        record.budget.max_model_turns,
        record.budget.max_tool_calls,
        record.budget.max_input_tokens,
        record.budget.max_output_tokens,
        record.budget.max_prompt_bytes,
        record.budget.max_result_bytes,
        _duration_microseconds(record.budget.duration),
        record.status.value,
        record.request_digest,
        record.compatibility_digest,
        record.version.value,
        record.recovery_state.value,
        record.created_at.isoformat(),
        record.updated_at.isoformat(),
        record.deadline.isoformat(),
        record.error_code,
    )


def _require_same_identity(
    current: DurableDelegationRecord,
    candidate: DurableDelegationRecord,
) -> None:
    immutable = (
        "delegation_id",
        "namespace",
        "parent_agent_id",
        "parent_run_id",
        "root_run_id",
        "child_agent_id",
        "child_run_id",
        "depth",
        "budget",
        "request_digest",
        "compatibility_digest",
        "created_at",
        "deadline",
    )
    for field_name in immutable:
        if getattr(current, field_name) != getattr(candidate, field_name):
            raise AgentStateConflictError()
    if candidate.updated_at < current.updated_at:
        raise AgentStateConflictError()
