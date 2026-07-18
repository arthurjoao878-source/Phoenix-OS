"""Durable SQLite audit store with transactional recovery and append-only guards."""

from __future__ import annotations

import asyncio
import inspect
import json
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final
from uuid import UUID

from phoenix_os.audit.codec import compute_audit_digest
from phoenix_os.audit.contracts import (
    AUDIT_GENESIS_DIGEST,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditRecord,
    AuditSeal,
    AuditSeverity,
    AuditSigner,
    AuditStoreSnapshot,
    AuditVerification,
)
from phoenix_os.audit.errors import (
    AuditPersistenceError,
    AuditRecoveryError,
    AuditSchemaError,
    AuditSignerError,
    AuditStoreClosedError,
    AuditStoreCorruptionError,
)
from phoenix_os.secrets import KeyRef

if TYPE_CHECKING:
    from sqlite3 import Connection, Row

_SCHEMA_VERSION: Final = 1
_DEFAULT_BUSY_TIMEOUT_MS: Final = 5_000

_RECORD_COLUMNS: Final = """
    sequence,
    event_id,
    name,
    source,
    category,
    action,
    resource,
    actor,
    outcome,
    severity,
    details_json,
    occurred_at,
    correlation_id,
    causation_id,
    recorded_at,
    previous_digest,
    digest,
    seal_key_name,
    seal_key_provider,
    seal_key_version,
    seal_algorithm,
    seal_signature
"""


def _portable(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _portable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_portable(item) for item in value]
    raise TypeError(f"unsupported persistent audit value: {type(value).__name__}")


def _details_json(details: Mapping[str, object]) -> str:
    return json.dumps(
        _portable(details),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _parse_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return parsed


def _row_sequence(row: Row, fallback: int) -> int:
    value = row["sequence"]
    return value if isinstance(value, int) and value > 0 else fallback


class SQLiteAuditStore:
    """File-backed audit chain using SQLite WAL and atomic append transactions.

    SQLite guards reject updates, deletes, sequence gaps, and broken previous-digest
    links through ordinary SQL writes. ``verify_on_open`` additionally verifies an
    existing complete chain before the store accepts a new append.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        signer: AuditSigner | None = None,
        signing_key: KeyRef | None = None,
        signing_algorithm: str = "external",
        verify_on_open: bool = True,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
        create_parent: bool = True,
    ) -> None:
        if (signer is None) is not (signing_key is None):
            raise ValueError("signer and signing_key must be configured together")
        algorithm = signing_algorithm.strip().lower()
        if not algorithm:
            raise ValueError("signing_algorithm must not be blank")
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms cannot be negative")

        database_path = Path(path).expanduser()
        if str(database_path).strip() in {"", ":memory:"}:
            raise ValueError("SQLite audit path must identify a durable file")
        if database_path.exists() and database_path.is_dir():
            raise ValueError("SQLite audit path must not be a directory")
        if create_parent:
            database_path.parent.mkdir(parents=True, exist_ok=True)
        elif not database_path.parent.exists():
            raise ValueError("SQLite audit parent directory does not exist")

        self._path = database_path.resolve()
        self._signer = signer
        self._signing_key = signing_key
        self._signing_algorithm = algorithm
        self._verify_on_open = bool(verify_on_open)
        self._busy_timeout_ms = busy_timeout_ms
        self._connection: Connection | None = None
        self._initialized = False
        self._verified_head_digest: str | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def closed(self) -> bool:
        return self._closed

    async def append(self, event: AuditEvent, *, recorded_at: datetime) -> AuditRecord:
        self._ensure_open()
        if recorded_at.tzinfo is None:
            raise ValueError("recorded_at must be timezone-aware")

        async with self._lock:
            self._ensure_open()
            connection = self._writer_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                meta = self._meta(connection)
                if self._verify_on_open and self._verified_head_digest != meta[1]:
                    recovery = await self._verify_connection(connection)
                    if not recovery.valid:
                        raise AuditRecoveryError(
                            "refusing audit append because recovery verification failed: "
                            f"{recovery.reason}"
                        )
                    self._verified_head_digest = recovery.head_digest
                    meta = self._meta(connection)

                head_sequence, head_digest = self._head(connection)
                meta_sequence, meta_digest = meta
                if meta_sequence != head_sequence or meta_digest != head_digest:
                    raise AuditRecoveryError(
                        "audit metadata does not match the persisted chain head"
                    )

                sequence = 1 if head_sequence is None else head_sequence + 1
                digest = compute_audit_digest(
                    event,
                    sequence=sequence,
                    recorded_at=recorded_at,
                    previous_digest=head_digest,
                )
                seal = await self._seal(digest)
                record = AuditRecord(
                    event=event,
                    sequence=sequence,
                    recorded_at=recorded_at,
                    previous_digest=head_digest,
                    digest=digest,
                    seal=seal,
                )
                self._insert(connection, record)
                connection.execute(
                    """
                    UPDATE audit_meta
                    SET head_sequence = ?, head_digest = ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (record.sequence, record.digest, datetime.now(UTC).isoformat()),
                )
                connection.execute("COMMIT")
                self._verified_head_digest = record.digest
                return record
            except asyncio.CancelledError:
                self._rollback(connection)
                raise
            except (AuditRecoveryError, AuditSignerError):
                self._rollback(connection)
                raise
            except sqlite3.IntegrityError as exception:
                self._rollback(connection)
                raise AuditPersistenceError(
                    f"SQLite rejected audit append: {exception}"
                ) from exception
            except sqlite3.Error as exception:
                self._rollback(connection)
                raise AuditPersistenceError("SQLite audit append failed") from exception
            except Exception:
                self._rollback(connection)
                raise

    async def read(self, query: AuditQuery) -> tuple[AuditRecord, ...]:
        async with self._lock:
            connection, transient = self._read_connection()
            try:
                clauses = ["sequence >= ?"]
                parameters: list[object] = [query.start_sequence]
                if query.end_sequence is not None:
                    clauses.append("sequence <= ?")
                    parameters.append(query.end_sequence)
                self._add_set_filter(clauses, parameters, "category", query.categories)
                self._add_set_filter(clauses, parameters, "outcome", query.outcomes)
                self._add_set_filter(clauses, parameters, "source", query.sources)
                self._add_set_filter(clauses, parameters, "actor", query.actors)
                self._add_set_filter(clauses, parameters, "action", query.actions)
                parameters.append(query.limit)
                rows = connection.execute(
                    f"""
                    SELECT {_RECORD_COLUMNS}
                    FROM audit_records
                    WHERE {" AND ".join(clauses)}
                    ORDER BY sequence ASC
                    LIMIT ?
                    """,
                    parameters,
                ).fetchall()
                try:
                    return tuple(self._decode_row(row) for row in rows)
                except (TypeError, ValueError, json.JSONDecodeError) as exception:
                    raise AuditStoreCorruptionError(
                        "persisted audit record cannot be decoded"
                    ) from exception
            except sqlite3.Error as exception:
                raise AuditPersistenceError("SQLite audit read failed") from exception
            finally:
                if transient:
                    connection.close()

    async def verify(self) -> AuditVerification:
        async with self._lock:
            connection, transient = self._read_connection()
            try:
                connection.execute("BEGIN")
                result = await self._verify_connection(connection)
                connection.execute("COMMIT")
                if result.valid:
                    self._verified_head_digest = result.head_digest
                else:
                    self._verified_head_digest = None
                return result
            except asyncio.CancelledError:
                self._rollback(connection)
                raise
            except AuditSignerError:
                self._rollback(connection)
                raise
            except sqlite3.Error as exception:
                self._rollback(connection)
                raise AuditPersistenceError("SQLite audit verification failed") from exception
            finally:
                if transient:
                    connection.close()

    async def snapshot(self) -> AuditStoreSnapshot:
        async with self._lock:
            if self._closed and not self._path.exists():
                return AuditStoreSnapshot(True, 0, None, AUDIT_GENESIS_DIGEST, 0)
            connection, transient = self._read_connection()
            try:
                row = connection.execute(
                    """
                    SELECT
                        COUNT(*) AS records,
                        MAX(sequence) AS head_sequence,
                        SUM(
                            CASE WHEN seal_signature IS NOT NULL THEN 1 ELSE 0 END
                        ) AS signed_records
                    FROM audit_records
                    """
                ).fetchone()
                assert row is not None
                head_sequence, head_digest = self._head(connection)
                return AuditStoreSnapshot(
                    closed=self._closed,
                    records=int(row["records"]),
                    head_sequence=head_sequence,
                    head_digest=head_digest,
                    signed_records=int(row["signed_records"] or 0),
                )
            except sqlite3.Error as exception:
                raise AuditPersistenceError("SQLite audit snapshot failed") from exception
            finally:
                if transient:
                    connection.close()

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()
        async with self._lock:
            connection = self._writer_connection()
            if not self._verify_on_open:
                return
            try:
                connection.execute("BEGIN IMMEDIATE")
                result = await self._verify_connection(connection)
                if not result.valid:
                    raise AuditRecoveryError(f"audit recovery verification failed: {result.reason}")
                connection.execute("COMMIT")
                self._verified_head_digest = result.head_digest
            except asyncio.CancelledError:
                self._rollback(connection)
                raise
            except AuditRecoveryError:
                self._rollback(connection)
                raise
            except sqlite3.Error as exception:
                self._rollback(connection)
                raise AuditPersistenceError("SQLite audit recovery failed") from exception

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            connection = self._connection
            self._connection = None
            if connection is not None:
                connection.close()

    def _writer_connection(self) -> Connection:
        if self._connection is None:
            connection = self._connect()
            try:
                self._initialize(connection)
            except Exception:
                connection.close()
                raise
            self._connection = connection
            self._initialized = True
        elif not self._initialized:
            self._initialize(self._connection)
            self._initialized = True
        return self._connection

    def _read_connection(self) -> tuple[Connection, bool]:
        if not self._closed:
            return self._writer_connection(), False
        if not self._path.exists():
            raise AuditPersistenceError("SQLite audit database does not exist")
        connection = self._connect()
        try:
            self._validate_schema(connection)
        except Exception:
            connection.close()
            raise
        return connection, True

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
            raise AuditPersistenceError("cannot open SQLite audit database") from exception

    def _initialize(self, connection: Connection) -> None:
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SCHEMA_VERSION}:
                raise AuditSchemaError(f"unsupported SQLite audit schema version: {version}")
            connection.execute("BEGIN IMMEDIATE")
            self._create_schema(connection)
            if version == 0:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            now = datetime.now(UTC).isoformat()
            connection.execute(
                """
                INSERT OR IGNORE INTO audit_meta (
                    singleton, schema_version, head_sequence, head_digest, created_at, updated_at
                ) VALUES (1, ?, NULL, ?, ?, ?)
                """,
                (_SCHEMA_VERSION, AUDIT_GENESIS_DIGEST, now, now),
            )
            connection.execute("COMMIT")
            self._validate_schema(connection)
        except AuditSchemaError:
            self._rollback(connection)
            raise
        except sqlite3.Error as exception:
            self._rollback(connection)
            raise AuditPersistenceError("cannot initialize SQLite audit schema") from exception

    def _create_schema(self, connection: Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                head_sequence INTEGER,
                head_digest TEXT NOT NULL CHECK (length(head_digest) = 64),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                event_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                actor TEXT NOT NULL,
                outcome TEXT NOT NULL,
                severity TEXT NOT NULL,
                details_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                correlation_id TEXT,
                causation_id TEXT,
                recorded_at TEXT NOT NULL,
                previous_digest TEXT NOT NULL CHECK (length(previous_digest) = 64),
                digest TEXT NOT NULL UNIQUE CHECK (length(digest) = 64),
                seal_key_name TEXT,
                seal_key_provider TEXT,
                seal_key_version INTEGER,
                seal_algorithm TEXT,
                seal_signature BLOB,
                CHECK (
                    (seal_signature IS NULL AND seal_key_name IS NULL
                        AND seal_key_provider IS NULL AND seal_key_version IS NULL
                        AND seal_algorithm IS NULL)
                    OR
                    (seal_signature IS NOT NULL AND seal_key_name IS NOT NULL
                        AND seal_key_provider IS NOT NULL AND seal_algorithm IS NOT NULL)
                )
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS audit_records_category_sequence
            ON audit_records(category, sequence)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS audit_records_actor_sequence
            ON audit_records(actor, sequence)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS audit_records_action_sequence
            ON audit_records(action, sequence)
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_records_no_update
            BEFORE UPDATE ON audit_records
            BEGIN
                SELECT RAISE(ABORT, 'audit records are append-only');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_records_no_delete
            BEFORE DELETE ON audit_records
            BEGIN
                SELECT RAISE(ABORT, 'audit records are append-only');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_records_sequence_guard
            BEFORE INSERT ON audit_records
            WHEN NEW.sequence != COALESCE(
                (SELECT MAX(sequence) + 1 FROM audit_records), 1
            )
            BEGIN
                SELECT RAISE(ABORT, 'audit sequence must be contiguous');
            END
            """
        )
        connection.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS audit_records_link_guard
            BEFORE INSERT ON audit_records
            WHEN NEW.previous_digest != COALESCE(
                (SELECT digest FROM audit_records ORDER BY sequence DESC LIMIT 1),
                '{AUDIT_GENESIS_DIGEST}'
            )
            BEGIN
                SELECT RAISE(ABORT, 'audit previous digest must match the chain head');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_records_no_meta_delete
            BEFORE DELETE ON audit_meta
            BEGIN
                SELECT RAISE(ABORT, 'audit metadata cannot be deleted');
            END
            """
        )

    def _validate_schema(self, connection: Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != _SCHEMA_VERSION:
            raise AuditSchemaError(f"unsupported SQLite audit schema version: {version}")
        meta = connection.execute(
            "SELECT schema_version FROM audit_meta WHERE singleton = 1"
        ).fetchone()
        if meta is None or int(meta["schema_version"]) != _SCHEMA_VERSION:
            raise AuditSchemaError("SQLite audit metadata is missing or incompatible")

    def _insert(self, connection: Connection, record: AuditRecord) -> None:
        seal = record.seal
        connection.execute(
            f"""
            INSERT INTO audit_records ({_RECORD_COLUMNS})
            VALUES ({", ".join("?" for _ in range(22))})
            """,
            (
                record.sequence,
                str(record.event.id),
                record.event.name,
                record.event.source,
                record.event.category.value,
                record.event.action,
                record.event.resource,
                record.event.actor,
                record.event.outcome.value,
                record.event.severity.value,
                _details_json(record.event.details),
                record.event.occurred_at.isoformat(),
                record.event.correlation_id,
                None if record.event.causation_id is None else str(record.event.causation_id),
                record.recorded_at.isoformat(),
                record.previous_digest,
                record.digest,
                None if seal is None else seal.key.name,
                None if seal is None else seal.key.provider,
                None if seal is None else seal.key.version,
                None if seal is None else seal.algorithm,
                None if seal is None else sqlite3.Binary(seal.signature),
            ),
        )

    def _decode_row(self, row: Row) -> AuditRecord:
        raw_details = json.loads(row["details_json"])
        if not isinstance(raw_details, dict):
            raise ValueError("audit details must decode to an object")
        event = AuditEvent(
            id=UUID(row["event_id"]),
            name=row["name"],
            source=row["source"],
            category=AuditCategory(row["category"]),
            action=row["action"],
            resource=row["resource"],
            actor=row["actor"],
            outcome=AuditOutcome(row["outcome"]),
            severity=AuditSeverity(row["severity"]),
            details=MappingProxyType(raw_details),
            occurred_at=_parse_datetime(row["occurred_at"], "occurred_at"),
            correlation_id=row["correlation_id"],
            causation_id=None if row["causation_id"] is None else UUID(row["causation_id"]),
        )
        seal = None
        if row["seal_signature"] is not None:
            signature = row["seal_signature"]
            if isinstance(signature, memoryview):
                signature = signature.tobytes()
            seal = AuditSeal(
                key=KeyRef(
                    name=row["seal_key_name"],
                    provider=row["seal_key_provider"],
                    version=row["seal_key_version"],
                ),
                algorithm=row["seal_algorithm"],
                signature=bytes(signature),
            )
        return AuditRecord(
            event=event,
            sequence=row["sequence"],
            recorded_at=_parse_datetime(row["recorded_at"], "recorded_at"),
            previous_digest=row["previous_digest"],
            digest=row["digest"],
            seal=seal,
        )

    async def _verify_connection(self, connection: Connection) -> AuditVerification:
        rows = connection.execute(
            f"SELECT {_RECORD_COLUMNS} FROM audit_records ORDER BY sequence ASC"
        ).fetchall()
        meta_sequence, meta_digest = self._meta(connection)
        if not rows:
            if meta_sequence is not None or meta_digest != AUDIT_GENESIS_DIGEST:
                return AuditVerification(
                    valid=False,
                    checked_records=0,
                    head_digest=AUDIT_GENESIS_DIGEST,
                    failure_sequence=1,
                    reason="audit metadata does not represent an empty chain",
                )
            return AuditVerification(True, 0, AUDIT_GENESIS_DIGEST)

        records: list[AuditRecord] = []
        previous_digest = AUDIT_GENESIS_DIGEST
        signatures_checked = 0
        for expected_sequence, row in enumerate(rows, start=1):
            failure_sequence = _row_sequence(row, expected_sequence)
            try:
                record = self._decode_row(row)
            except (TypeError, ValueError, json.JSONDecodeError) as exception:
                return AuditVerification(
                    valid=False,
                    checked_records=expected_sequence,
                    first_sequence=1,
                    last_sequence=len(rows),
                    head_digest=previous_digest,
                    failure_sequence=failure_sequence,
                    reason=f"record decoding failed: {type(exception).__name__}",
                    signatures_checked=signatures_checked,
                )
            records.append(record)
            if record.sequence != expected_sequence:
                return self._invalid(
                    records,
                    len(rows),
                    expected_sequence,
                    record.sequence,
                    f"sequence mismatch: expected {expected_sequence}, found {record.sequence}",
                    signatures_checked,
                    previous_digest,
                )
            if record.previous_digest != previous_digest:
                return self._invalid(
                    records,
                    len(rows),
                    expected_sequence,
                    record.sequence,
                    "previous digest link mismatch",
                    signatures_checked,
                    previous_digest,
                )
            expected_digest = compute_audit_digest(
                record.event,
                sequence=record.sequence,
                recorded_at=record.recorded_at,
                previous_digest=record.previous_digest,
            )
            if record.digest != expected_digest:
                return self._invalid(
                    records,
                    len(rows),
                    expected_sequence,
                    record.sequence,
                    "record digest mismatch",
                    signatures_checked,
                    previous_digest,
                )
            if record.seal is not None:
                if self._signer is None:
                    return self._invalid(
                        records,
                        len(rows),
                        expected_sequence,
                        record.sequence,
                        "signature verifier unavailable",
                        signatures_checked,
                        previous_digest,
                    )
                try:
                    valid = self._signer.verify(
                        bytes.fromhex(record.digest),
                        record.seal.signature,
                        key=record.seal.key,
                    )
                    if inspect.isawaitable(valid):
                        valid = await valid
                except asyncio.CancelledError:
                    raise
                except Exception as exception:
                    raise AuditSignerError("audit signature verification failed") from exception
                if not valid:
                    return self._invalid(
                        records,
                        len(rows),
                        expected_sequence,
                        record.sequence,
                        "external signature mismatch",
                        signatures_checked,
                        previous_digest,
                    )
                signatures_checked += 1
            previous_digest = record.digest

        head = records[-1]
        if meta_sequence != head.sequence or meta_digest != head.digest:
            return AuditVerification(
                valid=False,
                checked_records=len(records),
                first_sequence=records[0].sequence,
                last_sequence=head.sequence,
                head_digest=head.digest,
                failure_sequence=head.sequence,
                reason="audit metadata does not match the persisted chain head",
                signatures_checked=signatures_checked,
            )
        return AuditVerification(
            valid=True,
            checked_records=len(records),
            first_sequence=records[0].sequence,
            last_sequence=head.sequence,
            head_digest=head.digest,
            signatures_checked=signatures_checked,
        )

    async def _seal(self, digest: str) -> AuditSeal | None:
        if self._signer is None or self._signing_key is None:
            return None
        try:
            signature = self._signer.sign(bytes.fromhex(digest), key=self._signing_key)
            if inspect.isawaitable(signature):
                signature = await signature
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            raise AuditSignerError("audit signature creation failed") from exception
        return AuditSeal(
            key=self._signing_key,
            algorithm=self._signing_algorithm,
            signature=bytes(signature),
        )

    @staticmethod
    def _invalid(
        records: list[AuditRecord],
        total_rows: int,
        checked_records: int,
        failure_sequence: int,
        reason: str,
        signatures_checked: int,
        head_digest: str,
    ) -> AuditVerification:
        first_sequence = records[0].sequence if records else 1
        last_sequence = records[-1].sequence if records else total_rows
        return AuditVerification(
            valid=False,
            checked_records=checked_records,
            first_sequence=first_sequence,
            last_sequence=last_sequence,
            head_digest=head_digest,
            failure_sequence=failure_sequence,
            reason=reason,
            signatures_checked=signatures_checked,
        )

    @staticmethod
    def _add_set_filter(
        clauses: list[str],
        parameters: list[object],
        column: str,
        values: frozenset[object],
    ) -> None:
        if not values:
            return
        ordered = sorted(str(value.value if hasattr(value, "value") else value) for value in values)
        clauses.append(f"{column} IN ({', '.join('?' for _ in ordered)})")
        parameters.extend(ordered)

    @staticmethod
    def _rollback(connection: Connection) -> None:
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    @staticmethod
    def _head(connection: Connection) -> tuple[int | None, str]:
        row = connection.execute(
            "SELECT sequence, digest FROM audit_records ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None, AUDIT_GENESIS_DIGEST
        return int(row["sequence"]), str(row["digest"])

    @staticmethod
    def _meta(connection: Connection) -> tuple[int | None, str]:
        row = connection.execute(
            "SELECT head_sequence, head_digest FROM audit_meta WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise AuditSchemaError("SQLite audit metadata row is missing")
        sequence = None if row["head_sequence"] is None else int(row["head_sequence"])
        return sequence, str(row["head_digest"])

    def _ensure_open(self) -> None:
        if self._closed:
            raise AuditStoreClosedError("audit store is closed")
