from __future__ import annotations

import sqlite3
from pathlib import Path

from phoenix_os.agent.durable_sqlite import (
    DURABLE_SQLITE_SCHEMA_VERSION,
    SQLiteDurableRunStore,
)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _create_v2_database(path: Path) -> None:
    connection = _connect(path)
    now = "2026-08-02T12:00:00+00:00"

    connection.execute("PRAGMA user_version = 2")
    connection.execute(
        """
        CREATE TABLE durable_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO durable_meta (
            singleton, schema_version, created_at, updated_at
        ) VALUES (1, 2, ?, ?)
        """,
        (now, now),
    )
    connection.execute(
        """
        CREATE TABLE durable_runs (
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
        CREATE TABLE durable_checkpoints (
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
            FOREIGN KEY (run_id)
                REFERENCES durable_runs(run_id)
                ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE durable_leases (
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
        CREATE TABLE durable_protected_payloads (
            reference TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            checkpoint_id TEXT NOT NULL,
            schema_version INTEGER NOT NULL CHECK (schema_version > 0),
            profile TEXT NOT NULL,
            key_version TEXT NOT NULL,
            plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0),
            ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
            ciphertext_digest TEXT NOT NULL CHECK (
                length(ciphertext_digest) = 64
            ),
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
    connection.close()


def _assert_v3_tombstone_schema(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'durable_tombstones'
        """
    ).fetchone()
    assert table is not None

    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(durable_tombstones)").fetchall()
    }
    assert columns == {
        "run_id",
        "terminal_status",
        "terminal_version",
        "final_checkpoint_digest",
        "deletion_generation",
        "terminal_at",
        "retain_until",
    }

    index = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'index'
          AND name = 'durable_tombstones_retention'
        """
    ).fetchone()
    assert index is not None


async def test_fresh_sqlite_database_uses_v3_tombstone_schema(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fresh.sqlite3"
    store = SQLiteDurableRunStore(path)

    await store.get_current(
        __import__(
            "phoenix_os.agent.durable_contracts",
            fromlist=["DurableAgentRunId"],
        ).DurableAgentRunId(__import__("uuid").UUID(int=1))
    )

    assert DURABLE_SQLITE_SCHEMA_VERSION == 5

    connection = _connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == DURABLE_SQLITE_SCHEMA_VERSION
    meta = connection.execute(
        "SELECT schema_version FROM durable_meta WHERE singleton = 1"
    ).fetchone()
    assert meta is not None
    assert meta["schema_version"] == DURABLE_SQLITE_SCHEMA_VERSION
    _assert_v3_tombstone_schema(connection)
    connection.close()

    await store.close()


async def test_sqlite_schema_migrates_v2_database_to_v3_tombstones(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v2.sqlite3"
    _create_v2_database(path)

    store = SQLiteDurableRunStore(path)
    await store.get_current(
        __import__(
            "phoenix_os.agent.durable_contracts",
            fromlist=["DurableAgentRunId"],
        ).DurableAgentRunId(__import__("uuid").UUID(int=2))
    )

    connection = _connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == DURABLE_SQLITE_SCHEMA_VERSION

    meta = connection.execute(
        "SELECT schema_version FROM durable_meta WHERE singleton = 1"
    ).fetchone()
    assert meta is not None
    assert meta["schema_version"] == DURABLE_SQLITE_SCHEMA_VERSION

    protected_table = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'durable_protected_payloads'
        """
    ).fetchone()
    assert protected_table is not None

    _assert_v3_tombstone_schema(connection)
    connection.close()

    await store.close()
