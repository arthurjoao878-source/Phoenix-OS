from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane import (
    MAX_COMMAND_JOURNAL_CAPACITY,
    ControlPlaneCommandAction,
    ControlPlaneCommandJournalAlreadyExistsError,
    ControlPlaneCommandJournalCapacityError,
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandJournalCorruptionError,
    ControlPlaneCommandJournalNotFoundError,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalPersistenceError,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalRepositoryClosedError,
    ControlPlaneCommandJournalSchemaError,
    ControlPlaneCommandJournalStatus,
    StateControlPlaneCommandJournalRepository,
    canonical_command_journal_record_bytes,
    command_journal_record_digest,
)
from phoenix_os.state import ABSENT_VERSION, MemoryStateStore, StateKey

_NOW = datetime(2026, 7, 19, 4, 0, tzinfo=UTC)
_NAMESPACE = "control-plane-command-journal"


def _record(
    *,
    command_id: UUID | None = None,
    digest_character: str = "a",
    fingerprint_character: str = "b",
    requested_at: datetime = _NOW,
) -> ControlPlaneCommandJournalRecord:
    return ControlPlaneCommandJournalRecord(
        command_id=command_id or uuid4(),
        action=ControlPlaneCommandAction.CREATE_JOB,
        target="job:daily-report",
        principal="phoenix.dashboard",
        idempotency_digest=digest_character * 64,
        fingerprint=fingerprint_character * 64,
        status=ControlPlaneCommandJournalStatus.PENDING,
        requested_at=requested_at,
        updated_at=requested_at,
    )


def _record_key(command_id: UUID) -> StateKey[dict[str, object]]:
    return StateKey(_NAMESPACE, f"record_{command_id.hex}", dict)


def _index_key(digest: str) -> StateKey[dict[str, object]]:
    return StateKey(_NAMESPACE, f"idempotency_{digest}", dict)


def _object_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return dict(cast(dict[str, object], value))


def _canonical_mapping_digest(value: dict[str, object]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


async def _stored_value(
    store: MemoryStateStore,
    key: StateKey[dict[str, object]],
) -> tuple[dict[str, object], int]:
    stored = await store.get(key)
    assert stored is not None
    return dict(stored.value), stored.version


def test_canonical_command_journal_record_bytes_are_deterministic() -> None:
    record = _record(command_id=UUID(int=1))

    first = canonical_command_journal_record_bytes(record)
    second = canonical_command_journal_record_bytes(record)

    assert first == second
    assert first.startswith(b'{"action":"job.create"')
    assert b" " not in first


def test_canonical_command_journal_record_bytes_contain_only_payload_free_fields() -> None:
    payload = canonical_command_journal_record_bytes(_record())

    assert b"arguments" not in payload
    assert b"output" not in payload
    assert b"csrf" not in payload
    assert b"confirmation" not in payload
    assert b"secret" not in payload


def test_command_journal_record_digest_is_sha256_of_canonical_bytes() -> None:
    record = _record()

    assert (
        command_journal_record_digest(record)
        == hashlib.sha256(canonical_command_journal_record_bytes(record)).hexdigest()
    )


def test_command_journal_record_digest_changes_with_revision() -> None:
    record = _record()
    executing = replace(
        record,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    assert command_journal_record_digest(executing) != command_journal_record_digest(record)


@pytest.mark.parametrize("capacity", [0, -1, MAX_COMMAND_JOURNAL_CAPACITY + 1])
def test_state_command_journal_rejects_invalid_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        StateControlPlaneCommandJournalRepository(MemoryStateStore(), capacity=capacity)


def test_state_command_journal_normalizes_namespace() -> None:
    repository = StateControlPlaneCommandJournalRepository(
        MemoryStateStore(),
        namespace=" COMMAND-JOURNAL ",
    )

    assert repository.closed is False


async def test_state_command_journal_adds_and_reads_record() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()

    await repository.add(record)

    assert await repository.get(record.command_id) == record
    assert await repository.get_by_idempotency_digest(record.idempotency_digest) == record


async def test_state_command_journal_survives_repository_restart() -> None:
    store = MemoryStateStore()
    first = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await first.add(record)
    await first.close()

    second = StateControlPlaneCommandJournalRepository(store)

    assert await second.get(record.command_id) == record
    assert await second.get_by_idempotency_digest(record.idempotency_digest) == record


async def test_state_command_journal_normalizes_digest_lookup() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)

    assert await repository.get_by_idempotency_digest("A" * 64) == record


async def test_state_command_journal_rejects_invalid_digest_lookup() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())

    with pytest.raises(ValueError, match="SHA-256"):
        await repository.get_by_idempotency_digest("not-a-digest")


async def test_state_command_journal_rejects_duplicate_command_id() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    command_id = uuid4()
    await repository.add(_record(command_id=command_id))

    with pytest.raises(ControlPlaneCommandJournalAlreadyExistsError):
        await repository.add(
            _record(
                command_id=command_id,
                digest_character="c",
                fingerprint_character="d",
            )
        )


async def test_state_command_journal_rejects_duplicate_idempotency_digest() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    await repository.add(_record())

    with pytest.raises(ControlPlaneCommandJournalAlreadyExistsError):
        await repository.add(_record(fingerprint_character="c"))


async def test_state_command_journal_enforces_capacity() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore(), capacity=1)
    await repository.add(_record())

    with pytest.raises(ControlPlaneCommandJournalCapacityError):
        await repository.add(_record(digest_character="c", fingerprint_character="d"))


async def test_state_command_journal_concurrent_duplicate_add_is_atomic() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    record = _record()

    results = await asyncio.gather(
        repository.add(record),
        repository.add(record),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    assert (
        sum(isinstance(result, ControlPlaneCommandJournalAlreadyExistsError) for result in results)
        == 1
    )


async def test_state_command_journal_lists_newest_first_with_pagination() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    older = _record(command_id=UUID(int=1))
    newer = _record(
        command_id=UUID(int=2),
        digest_character="c",
        fingerprint_character="d",
        requested_at=_NOW + timedelta(seconds=1),
    )
    await repository.add(older)
    await repository.add(newer)

    first = await repository.list_page(ControlPlaneCommandJournalPageRequest(limit=1))
    second = await repository.list_page(ControlPlaneCommandJournalPageRequest(offset=1, limit=1))

    assert first.items == (newer,)
    assert first.page.next_offset == 1
    assert second.items == (older,)
    assert second.page.next_offset is None


async def test_state_command_journal_transitions_to_executing() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    updated = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW + timedelta(seconds=1),
    )

    assert updated.status is ControlPlaneCommandJournalStatus.EXECUTING
    assert updated.revision == 2
    assert await repository.get(record.command_id) == updated


@pytest.mark.parametrize(
    ("status", "result_code"),
    [
        (ControlPlaneCommandJournalStatus.SUCCEEDED, "job.created"),
        (ControlPlaneCommandJournalStatus.REJECTED, "command.denied"),
        (ControlPlaneCommandJournalStatus.FAILED, "command.failed"),
    ],
)
async def test_state_command_journal_persists_terminal_transitions(
    status: ControlPlaneCommandJournalStatus,
    result_code: str,
) -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    completed_at = _NOW + timedelta(seconds=1)

    updated = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=status,
        updated_at=completed_at,
        result_code=result_code,
    )
    recovered = await StateControlPlaneCommandJournalRepository(store).get(record.command_id)

    assert updated.status is status
    assert updated.completed_at == completed_at
    assert updated.result_code == result_code
    assert recovered == updated


async def test_state_command_journal_rejects_stale_revision() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="revision"):
        await repository.transition(
            record.command_id,
            expected_revision=2,
            status=ControlPlaneCommandJournalStatus.EXECUTING,
            updated_at=_NOW + timedelta(seconds=1),
        )


async def test_state_command_journal_rejects_terminal_replacement() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)
    succeeded = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.SUCCEEDED,
        updated_at=_NOW + timedelta(seconds=1),
        result_code="job.created",
    )

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="transition"):
        await repository.transition(
            record.command_id,
            expected_revision=succeeded.revision,
            status=ControlPlaneCommandJournalStatus.FAILED,
            updated_at=_NOW + timedelta(seconds=2),
            result_code="command.failed",
        )


async def test_state_command_journal_rejects_time_travel() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="backwards"):
        await repository.transition(
            record.command_id,
            expected_revision=1,
            status=ControlPlaneCommandJournalStatus.EXECUTING,
            updated_at=_NOW - timedelta(seconds=1),
        )


async def test_state_command_journal_reports_missing_record() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())

    with pytest.raises(ControlPlaneCommandJournalNotFoundError):
        await repository.transition(
            uuid4(),
            expected_revision=1,
            status=ControlPlaneCommandJournalStatus.EXECUTING,
            updated_at=_NOW,
        )


async def test_state_command_journal_snapshot_counts_durable_states() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore(), capacity=10)
    pending = _record()
    executing = _record(digest_character="c", fingerprint_character="d")
    failed = _record(digest_character="e", fingerprint_character="f")
    await repository.add(pending)
    await repository.add(executing)
    await repository.add(failed)
    await repository.transition(
        executing.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW + timedelta(seconds=1),
    )
    await repository.transition(
        failed.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.FAILED,
        updated_at=_NOW + timedelta(seconds=1),
        result_code="command.failed",
    )

    snapshot = await repository.snapshot()

    assert snapshot.entries == 3
    assert snapshot.pending == 1
    assert snapshot.executing == 1
    assert snapshot.failed == 1
    assert snapshot.capacity == 10


async def test_state_command_journal_close_preserves_durable_records() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)

    await repository.close()
    snapshot = await repository.snapshot()

    assert repository.closed is True
    assert snapshot.closed is True
    assert snapshot.entries == 1
    assert store.closed is False


async def test_state_command_journal_rejects_operations_after_close() -> None:
    repository = StateControlPlaneCommandJournalRepository(MemoryStateStore())
    await repository.close()

    with pytest.raises(ControlPlaneCommandJournalRepositoryClosedError):
        await repository.get(uuid4())


async def test_state_command_journal_maps_closed_store_to_persistence_error() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    await store.close()

    with pytest.raises(ControlPlaneCommandJournalPersistenceError):
        await repository.get(uuid4())


async def test_state_command_journal_detects_missing_envelope_field() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    value.pop("record_digest")
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="fields"):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_extra_envelope_field() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    value["payload"] = {"secret": "must-not-exist"}
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="fields"):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_unknown_envelope_schema() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    value["schema_version"] = 2
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalSchemaError):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_unknown_record_schema() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["schema_version"] = 2
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalSchemaError):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_wrong_record_kind() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    value["kind"] = "phoenix.invalid"
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="kind"):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_record_digest_mismatch() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["target"] = "job:tampered"
    value["record"] = document
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="digest"):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_malformed_record_identity() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["command_id"] = "not-a-uuid"
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="invalid"):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_naive_persisted_timestamp() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.command_id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["requested_at"] = "2026-07-19T04:00:00"
    document["updated_at"] = "2026-07-19T04:00:00"
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="invalid"):
        await repository.get(record.command_id)


async def test_state_command_journal_detects_record_key_mismatch() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    value, _ = await _stored_value(store, _record_key(record.command_id))
    other_id = uuid4()
    await store.put(
        _record_key(other_id),
        value,
        expected_version=ABSENT_VERSION,
    )

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="state key"):
        await repository.get(other_id)


async def test_state_command_journal_detects_missing_index_on_transition() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    index_key = _index_key(record.idempotency_digest)
    stored = await store.get(index_key)
    assert stored is not None
    await store.delete(index_key, expected_version=stored.version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="no idempotency index"):
        await repository.transition(
            record.command_id,
            expected_revision=1,
            status=ControlPlaneCommandJournalStatus.EXECUTING,
            updated_at=_NOW + timedelta(seconds=1),
        )


async def test_state_command_journal_detects_index_referencing_missing_record() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    record_key = _record_key(record.command_id)
    stored = await store.get(record_key)
    assert stored is not None
    await store.delete(record_key, expected_version=stored.version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="missing record"):
        await repository.get_by_idempotency_digest(record.idempotency_digest)


async def test_state_command_journal_detects_mismatched_index_fingerprint() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _index_key(record.idempotency_digest)
    value, version = await _stored_value(store, key)
    value["fingerprint"] = "c" * 64
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="do not match"):
        await repository.get_by_idempotency_digest(record.idempotency_digest)


async def test_state_command_journal_detects_unknown_index_schema() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _index_key(record.idempotency_digest)
    value, version = await _stored_value(store, key)
    value["schema_version"] = 2
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalSchemaError):
        await repository.get_by_idempotency_digest(record.idempotency_digest)


async def test_state_command_journal_detects_invalid_index_fields() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    record = _record()
    await repository.add(record)
    key = _index_key(record.idempotency_digest)
    value, version = await _stored_value(store, key)
    value["plaintext_key"] = "must-not-exist"
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="fields"):
        await repository.get_by_idempotency_digest(record.idempotency_digest)


async def test_state_command_journal_detects_duplicate_persisted_digest() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneCommandJournalRepository(store)
    first = _record(command_id=UUID(int=1))
    second = _record(
        command_id=UUID(int=2),
        digest_character="c",
        fingerprint_character="d",
    )
    await repository.add(first)
    await repository.add(second)
    key = _record_key(second.command_id)
    value, version = await _stored_value(store, key)
    corrupted = replace(second, idempotency_digest=first.idempotency_digest)
    document = json.loads(canonical_command_journal_record_bytes(corrupted))
    assert isinstance(document, dict)
    value["record"] = document
    value["record_digest"] = command_journal_record_digest(corrupted)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneCommandJournalCorruptionError, match="duplicate"):
        await repository.list_page()
