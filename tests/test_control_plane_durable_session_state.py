from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    MAX_DURABLE_SESSION_CAPACITY,
    MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionAlreadyExistsError,
    ControlPlaneDurableSessionCapacityError,
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionCorruptionError,
    ControlPlaneDurableSessionNotFoundError,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionPersistenceError,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepositoryClosedError,
    ControlPlaneDurableSessionSchemaError,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
    StateControlPlaneDurableSessionRepository,
    canonical_control_plane_durable_session_record_bytes,
    control_plane_durable_session_record_digest,
)
from phoenix_os.state import ABSENT_VERSION, MemoryStateStore, StateKey

NOW = datetime(2026, 7, 19, 16, 0, tzinfo=UTC)
NAMESPACE = "control-plane-durable-sessions"
DEFAULT_OPERATOR_ID = UUID(int=100)
POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=2),
    idle_ttl=timedelta(minutes=30),
    rotation_interval=timedelta(minutes=10),
)


def _record(
    value: int = 1,
    *,
    operator_id: UUID = DEFAULT_OPERATOR_ID,
    issued_at: datetime = NOW,
    generation: int = 1,
    predecessor_session_id: UUID | None = None,
    absolute_expires_at: datetime | None = None,
) -> ControlPlaneDurableSessionRecord:
    return ControlPlaneDurableSessionRecord.issue(
        session_id=UUID(int=value),
        operator_id=operator_id,
        username=f"operator.{operator_id.int}",
        token=ControlPlaneDurableSessionToken(f"token-{value:026d}"),
        csrf_secret=ControlPlaneDurableCsrfSecret(f"csrf-{value:027d}"),
        operator_revision=4,
        operator_token_version=3,
        issued_at=issued_at,
        policy=POLICY,
        generation=generation,
        predecessor_session_id=predecessor_session_id,
        absolute_expires_at=absolute_expires_at,
    )


def _successor(
    current: ControlPlaneDurableSessionRecord,
    *,
    value: int = 2,
    rotated_at: datetime = NOW + timedelta(minutes=10),
) -> ControlPlaneDurableSessionRecord:
    return _record(
        value,
        operator_id=current.operator_id,
        issued_at=rotated_at,
        generation=current.generation + 1,
        predecessor_session_id=current.id,
        absolute_expires_at=current.absolute_expires_at,
    )


def _record_key(session_id: UUID) -> StateKey[dict[str, object]]:
    return StateKey(NAMESPACE, f"session_{session_id.hex}", dict)


def _token_key(token_digest: str) -> StateKey[dict[str, object]]:
    return StateKey(NAMESPACE, f"token_{token_digest}", dict)


def _operator_key(record: ControlPlaneDurableSessionRecord) -> StateKey[dict[str, object]]:
    return StateKey(NAMESPACE, f"operator_{record.operator_id.hex}_{record.id.hex}", dict)


def _lineage_key(session_id: UUID) -> StateKey[dict[str, object]]:
    return StateKey(NAMESPACE, f"lineage_{session_id.hex}", dict)


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


async def _rewrite_record_document(
    store: MemoryStateStore,
    record: ControlPlaneDurableSessionRecord,
    mutation: Callable[[dict[str, object]], None],
) -> None:
    key = _record_key(record.id)
    envelope, version = await _stored_value(store, key)
    document = _object_dict(envelope["record"])
    mutation(document)
    envelope["record"] = document
    envelope["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, envelope, expected_version=version)


def test_canonical_session_record_bytes_are_deterministic() -> None:
    record = _record()

    first = canonical_control_plane_durable_session_record_bytes(record)
    second = canonical_control_plane_durable_session_record_bytes(record)

    assert first == second
    assert first.startswith(b'{"absolute_expires_at":')
    assert b" " not in first


def test_canonical_session_record_contains_only_digests() -> None:
    payload = canonical_control_plane_durable_session_record_bytes(_record())

    assert b"token-00000000000000000000000001" not in payload
    assert b"csrf-000000000000000000000000001" not in payload
    assert b'"token_digest"' in payload
    assert b'"csrf_digest"' in payload


def test_session_record_digest_is_sha256_of_canonical_bytes() -> None:
    record = _record()

    assert (
        control_plane_durable_session_record_digest(record)
        == hashlib.sha256(canonical_control_plane_durable_session_record_bytes(record)).hexdigest()
    )


def test_session_record_digest_changes_with_revision() -> None:
    record = _record()
    updated = replace(
        record,
        last_seen_at=NOW + timedelta(minutes=1),
        idle_expires_at=NOW + timedelta(minutes=31),
        revision=2,
    )

    assert control_plane_durable_session_record_digest(updated) != (
        control_plane_durable_session_record_digest(record)
    )


@pytest.mark.parametrize(
    "capacity,max_sessions_per_operator",
    [
        (0, 8),
        (MAX_DURABLE_SESSION_CAPACITY + 1, 8),
        (4096, 0),
        (4096, MAX_DURABLE_SESSIONS_PER_OPERATOR + 1),
    ],
)
def test_state_repository_rejects_invalid_bounds(
    capacity: int,
    max_sessions_per_operator: int,
) -> None:
    with pytest.raises(ValueError):
        StateControlPlaneDurableSessionRepository(
            MemoryStateStore(),
            capacity=capacity,
            max_sessions_per_operator=max_sessions_per_operator,
        )


def test_state_repository_normalizes_namespace() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        namespace=" CONTROL-PLANE-DURABLE-SESSIONS ",
    )

    assert repository.closed is False


async def test_state_repository_adds_and_reads_all_indexes() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    record = _record()

    await repository.add(record)

    assert await repository.get(record.id) == record
    assert await repository.get_by_token_digest(record.token_digest.upper()) == record


async def test_state_repository_returns_none_for_unknown_identity() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())

    assert await repository.get(UUID(int=999)) is None
    assert await repository.get_by_token_digest("0" * 64) is None


async def test_state_repository_rejects_invalid_digest_lookup() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())

    with pytest.raises(ValueError, match="digest"):
        await repository.get_by_token_digest("not-a-digest")


async def test_state_repository_survives_repository_restart() -> None:
    store = MemoryStateStore()
    first = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await first.add(record)
    await first.close()

    second = StateControlPlaneDurableSessionRepository(store)

    assert await second.get(record.id) == record
    assert await second.get_by_token_digest(record.token_digest) == record


async def test_state_repository_rejects_duplicate_identity() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError, match="identity"):
        await repository.add(record)


async def test_state_repository_rejects_duplicate_token_digest() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    duplicate = replace(_record(2), token_digest=record.token_digest)
    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError, match="digest"):
        await repository.add(duplicate)


async def test_state_repository_rejects_cross_token_csrf_digest_reuse() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    first = _record()
    await repository.add(first)

    duplicate = replace(_record(2), csrf_digest=first.token_digest)
    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError, match="protected"):
        await repository.add(duplicate)


async def test_state_repository_rejects_lineage_record_added_directly() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    first = _record()
    await repository.add(first)
    successor = _successor(first)

    with pytest.raises(ControlPlaneDurableSessionConflictError, match="rotate"):
        await repository.add(successor)


async def test_state_repository_enforces_total_capacity() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        capacity=1,
        max_sessions_per_operator=2,
    )
    await repository.add(_record())

    with pytest.raises(ControlPlaneDurableSessionCapacityError, match="capacity"):
        await repository.add(_record(2, operator_id=UUID(int=200)))


async def test_state_repository_enforces_active_capacity_per_operator() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        capacity=4,
        max_sessions_per_operator=1,
    )
    await repository.add(_record())

    with pytest.raises(ControlPlaneDurableSessionCapacityError, match="per-operator"):
        await repository.add(_record(2))

    await repository.add(_record(3, operator_id=UUID(int=200)))


async def test_terminal_session_does_not_consume_active_operator_limit() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        max_sessions_per_operator=1,
    )
    terminal = replace(
        _record(),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )

    await repository.add(terminal)
    await repository.add(_record(2))

    assert (await repository.snapshot()).active == 1


async def test_state_repository_lists_newest_first_with_stable_ties() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        max_sessions_per_operator=8,
    )
    await repository.add(_record(3, issued_at=NOW + timedelta(minutes=2)))
    await repository.add(_record(2, issued_at=NOW + timedelta(minutes=1)))
    await repository.add(_record(1, issued_at=NOW + timedelta(minutes=1)))

    first = await repository.list_page(ControlPlaneDurableSessionPageRequest(limit=2))
    second = await repository.list_page(ControlPlaneDurableSessionPageRequest(offset=2, limit=2))

    assert [item.id for item in first.items] == [UUID(int=3), UUID(int=1)]
    assert first.page.next_offset == 2
    assert [item.id for item in second.items] == [UUID(int=2)]


async def test_state_repository_applies_exact_operator_and_status_filters() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        max_sessions_per_operator=8,
    )
    operator_id = UUID(int=300)
    active = _record(1, operator_id=operator_id)
    revoked = replace(
        _record(2, operator_id=operator_id),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        revision=2,
    )
    await repository.add(active)
    await repository.add(revoked)
    await repository.add(_record(3, operator_id=UUID(int=301)))

    page = await repository.list_page(
        ControlPlaneDurableSessionPageRequest(
            operator_id=operator_id,
            status=ControlPlaneDurableSessionStatus.REVOKED,
        )
    )

    assert page.items == (revoked,)


async def test_state_repository_lists_active_sessions_for_operator() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        max_sessions_per_operator=4,
    )
    operator_id = UUID(int=400)
    await repository.add(_record(1, operator_id=operator_id, issued_at=NOW))
    await repository.add(_record(2, operator_id=operator_id, issued_at=NOW + timedelta(minutes=1)))
    await repository.add(_record(3, operator_id=UUID(int=401)))

    active = await repository.list_active_for_operator(operator_id, limit=1)

    assert [item.id for item in active] == [UUID(int=2)]


@pytest.mark.parametrize("limit", [0, MAX_DURABLE_SESSIONS_PER_OPERATOR + 1])
async def test_state_repository_rejects_invalid_active_limit(limit: int) -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())

    with pytest.raises(ValueError, match="limit"):
        await repository.list_active_for_operator(DEFAULT_OPERATOR_ID, limit=limit)


async def test_state_repository_touch_is_atomic_and_survives_restart() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    seen_at = NOW + timedelta(minutes=5)
    idle_expires_at = NOW + timedelta(minutes=35)

    updated = await repository.touch(
        record.id,
        expected_revision=1,
        seen_at=seen_at,
        idle_expires_at=idle_expires_at,
    )

    assert updated.revision == 2
    assert updated.last_seen_at == seen_at
    recovered = StateControlPlaneDurableSessionRepository(store)
    assert await recovered.get(record.id) == updated


@pytest.mark.parametrize(
    "expected_revision,seen_at,idle_expires_at,error",
    [
        (0, NOW, NOW + timedelta(minutes=1), ValueError),
        (2, NOW, NOW + timedelta(minutes=1), ControlPlaneDurableSessionConflictError),
        (
            1,
            NOW - timedelta(seconds=1),
            NOW + timedelta(minutes=1),
            ControlPlaneDurableSessionConflictError,
        ),
        (
            1,
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=1),
            ControlPlaneDurableSessionConflictError,
        ),
        (
            1,
            NOW + timedelta(hours=2),
            NOW + timedelta(hours=2, minutes=1),
            ControlPlaneDurableSessionConflictError,
        ),
    ],
)
async def test_state_repository_touch_rejects_invalid_updates(
    expected_revision: int,
    seen_at: datetime,
    idle_expires_at: datetime,
    error: type[Exception],
) -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    with pytest.raises(error):
        await repository.touch(
            record.id,
            expected_revision=expected_revision,
            seen_at=seen_at,
            idle_expires_at=idle_expires_at,
        )


async def test_state_repository_terminate_is_atomic_and_survives_restart() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)

    terminated = await repository.terminate(
        record.id,
        expected_revision=1,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        terminated_at=NOW + timedelta(minutes=1),
    )

    assert terminated.status is ControlPlaneDurableSessionStatus.REVOKED
    assert terminated.revision == 2
    recovered = StateControlPlaneDurableSessionRepository(store)
    assert await recovered.get_by_token_digest(record.token_digest) == terminated


@pytest.mark.parametrize(
    "status,reason",
    [
        (
            ControlPlaneDurableSessionStatus.ACTIVE,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
        ),
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
        ),
        (
            ControlPlaneDurableSessionStatus.EXPIRED,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
        ),
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
        ),
    ],
)
async def test_state_repository_terminate_rejects_invalid_status_reason_pairs(
    status: ControlPlaneDurableSessionStatus,
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    with pytest.raises(ValueError):
        await repository.terminate(
            record.id,
            expected_revision=1,
            status=status,
            reason=reason,
            terminated_at=NOW + timedelta(minutes=1),
        )


async def test_state_repository_rejects_terminal_mutation() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    terminal = replace(
        _record(),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )
    await repository.add(terminal)

    with pytest.raises(ControlPlaneDurableSessionConflictError, match="terminal"):
        await repository.touch(
            terminal.id,
            expected_revision=2,
            seen_at=NOW + timedelta(minutes=2),
            idle_expires_at=NOW + timedelta(minutes=32),
        )


async def test_state_repository_rotate_updates_lineage_and_both_indexes_atomically() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    current = _record()
    await repository.add(current)
    successor = _successor(current)

    rotation = await repository.rotate(
        current.id,
        expected_revision=1,
        successor=successor,
        rotated_at=successor.issued_at,
    )

    assert rotation.previous.status is ControlPlaneDurableSessionStatus.ROTATED
    assert rotation.previous.successor_session_id == successor.id
    assert await repository.get_by_token_digest(current.token_digest) == rotation.previous
    assert await repository.get_by_token_digest(successor.token_digest) == successor
    recovered = StateControlPlaneDurableSessionRepository(store)
    assert await recovered.get(current.id) == rotation.previous
    assert await recovered.get(successor.id) == successor


async def test_state_repository_rotate_rejects_stale_revision() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    current = _record()
    await repository.add(current)

    with pytest.raises(ControlPlaneDurableSessionConflictError, match="revision"):
        await repository.rotate(
            current.id,
            expected_revision=2,
            successor=_successor(current),
            rotated_at=NOW + timedelta(minutes=10),
        )


async def test_state_repository_rotate_rejects_duplicate_successor_digest() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        max_sessions_per_operator=4,
    )
    current = _record()
    other = _record(3, operator_id=UUID(int=200))
    await repository.add(current)
    await repository.add(other)
    successor = replace(_successor(current), token_digest=other.token_digest)

    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError, match="digest"):
        await repository.rotate(
            current.id,
            expected_revision=1,
            successor=successor,
            rotated_at=successor.issued_at,
        )


async def test_state_repository_rotate_rejects_absolute_extension() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    current = _record()
    await repository.add(current)
    successor = _successor(current)
    successor = replace(
        successor,
        absolute_expires_at=successor.absolute_expires_at + timedelta(minutes=1),
        idle_expires_at=successor.idle_expires_at + timedelta(minutes=1),
    )

    with pytest.raises(ControlPlaneDurableSessionConflictError, match="absolute"):
        await repository.rotate(
            current.id,
            expected_revision=1,
            successor=successor,
            rotated_at=successor.issued_at,
        )


async def test_state_repository_delete_terminal_removes_all_indexes() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    terminal = replace(
        _record(),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )
    await repository.add(terminal)

    await repository.delete_terminal(terminal.id, expected_revision=2)

    assert await repository.get(terminal.id) is None
    assert await repository.get_by_token_digest(terminal.token_digest) is None
    assert await store.get(_operator_key(terminal)) is None
    assert await store.get(_lineage_key(terminal.id)) is None


async def test_state_repository_delete_rejects_active_or_stale_record() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneDurableSessionConflictError, match="active"):
        await repository.delete_terminal(record.id, expected_revision=1)
    with pytest.raises(ControlPlaneDurableSessionConflictError, match="revision"):
        await repository.delete_terminal(record.id, expected_revision=2)


async def test_state_repository_delete_rejects_lineage_bound_terminal_record() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    current = _record()
    await repository.add(current)
    successor = _successor(current)
    rotation = await repository.rotate(
        current.id,
        expected_revision=1,
        successor=successor,
        rotated_at=successor.issued_at,
    )

    with pytest.raises(ControlPlaneDurableSessionConflictError, match="chain-aware"):
        await repository.delete_terminal(
            rotation.previous.id,
            expected_revision=rotation.previous.revision,
        )


async def test_state_repository_raises_not_found_for_mutations() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())

    with pytest.raises(ControlPlaneDurableSessionNotFoundError):
        await repository.touch(
            UUID(int=999),
            expected_revision=1,
            seen_at=NOW,
            idle_expires_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(ControlPlaneDurableSessionNotFoundError):
        await repository.delete_terminal(UUID(int=999), expected_revision=1)


async def test_state_repository_snapshot_contains_safe_counts() -> None:
    repository = StateControlPlaneDurableSessionRepository(
        MemoryStateStore(),
        capacity=8,
        max_sessions_per_operator=4,
    )
    active = _record(1)
    revoked = replace(
        _record(2),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )
    expired = replace(
        _record(3),
        status=ControlPlaneDurableSessionStatus.EXPIRED,
        terminated_at=NOW + timedelta(minutes=31),
        termination_reason=ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
        revision=2,
    )
    await repository.add(active)
    await repository.add(revoked)
    await repository.add(expired)

    snapshot = await repository.snapshot()

    assert snapshot.entries == 3
    assert snapshot.active == 1
    assert snapshot.revoked == 1
    assert snapshot.expired == 1
    assert snapshot.rotated == 0
    assert snapshot.capacity == 8


async def test_state_repository_close_preserves_store_and_snapshot() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)

    await repository.close()

    assert store.closed is False
    assert (await repository.snapshot()).closed is True
    recovered = StateControlPlaneDurableSessionRepository(store)
    assert await recovered.get(record.id) == record


async def test_state_repository_rejects_operations_after_close() -> None:
    repository = StateControlPlaneDurableSessionRepository(MemoryStateStore())
    await repository.close()

    with pytest.raises(ControlPlaneDurableSessionRepositoryClosedError):
        await repository.get(UUID(int=1))
    with pytest.raises(ControlPlaneDurableSessionRepositoryClosedError):
        await repository.list_page()


async def test_state_repository_maps_closed_store_to_persistence_error() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    await store.close()

    with pytest.raises(ControlPlaneDurableSessionPersistenceError):
        await repository.get(UUID(int=1))


async def test_state_repository_detects_missing_envelope_field() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    value.pop("record_digest")
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="fields"):
        await repository.get(record.id)


async def test_state_repository_detects_extra_record_field() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)

    await _rewrite_record_document(
        store, record, lambda document: document.__setitem__("token", "x")
    )

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="fields"):
        await repository.get(record.id)


async def test_state_repository_detects_unknown_envelope_schema() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    value["schema_version"] = 2
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneDurableSessionSchemaError):
        await repository.get(record.id)


async def test_state_repository_detects_unknown_record_schema() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)

    await _rewrite_record_document(
        store,
        record,
        lambda document: document.__setitem__("schema_version", 2),
    )

    with pytest.raises(ControlPlaneDurableSessionSchemaError):
        await repository.get(record.id)


async def test_state_repository_detects_wrong_record_kind() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    value["kind"] = "wrong"
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="kind"):
        await repository.get(record.id)


async def test_state_repository_detects_record_checksum_mismatch() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["operator_revision"] = 99
    value["record"] = document
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="digest"):
        await repository.get(record.id)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "not-a-uuid"),
        ("operator_id", "not-a-uuid"),
        ("issued_at", "2026-07-19T16:00:00"),
        ("status", "unknown"),
        ("token_digest", "bad"),
        ("revision", 0),
        ("generation", 0),
    ],
)
async def test_state_repository_detects_invalid_record_fields(field: str, value: object) -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)

    await _rewrite_record_document(
        store,
        record,
        lambda document: document.__setitem__(field, value),
    )

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="record"):
        await repository.get(record.id)


@pytest.mark.parametrize(
    "key_factory",
    [
        _token_key,
        lambda _digest: _operator_key(_record()),
        lambda _digest: _lineage_key(_record().id),
    ],
)
async def test_state_repository_detects_missing_indexes(
    key_factory: Callable[[str], StateKey[dict[str, object]]],
) -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    key = key_factory(record.token_digest)
    stored = await store.get(key)
    assert stored is not None
    await store.delete(key, expected_version=stored.version)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="incomplete"):
        await repository.get(record.id)


@pytest.mark.parametrize(
    "key",
    [
        StateKey(NAMESPACE, "token_" + "f" * 64, dict),
        StateKey(NAMESPACE, f"operator_{UUID(int=9).hex}_{UUID(int=9).hex}", dict),
        StateKey(NAMESPACE, f"lineage_{UUID(int=9).hex}", dict),
    ],
)
async def test_state_repository_detects_orphan_indexes(key: StateKey[dict[str, object]]) -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    source_key = (
        _token_key(record.token_digest)
        if key.name.startswith("token_")
        else _operator_key(record)
        if key.name.startswith("operator_")
        else _lineage_key(record.id)
    )
    source, _ = await _stored_value(store, source_key)
    await store.put(key, source, expected_version=ABSENT_VERSION)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError):
        await repository.list_page()


@pytest.mark.parametrize(
    "key_factory,field,value",
    [
        (_token_key, "revision", 99),
        (lambda _digest: _operator_key(_record()), "username", "other.user"),
        (lambda _digest: _lineage_key(_record().id), "generation", 99),
    ],
)
async def test_state_repository_detects_index_record_mismatch(
    key_factory: Callable[[str], StateKey[dict[str, object]]],
    field: str,
    value: object,
) -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    key = key_factory(record.token_digest)
    index, version = await _stored_value(store, key)
    index[field] = value
    await store.put(key, index, expected_version=version)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="do not match"):
        await repository.get(record.id)


async def test_state_repository_detects_token_index_key_mismatch() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    await repository.add(record)
    source_key = _token_key(record.token_digest)
    source, version = await _stored_value(store, source_key)
    await store.delete(source_key, expected_version=version)
    wrong_key = _token_key("f" * 64)
    await store.put(wrong_key, source, expected_version=ABSENT_VERSION)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="state key"):
        await repository.list_page()


async def test_state_repository_detects_record_key_mismatch() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    record = _record()
    source_key = _record_key(record.id)
    await repository.add(record)
    source, version = await _stored_value(store, source_key)
    await store.delete(source_key, expected_version=version)
    await store.put(_record_key(UUID(int=999)), source, expected_version=ABSENT_VERSION)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="state key"):
        await repository.list_page()


async def test_state_repository_detects_broken_rotation_lineage() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store)
    current = _record()
    await repository.add(current)
    successor = _successor(current)
    await repository.rotate(
        current.id,
        expected_revision=1,
        successor=successor,
        rotated_at=successor.issued_at,
    )
    successor_keys = (
        _record_key(successor.id),
        _token_key(successor.token_digest),
        _operator_key(successor),
        _lineage_key(successor.id),
    )
    for key in successor_keys:
        stored = await store.get(key)
        assert stored is not None
        await store.delete(key, expected_version=stored.version)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="successor"):
        await repository.get(current.id)


async def test_state_repository_detects_capacity_corruption_after_reopen() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(store, capacity=2)
    await repository.add(_record(1))
    await repository.add(_record(2, operator_id=UUID(int=200)))

    constrained = StateControlPlaneDurableSessionRepository(store, capacity=1)

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="capacity"):
        await constrained.list_page()


async def test_state_repository_detects_per_operator_limit_corruption_after_reopen() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneDurableSessionRepository(
        store,
        max_sessions_per_operator=2,
    )
    await repository.add(_record(1))
    await repository.add(_record(2))

    constrained = StateControlPlaneDurableSessionRepository(
        store,
        max_sessions_per_operator=1,
    )

    with pytest.raises(ControlPlaneDurableSessionCorruptionError, match="per-operator"):
        await constrained.list_page()
