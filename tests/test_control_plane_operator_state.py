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
    MAX_CONTROL_PLANE_OPERATOR_CAPACITY,
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorCapacityError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorCorruptionError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorPersistenceError,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistryClosedError,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorSchemaError,
    ControlPlaneOperatorStatus,
    StateControlPlaneOperatorRegistry,
    canonical_control_plane_operator_record_bytes,
    control_plane_operator_record_digest,
)
from phoenix_os.state import ABSENT_VERSION, MemoryStateStore, StateKey

_NOW = datetime(2026, 7, 19, 18, tzinfo=UTC)
_NAMESPACE = "control-plane-operators"


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def _record(
    username: str = "alice",
    *,
    operator_id: UUID | None = None,
    token_digest: str | None = None,
    display_name: str | None = None,
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.VIEWER,
    additional_permissions: frozenset[str] = frozenset(),
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime = _NOW,
    updated_at: datetime = _NOW,
    token_version: int = 1,
    revision: int = 1,
) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=operator_id or uuid4(),
        username=username,
        display_name=display_name or username.title(),
        role=role,
        token_digest=token_digest or _digest(username),
        created_at=created_at,
        updated_at=updated_at,
        additional_permissions=additional_permissions,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        token_version=token_version,
        revision=revision,
    )


def _record_key(operator_id: UUID) -> StateKey[dict[str, object]]:
    return StateKey(_NAMESPACE, f"operator_{operator_id.hex}", dict)


def _username_key(username: str) -> StateKey[dict[str, object]]:
    return StateKey(_NAMESPACE, f"username_{username}", dict)


def _token_key(token_digest: str) -> StateKey[dict[str, object]]:
    return StateKey(_NAMESPACE, f"token_{token_digest}", dict)


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


def test_canonical_operator_record_bytes_are_deterministic() -> None:
    record = _record(operator_id=UUID(int=1))

    first = canonical_control_plane_operator_record_bytes(record)
    second = canonical_control_plane_operator_record_bytes(record)

    assert first == second
    assert first.startswith(b'{"additional_permissions":[')
    assert b" " not in first


def test_canonical_operator_record_bytes_sort_permissions() -> None:
    record = _record(additional_permissions=frozenset({"z.read", "a.read"}))

    payload = canonical_control_plane_operator_record_bytes(record)

    assert b'"additional_permissions":["a.read","z.read"]' in payload


def test_canonical_operator_record_contains_no_plaintext_credential() -> None:
    payload = canonical_control_plane_operator_record_bytes(_record())

    assert b"operator-token-plaintext" not in payload
    assert b"bearer" not in payload
    assert b"csrf" not in payload
    assert b"confirmation" not in payload


def test_operator_record_digest_is_sha256_of_canonical_bytes() -> None:
    record = _record()

    assert (
        control_plane_operator_record_digest(record)
        == hashlib.sha256(canonical_control_plane_operator_record_bytes(record)).hexdigest()
    )


def test_operator_record_digest_changes_with_revision() -> None:
    record = _record()
    updated = replace(record, updated_at=_NOW + timedelta(seconds=1), revision=2)

    assert control_plane_operator_record_digest(updated) != control_plane_operator_record_digest(
        record
    )


@pytest.mark.parametrize("capacity", [0, -1, MAX_CONTROL_PLANE_OPERATOR_CAPACITY + 1])
def test_state_operator_registry_rejects_invalid_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        StateControlPlaneOperatorRegistry(MemoryStateStore(), capacity=capacity)


def test_state_operator_registry_normalizes_namespace() -> None:
    registry = StateControlPlaneOperatorRegistry(
        MemoryStateStore(),
        namespace=" CONTROL-PLANE-OPERATORS ",
    )

    assert registry.closed is False


async def test_state_operator_registry_adds_and_reads_every_index() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()

    await registry.add(record)

    assert await registry.get(record.id) == record
    assert await registry.get_by_username(" ALICE ") == record
    assert await registry.get_by_token_digest(record.token_digest.upper()) == record


async def test_state_operator_registry_returns_none_for_unknown_identity() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())

    assert await registry.get(uuid4()) is None
    assert await registry.get_by_username("missing") is None
    assert await registry.get_by_token_digest(_digest("missing")) is None


async def test_state_operator_registry_survives_registry_restart() -> None:
    store = MemoryStateStore()
    first = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await first.add(record)
    await first.close()

    second = StateControlPlaneOperatorRegistry(store)

    assert await second.get(record.id) == record
    assert await second.get_by_username(record.username) == record
    assert await second.get_by_token_digest(record.token_digest) == record


async def test_state_operator_registry_rejects_invalid_lookup_values() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())

    with pytest.raises(ValueError, match="username"):
        await registry.get_by_username("x")
    with pytest.raises(ValueError, match="digest"):
        await registry.get_by_token_digest("not-a-digest")


async def test_state_operator_registry_rejects_duplicate_id() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    operator_id = uuid4()
    await registry.add(_record("alice", operator_id=operator_id))

    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="id"):
        await registry.add(_record("bob", operator_id=operator_id))


async def test_state_operator_registry_rejects_duplicate_username() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    await registry.add(_record("alice"))

    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="username"):
        await registry.add(_record("ALICE", token_digest=_digest("other")))


async def test_state_operator_registry_rejects_duplicate_token_digest() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    digest = _digest("shared")
    await registry.add(_record("alice", token_digest=digest))

    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="digest"):
        await registry.add(_record("bob", token_digest=digest))


async def test_state_operator_registry_enforces_capacity() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore(), capacity=1)
    await registry.add(_record("alice"))

    with pytest.raises(ControlPlaneOperatorCapacityError):
        await registry.add(_record("bob"))


async def test_state_operator_registry_concurrent_duplicate_add_is_atomic() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()

    results = await asyncio.gather(
        registry.add(record),
        registry.add(record),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    assert (
        sum(isinstance(result, ControlPlaneOperatorAlreadyExistsError) for result in results) == 1
    )


async def test_state_operator_registry_lists_and_paginates_by_username() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    for username in ("delta", "alpha", "charlie", "bravo"):
        await registry.add(_record(username))

    first = await registry.list_page(ControlPlaneOperatorPageRequest(limit=2))
    second = await registry.list_page(ControlPlaneOperatorPageRequest(offset=2, limit=2))

    assert tuple(item.username for item in first.items) == ("alpha", "bravo")
    assert first.page.next_offset == 2
    assert tuple(item.username for item in second.items) == ("charlie", "delta")
    assert second.page.next_offset is None


async def test_state_operator_registry_replaces_record() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()
    await registry.add(record)
    updated = replace(
        record,
        display_name="Alice Maintainer",
        role=ControlPlaneOperatorRole.MAINTAINER,
        additional_permissions=frozenset({"audit.read"}),
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    result = await registry.replace(updated, expected_revision=1)

    assert result == updated
    assert await registry.get(record.id) == updated


async def test_state_operator_registry_replace_updates_username_index() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()
    await registry.add(record)
    updated = replace(
        record,
        username="alice.admin",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    await registry.replace(updated, expected_revision=1)

    assert await registry.get_by_username("alice") is None
    assert await registry.get_by_username("alice.admin") == updated


async def test_state_operator_registry_replace_updates_token_index() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()
    await registry.add(record)
    new_digest = _digest("rotated")
    updated = replace(
        record,
        token_digest=new_digest,
        token_version=2,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    await registry.replace(updated, expected_revision=1)

    assert await registry.get_by_token_digest(record.token_digest) is None
    assert await registry.get_by_token_digest(new_digest) == updated


async def test_state_operator_registry_replace_survives_restart() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    updated = replace(
        record,
        role=ControlPlaneOperatorRole.OPERATOR,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    await registry.replace(updated, expected_revision=1)

    recovered = StateControlPlaneOperatorRegistry(store)

    assert await recovered.get(record.id) == updated


async def test_state_operator_registry_replace_rejects_unknown_record() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())

    with pytest.raises(ControlPlaneOperatorNotFoundError):
        await registry.replace(_record(revision=2), expected_revision=1)


async def test_state_operator_registry_replace_rejects_stale_revision() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()
    await registry.add(record)
    updated = replace(record, updated_at=_NOW + timedelta(seconds=1), revision=2)

    with pytest.raises(ControlPlaneOperatorConflictError, match="revision"):
        await registry.replace(updated, expected_revision=2)


async def test_state_operator_registry_replace_rejects_revision_jump() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    record = _record()
    await registry.add(record)
    updated = replace(record, updated_at=_NOW + timedelta(seconds=1), revision=3)

    with pytest.raises(ControlPlaneOperatorConflictError, match="increment"):
        await registry.replace(updated, expected_revision=1)


async def test_state_operator_registry_replace_rejects_duplicate_indexes() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    alice = _record("alice")
    bob = _record("bob")
    await registry.add(alice)
    await registry.add(bob)
    duplicate_username = replace(
        alice,
        username="bob",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="username"):
        await registry.replace(duplicate_username, expected_revision=1)

    duplicate_token = replace(
        alice,
        token_digest=bob.token_digest,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="digest"):
        await registry.replace(duplicate_token, expected_revision=1)


async def test_state_operator_registry_snapshot_contains_safe_counts() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore(), capacity=8)
    await registry.add(_record("viewer"))
    await registry.add(_record("operator", role=ControlPlaneOperatorRole.OPERATOR))
    await registry.add(
        _record(
            "maintainer",
            role=ControlPlaneOperatorRole.MAINTAINER,
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=_NOW,
        )
    )

    snapshot = await registry.snapshot()

    assert snapshot.operators == 3
    assert snapshot.active == 2
    assert snapshot.disabled == 1
    assert snapshot.viewers == 1
    assert snapshot.operators_role == 1
    assert snapshot.maintainers == 1
    assert snapshot.capacity == 8


async def test_state_operator_registry_close_preserves_store_and_snapshot() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)

    await registry.close()

    assert store.closed is False
    assert (await registry.snapshot()).closed is True
    recovered = StateControlPlaneOperatorRegistry(store)
    assert await recovered.get(record.id) == record


async def test_state_operator_registry_rejects_operations_after_close() -> None:
    registry = StateControlPlaneOperatorRegistry(MemoryStateStore())
    await registry.close()

    with pytest.raises(ControlPlaneOperatorRegistryClosedError):
        await registry.get(uuid4())
    with pytest.raises(ControlPlaneOperatorRegistryClosedError):
        await registry.list_page()


async def test_state_operator_registry_maps_closed_store_to_persistence_error() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    await store.close()

    with pytest.raises(ControlPlaneOperatorPersistenceError):
        await registry.get(uuid4())


async def test_state_operator_registry_detects_missing_envelope_field() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    value.pop("record_digest")
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="fields"):
        await registry.get(record.id)


async def test_state_operator_registry_detects_extra_record_field() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["plaintext_token"] = "must-not-exist"
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="fields"):
        await registry.get(record.id)


async def test_state_operator_registry_detects_unknown_schemas() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    value["schema_version"] = 2
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorSchemaError):
        await registry.get(record.id)

    value["schema_version"] = 1
    document = _object_dict(value["record"])
    document["schema_version"] = 2
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    current = await store.get(key)
    assert current is not None
    await store.put(key, value, expected_version=current.version)
    with pytest.raises(ControlPlaneOperatorSchemaError):
        await registry.get(record.id)


async def test_state_operator_registry_detects_wrong_record_kind() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    value["kind"] = "phoenix.invalid"
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="kind"):
        await registry.get(record.id)


async def test_state_operator_registry_detects_record_digest_mismatch() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["display_name"] = "Tampered"
    value["record"] = document
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="digest"):
        await registry.get(record.id)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("id", "not-a-uuid"),
        ("created_at", "2026-07-19T18:00:00"),
        ("role", "superuser"),
        ("token_version", 0),
    ],
)
async def test_state_operator_registry_detects_invalid_record_fields(
    field: str,
    invalid: object,
) -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document[field] = invalid
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="invalid"):
        await registry.get(record.id)


async def test_state_operator_registry_detects_noncanonical_permissions() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record(additional_permissions=frozenset({"a.read", "z.read"}))
    await registry.add(record)
    key = _record_key(record.id)
    value, version = await _stored_value(store, key)
    document = _object_dict(value["record"])
    document["additional_permissions"] = ["z.read", "a.read"]
    value["record"] = document
    value["record_digest"] = _canonical_mapping_digest(document)
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="invalid"):
        await registry.get(record.id)


async def test_state_operator_registry_detects_record_key_mismatch() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    value, _ = await _stored_value(store, _record_key(record.id))
    other_id = uuid4()
    await store.put(_record_key(other_id), value, expected_version=ABSENT_VERSION)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="state key"):
        await registry.get(other_id)


@pytest.mark.parametrize("index", ["username", "token"])
async def test_state_operator_registry_detects_missing_index(index: str) -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _username_key(record.username) if index == "username" else _token_key(record.token_digest)
    stored = await store.get(key)
    assert stored is not None
    await store.delete(key, expected_version=stored.version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="incomplete"):
        await registry.get(record.id)


async def test_state_operator_registry_detects_index_referencing_missing_record() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _record_key(record.id)
    stored = await store.get(key)
    assert stored is not None
    await store.delete(key, expected_version=stored.version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="missing record"):
        await registry.get_by_username(record.username)


async def test_state_operator_registry_detects_index_schema_and_fields() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _username_key(record.username)
    value, version = await _stored_value(store, key)
    value["schema_version"] = 2
    await store.put(key, value, expected_version=version)

    with pytest.raises(ControlPlaneOperatorSchemaError):
        await registry.get_by_username(record.username)

    value["schema_version"] = 1
    value["plaintext_token"] = "must-not-exist"
    current = await store.get(key)
    assert current is not None
    await store.put(key, value, expected_version=current.version)
    with pytest.raises(ControlPlaneOperatorCorruptionError, match="fields"):
        await registry.get_by_username(record.username)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("revision", 99),
        ("token_version", 99),
        ("record_digest", "f" * 64),
        ("operator_id", str(UUID(int=2))),
    ],
)
async def test_state_operator_registry_detects_mismatched_index(
    field: str,
    value: object,
) -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    key = _token_key(record.token_digest)
    document, version = await _stored_value(store, key)
    document[field] = value
    await store.put(key, document, expected_version=version)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match=r"do not match|missing record"):
        await registry.get_by_token_digest(record.token_digest)


async def test_state_operator_registry_detects_orphan_index_during_list() -> None:
    store = MemoryStateStore()
    registry = StateControlPlaneOperatorRegistry(store)
    record = _record()
    await registry.add(record)
    orphan = _object_dict((await store.get(_username_key(record.username))).value)  # type: ignore[union-attr]
    orphan["username"] = "orphan"
    await store.put(
        _username_key("orphan"),
        orphan,
        expected_version=ABSENT_VERSION,
    )

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="incomplete"):
        await registry.list_page()


async def test_state_operator_registry_detects_persisted_entries_above_capacity() -> None:
    store = MemoryStateStore()
    writer = StateControlPlaneOperatorRegistry(store, capacity=2)
    await writer.add(_record("alice"))
    await writer.add(_record("bob"))
    constrained = StateControlPlaneOperatorRegistry(store, capacity=1)

    with pytest.raises(ControlPlaneOperatorCorruptionError, match="capacity"):
        await constrained.snapshot()
