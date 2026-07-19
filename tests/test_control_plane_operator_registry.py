from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane import (
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorCapacityError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistryClosedError,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    InMemoryControlPlaneOperatorRegistry,
)

_NOW = datetime(2026, 7, 19, 12, tzinfo=UTC)


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def _record(
    username: str,
    *,
    operator_id: UUID | None = None,
    digest: str | None = None,
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.VIEWER,
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime = _NOW,
    updated_at: datetime = _NOW,
    revision: int = 1,
    token_version: int = 1,
) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=operator_id or uuid4(),
        username=username,
        display_name=username.title(),
        role=role,
        token_digest=digest or _digest(username),
        created_at=created_at,
        updated_at=updated_at,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
        token_version=token_version,
    )


@pytest.mark.asyncio
async def test_registry_adds_and_reads_operator_by_every_index() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)

    assert await registry.get(record.id) is record
    assert await registry.get_by_username(" ALICE ") is record
    assert await registry.get_by_token_digest(record.token_digest.upper()) is record


@pytest.mark.asyncio
async def test_registry_returns_none_for_unknown_operator() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    assert await registry.get(uuid4()) is None
    assert await registry.get_by_username("missing") is None
    assert await registry.get_by_token_digest(_digest("missing")) is None


@pytest.mark.asyncio
async def test_registry_rejects_duplicate_id() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    operator_id = uuid4()
    await registry.add(_record("alice", operator_id=operator_id))
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="id"):
        await registry.add(_record("bob", operator_id=operator_id))


@pytest.mark.asyncio
async def test_registry_rejects_duplicate_normalized_username() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record("alice"))
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="username"):
        await registry.add(_record("ALICE", digest=_digest("other")))


@pytest.mark.asyncio
async def test_registry_rejects_duplicate_token_digest() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    digest = _digest("shared")
    await registry.add(_record("alice", digest=digest))
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="digest"):
        await registry.add(_record("bob", digest=digest))


@pytest.mark.parametrize("capacity", [0, -1, 10_001])
def test_registry_rejects_invalid_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        InMemoryControlPlaneOperatorRegistry(capacity=capacity)


@pytest.mark.asyncio
async def test_registry_enforces_capacity() -> None:
    registry = InMemoryControlPlaneOperatorRegistry(capacity=1)
    await registry.add(_record("alice"))
    with pytest.raises(ControlPlaneOperatorCapacityError):
        await registry.add(_record("bob"))


@pytest.mark.asyncio
async def test_registry_lists_operators_by_normalized_username() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    for username in ("charlie", "alice", "bob"):
        await registry.add(_record(username))
    page = await registry.list_page()
    assert tuple(item.username for item in page.items) == ("alice", "bob", "charlie")
    assert page.page.total == 3
    assert page.page.next_offset is None


@pytest.mark.asyncio
async def test_registry_paginates_deterministically() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    for username in ("delta", "alpha", "charlie", "bravo"):
        await registry.add(_record(username))
    first = await registry.list_page(ControlPlaneOperatorPageRequest(offset=0, limit=2))
    second = await registry.list_page(ControlPlaneOperatorPageRequest(offset=2, limit=2))
    assert tuple(item.username for item in first.items) == ("alpha", "bravo")
    assert first.page.next_offset == 2
    assert tuple(item.username for item in second.items) == ("charlie", "delta")
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_registry_replaces_operator_with_optimistic_revision() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    updated = replace(
        record,
        display_name="Alice Maintainer",
        role=ControlPlaneOperatorRole.MAINTAINER,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    result = await registry.replace(updated, expected_revision=1)
    assert result is updated
    assert await registry.get(record.id) is updated


@pytest.mark.asyncio
async def test_registry_replace_updates_username_index() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    updated = replace(
        record,
        username="alice.admin",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    await registry.replace(updated, expected_revision=1)
    assert await registry.get_by_username("alice") is None
    assert await registry.get_by_username("alice.admin") is updated


@pytest.mark.asyncio
async def test_registry_replace_updates_token_index() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    old_digest = record.token_digest
    new_digest = _digest("rotated")
    updated = replace(
        record,
        token_digest=new_digest,
        token_version=2,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    await registry.replace(updated, expected_revision=1)
    assert await registry.get_by_token_digest(old_digest) is None
    assert await registry.get_by_token_digest(new_digest) is updated


@pytest.mark.asyncio
async def test_registry_replace_rejects_unknown_operator() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    with pytest.raises(ControlPlaneOperatorNotFoundError):
        await registry.replace(_record("alice", revision=2), expected_revision=1)


@pytest.mark.asyncio
async def test_registry_replace_rejects_stale_expected_revision() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    updated = replace(record, updated_at=_NOW + timedelta(seconds=1), revision=2)
    with pytest.raises(ControlPlaneOperatorConflictError, match="revision"):
        await registry.replace(updated, expected_revision=2)


@pytest.mark.asyncio
async def test_registry_replace_requires_exact_next_revision() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    updated = replace(record, updated_at=_NOW + timedelta(seconds=1), revision=3)
    with pytest.raises(ControlPlaneOperatorConflictError, match="increment"):
        await registry.replace(updated, expected_revision=1)


@pytest.mark.asyncio
async def test_registry_replace_rejects_changed_created_at() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    updated = replace(
        record,
        created_at=_NOW - timedelta(seconds=1),
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    with pytest.raises(ControlPlaneOperatorConflictError, match="created_at"):
        await registry.replace(updated, expected_revision=1)


@pytest.mark.asyncio
async def test_registry_replace_rejects_backwards_update_time() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice", updated_at=_NOW + timedelta(seconds=2))
    await registry.add(record)
    updated = replace(record, updated_at=_NOW + timedelta(seconds=1), revision=2)
    with pytest.raises(ControlPlaneOperatorConflictError, match="backwards"):
        await registry.replace(updated, expected_revision=1)


@pytest.mark.asyncio
async def test_registry_replace_rejects_duplicate_username() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    alice = _record("alice")
    bob = _record("bob")
    await registry.add(alice)
    await registry.add(bob)
    updated = replace(
        alice,
        username="bob",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="username"):
        await registry.replace(updated, expected_revision=1)


@pytest.mark.asyncio
async def test_registry_replace_rejects_duplicate_digest() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    alice = _record("alice")
    bob = _record("bob")
    await registry.add(alice)
    await registry.add(bob)
    updated = replace(
        alice,
        token_digest=bob.token_digest,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="digest"):
        await registry.replace(updated, expected_revision=1)


@pytest.mark.asyncio
async def test_registry_snapshot_reports_status_and_role_counts() -> None:
    registry = InMemoryControlPlaneOperatorRegistry(capacity=10)
    await registry.add(_record("viewer"))
    await registry.add(
        _record(
            "operator",
            role=ControlPlaneOperatorRole.OPERATOR,
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=_NOW,
        )
    )
    await registry.add(
        _record(
            "maintainer",
            role=ControlPlaneOperatorRole.MAINTAINER,
            status=ControlPlaneOperatorStatus.REVOKED,
            revoked_at=_NOW,
        )
    )
    snapshot = await registry.snapshot()
    assert snapshot.operators == 3
    assert (snapshot.active, snapshot.disabled, snapshot.revoked) == (1, 1, 1)
    assert (snapshot.viewers, snapshot.operators_role, snapshot.maintainers) == (1, 1, 1)
    assert snapshot.capacity == 10
    assert not snapshot.closed


@pytest.mark.asyncio
async def test_registry_close_clears_records_and_is_idempotent() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record("alice"))
    await registry.close()
    await registry.close()
    snapshot = await registry.snapshot()
    assert snapshot.closed
    assert snapshot.operators == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["get", "username", "digest", "list", "add", "replace"])
async def test_registry_rejects_operations_after_close(operation: str) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record("alice")
    await registry.add(record)
    await registry.close()
    with pytest.raises(ControlPlaneOperatorRegistryClosedError):
        if operation == "get":
            await registry.get(record.id)
        elif operation == "username":
            await registry.get_by_username(record.username)
        elif operation == "digest":
            await registry.get_by_token_digest(record.token_digest)
        elif operation == "list":
            await registry.list_page()
        elif operation == "add":
            await registry.add(_record("bob"))
        else:
            await registry.replace(
                replace(record, updated_at=_NOW + timedelta(seconds=1), revision=2),
                expected_revision=1,
            )


@pytest.mark.asyncio
async def test_registry_serializes_concurrent_duplicate_adds() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    first = _record("alice")
    second = _record("alice", digest=_digest("other"))
    results = await asyncio.gather(
        registry.add(first),
        registry.add(second),
        return_exceptions=True,
    )
    assert sum(result is None for result in results) == 1
    assert (
        sum(isinstance(result, ControlPlaneOperatorAlreadyExistsError) for result in results) == 1
    )
    assert (await registry.snapshot()).operators == 1
