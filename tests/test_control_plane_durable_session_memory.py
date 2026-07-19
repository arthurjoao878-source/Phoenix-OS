from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.durable_session_contracts import (
    MAX_DURABLE_SESSION_CAPACITY,
    MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionAlreadyExistsError,
    ControlPlaneDurableSessionCapacityError,
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionNotFoundError,
    ControlPlaneDurableSessionRepositoryClosedError,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
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


@pytest.mark.parametrize(
    "kwargs",
    [
        {"capacity": 0},
        {"capacity": MAX_DURABLE_SESSION_CAPACITY + 1},
        {"max_sessions_per_operator": 0},
        {"max_sessions_per_operator": MAX_DURABLE_SESSIONS_PER_OPERATOR + 1},
    ],
)
def test_repository_rejects_invalid_bounds(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        InMemoryControlPlaneDurableSessionRepository(**kwargs)


@pytest.mark.asyncio
async def test_add_get_and_digest_lookup() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()

    await repository.add(record)

    assert await repository.get(record.id) == record
    assert await repository.get_by_token_digest(record.token_digest.upper()) == record
    assert await repository.get(UUID(int=999)) is None
    assert await repository.get_by_token_digest("0" * 64) is None


@pytest.mark.asyncio
async def test_digest_lookup_rejects_invalid_digest() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()

    with pytest.raises(ValueError):
        await repository.get_by_token_digest("not-a-digest")


@pytest.mark.asyncio
async def test_add_rejects_duplicate_identity_and_digest() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError):
        await repository.add(record)

    duplicate_digest = replace(_record(2), token_digest=record.token_digest)
    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError):
        await repository.add(duplicate_digest)


@pytest.mark.asyncio
async def test_total_capacity_is_bounded_without_implicit_eviction() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(
        capacity=1,
        max_sessions_per_operator=2,
    )
    await repository.add(_record())

    with pytest.raises(ControlPlaneDurableSessionCapacityError):
        await repository.add(_record(2, operator_id=UUID(int=200)))


@pytest.mark.asyncio
async def test_active_capacity_is_bounded_per_operator() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(
        capacity=4,
        max_sessions_per_operator=1,
    )
    operator_id = UUID(int=300)
    await repository.add(_record(1, operator_id=operator_id))

    with pytest.raises(ControlPlaneDurableSessionCapacityError):
        await repository.add(_record(2, operator_id=operator_id))

    await repository.add(_record(3, operator_id=UUID(int=301)))


@pytest.mark.asyncio
async def test_terminal_records_do_not_consume_active_operator_limit() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(
        capacity=3,
        max_sessions_per_operator=1,
    )
    operator_id = UUID(int=400)
    terminal = replace(
        _record(1, operator_id=operator_id),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )

    await repository.add(terminal)
    await repository.add(_record(2, operator_id=operator_id))

    assert (await repository.snapshot()).active == 1


@pytest.mark.asyncio
async def test_list_page_is_newest_first_and_stable_for_ties() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(max_sessions_per_operator=8)
    await repository.add(_record(3, issued_at=NOW + timedelta(minutes=2)))
    await repository.add(_record(2, issued_at=NOW + timedelta(minutes=1)))
    await repository.add(_record(1, issued_at=NOW + timedelta(minutes=1)))

    first = await repository.list_page(ControlPlaneDurableSessionPageRequest(limit=2))
    second = await repository.list_page(ControlPlaneDurableSessionPageRequest(offset=2, limit=2))

    assert [item.id for item in first.items] == [UUID(int=3), UUID(int=1)]
    assert first.page.next_offset == 2
    assert [item.id for item in second.items] == [UUID(int=2)]
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_list_page_applies_exact_operator_and_status_filters() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(max_sessions_per_operator=8)
    operator_id = UUID(int=500)
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
    await repository.add(_record(3, operator_id=UUID(int=501)))

    page = await repository.list_page(
        ControlPlaneDurableSessionPageRequest(
            operator_id=operator_id,
            status=ControlPlaneDurableSessionStatus.REVOKED,
        )
    )

    assert page.items == (revoked,)
    assert page.page.total == 1


@pytest.mark.asyncio
async def test_list_active_for_operator_is_bounded_and_newest_first() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(max_sessions_per_operator=4)
    operator_id = UUID(int=600)
    await repository.add(_record(1, operator_id=operator_id, issued_at=NOW))
    await repository.add(_record(2, operator_id=operator_id, issued_at=NOW + timedelta(minutes=1)))
    await repository.add(_record(3, operator_id=UUID(int=601)))

    active = await repository.list_active_for_operator(operator_id, limit=1)

    assert [item.id for item in active] == [UUID(int=2)]


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, MAX_DURABLE_SESSIONS_PER_OPERATOR + 1])
async def test_list_active_rejects_invalid_limit(limit: int) -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()

    with pytest.raises(ValueError):
        await repository.list_active_for_operator(UUID(int=1), limit=limit)


@pytest.mark.asyncio
async def test_touch_advances_activity_and_revision() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)
    seen_at = NOW + timedelta(minutes=5)
    idle_expires_at = seen_at + timedelta(minutes=20)

    updated = await repository.touch(
        record.id,
        expected_revision=1,
        seen_at=seen_at,
        idle_expires_at=idle_expires_at,
    )

    assert updated.last_seen_at == seen_at
    assert updated.idle_expires_at == idle_expires_at
    assert updated.revision == 2
    assert await repository.get(record.id) == updated


@pytest.mark.asyncio
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
            NOW + timedelta(minutes=1),
            NOW + timedelta(hours=3),
            ControlPlaneDurableSessionConflictError,
        ),
    ],
)
async def test_touch_rejects_invalid_updates(
    expected_revision: int,
    seen_at: datetime,
    idle_expires_at: datetime,
    error: type[Exception],
) -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)

    with pytest.raises(error):
        await repository.touch(
            record.id,
            expected_revision=expected_revision,
            seen_at=seen_at,
            idle_expires_at=idle_expires_at,
        )


@pytest.mark.asyncio
async def test_touch_rejects_missing_and_terminal_records() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()

    with pytest.raises(ControlPlaneDurableSessionNotFoundError):
        await repository.touch(
            UUID(int=99),
            expected_revision=1,
            seen_at=NOW,
            idle_expires_at=NOW + timedelta(minutes=1),
        )

    terminal = replace(
        _record(),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )
    await repository.add(terminal)
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.touch(
            terminal.id,
            expected_revision=2,
            seen_at=NOW + timedelta(minutes=2),
            idle_expires_at=NOW + timedelta(minutes=3),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,reason",
    [
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
        ),
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.ROLE_CHANGED,
        ),
        (
            ControlPlaneDurableSessionStatus.EXPIRED,
            ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
        ),
        (
            ControlPlaneDurableSessionStatus.EXPIRED,
            ControlPlaneDurableSessionTerminationReason.ABSOLUTE_TIMEOUT,
        ),
    ],
)
async def test_terminate_creates_valid_terminal_record(
    status: ControlPlaneDurableSessionStatus,
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)

    terminal = await repository.terminate(
        record.id,
        expected_revision=1,
        status=status,
        reason=reason,
        terminated_at=NOW + timedelta(minutes=1),
    )

    assert terminal.status is status
    assert terminal.termination_reason is reason
    assert terminal.revision == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,reason,error",
    [
        (
            ControlPlaneDurableSessionStatus.ACTIVE,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
            ValueError,
        ),
        (
            ControlPlaneDurableSessionStatus.ROTATED,
            ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
            ValueError,
        ),
        (
            ControlPlaneDurableSessionStatus.EXPIRED,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
            ValueError,
        ),
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
            ValueError,
        ),
    ],
)
async def test_terminate_rejects_invalid_status_reason_pairs(
    status: ControlPlaneDurableSessionStatus,
    reason: ControlPlaneDurableSessionTerminationReason,
    error: type[Exception],
) -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(_record())

    with pytest.raises(error):
        await repository.terminate(
            UUID(int=1),
            expected_revision=1,
            status=status,
            reason=reason,
            terminated_at=NOW + timedelta(minutes=1),
        )


@pytest.mark.asyncio
async def test_terminate_rejects_stale_missing_terminal_and_backwards_updates() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneDurableSessionNotFoundError):
        await repository.terminate(
            UUID(int=99),
            expected_revision=1,
            status=ControlPlaneDurableSessionStatus.REVOKED,
            reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            terminated_at=NOW,
        )
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.terminate(
            record.id,
            expected_revision=2,
            status=ControlPlaneDurableSessionStatus.REVOKED,
            reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            terminated_at=NOW,
        )
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.terminate(
            record.id,
            expected_revision=1,
            status=ControlPlaneDurableSessionStatus.REVOKED,
            reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            terminated_at=NOW - timedelta(seconds=1),
        )

    terminal = await repository.terminate(
        record.id,
        expected_revision=1,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        terminated_at=NOW,
    )
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.terminate(
            terminal.id,
            expected_revision=terminal.revision,
            status=ControlPlaneDurableSessionStatus.REVOKED,
            reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
            terminated_at=NOW + timedelta(minutes=1),
        )


@pytest.mark.asyncio
async def test_rotate_is_atomic_and_preserves_absolute_expiry() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(
        capacity=4,
        max_sessions_per_operator=1,
    )
    current = _record()
    await repository.add(current)
    rotated_at = NOW + timedelta(minutes=10)
    successor = _record(
        2,
        operator_id=current.operator_id,
        issued_at=rotated_at,
        generation=2,
        predecessor_session_id=current.id,
        absolute_expires_at=current.absolute_expires_at,
    )

    rotation = await repository.rotate(
        current.id,
        expected_revision=1,
        successor=successor,
        rotated_at=rotated_at,
    )

    assert rotation.previous.status is ControlPlaneDurableSessionStatus.ROTATED
    assert rotation.previous.successor_session_id == successor.id
    assert rotation.successor.predecessor_session_id == current.id
    assert await repository.get_by_token_digest(current.token_digest) == rotation.previous
    assert await repository.get_by_token_digest(successor.token_digest) == successor
    assert len(await repository.list_active_for_operator(current.operator_id)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "status",
        "operator_id",
        "username",
        "operator_revision",
        "operator_token_version",
        "generation",
        "predecessor_session_id",
        "issued_at",
        "last_seen_at",
        "absolute_expires_at",
    ],
)
async def test_rotate_rejects_inconsistent_successor(change: str) -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(capacity=4)
    current = _record()
    await repository.add(current)
    rotated_at = NOW + timedelta(minutes=10)
    successor = _record(
        2,
        operator_id=current.operator_id,
        issued_at=rotated_at,
        generation=2,
        predecessor_session_id=current.id,
        absolute_expires_at=current.absolute_expires_at,
    )
    if change == "status":
        successor = replace(
            successor,
            status=ControlPlaneDurableSessionStatus.REVOKED,
            terminated_at=rotated_at,
            termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            revision=2,
        )
    elif change == "operator_id":
        successor = replace(successor, operator_id=UUID(int=999))
    elif change == "username":
        successor = replace(successor, username="different.user")
    elif change == "operator_revision":
        successor = replace(successor, operator_revision=5)
    elif change == "operator_token_version":
        successor = replace(successor, operator_token_version=4)
    elif change == "generation":
        successor = replace(successor, generation=3)
    elif change == "predecessor_session_id":
        successor = replace(successor, predecessor_session_id=UUID(int=99))
    elif change == "issued_at":
        new_time = rotated_at + timedelta(seconds=1)
        successor = replace(
            successor,
            issued_at=new_time,
            last_seen_at=new_time,
            idle_expires_at=new_time + timedelta(minutes=30),
            rotate_after=new_time + timedelta(minutes=10),
        )
    elif change == "last_seen_at":
        successor = replace(successor, last_seen_at=rotated_at + timedelta(seconds=1))
    else:
        successor = replace(
            successor, absolute_expires_at=current.absolute_expires_at - timedelta(minutes=1)
        )

    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.rotate(
            current.id,
            expected_revision=1,
            successor=successor,
            rotated_at=rotated_at,
        )


@pytest.mark.asyncio
async def test_rotate_rejects_duplicate_digest_stale_revision_and_full_capacity() -> None:
    current = _record()
    rotated_at = NOW + timedelta(minutes=10)
    successor = _record(
        2,
        operator_id=current.operator_id,
        issued_at=rotated_at,
        generation=2,
        predecessor_session_id=current.id,
        absolute_expires_at=current.absolute_expires_at,
    )

    repository = InMemoryControlPlaneDurableSessionRepository(capacity=3)
    await repository.add(current)
    duplicate = replace(successor, token_digest=current.token_digest)
    with pytest.raises(ControlPlaneDurableSessionAlreadyExistsError):
        await repository.rotate(
            current.id,
            expected_revision=1,
            successor=duplicate,
            rotated_at=rotated_at,
        )
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.rotate(
            current.id,
            expected_revision=2,
            successor=successor,
            rotated_at=rotated_at,
        )

    full = InMemoryControlPlaneDurableSessionRepository(capacity=1)
    await full.add(current)
    with pytest.raises(ControlPlaneDurableSessionCapacityError):
        await full.rotate(
            current.id,
            expected_revision=1,
            successor=successor,
            rotated_at=rotated_at,
        )


@pytest.mark.asyncio
async def test_delete_terminal_removes_record_and_digest_index() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)
    terminal = await repository.terminate(
        record.id,
        expected_revision=1,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        terminated_at=NOW + timedelta(minutes=1),
    )

    await repository.delete_terminal(terminal.id, expected_revision=terminal.revision)

    assert await repository.get(terminal.id) is None
    assert await repository.get_by_token_digest(terminal.token_digest) is None


@pytest.mark.asyncio
async def test_delete_terminal_rejects_active_stale_and_missing_records() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.delete_terminal(record.id, expected_revision=1)
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await repository.delete_terminal(record.id, expected_revision=2)
    with pytest.raises(ControlPlaneDurableSessionNotFoundError):
        await repository.delete_terminal(UUID(int=99), expected_revision=1)
    with pytest.raises(ValueError):
        await repository.delete_terminal(record.id, expected_revision=0)


@pytest.mark.asyncio
async def test_snapshot_counts_all_states_without_secrets() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository(
        capacity=8,
        max_sessions_per_operator=4,
    )
    await repository.add(_record(1))
    await repository.add(
        replace(
            _record(2, operator_id=UUID(int=101)),
            status=ControlPlaneDurableSessionStatus.REVOKED,
            terminated_at=NOW + timedelta(minutes=1),
            termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            revision=2,
        )
    )
    await repository.add(
        replace(
            _record(3, operator_id=UUID(int=102)),
            status=ControlPlaneDurableSessionStatus.EXPIRED,
            terminated_at=NOW + timedelta(minutes=1),
            termination_reason=ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
            revision=2,
        )
    )
    rotated = replace(
        _record(4, operator_id=UUID(int=103)),
        status=ControlPlaneDurableSessionStatus.ROTATED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
        successor_session_id=UUID(int=5),
        revision=2,
    )
    await repository.add(rotated)

    snapshot = await repository.snapshot()

    assert snapshot.entries == 4
    assert snapshot.active == 1
    assert snapshot.revoked == 1
    assert snapshot.expired == 1
    assert snapshot.rotated == 1
    assert snapshot.capacity == 8
    assert snapshot.max_sessions_per_operator == 4
    assert "digest" not in repr(snapshot).lower()


@pytest.mark.asyncio
async def test_close_clears_memory_and_fails_future_operations() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(_record())

    await repository.close()

    assert repository.closed
    snapshot = await repository.snapshot()
    assert snapshot.closed
    assert snapshot.entries == 0
    with pytest.raises(ControlPlaneDurableSessionRepositoryClosedError):
        await repository.get(UUID(int=1))
    with pytest.raises(ControlPlaneDurableSessionRepositoryClosedError):
        await repository.add(_record(2))
    with pytest.raises(ControlPlaneDurableSessionRepositoryClosedError):
        await repository.list_page()
