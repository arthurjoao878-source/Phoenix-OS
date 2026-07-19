from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorSessionCapacityError,
    ControlPlaneOperatorSessionConflictError,
    ControlPlaneOperatorSessionStoreClosedError,
)
from phoenix_os.control_plane.operator_sessions import (
    MAX_CONTROL_PLANE_OPERATOR_SESSION_TTL,
    ControlPlaneOperatorSessionAuthentication,
    ControlPlaneOperatorSessionGrant,
    ControlPlaneOperatorSessionRecord,
    ControlPlaneOperatorSessionRevocationReason,
    ControlPlaneOperatorSessionSnapshot,
    ControlPlaneOperatorSessionStatus,
    ControlPlaneOperatorSessionToken,
    InMemoryControlPlaneOperatorSessionStore,
)

_NOW = datetime(2026, 7, 19, 18, tzinfo=UTC)
_TOKEN = ControlPlaneOperatorSessionToken("session-token-0123456789abcdef-operator")


def _record(
    *,
    session_id: UUID | None = None,
    operator_id: UUID | None = None,
    token: ControlPlaneOperatorSessionToken = _TOKEN,
    issued_at: datetime = _NOW,
    expires_at: datetime | None = None,
    status: ControlPlaneOperatorSessionStatus = ControlPlaneOperatorSessionStatus.ACTIVE,
    revoked_at: datetime | None = None,
    reason: ControlPlaneOperatorSessionRevocationReason | None = None,
    revision: int = 1,
) -> ControlPlaneOperatorSessionRecord:
    return ControlPlaneOperatorSessionRecord(
        id=session_id or uuid4(),
        operator_id=operator_id or uuid4(),
        username="Alice",
        token_digest=token.digest,
        operator_token_version=2,
        issued_at=issued_at,
        expires_at=expires_at or issued_at + timedelta(minutes=30),
        status=status,
        revoked_at=revoked_at,
        revocation_reason=reason,
        revision=revision,
    )


def test_session_token_is_redacted_and_digested() -> None:
    assert str(_TOKEN) == "<redacted>"
    assert repr(_TOKEN) == "ControlPlaneOperatorSessionToken(<redacted>)"
    assert len(_TOKEN.digest) == 64
    assert _TOKEN.value not in _TOKEN.digest


@pytest.mark.parametrize(
    "value",
    [
        "short",
        " leading-session-token-0123456789abcdef",
        "trailing-session-token-0123456789abcdef ",
        "á" * 32,
        "invalid/session/token/0123456789abcdef",
        "x" * 129,
    ],
)
def test_session_token_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        ControlPlaneOperatorSessionToken(value)


def test_session_record_normalizes_username_and_digest() -> None:
    record = _record()
    assert record.username == "alice"
    assert record.token_digest == _TOKEN.digest
    assert record.active_at(_NOW)
    assert not record.active_at(record.expires_at)
    assert _TOKEN.digest not in repr(record)


@pytest.mark.parametrize(
    "changes",
    [
        {"username": ""},
        {"token_digest": "bad"},
        {"operator_token_version": 0},
        {"issued_at": datetime(2026, 7, 19, 18)},
        {"expires_at": _NOW},
        {"expires_at": _NOW + MAX_CONTROL_PLANE_OPERATOR_SESSION_TTL + timedelta(seconds=1)},
        {"revision": 0},
        {"schema_version": 2},
        {"status": ControlPlaneOperatorSessionStatus.REVOKED},
        {
            "status": ControlPlaneOperatorSessionStatus.ACTIVE,
            "revoked_at": _NOW,
            "revocation_reason": ControlPlaneOperatorSessionRevocationReason.LOGOUT,
        },
        {
            "status": ControlPlaneOperatorSessionStatus.REVOKED,
            "revoked_at": _NOW - timedelta(seconds=1),
            "revocation_reason": ControlPlaneOperatorSessionRevocationReason.LOGOUT,
        },
    ],
)
def test_session_record_rejects_invalid_fields(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "id": uuid4(),
        "operator_id": uuid4(),
        "username": "alice",
        "token_digest": _TOKEN.digest,
        "operator_token_version": 1,
        "issued_at": _NOW,
        "expires_at": _NOW + timedelta(minutes=30),
    }
    values.update(changes)
    with pytest.raises(ValueError):
        ControlPlaneOperatorSessionRecord(**values)  # type: ignore[arg-type]


def test_session_grant_redacts_token() -> None:
    grant = ControlPlaneOperatorSessionGrant(
        session_id=uuid4(),
        operator_id=uuid4(),
        username="alice",
        token=_TOKEN,
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=30),
    )
    assert _TOKEN.value not in repr(grant)


def test_session_authentication_contract_validates_expiry() -> None:
    from phoenix_os.control_plane.auth import ControlPlanePrincipal

    with pytest.raises(ValueError, match="expired"):
        ControlPlaneOperatorSessionAuthentication(
            session_id=uuid4(),
            operator_id=uuid4(),
            principal=ControlPlanePrincipal("alice"),
            authenticated_at=_NOW,
            expires_at=_NOW,
        )


@pytest.mark.asyncio
async def test_session_store_adds_and_reads_by_id_and_digest() -> None:
    store = InMemoryControlPlaneOperatorSessionStore()
    record = _record()
    await store.add(record)
    assert await store.get(record.id) == record
    assert await store.get_by_token_digest(record.token_digest.upper()) == record


@pytest.mark.asyncio
async def test_session_store_rejects_duplicate_id_and_digest() -> None:
    store = InMemoryControlPlaneOperatorSessionStore()
    record = _record()
    await store.add(record)
    with pytest.raises(ControlPlaneOperatorSessionConflictError):
        await store.add(replace(record, token_digest="1" * 64))
    with pytest.raises(ControlPlaneOperatorSessionConflictError):
        await store.add(_record(token=_TOKEN))


@pytest.mark.asyncio
async def test_session_store_revokes_with_optimistic_revision() -> None:
    store = InMemoryControlPlaneOperatorSessionStore()
    record = _record()
    await store.add(record)
    revoked = await store.revoke(
        record.id,
        expected_revision=1,
        revoked_at=_NOW + timedelta(minutes=1),
        reason=ControlPlaneOperatorSessionRevocationReason.LOGOUT,
    )
    assert revoked.status is ControlPlaneOperatorSessionStatus.REVOKED
    assert revoked.revision == 2
    assert revoked.revocation_reason is ControlPlaneOperatorSessionRevocationReason.LOGOUT
    assert (
        await store.revoke(
            record.id,
            expected_revision=2,
            revoked_at=_NOW + timedelta(minutes=2),
            reason=ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE,
        )
        == revoked
    )


@pytest.mark.asyncio
async def test_session_store_rejects_stale_or_missing_revoke() -> None:
    store = InMemoryControlPlaneOperatorSessionStore()
    record = _record()
    await store.add(record)
    with pytest.raises(ControlPlaneOperatorSessionConflictError, match="revision"):
        await store.revoke(
            record.id,
            expected_revision=2,
            revoked_at=_NOW,
            reason=ControlPlaneOperatorSessionRevocationReason.LOGOUT,
        )
    with pytest.raises(ControlPlaneOperatorSessionConflictError, match="not found"):
        await store.revoke(
            uuid4(),
            expected_revision=1,
            revoked_at=_NOW,
            reason=ControlPlaneOperatorSessionRevocationReason.LOGOUT,
        )


@pytest.mark.asyncio
async def test_session_store_bulk_revokes_one_operator_in_deterministic_order() -> None:
    store = InMemoryControlPlaneOperatorSessionStore(max_sessions_per_operator=3)
    operator_id = uuid4()
    first = _record(operator_id=operator_id, issued_at=_NOW)
    second = _record(
        operator_id=operator_id,
        token=ControlPlaneOperatorSessionToken("second-session-token-0123456789abcdef"),
        issued_at=_NOW + timedelta(seconds=1),
    )
    unrelated = _record(
        token=ControlPlaneOperatorSessionToken("third-session-token-0123456789abcdef"),
    )
    for record in (second, unrelated, first):
        await store.add(record)
    changed = await store.revoke_operator(
        operator_id,
        revoked_at=_NOW + timedelta(minutes=1),
        reason=ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE,
    )
    assert tuple(item.id for item in changed) == (first.id, second.id)
    assert (await store.get(unrelated.id)).status is ControlPlaneOperatorSessionStatus.ACTIVE  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_session_store_enforces_per_operator_active_limit() -> None:
    store = InMemoryControlPlaneOperatorSessionStore(max_sessions_per_operator=1)
    operator_id = uuid4()
    await store.add(_record(operator_id=operator_id))
    with pytest.raises(ControlPlaneOperatorSessionCapacityError, match="active session"):
        await store.add(
            _record(
                operator_id=operator_id,
                token=ControlPlaneOperatorSessionToken(
                    "replacement-session-token-0123456789abcdef"
                ),
            )
        )


@pytest.mark.asyncio
async def test_session_store_evicts_oldest_revoked_at_total_capacity() -> None:
    store = InMemoryControlPlaneOperatorSessionStore(capacity=2)
    first = _record()
    second = _record(
        token=ControlPlaneOperatorSessionToken("second-token-0123456789abcdef-session")
    )
    await store.add(first)
    await store.add(second)
    await store.revoke(
        first.id,
        expected_revision=1,
        revoked_at=_NOW + timedelta(seconds=1),
        reason=ControlPlaneOperatorSessionRevocationReason.LOGOUT,
    )
    third = _record(token=ControlPlaneOperatorSessionToken("third-token-0123456789abcdef-session"))
    await store.add(third)
    assert await store.get(first.id) is None
    assert await store.get(second.id) == second
    assert await store.get(third.id) == third


@pytest.mark.asyncio
async def test_session_store_rejects_capacity_with_only_active_records() -> None:
    store = InMemoryControlPlaneOperatorSessionStore(capacity=1)
    await store.add(_record())
    with pytest.raises(ControlPlaneOperatorSessionCapacityError, match="full"):
        await store.add(
            _record(
                token=ControlPlaneOperatorSessionToken("another-token-0123456789abcdef-session")
            )
        )


@pytest.mark.asyncio
async def test_session_store_snapshot_and_close_are_safe() -> None:
    store = InMemoryControlPlaneOperatorSessionStore(capacity=2, max_sessions_per_operator=2)
    record = _record()
    await store.add(record)
    await store.revoke(
        record.id,
        expected_revision=1,
        revoked_at=_NOW,
        reason=ControlPlaneOperatorSessionRevocationReason.LOGOUT,
    )
    assert await store.snapshot() == ControlPlaneOperatorSessionSnapshot(
        closed=False,
        sessions=1,
        active=0,
        revoked=1,
        capacity=2,
        max_sessions_per_operator=2,
    )
    await store.close()
    assert (await store.snapshot()).closed
    with pytest.raises(ControlPlaneOperatorSessionStoreClosedError):
        await store.get(record.id)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"capacity": 0},
        {"capacity": 10_001},
        {"max_sessions_per_operator": 0},
        {"max_sessions_per_operator": 65},
    ],
)
def test_session_store_rejects_invalid_bounds(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        InMemoryControlPlaneOperatorSessionStore(**kwargs)
