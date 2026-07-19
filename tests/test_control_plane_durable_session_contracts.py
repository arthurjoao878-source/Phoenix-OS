from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane.durable_session_contracts import (
    DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    MAX_DURABLE_SESSION_ABSOLUTE_TTL,
    MAX_DURABLE_SESSION_IDLE_TTL,
    MAX_DURABLE_SESSION_PAGE_SIZE,
    MAX_DURABLE_SESSION_ROTATION_INTERVAL,
    MAX_DURABLE_SESSION_TERMINAL_RETENTION,
    MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionPage,
    ControlPlaneDurableSessionPageInfo,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRotation,
    ControlPlaneDurableSessionSnapshot,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
OPERATOR_ID = UUID(int=10)
SESSION_ID = UUID(int=1)


def _token(value: int = 1) -> ControlPlaneDurableSessionToken:
    return ControlPlaneDurableSessionToken(f"token-{value:026d}")


def _csrf(value: int = 1) -> ControlPlaneDurableCsrfSecret:
    return ControlPlaneDurableCsrfSecret(f"csrf-{value:027d}")


def _record(
    *,
    session_id: UUID = SESSION_ID,
    operator_id: UUID = OPERATOR_ID,
    issued_at: datetime = NOW,
    generation: int = 1,
    predecessor_session_id: UUID | None = None,
    token_value: int = 1,
    csrf_value: int = 1,
) -> ControlPlaneDurableSessionRecord:
    return ControlPlaneDurableSessionRecord.issue(
        session_id=session_id,
        operator_id=operator_id,
        username="Maintainer.One",
        token=_token(token_value),
        csrf_secret=_csrf(csrf_value),
        operator_revision=3,
        operator_token_version=2,
        generation=generation,
        predecessor_session_id=predecessor_session_id,
        issued_at=issued_at,
    )


def test_session_token_is_redacted_and_digest_is_stable() -> None:
    token = _token()

    assert str(token) == "<redacted>"
    assert repr(token) == "ControlPlaneDurableSessionToken(<redacted>)"
    assert token.value not in repr(token)
    assert token.digest == token.digest
    assert len(token.digest) == 64


def test_csrf_secret_is_redacted_and_separate_from_token() -> None:
    token = _token()
    secret = _csrf()

    assert str(secret) == "<redacted>"
    assert repr(secret) == "ControlPlaneDurableCsrfSecret(<redacted>)"
    assert secret.value not in repr(secret)
    assert secret.digest != token.digest


@pytest.mark.parametrize(
    "factory,value",
    [
        (ControlPlaneDurableSessionToken, "short"),
        (ControlPlaneDurableSessionToken, " x" * 20),
        (ControlPlaneDurableSessionToken, "x" * 129),
        (ControlPlaneDurableSessionToken, "x" * 31 + "/"),
        (ControlPlaneDurableCsrfSecret, "short"),
        (ControlPlaneDurableCsrfSecret, "x" * 32 + " "),
        (ControlPlaneDurableCsrfSecret, "x" * 129),
        (ControlPlaneDurableCsrfSecret, "á" * 32),
    ],
)
def test_secret_contract_rejects_invalid_values(
    factory: type[ControlPlaneDurableSessionToken] | type[ControlPlaneDurableCsrfSecret],
    value: str,
) -> None:
    with pytest.raises(ValueError):
        factory(value)


def test_policy_builds_bounded_deadlines() -> None:
    policy = ControlPlaneDurableSessionPolicy(
        absolute_ttl=timedelta(hours=2),
        idle_ttl=timedelta(minutes=20),
        rotation_interval=timedelta(minutes=5),
    )
    absolute = policy.absolute_expiry(NOW)

    assert absolute == NOW + timedelta(hours=2)
    assert policy.idle_expiry(NOW, absolute_expires_at=absolute) == NOW + timedelta(minutes=20)
    assert policy.rotation_due_at(NOW, absolute_expires_at=absolute) == NOW + timedelta(minutes=5)


def test_policy_clamps_idle_and_rotation_to_absolute_expiry() -> None:
    policy = ControlPlaneDurableSessionPolicy(
        absolute_ttl=timedelta(minutes=10),
        idle_ttl=timedelta(minutes=10),
        rotation_interval=timedelta(minutes=10),
    )
    absolute = NOW + timedelta(minutes=4)

    assert policy.idle_expiry(NOW, absolute_expires_at=absolute) == absolute
    assert policy.rotation_due_at(NOW, absolute_expires_at=absolute) == absolute


@pytest.mark.parametrize(
    "changes",
    [
        {"absolute_ttl": timedelta(0)},
        {"absolute_ttl": MAX_DURABLE_SESSION_ABSOLUTE_TTL + timedelta(seconds=1)},
        {"idle_ttl": timedelta(0)},
        {"idle_ttl": MAX_DURABLE_SESSION_IDLE_TTL + timedelta(seconds=1)},
        {"rotation_interval": timedelta(0)},
        {"rotation_interval": MAX_DURABLE_SESSION_ROTATION_INTERVAL + timedelta(seconds=1)},
        {"terminal_retention": timedelta(0)},
        {"terminal_retention": MAX_DURABLE_SESSION_TERMINAL_RETENTION + timedelta(seconds=1)},
        {"max_sessions_per_operator": 0},
        {"max_sessions_per_operator": MAX_DURABLE_SESSIONS_PER_OPERATOR + 1},
        {"schema_version": 2},
        {"absolute_ttl": timedelta(minutes=10), "idle_ttl": timedelta(minutes=11)},
        {
            "absolute_ttl": timedelta(minutes=10),
            "rotation_interval": timedelta(minutes=11),
        },
    ],
)
def test_policy_rejects_invalid_bounds(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionPolicy(**changes)


def test_policy_rejects_naive_deadline_inputs() -> None:
    policy = ControlPlaneDurableSessionPolicy()
    naive = NOW.replace(tzinfo=None)

    with pytest.raises(ValueError):
        policy.absolute_expiry(naive)
    with pytest.raises(ValueError):
        policy.idle_expiry(NOW, absolute_expires_at=naive)
    with pytest.raises(ValueError):
        policy.rotation_due_at(naive, absolute_expires_at=NOW)


def test_issue_normalizes_identity_and_retains_only_digests() -> None:
    token = _token()
    csrf = _csrf()
    record = ControlPlaneDurableSessionRecord.issue(
        session_id=UUID(int=2),
        operator_id=OPERATOR_ID,
        username="  Maintainer.One  ",
        token=token,
        csrf_secret=csrf,
        operator_revision=4,
        operator_token_version=3,
        issued_at=NOW,
    )

    assert record.username == "maintainer.one"
    assert record.token_digest == token.digest
    assert record.csrf_digest == csrf.digest
    assert token.value not in repr(record)
    assert csrf.value not in repr(record)
    assert record.status is ControlPlaneDurableSessionStatus.ACTIVE
    assert record.revision == 1


def test_issue_preserves_absolute_expiry_across_rotation_generation() -> None:
    absolute = NOW + timedelta(hours=3)
    record = ControlPlaneDurableSessionRecord.issue(
        session_id=UUID(int=3),
        operator_id=OPERATOR_ID,
        username="operator.one",
        token=_token(2),
        csrf_secret=_csrf(2),
        operator_revision=1,
        operator_token_version=1,
        issued_at=NOW + timedelta(minutes=15),
        generation=2,
        predecessor_session_id=UUID(int=1),
        absolute_expires_at=absolute,
    )

    assert record.generation == 2
    assert record.predecessor_session_id == UUID(int=1)
    assert record.absolute_expires_at == absolute


@pytest.mark.parametrize(
    "changes",
    [
        {"username": "x"},
        {"token_digest": "z" * 64},
        {"csrf_digest": "z" * 64},
        {"csrf_digest": _token().digest},
        {"operator_revision": 0},
        {"operator_token_version": 0},
        {"generation": 0},
        {"revision": 0},
        {"schema_version": 2},
        {"last_seen_at": NOW - timedelta(seconds=1)},
        {"absolute_expires_at": NOW},
        {"absolute_expires_at": NOW + MAX_DURABLE_SESSION_ABSOLUTE_TTL + timedelta(seconds=1)},
        {"idle_expires_at": NOW},
        {"idle_expires_at": NOW + timedelta(days=2)},
        {"rotate_after": NOW},
        {"rotate_after": NOW + timedelta(days=2)},
        {"predecessor_session_id": UUID(int=5)},
        {"generation": 2, "predecessor_session_id": None},
        {"successor_session_id": UUID(int=1)},
    ],
)
def test_record_rejects_invalid_active_invariants(changes: dict[str, Any]) -> None:
    record = _record()

    with pytest.raises(ValueError):
        replace(record, **changes)


@pytest.mark.parametrize(
    "status,reason,successor,valid",
    [
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
            None,
            True,
        ),
        (
            ControlPlaneDurableSessionStatus.EXPIRED,
            ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
            None,
            True,
        ),
        (
            ControlPlaneDurableSessionStatus.ROTATED,
            ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
            UUID(int=2),
            True,
        ),
        (
            ControlPlaneDurableSessionStatus.EXPIRED,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
            None,
            False,
        ),
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
            None,
            False,
        ),
        (
            ControlPlaneDurableSessionStatus.ROTATED,
            ControlPlaneDurableSessionTerminationReason.LOGOUT,
            UUID(int=2),
            False,
        ),
        (
            ControlPlaneDurableSessionStatus.ROTATED,
            ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
            None,
            False,
        ),
        (
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
            None,
            False,
        ),
    ],
)
def test_terminal_record_invariants(
    status: ControlPlaneDurableSessionStatus,
    reason: ControlPlaneDurableSessionTerminationReason,
    successor: UUID | None,
    valid: bool,
) -> None:
    record = _record()
    kwargs: dict[str, Any] = {
        "status": status,
        "terminated_at": NOW + timedelta(minutes=1),
        "termination_reason": reason,
        "successor_session_id": successor,
        "revision": 2,
    }

    if valid:
        terminal = replace(record, **kwargs)
        assert terminal.status is status
    else:
        with pytest.raises(ValueError):
            replace(record, **kwargs)


def test_active_expiration_and_rotation_decisions_are_deterministic() -> None:
    record = _record()

    assert record.expiration_reason_at(NOW + timedelta(minutes=1)) is None
    assert record.active_at(NOW + timedelta(minutes=1))
    assert not record.rotation_due_at(NOW + timedelta(minutes=1))
    assert record.rotation_due_at(record.rotate_after)
    assert record.expiration_reason_at(record.idle_expires_at) is (
        ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT
    )
    assert not record.active_at(record.idle_expires_at)
    assert record.expiration_reason_at(record.absolute_expires_at) is (
        ControlPlaneDurableSessionTerminationReason.ABSOLUTE_TIMEOUT
    )


def test_terminal_record_has_no_new_expiration_decision() -> None:
    record = replace(
        _record(),
        status=ControlPlaneDurableSessionStatus.REVOKED,
        terminated_at=NOW + timedelta(minutes=1),
        termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
        revision=2,
    )

    assert record.expiration_reason_at(record.absolute_expires_at) is None
    assert not record.active_at(NOW)
    assert not record.rotation_due_at(record.rotate_after)


def test_record_time_decisions_reject_naive_clock() -> None:
    record = _record()
    naive = NOW.replace(tzinfo=None)

    with pytest.raises(ValueError):
        record.expiration_reason_at(naive)
    with pytest.raises(ValueError):
        record.rotation_due_at(naive)


@pytest.mark.parametrize(
    "values",
    [
        {"offset": -1},
        {"limit": 0},
        {"limit": MAX_DURABLE_SESSION_PAGE_SIZE + 1},
        {"status": "unknown"},
    ],
)
def test_page_request_rejects_invalid_values(values: dict[str, Any]) -> None:
    with pytest.raises((ValueError, TypeError)):
        ControlPlaneDurableSessionPageRequest(**values)


def test_default_page_request_is_bounded() -> None:
    assert DEFAULT_DURABLE_SESSION_PAGE_REQUEST.offset == 0
    assert DEFAULT_DURABLE_SESSION_PAGE_REQUEST.limit == 50


def test_page_info_builds_next_offset() -> None:
    request = ControlPlaneDurableSessionPageRequest(offset=2, limit=3)

    page = ControlPlaneDurableSessionPageInfo.from_slice(request, returned=3, total=9)
    final = ControlPlaneDurableSessionPageInfo.from_slice(request, returned=2, total=4)

    assert page.next_offset == 5
    assert final.next_offset is None


@pytest.mark.parametrize(
    "changes",
    [
        {"offset": -1},
        {"limit": 0},
        {"returned": 3, "limit": 2},
        {"returned": 2, "total": 1},
        {"next_offset": None, "returned": 1, "total": 3},
        {"next_offset": 4, "returned": 1, "total": 3},
    ],
)
def test_page_info_rejects_inconsistent_values(changes: dict[str, Any]) -> None:
    values: dict[str, Any] = {
        "offset": 0,
        "limit": 2,
        "returned": 2,
        "total": 2,
        "next_offset": None,
    }
    values.update(changes)

    with pytest.raises(ValueError):
        ControlPlaneDurableSessionPageInfo(**values)


def test_page_rejects_count_mismatch_and_duplicates() -> None:
    record = _record()
    info = ControlPlaneDurableSessionPageInfo(
        offset=0,
        limit=2,
        returned=1,
        total=1,
        next_offset=None,
    )

    with pytest.raises(ValueError):
        ControlPlaneDurableSessionPage(items=(), page=info)

    duplicate_info = replace(info, returned=2, total=2)
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionPage(items=(record, record), page=duplicate_info)


@pytest.mark.parametrize(
    "changes",
    [
        {"entries": -1},
        {"capacity": 0},
        {"entries": 2, "capacity": 1},
        {"entries": 2, "active": 1},
        {"max_sessions_per_operator": 0},
        {"max_sessions_per_operator": MAX_DURABLE_SESSIONS_PER_OPERATOR + 1},
    ],
)
def test_snapshot_rejects_inconsistent_values(changes: dict[str, Any]) -> None:
    values: dict[str, Any] = {
        "closed": False,
        "entries": 1,
        "active": 1,
        "revoked": 0,
        "expired": 0,
        "rotated": 0,
        "capacity": 10,
        "max_sessions_per_operator": 2,
    }
    values.update(changes)

    with pytest.raises(ValueError):
        ControlPlaneDurableSessionSnapshot(**values)


def test_rotation_contract_validates_bidirectional_lineage() -> None:
    previous = replace(
        _record(),
        status=ControlPlaneDurableSessionStatus.ROTATED,
        terminated_at=NOW + timedelta(minutes=5),
        termination_reason=ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
        successor_session_id=UUID(int=2),
        revision=2,
    )
    successor = _record(
        session_id=UUID(int=2),
        issued_at=NOW + timedelta(minutes=5),
        generation=2,
        predecessor_session_id=previous.id,
        token_value=2,
        csrf_value=2,
    )

    rotation = ControlPlaneDurableSessionRotation(previous=previous, successor=successor)

    assert rotation.previous.successor_session_id == rotation.successor.id


@pytest.mark.parametrize("field", ["previous", "successor"])
def test_rotation_contract_rejects_invalid_state(field: str) -> None:
    active = _record()
    previous = replace(
        active,
        status=ControlPlaneDurableSessionStatus.ROTATED,
        terminated_at=NOW + timedelta(minutes=5),
        termination_reason=ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
        successor_session_id=UUID(int=2),
        revision=2,
    )
    successor = _record(
        session_id=UUID(int=2),
        issued_at=NOW + timedelta(minutes=5),
        generation=2,
        predecessor_session_id=previous.id,
        token_value=2,
        csrf_value=2,
    )
    if field == "previous":
        previous = active
    else:
        successor = replace(
            successor,
            status=ControlPlaneDurableSessionStatus.REVOKED,
            terminated_at=NOW + timedelta(minutes=6),
            termination_reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            revision=2,
        )

    with pytest.raises(ValueError):
        ControlPlaneDurableSessionRotation(previous=previous, successor=successor)
