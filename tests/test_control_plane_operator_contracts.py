from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
    CONTROL_PLANE_OPERATORS_CREATE_PERMISSION,
    CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION,
    CONTROL_PLANE_OPERATORS_READ_PERMISSION,
    CONTROL_PLANE_OPERATORS_ROTATE_PERMISSION,
    CONTROL_PLANE_OPERATORS_UPDATE_PERMISSION,
    MAX_CONTROL_PLANE_OPERATOR_CAPACITY,
    MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE,
    ControlPlaneOperatorPage,
    ControlPlaneOperatorPageInfo,
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistrySnapshot,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.auth import CONTROL_PLANE_READ_PERMISSION
from phoenix_os.control_plane.commands import ControlPlaneCommandAction

_NOW = datetime(2026, 7, 19, 12, tzinfo=UTC)
_TOKEN = "operator-token-0123456789abcdef-xyz"
_DIGEST = hashlib.sha256(_TOKEN.encode("ascii")).hexdigest()


def _record(
    *,
    operator_id: UUID | None = None,
    username: str = "alice",
    display_name: str = "Alice Operator",
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.VIEWER,
    token_digest: str = _DIGEST,
    additional_permissions: frozenset[str] = frozenset(),
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime = _NOW,
    updated_at: datetime = _NOW,
    token_version: int = 1,
    revision: int = 1,
    schema_version: int = 1,
) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=operator_id or uuid4(),
        username=username,
        display_name=display_name,
        role=role,
        token_digest=token_digest,
        created_at=created_at,
        updated_at=updated_at,
        additional_permissions=additional_permissions,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        token_version=token_version,
        revision=revision,
        schema_version=schema_version,
    )


def test_viewer_role_has_read_only_permission() -> None:
    assert ControlPlaneOperatorRole.VIEWER.permissions == frozenset({CONTROL_PLANE_READ_PERMISSION})


def test_operator_role_has_read_and_every_command_permission() -> None:
    expected = {CONTROL_PLANE_READ_PERMISSION}
    expected.update(action.permission for action in ControlPlaneCommandAction)
    assert ControlPlaneOperatorRole.OPERATOR.permissions == frozenset(expected)


def test_maintainer_role_has_operator_and_access_management_permissions() -> None:
    permissions = ControlPlaneOperatorRole.MAINTAINER.permissions
    assert ControlPlaneOperatorRole.OPERATOR.permissions < permissions
    assert {
        CONTROL_PLANE_OPERATORS_READ_PERMISSION,
        CONTROL_PLANE_OPERATORS_CREATE_PERMISSION,
        CONTROL_PLANE_OPERATORS_UPDATE_PERMISSION,
        CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION,
        CONTROL_PLANE_OPERATORS_ROTATE_PERMISSION,
        CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
    } <= permissions


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (ControlPlaneOperatorStatus.ACTIVE, True),
        (ControlPlaneOperatorStatus.DISABLED, False),
        (ControlPlaneOperatorStatus.REVOKED, False),
    ],
)
def test_operator_status_authenticatable(
    status: ControlPlaneOperatorStatus,
    expected: bool,
) -> None:
    assert status.authenticatable is expected


def test_operator_token_is_redacted_and_has_stable_digest() -> None:
    token = ControlPlaneOperatorToken(_TOKEN)
    assert token.digest == _DIGEST
    assert str(token) == "<redacted>"
    assert repr(token) == "ControlPlaneOperatorToken(<redacted>)"
    assert _TOKEN not in repr(token)


@pytest.mark.parametrize(
    "token",
    [
        "short",
        " " + _TOKEN,
        _TOKEN + " ",
        "á" * 32,
        "a" * 31,
        "a" * 129,
        "a" * 31 + "/",
    ],
)
def test_operator_token_rejects_unsafe_values(token: str) -> None:
    with pytest.raises(ValueError):
        ControlPlaneOperatorToken(token)


def test_operator_record_normalizes_identity_and_permissions() -> None:
    record = _record(
        username=" Alice.Admin ",
        display_name=" Alice Admin ",
        role=ControlPlaneOperatorRole.OPERATOR,
        token_digest=_DIGEST.upper(),
        additional_permissions=frozenset({" Audit.Read ", "custom.permission"}),
    )
    assert record.username == "alice.admin"
    assert record.display_name == "Alice Admin"
    assert record.token_digest == _DIGEST
    assert record.additional_permissions == frozenset({"audit.read", "custom.permission"})
    assert ControlPlaneOperatorRole.OPERATOR.permissions <= record.effective_permissions
    assert {"audit.read", "custom.permission"} <= record.effective_permissions


def test_active_operator_creates_existing_transport_principal() -> None:
    record = _record(
        role=ControlPlaneOperatorRole.MAINTAINER,
        additional_permissions=frozenset({"audit.read"}),
    )
    principal = record.principal()
    assert principal.name == "alice"
    assert principal.permissions == record.effective_permissions


@pytest.mark.parametrize(
    "username",
    ["", "ab", "2alice", "alice space", "alice/ops", "álice", "a" * 65],
)
def test_operator_record_rejects_invalid_username(username: str) -> None:
    with pytest.raises(ValueError, match="username"):
        _record(username=username)


@pytest.mark.parametrize("display_name", ["", " ", "a\nname", "a" * 129])
def test_operator_record_rejects_invalid_display_name(display_name: str) -> None:
    with pytest.raises(ValueError, match="display name"):
        _record(display_name=display_name)


@pytest.mark.parametrize("digest", ["", "0" * 63, "g" * 64, "0" * 65])
def test_operator_record_rejects_invalid_digest(digest: str) -> None:
    with pytest.raises(ValueError, match="digest"):
        _record(token_digest=digest)


@pytest.mark.parametrize(
    "permission",
    ["", " ", "contains space", "bad/slash", "á.permission"],
)
def test_operator_record_rejects_invalid_additional_permission(permission: str) -> None:
    with pytest.raises(ValueError, match="permissions"):
        _record(additional_permissions=frozenset({permission}))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("created_at", datetime(2026, 1, 1)),
        ("updated_at", datetime(2026, 1, 1)),
    ],
)
def test_operator_record_requires_aware_core_timestamps(
    field_name: str,
    value: datetime,
) -> None:
    kwargs: dict[str, datetime] = {field_name: value}
    with pytest.raises(ValueError, match=field_name):
        _record(**kwargs)  # type: ignore[arg-type]


def test_operator_record_rejects_updated_before_created() -> None:
    with pytest.raises(ValueError, match="updated_at"):
        _record(updated_at=_NOW - timedelta(seconds=1))


@pytest.mark.parametrize("field", ["token_version", "revision"])
def test_operator_record_requires_positive_versions(field: str) -> None:
    if field == "token_version":
        with pytest.raises(ValueError, match="token version"):
            _record(token_version=0)
    else:
        with pytest.raises(ValueError, match="revision"):
            _record(revision=0)


def test_operator_record_rejects_unknown_schema() -> None:
    with pytest.raises(ValueError, match="schema"):
        _record(schema_version=2)


def test_active_operator_rejects_inactive_timestamps() -> None:
    with pytest.raises(ValueError, match="active"):
        _record(disabled_at=_NOW)
    with pytest.raises(ValueError, match="active"):
        _record(revoked_at=_NOW)


def test_disabled_operator_requires_only_disabled_at() -> None:
    record = _record(
        status=ControlPlaneOperatorStatus.DISABLED,
        disabled_at=_NOW,
    )
    assert record.status is ControlPlaneOperatorStatus.DISABLED
    with pytest.raises(ValueError, match="disabled"):
        _record(status=ControlPlaneOperatorStatus.DISABLED)
    with pytest.raises(ValueError, match="disabled"):
        _record(
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=_NOW,
            revoked_at=_NOW,
        )


def test_revoked_operator_requires_revoked_at_and_cannot_create_principal() -> None:
    with pytest.raises(ValueError, match="revoked"):
        _record(status=ControlPlaneOperatorStatus.REVOKED)
    record = _record(
        status=ControlPlaneOperatorStatus.REVOKED,
        revoked_at=_NOW,
    )
    with pytest.raises(ValueError, match="inactive"):
        record.principal()


def test_operator_record_rejects_naive_inactive_timestamp() -> None:
    with pytest.raises(ValueError, match="disabled_at"):
        _record(
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=datetime(2026, 1, 1),
        )


@pytest.mark.parametrize(
    ("offset", "limit"),
    [(-1, 1), (0, 0), (0, -1), (0, MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE + 1)],
)
def test_operator_page_request_rejects_invalid_bounds(offset: int, limit: int) -> None:
    with pytest.raises(ValueError):
        ControlPlaneOperatorPageRequest(offset=offset, limit=limit)


def test_operator_page_info_builds_next_offset() -> None:
    request = ControlPlaneOperatorPageRequest(offset=10, limit=5)
    info = ControlPlaneOperatorPageInfo.from_slice(request, returned=5, total=20)
    assert info.next_offset == 15


def test_operator_page_info_omits_next_offset_at_end() -> None:
    request = ControlPlaneOperatorPageRequest(offset=10, limit=10)
    info = ControlPlaneOperatorPageInfo.from_slice(request, returned=2, total=12)
    assert info.next_offset is None


@pytest.mark.parametrize(
    "info",
    [
        ControlPlaneOperatorPageInfo(0, 10, 0, 0, None),
    ],
)
def test_operator_page_accepts_consistent_empty_page(info: ControlPlaneOperatorPageInfo) -> None:
    assert ControlPlaneOperatorPage(items=(), page=info).items == ()


def test_operator_page_rejects_count_mismatch() -> None:
    info = ControlPlaneOperatorPageInfo(0, 10, 0, 0, None)
    with pytest.raises(ValueError, match="count"):
        ControlPlaneOperatorPage(items=(_record(),), page=info)


def test_operator_page_rejects_duplicate_items() -> None:
    record = _record()
    info = ControlPlaneOperatorPageInfo(0, 10, 2, 2, None)
    with pytest.raises(ValueError, match="unique"):
        ControlPlaneOperatorPage(items=(record, record), page=info)


def test_operator_registry_snapshot_accepts_consistent_counts() -> None:
    snapshot = ControlPlaneOperatorRegistrySnapshot(
        closed=False,
        operators=3,
        active=1,
        disabled=1,
        revoked=1,
        viewers=1,
        operators_role=1,
        maintainers=1,
        capacity=10,
    )
    assert snapshot.operators == 3


@pytest.mark.parametrize(
    (
        "operators",
        "active",
        "disabled",
        "revoked",
        "viewers",
        "operators_role",
        "maintainers",
        "capacity",
    ),
    [
        (-1, 0, 0, 0, 0, 0, 0, 1),
        (2, 1, 0, 0, 1, 0, 0, 2),
        (2, 2, 0, 0, 1, 0, 0, 2),
        (2, 2, 0, 0, 2, 0, 0, 1),
        (0, 0, 0, 0, 0, 0, 0, MAX_CONTROL_PLANE_OPERATOR_CAPACITY + 1),
    ],
)
def test_operator_registry_snapshot_rejects_inconsistent_counts(
    operators: int,
    active: int,
    disabled: int,
    revoked: int,
    viewers: int,
    operators_role: int,
    maintainers: int,
    capacity: int,
) -> None:
    with pytest.raises(ValueError):
        ControlPlaneOperatorRegistrySnapshot(
            closed=False,
            operators=operators,
            active=active,
            disabled=disabled,
            revoked=revoked,
            viewers=viewers,
            operators_role=operators_role,
            maintainers=maintainers,
            capacity=capacity,
        )


def test_replace_can_construct_next_revision_without_mutating_original() -> None:
    record = _record()
    updated = replace(
        record,
        display_name="Updated",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )
    assert record.display_name == "Alice Operator"
    assert updated.display_name == "Updated"
    assert updated.revision == 2
