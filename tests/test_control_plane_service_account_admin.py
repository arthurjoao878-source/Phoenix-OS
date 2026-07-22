from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION,
    CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION,
    ControlPlaneApiTokenStatus,
    ControlPlanePrincipal,
    ControlPlaneServiceAccountAdministration,
    ControlPlaneServiceAccountAdministrationPermissionDeniedError,
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountLifecycleService,
    ControlPlaneServiceAccountStatus,
    InMemoryControlPlaneServiceAccountRepository,
    api_token_grant_to_dict,
    api_token_view_to_dict,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRole,
)

_NOW = datetime(
    2026,
    7,
    21,
    12,
    tzinfo=UTC,
)

_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")
_SUCCESSOR_ID = UUID("20000000-0000-0000-0000-000000000002")

_FIRST_TOKEN = "phx_sa_" + "A" * 48
_SECOND_TOKEN = "phx_sa_" + "B" * 48


def _maintainer() -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        "maintainer",
        ControlPlaneOperatorRole.MAINTAINER.permissions,
    )


def _operator() -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        "operator",
        ControlPlaneOperatorRole.OPERATOR.permissions,
    )


def _administration() -> tuple[
    InMemoryControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountLifecycleService,
    ControlPlaneServiceAccountAdministration,
]:
    repository = InMemoryControlPlaneServiceAccountRepository()

    token_values = iter(
        (
            _FIRST_TOKEN,
            _SECOND_TOKEN,
        )
    )
    token_ids = iter(
        (
            _TOKEN_ID,
            _SUCCESSOR_ID,
        )
    )

    lifecycle = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: _NOW,
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: next(token_ids),
        token_factory=lambda: next(token_values),
    )

    audit = ControlPlaneServiceAccountAudit(
        None,
        ControlPlaneServiceAccountAuditProtector(b"A" * 32),
    )

    administration = ControlPlaneServiceAccountAdministration(
        repository=repository,
        lifecycle=lifecycle,
        audit=audit,
    )

    return repository, lifecycle, administration


def test_maintainer_receives_exact_management_permissions() -> None:
    maintainer = ControlPlaneOperatorRole.MAINTAINER.permissions
    operator = ControlPlaneOperatorRole.OPERATOR.permissions

    assert CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION in maintainer
    assert CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION in maintainer

    assert CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION not in operator
    assert CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION not in operator


@pytest.mark.asyncio
async def test_non_maintainer_cannot_list_accounts() -> None:
    _, _, administration = _administration()

    with pytest.raises(
        ControlPlaneServiceAccountAdministrationPermissionDeniedError,
        match="permission denied",
    ):
        await administration.list_accounts(_operator())


@pytest.mark.asyncio
async def test_create_list_and_update_account() -> None:
    _, _, administration = _administration()
    actor = _maintainer()

    created = await administration.create_account(
        actor,
        name="release.bot",
        display_name="Release Bot",
    )

    assert created.service_account_id == _ACCOUNT_ID
    assert created.status is (ControlPlaneServiceAccountStatus.ACTIVE)
    assert created.revision == 1

    page = await administration.list_accounts(actor)

    assert page.page.total == 1
    assert page.items == (created,)

    updated = await administration.update_account(
        actor,
        _ACCOUNT_ID,
        expected_revision=1,
        display_name="Release Automation",
    )

    assert updated.display_name == ("Release Automation")
    assert updated.revision == 2


@pytest.mark.asyncio
async def test_stale_account_revision_is_rejected() -> None:
    _, _, administration = _administration()
    actor = _maintainer()

    await administration.create_account(
        actor,
        name="release.bot",
        display_name="Release Bot",
    )

    await administration.update_account(
        actor,
        _ACCOUNT_ID,
        expected_revision=1,
        display_name="Release Automation",
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="revision conflict",
    ):
        await administration.disable_account(
            actor,
            _ACCOUNT_ID,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_one_time_grant_contains_no_persisted_digest() -> None:
    _, _, administration = _administration()
    actor = _maintainer()

    account = await administration.create_account(
        actor,
        name="release.bot",
        display_name="Release Bot",
    )

    grant = await administration.issue_token(
        actor,
        account.service_account_id,
        label="deployment",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        resources=frozenset(
            {
                "job:*",
            }
        ),
        expires_at=_NOW + timedelta(hours=1),
    )

    payload = api_token_grant_to_dict(grant)
    metadata = payload["metadata"]

    assert payload["token"] == _FIRST_TOKEN
    assert isinstance(metadata, dict)
    assert "token_digest" not in metadata
    assert grant.metadata.token_digest not in repr(metadata)

    view_payload = api_token_view_to_dict(
        (
            await administration.list_tokens(
                actor,
                account.service_account_id,
            )
        ).items[0]
    )

    assert "token" not in view_payload
    assert "token_digest" not in view_payload
    assert _FIRST_TOKEN not in repr(view_payload)


@pytest.mark.asyncio
async def test_rotate_and_revoke_token_with_revisions() -> None:
    _, _, administration = _administration()
    actor = _maintainer()

    account = await administration.create_account(
        actor,
        name="release.bot",
        display_name="Release Bot",
    )

    original = await administration.issue_token(
        actor,
        account.service_account_id,
        label="deployment",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        expires_at=_NOW + timedelta(hours=1),
    )

    successor = await administration.rotate_token(
        actor,
        original.metadata.id,
        expected_revision=1,
        expires_at=_NOW + timedelta(hours=2),
    )

    assert successor.token.value == _SECOND_TOKEN
    assert successor.metadata.id == _SUCCESSOR_ID
    assert successor.metadata.rotated_from == _TOKEN_ID
    assert successor.metadata.token_version == 2

    revoked = await administration.revoke_token(
        actor,
        successor.metadata.id,
        expected_revision=1,
    )

    assert revoked.status is (ControlPlaneApiTokenStatus.REVOKED)
    assert revoked.revision == 2


@pytest.mark.asyncio
async def test_account_state_management_is_revision_bound() -> None:
    _, _, administration = _administration()
    actor = _maintainer()

    created = await administration.create_account(
        actor,
        name="release.bot",
        display_name="Release Bot",
    )

    disabled = await administration.disable_account(
        actor,
        created.service_account_id,
        expected_revision=created.revision,
    )

    assert disabled.status is (ControlPlaneServiceAccountStatus.DISABLED)

    enabled = await administration.enable_account(
        actor,
        disabled.service_account_id,
        expected_revision=disabled.revision,
    )

    assert enabled.status is (ControlPlaneServiceAccountStatus.ACTIVE)

    revoked = await administration.revoke_account(
        actor,
        enabled.service_account_id,
        expected_revision=enabled.revision,
    )

    assert revoked.status is (ControlPlaneServiceAccountStatus.REVOKED)


def test_admin_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountAdministration
        is ControlPlaneServiceAccountAdministration
    )
    assert control_plane.api_token_grant_to_dict is api_token_grant_to_dict
