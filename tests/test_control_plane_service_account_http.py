from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import ClassVar
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneBrowserOrigin,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlanePrincipal,
    ControlPlaneServiceAccountAdministration,
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
    ControlPlaneServiceAccountHttpAdapter,
    ControlPlaneServiceAccountLifecycleService,
    ControlPlaneStepUpRejectedError,
    InMemoryControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRole,
)
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction

_NOW = datetime(
    2026,
    7,
    21,
    15,
    tzinfo=UTC,
)

_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:9443")

_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000011")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000011")
_SESSION_ID = UUID("30000000-0000-0000-0000-000000000011")
_OPERATOR_ID = UUID("40000000-0000-0000-0000-000000000011")

_TOKEN_VALUE = "phx_sa_" + "H" * 48

_ROTATED_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000012")

_ROTATED_TOKEN_VALUE = "phx_sa_" + "J" * 48


class _StepUp:
    calls: ClassVar[
        list[
            tuple[
                str | None,
                ControlPlaneDurableSessionAuthentication,
                ControlPlaneStepUpAction,
            ]
        ]
    ] = []

    def __init__(self) -> None:
        type(self).calls = []

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        type(self).calls.append(
            (
                token_value,
                session,
                action,
            )
        )

        return object()


class _Boundary:
    def __init__(
        self,
        *,
        reject: bool = False,
    ) -> None:
        self.reject = reject
        self.calls = 0

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: (ControlPlaneDurableSessionAuthentication),
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object:
        self.calls += 1

        if self.reject:
            raise (ControlPlaneDurableSessionCsrfRejectedError("CSRF rejected"))

        assert token_value == "csrf-value"
        assert authentication.session_id == _SESSION_ID
        assert supplied_origin == _ORIGIN
        assert expected_origin == _ORIGIN

        return object()


def _principal(
    *,
    maintainer: bool = True,
) -> ControlPlanePrincipal:
    role = ControlPlaneOperatorRole.MAINTAINER if maintainer else ControlPlaneOperatorRole.OPERATOR

    return ControlPlanePrincipal(
        "maintainer" if maintainer else "operator",
        role.permissions,
    )


def _authentication(
    *,
    maintainer: bool = True,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=_principal(maintainer=maintainer),
        generation=1,
        authenticated_at=_NOW,
        absolute_expires_at=(_NOW + timedelta(hours=2)),
        idle_expires_at=(_NOW + timedelta(minutes=30)),
    )


def _system(
    *,
    maintainer: bool = True,
    reject_csrf: bool = False,
) -> tuple[
    ControlPlaneServiceAccountHttpAdapter,
    ControlPlaneServiceAccountAdministration,
    _Boundary,
    ControlPlaneDurableSessionAuthentication,
]:
    repository = InMemoryControlPlaneServiceAccountRepository()

    token_ids = iter(
        (
            _TOKEN_ID,
            _ROTATED_TOKEN_ID,
        )
    )

    token_values = iter(
        (
            _TOKEN_VALUE,
            _ROTATED_TOKEN_VALUE,
        )
    )

    lifecycle = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: _NOW,
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: next(token_ids),
        token_factory=lambda: next(token_values),
    )

    administration = ControlPlaneServiceAccountAdministration(
        repository=repository,
        lifecycle=lifecycle,
        audit=ControlPlaneServiceAccountAudit(
            None,
            ControlPlaneServiceAccountAuditProtector(b"B" * 32),
        ),
    )

    boundary = _Boundary(reject=reject_csrf)

    adapter = ControlPlaneServiceAccountHttpAdapter(
        administration=administration,
        boundary=boundary,
        step_up=_StepUp(),
    )

    return (
        adapter,
        administration,
        boundary,
        _authentication(maintainer=maintainer),
    )


def _headers(
    origin: str = "http://127.0.0.1:9443",
) -> dict[str, tuple[str, ...]]:
    return {
        "origin": (origin,),
        "x-phoenix-csrf": ("csrf-value",),
    }


def _body(
    value: Mapping[str, object],
) -> bytes:
    return json.dumps(dict(value)).encode("utf-8")


def test_adapter_handles_service_account_routes() -> None:
    assert ControlPlaneServiceAccountHttpAdapter.handles("/v1/control-plane/service-accounts")

    assert ControlPlaneServiceAccountHttpAdapter.handles(
        f"/v1/control-plane/service-accounts/{_ACCOUNT_ID}/tokens"
    )

    assert not (ControlPlaneServiceAccountHttpAdapter.handles("/v1/control-plane/operators"))


@pytest.mark.asyncio
async def test_create_and_list_account() -> None:
    (
        adapter,
        _,
        boundary,
        authentication,
    ) = _system()

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/service-accounts",
        query={},
        headers=_headers(),
        body=_body(
            {
                "name": "release.bot",
                "display_name": "Release Bot",
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CREATED
    assert headers == {}
    assert boundary.calls == 1
    assert payload["service_account_id"] == str(_ACCOUNT_ID)
    assert payload["revision"] == 1

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/service-accounts",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert headers == {}
    assert boundary.calls == 1
    assert payload["schema_version"] == 1
    assert "release.bot" in repr(payload)


@pytest.mark.asyncio
async def test_non_maintainer_is_forbidden() -> None:
    (
        adapter,
        _,
        boundary,
        authentication,
    ) = _system(maintainer=False)

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/service-accounts",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "forbidden",
    }
    assert headers == {}
    assert boundary.calls == 0


@pytest.mark.asyncio
async def test_wrong_origin_is_rejected() -> None:
    (
        adapter,
        _,
        boundary,
        authentication,
    ) = _system()

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/service-accounts",
        query={},
        headers=_headers("http://127.0.0.1:9555"),
        body=_body(
            {
                "name": "release.bot",
                "display_name": "Release Bot",
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "request_rejected",
    }
    assert headers == {}
    assert boundary.calls == 0


@pytest.mark.asyncio
async def test_csrf_rejection_is_generic() -> None:
    (
        adapter,
        _,
        boundary,
        authentication,
    ) = _system(reject_csrf=True)

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/service-accounts",
        query={},
        headers=_headers(),
        body=_body(
            {
                "name": "release.bot",
                "display_name": "Release Bot",
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "request_rejected",
    }
    assert headers == {}
    assert boundary.calls == 1


@pytest.mark.asyncio
async def test_update_disable_and_stale_revision() -> None:
    (
        adapter,
        _,
        boundary,
        authentication,
    ) = _system()

    await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/service-accounts",
        query={},
        headers=_headers(),
        body=_body(
            {
                "name": "release.bot",
                "display_name": "Release Bot",
            }
        ),
        server_origin=_ORIGIN,
    )

    path = f"/v1/control-plane/service-accounts/{_ACCOUNT_ID}"

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{path}/update",
        query={},
        headers=_headers(),
        body=_body(
            {
                "expected_revision": 1,
                "display_name": ("Release Automation"),
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["revision"] == 2
    assert payload["display_name"] == ("Release Automation")

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{path}/disable",
        query={},
        headers=_headers(),
        body=_body(
            {
                "expected_revision": 1,
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CONFLICT
    assert payload == {
        "error": "service_account_conflict",
    }

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{path}/disable",
        query={},
        headers=_headers(),
        body=_body(
            {
                "expected_revision": 2,
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["status"] == "disabled"
    assert payload["revision"] == 3
    assert boundary.calls == 4


@pytest.mark.asyncio
async def test_token_list_never_discloses_secret() -> None:
    (
        adapter,
        administration,
        boundary,
        authentication,
    ) = _system()

    account = await administration.create_account(
        authentication.principal,
        name="release.bot",
        display_name="Release Bot",
    )

    grant = await administration.issue_token(
        authentication.principal,
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
        expires_at=(_NOW + timedelta(hours=1)),
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path=(f"/v1/control-plane/service-accounts/{_ACCOUNT_ID}/tokens"),
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    rendered = repr(payload)

    assert status is HTTPStatus.OK
    assert headers == {}
    assert boundary.calls == 0
    assert _TOKEN_VALUE not in rendered
    assert grant.metadata.token_digest not in rendered
    assert "token_digest" not in rendered


@pytest.mark.asyncio
async def test_step_up_rejection_is_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        adapter,
        _,
        boundary,
        authentication,
    ) = _system()

    async def rejected_dispatch_post(
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        principal: ControlPlanePrincipal,
        path: str,
        document: Mapping[str, object],
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        del (
            authentication,
            headers,
            principal,
            path,
            document,
        )

        raise ControlPlaneStepUpRejectedError("step-up authentication rejected")

    monkeypatch.setattr(
        adapter,
        "_dispatch_post",
        rejected_dispatch_post,
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/service-accounts",
        query={},
        headers=_headers(),
        body=_body(
            {
                "name": "release.bot",
                "display_name": "Release Bot",
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "request_rejected",
    }
    assert headers == {}
    assert boundary.calls == 1


def _critical_headers() -> dict[str, tuple[str, ...]]:
    headers = _headers()

    headers["x-phoenix-step-up"] = ("step-up-proof",)

    return headers


def _assert_step_up(
    action: ControlPlaneStepUpAction,
    authentication: (ControlPlaneDurableSessionAuthentication),
) -> None:
    assert _StepUp.calls == [
        (
            "step-up-proof",
            authentication,
            action,
        )
    ]


@pytest.mark.asyncio
async def test_issue_token_requires_exact_step_up_and_no_store() -> None:
    (
        adapter,
        administration,
        boundary,
        authentication,
    ) = _system()

    account = await administration.create_account(
        authentication.principal,
        name="release.bot",
        display_name="Release Bot",
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=(f"/v1/control-plane/service-accounts/{account.service_account_id}/issue-token"),
        query={},
        headers=_critical_headers(),
        body=_body(
            {
                "label": "deployment",
                "scopes": [
                    "jobs.read",
                ],
                "resources": [
                    "job:*",
                ],
                "expires_at": (_NOW + timedelta(hours=1)).isoformat(),
            }
        ),
        server_origin=_ORIGIN,
    )

    rendered = repr(payload)

    assert status is HTTPStatus.CREATED
    assert headers == {
        "Cache-Control": "no-store",
    }
    assert _TOKEN_VALUE in rendered
    assert "token_digest" not in rendered
    assert boundary.calls == 1

    _assert_step_up(
        ControlPlaneStepUpAction.ISSUE_API_TOKEN,
        authentication,
    )


@pytest.mark.asyncio
async def test_rotate_token_requires_exact_step_up_and_new_secret() -> None:
    (
        adapter,
        administration,
        boundary,
        authentication,
    ) = _system()

    account = await administration.create_account(
        authentication.principal,
        name="release.bot",
        display_name="Release Bot",
    )

    original = await administration.issue_token(
        authentication.principal,
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
        expires_at=(_NOW + timedelta(hours=1)),
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=(f"/v1/control-plane/api-tokens/{original.metadata.id}/rotate"),
        query={},
        headers=_critical_headers(),
        body=_body(
            {
                "expected_revision": (original.metadata.revision),
                "expires_at": (_NOW + timedelta(hours=2)).isoformat(),
                "overlap_seconds": 60,
            }
        ),
        server_origin=_ORIGIN,
    )

    rendered = repr(payload)

    assert status is HTTPStatus.OK
    assert headers == {
        "Cache-Control": "no-store",
    }
    assert _ROTATED_TOKEN_VALUE in rendered
    assert "token_digest" not in rendered
    assert boundary.calls == 1

    _assert_step_up(
        ControlPlaneStepUpAction.ROTATE_API_TOKEN,
        authentication,
    )


@pytest.mark.asyncio
async def test_revoke_token_requires_exact_step_up() -> None:
    (
        adapter,
        administration,
        boundary,
        authentication,
    ) = _system()

    account = await administration.create_account(
        authentication.principal,
        name="release.bot",
        display_name="Release Bot",
    )

    grant = await administration.issue_token(
        authentication.principal,
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
        expires_at=(_NOW + timedelta(hours=1)),
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=(f"/v1/control-plane/api-tokens/{grant.metadata.id}/revoke"),
        query={},
        headers=_critical_headers(),
        body=_body(
            {
                "expected_revision": (grant.metadata.revision),
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["status"] == "revoked"
    assert headers == {}
    assert boundary.calls == 1

    _assert_step_up(
        ControlPlaneStepUpAction.REVOKE_API_TOKEN,
        authentication,
    )


@pytest.mark.asyncio
async def test_enable_account_requires_exact_step_up() -> None:
    (
        adapter,
        administration,
        boundary,
        authentication,
    ) = _system()

    account = await administration.create_account(
        authentication.principal,
        name="release.bot",
        display_name="Release Bot",
    )

    disabled = await administration.disable_account(
        authentication.principal,
        account.service_account_id,
        expected_revision=account.revision,
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=(f"/v1/control-plane/service-accounts/{account.service_account_id}/enable"),
        query={},
        headers=_critical_headers(),
        body=_body(
            {
                "expected_revision": (disabled.revision),
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["status"] == "active"
    assert headers == {}
    assert boundary.calls == 1

    _assert_step_up(
        ControlPlaneStepUpAction.ENABLE_SERVICE_ACCOUNT,
        authentication,
    )


@pytest.mark.asyncio
async def test_revoke_account_requires_exact_step_up() -> None:
    (
        adapter,
        administration,
        boundary,
        authentication,
    ) = _system()

    account = await administration.create_account(
        authentication.principal,
        name="release.bot",
        display_name="Release Bot",
    )

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=(f"/v1/control-plane/service-accounts/{account.service_account_id}/revoke"),
        query={},
        headers=_critical_headers(),
        body=_body(
            {
                "expected_revision": (account.revision),
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["status"] == "revoked"
    assert headers == {}
    assert boundary.calls == 1

    _assert_step_up(
        ControlPlaneStepUpAction.REVOKE_SERVICE_ACCOUNT,
        authentication,
    )
