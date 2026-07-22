from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    service_account_authentication as service_account_authentication_module,
)
from phoenix_os.control_plane.network_contracts import ControlPlaneClientIdentitySource
from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
    ControlPlaneServiceAccountMachineRequest,
    ControlPlaneServiceAccountMachineRoute,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
    current_control_plane_service_account_api_context,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
)

_NOW = datetime(
    2026,
    7,
    21,
    17,
    tzinfo=UTC,
)

_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000051")

_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000051")

_PATH = "/v1/control-plane/machine/jobs"


class _Authentication:
    def __init__(
        self,
        result: (ControlPlaneServiceAccountAuthentication | None),
    ) -> None:
        self.result = result
        self.calls: list[
            tuple[
                str | None,
                ControlPlaneServiceAccountAuthenticationContext,
                ControlPlaneServiceAccountReplayRequest,
            ]
        ] = []

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        self.calls.append(
            (
                authorization,
                context,
                request,
            )
        )

        return self.result


class _Policy:
    def __init__(
        self,
        *,
        denied: bool = False,
    ) -> None:
        self.denied = denied
        self.calls: list[
            tuple[
                ControlPlaneServiceAccountApiContext,
                str,
                str,
            ]
        ] = []

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object:
        self.calls.append(
            (
                context,
                action,
                resource,
            )
        )

        if self.denied:
            raise (
                ControlPlaneServiceAccountPermissionDeniedError(
                    "service-account authorization denied"
                )
            )

        return object()


class _Handler:
    def __init__(self) -> None:
        self.calls: list[
            tuple[
                ControlPlaneServiceAccountApiContext,
                ControlPlaneServiceAccountMachineRequest,
            ]
        ] = []

    async def __call__(
        self,
        context: ControlPlaneServiceAccountApiContext,
        request: ControlPlaneServiceAccountMachineRequest,
    ) -> tuple[
        HTTPStatus,
        dict[str, object],
        dict[str, str],
    ]:
        assert current_control_plane_service_account_api_context() is context

        self.calls.append(
            (
                context,
                request,
            )
        )

        return (
            HTTPStatus.OK,
            {
                "schema_version": 1,
                "accepted": True,
            },
            {},
        )


def _evidence() -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="release.bot",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        resources=frozenset(
            {
                "jobs",
            }
        ),
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=(_NOW + timedelta(hours=1)),
    )


def _context() -> ControlPlaneServiceAccountAuthenticationContext:
    authority = service_account_authentication_module._CONTEXT_AUTHORITY

    return ControlPlaneServiceAccountAuthenticationContext(
        client_address="127.0.0.1",
        peer_address="127.0.0.1",
        identity_source=(ControlPlaneClientIdentitySource.DIRECT),
        _authority=authority,
    )


def _headers() -> dict[str, tuple[str, ...]]:
    return {
        "authorization": ("Bearer phx_sa_" + "A" * 48,),
        "x-phoenix-request-nonce": ("N" * 32,),
        "x-phoenix-request-timestamp": (_NOW.isoformat(),),
        "content-type": ("application/json",),
    }


def _system(
    *,
    evidence: (ControlPlaneServiceAccountAuthentication | None) = None,
    policy_denied: bool = False,
) -> tuple[
    ControlPlaneServiceAccountMachineHttpAdapter,
    _Authentication,
    _Policy,
    ControlPlaneServiceAccountAudit,
    _Handler,
]:
    authentication = _Authentication(_evidence() if evidence is None else evidence)

    policy = _Policy(
        denied=policy_denied,
    )

    audit = ControlPlaneServiceAccountAudit(
        None,
        ControlPlaneServiceAccountAuditProtector(b"a" * 32),
    )

    handler = _Handler()

    adapter = ControlPlaneServiceAccountMachineHttpAdapter(
        authentication=authentication,
        policy=policy,
        audit=audit,
        routes=(
            ControlPlaneServiceAccountMachineRoute(
                method="GET",
                path=_PATH,
                action="jobs.read",
                resource="jobs",
                handler=handler,
            ),
        ),
    )

    return (
        adapter,
        authentication,
        policy,
        audit,
        handler,
    )


def test_exact_route_allowlist() -> None:
    adapter, _, _, _, _ = _system()

    assert adapter.handles(_PATH)
    assert not adapter.handles("/v1/control-plane/machine")
    assert not adapter.handles(f"{_PATH}/anything")
    assert not adapter.handles("/v1/control-plane/jobs")
    assert adapter.allowed_methods(_PATH) == ("GET",)


def test_duplicate_route_is_rejected() -> None:
    handler = _Handler()
    route = ControlPlaneServiceAccountMachineRoute(
        method="GET",
        path=_PATH,
        action="jobs.read",
        resource="jobs",
        handler=handler,
    )

    authentication = _Authentication(_evidence())

    policy = _Policy()

    audit = ControlPlaneServiceAccountAudit(
        None,
        ControlPlaneServiceAccountAuditProtector(b"a" * 32),
    )

    with pytest.raises(
        ValueError,
        match="duplicate machine HTTP route",
    ):
        ControlPlaneServiceAccountMachineHttpAdapter(
            authentication=authentication,
            policy=policy,
            audit=audit,
            routes=(
                route,
                route,
            ),
        )


@pytest.mark.asyncio
async def test_wrong_method_reports_exact_allowlist() -> None:
    adapter, authentication, _, _, handler = _system()

    status, payload, headers = await adapter.dispatch(
        context=_context(),
        method="POST",
        path=_PATH,
        query={},
        headers=_headers(),
        body=b"",
    )

    assert status is HTTPStatus.METHOD_NOT_ALLOWED
    assert payload == {
        "error": "method_not_allowed",
    }
    assert headers == {
        "Allow": "GET",
    }
    assert authentication.calls == []
    assert handler.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "browser_header",
    [
        "cookie",
        "x-phoenix-csrf",
        "x-phoenix-step-up",
    ],
)
async def test_browser_credentials_are_rejected(
    browser_header: str,
) -> None:
    adapter, authentication, _, _, handler = _system()

    headers = _headers()
    headers[browser_header] = ("browser-value",)

    status, payload, response_headers = await adapter.dispatch(
        context=_context(),
        method="GET",
        path=_PATH,
        query={},
        headers=headers,
        body=b"",
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "request_rejected",
    }
    assert response_headers == {}
    assert authentication.calls == []
    assert handler.calls == []


@pytest.mark.asyncio
async def test_missing_machine_headers_is_generic() -> None:
    adapter, authentication, _, audit, handler = _system()

    status, payload, headers = await adapter.dispatch(
        context=_context(),
        method="GET",
        path=_PATH,
        query={},
        headers={},
        body=b"",
    )

    assert status is HTTPStatus.UNAUTHORIZED
    assert payload == {
        "error": "unauthorized",
    }
    assert headers == {
        "WWW-Authenticate": ('Bearer realm="phoenix-service-account"'),
    }
    assert authentication.calls == []
    assert handler.calls == []

    snapshot = await audit.snapshot()

    assert snapshot.dropped == 1


@pytest.mark.asyncio
async def test_authenticated_request_is_canonical_and_sanitized() -> None:
    adapter, authentication, policy, audit, handler = _system()

    body = b'{"operation":"list"}'

    status, payload, headers = await adapter.dispatch(
        context=_context(),
        method="GET",
        path=_PATH,
        query={
            "tag": (
                "b",
                "a",
            ),
            "limit": ("10",),
        },
        headers=_headers(),
        body=body,
    )

    assert status is HTTPStatus.OK
    assert payload == {
        "schema_version": 1,
        "accepted": True,
    }
    assert headers == {}

    assert len(authentication.calls) == 1

    (
        authorization,
        _,
        replay,
    ) = authentication.calls[0]

    assert authorization == ("Bearer phx_sa_" + "A" * 48)
    assert replay.method == "GET"
    assert replay.target == (f"{_PATH}?limit=10&tag=a&tag=b")
    assert replay.body_digest == hashlib.sha256(body).hexdigest()

    assert len(policy.calls) == 1
    assert policy.calls[0][1:] == (
        "jobs.read",
        "jobs",
    )

    assert len(handler.calls) == 1

    _, request = handler.calls[0]

    assert request.body == body
    assert request.headers == {
        "content-type": ("application/json",),
    }

    assert "authorization" not in request.headers
    assert "x-phoenix-request-nonce" not in request.headers
    assert "x-phoenix-request-timestamp" not in request.headers

    snapshot = await audit.snapshot()

    assert snapshot.dropped == 2


@pytest.mark.asyncio
async def test_exact_scope_denial_never_calls_policy_or_handler() -> None:
    denied_evidence = replace(
        _evidence(),
        scopes=frozenset(
            {
                "jobs.write",
            }
        ),
    )

    (
        adapter,
        authentication,
        policy,
        _,
        handler,
    ) = _system(
        evidence=denied_evidence,
    )

    status, payload, headers = await adapter.dispatch(
        context=_context(),
        method="GET",
        path=_PATH,
        query={},
        headers=_headers(),
        body=b"",
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "forbidden",
    }
    assert headers == {}
    assert len(authentication.calls) == 1
    assert policy.calls == []
    assert handler.calls == []


@pytest.mark.asyncio
async def test_policy_denial_never_calls_handler() -> None:
    (
        adapter,
        authentication,
        policy,
        _,
        handler,
    ) = _system(
        policy_denied=True,
    )

    status, payload, headers = await adapter.dispatch(
        context=_context(),
        method="GET",
        path=_PATH,
        query={},
        headers=_headers(),
        body=b"",
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {
        "error": "forbidden",
    }
    assert headers == {}
    assert len(authentication.calls) == 1
    assert len(policy.calls) == 1
    assert handler.calls == []
