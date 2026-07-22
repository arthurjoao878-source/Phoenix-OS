from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneAuthenticator,
    ControlPlaneBrowserOrigin,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionHttpBoundary,
    ControlPlaneHttpServer,
    ControlPlanePrincipal,
    ControlPlaneReader,
    ControlPlaneServiceAccountHttpAdapter,
)
from phoenix_os.control_plane.http import _Request
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRole,
)

_NOW = datetime(
    2026,
    7,
    21,
    16,
    tzinfo=UTC,
)

_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:9443")

_SESSION_ID = UUID("30000000-0000-0000-0000-000000000021")

_OPERATOR_ID = UUID("40000000-0000-0000-0000-000000000021")


class _ServiceAccountHttp(ControlPlaneServiceAccountHttpAdapter):
    def __init__(self) -> None:
        self.calls: list[
            tuple[
                ControlPlaneDurableSessionAuthentication,
                str,
                str,
                Mapping[str, tuple[str, ...]],
                Mapping[str, tuple[str, ...]],
                bytes,
                ControlPlaneBrowserOrigin,
            ]
        ] = []

    @staticmethod
    def handles(path: str) -> bool:
        return path.startswith("/v1/control-plane/service-accounts")

    async def dispatch(
        self,
        *,
        authentication: (ControlPlaneDurableSessionAuthentication),
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        self.calls.append(
            (
                authentication,
                method,
                path,
                query,
                headers,
                body,
                server_origin,
            )
        )

        return (
            HTTPStatus.OK,
            {
                "schema_version": 1,
                "forwarded": True,
            },
            {
                "X-Test-Adapter": "service-account",
            },
        )


def _principal() -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        "maintainer",
        ControlPlaneOperatorRole.MAINTAINER.permissions,
    )


def _authentication() -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=_principal(),
        generation=1,
        authenticated_at=_NOW,
        absolute_expires_at=(_NOW + timedelta(hours=2)),
        idle_expires_at=(_NOW + timedelta(minutes=30)),
    )


def _reader() -> ControlPlaneReader:
    return cast(
        ControlPlaneReader,
        object(),
    )


def _durable_boundary() -> ControlPlaneDurableSessionHttpBoundary:
    return cast(
        ControlPlaneDurableSessionHttpBoundary,
        object(),
    )


def _request() -> _Request:
    return _Request(
        method="GET",
        path="/v1/control-plane/service-accounts",
        query={
            "offset": ("0",),
            "limit": ("10",),
        },
        headers={
            "cookie": ("phoenix_session=value",),
            "x-test": ("preserved",),
        },
        body=b"",
    )


def test_service_account_http_requires_durable_sessions() -> None:
    adapter = _ServiceAccountHttp()

    with pytest.raises(
        ValueError,
        match=("service-account HTTP requires durable session authentication"),
    ):
        ControlPlaneHttpServer(
            _reader(),
            cast(
                ControlPlaneAuthenticator,
                object(),
            ),
            service_account_http=adapter,
        )


@pytest.mark.asyncio
async def test_authenticated_durable_session_is_forwarded() -> None:
    adapter = _ServiceAccountHttp()

    server = ControlPlaneHttpServer(
        _reader(),
        None,
        durable_session_http=_durable_boundary(),
        service_account_http=adapter,
    )

    authentication = _authentication()
    request = _request()

    status, payload, headers = await server._dispatch_authenticated(
        request,
        principal=authentication.principal,
        durable_authentication=authentication,
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload == {
        "schema_version": 1,
        "forwarded": True,
    }
    assert headers == {
        "X-Test-Adapter": "service-account",
    }

    assert len(adapter.calls) == 1

    (
        forwarded_authentication,
        method,
        path,
        query,
        forwarded_headers,
        body,
        origin,
    ) = adapter.calls[0]

    assert forwarded_authentication is authentication
    assert method == request.method
    assert path == request.path
    assert query == request.query
    assert forwarded_headers == request.headers
    assert body == request.body
    assert origin == _ORIGIN


@pytest.mark.asyncio
async def test_bearer_only_principal_is_not_forwarded() -> None:
    adapter = _ServiceAccountHttp()

    server = ControlPlaneHttpServer(
        _reader(),
        cast(
            ControlPlaneAuthenticator,
            object(),
        ),
        durable_session_http=_durable_boundary(),
        service_account_http=adapter,
    )

    status, payload, headers = await server._dispatch_authenticated(
        _request(),
        principal=_principal(),
        durable_authentication=None,
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.NOT_FOUND
    assert payload == {
        "error": "not_found",
    }
    assert headers == {}
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_non_service_account_route_is_not_forwarded() -> None:
    adapter = _ServiceAccountHttp()

    server = ControlPlaneHttpServer(
        _reader(),
        None,
        durable_session_http=_durable_boundary(),
        service_account_http=adapter,
    )

    authentication = _authentication()

    request = _Request(
        method="GET",
        path="/v1/control-plane/unknown",
        query={},
        headers={
            "cookie": ("phoenix_session=value",),
        },
        body=b"",
    )

    status, payload, headers = await server._dispatch_authenticated(
        request,
        principal=authentication.principal,
        durable_authentication=authentication,
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.NOT_FOUND
    assert payload == {
        "error": "not_found",
    }
    assert headers == {}
    assert adapter.calls == []
