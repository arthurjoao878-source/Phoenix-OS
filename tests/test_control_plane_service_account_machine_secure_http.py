from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import cast

import pytest

from phoenix_os.control_plane import (
    service_account_authentication as service_account_authentication_module,
)
from phoenix_os.control_plane.auth import (
    ControlPlaneAuthenticator,
)
from phoenix_os.control_plane.contracts import (
    ControlPlaneReader,
)
from phoenix_os.control_plane.http import _Request
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentitySource,
    ControlPlaneNetworkPolicy,
)
from phoenix_os.control_plane.secure_http import (
    ControlPlaneSecureHttpServer,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
)

_PATH = "/v1/control-plane/machine/jobs"


class _MachineHttp:
    def __init__(self) -> None:
        self.calls: list[
            tuple[
                ControlPlaneServiceAccountAuthenticationContext,
                str,
                str,
                Mapping[str, tuple[str, ...]],
                Mapping[str, tuple[str, ...]],
                bytes,
            ]
        ] = []

    @staticmethod
    def handles(
        path: str,
    ) -> bool:
        return path == _PATH

    async def dispatch(
        self,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
        method: str,
        path: str,
        query: Mapping[
            str,
            tuple[str, ...],
        ],
        headers: Mapping[
            str,
            tuple[str, ...],
        ],
        body: bytes,
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        self.calls.append(
            (
                context,
                method,
                path,
                query,
                headers,
                body,
            )
        )

        return (
            HTTPStatus.OK,
            {
                "schema_version": 1,
                "machine": True,
            },
            {
                "X-Machine-Test": "accepted",
            },
        )


def _context() -> ControlPlaneServiceAccountAuthenticationContext:
    authority = service_account_authentication_module._CONTEXT_AUTHORITY

    return ControlPlaneServiceAccountAuthenticationContext(
        client_address="127.0.0.1",
        peer_address="127.0.0.1",
        identity_source=(ControlPlaneClientIdentitySource.DIRECT),
        _authority=authority,
    )


def _server(
    adapter: _MachineHttp,
) -> ControlPlaneSecureHttpServer:
    return ControlPlaneSecureHttpServer(
        cast(
            ControlPlaneReader,
            object(),
        ),
        cast(
            ControlPlaneAuthenticator,
            object(),
        ),
        network_policy=ControlPlaneNetworkPolicy(
            port=8080,
            public_origin=("http://127.0.0.1:8080"),
        ),
        service_account_machine_http=cast(
            ControlPlaneServiceAccountMachineHttpAdapter,
            adapter,
        ),
    )


def _request(
    *,
    method: str = "GET",
    path: str = _PATH,
) -> _Request:
    return _Request(
        method=method,
        path=path,
        query={
            "limit": ("10",),
        },
        headers={
            "authorization": ("Bearer phx_sa_" + "A" * 48,),
            "x-phoenix-request-nonce": ("N" * 32,),
            "x-phoenix-request-timestamp": ("2026-07-21T17:00:00+00:00",),
        },
        body=b"",
    )


def test_only_exact_registered_path_is_machine_route() -> None:
    adapter = _MachineHttp()
    server = _server(adapter)

    assert server._machine_http_handles(_PATH)

    assert not server._machine_http_handles(f"{_PATH}/extra")

    assert not server._machine_http_handles("/v1/control-plane/jobs")


def test_machine_post_does_not_require_browser_origin() -> None:
    server = _server(_MachineHttp())

    assert not server._requires_browser_origin(
        _request(
            method="POST",
        )
    )

    assert server._requires_browser_origin(
        _request(
            method="POST",
            path="/v1/control-plane/commands/jobs/create",
        )
    )

    assert not server._requires_browser_origin(
        _request(
            method="GET",
            path="/v1/control-plane/jobs",
        )
    )


@pytest.mark.asyncio
async def test_machine_route_fails_closed_without_transport_context() -> None:
    adapter = _MachineHttp()
    server = _server(adapter)

    status, payload, headers = await server._dispatch(_request())

    assert status is HTTPStatus.SERVICE_UNAVAILABLE
    assert payload == {
        "error": "machine_api_unavailable",
    }
    assert headers == {}
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_machine_route_dispatches_before_human_authentication() -> None:
    adapter = _MachineHttp()
    server = _server(adapter)

    context = _context()

    token = server._service_account_authentication_context.set(context)

    try:
        request = _request()

        status, payload, headers = await server._dispatch(request)

    finally:
        server._service_account_authentication_context.reset(token)

    assert status is HTTPStatus.OK
    assert payload == {
        "schema_version": 1,
        "machine": True,
    }
    assert headers == {
        "X-Machine-Test": "accepted",
    }

    assert len(adapter.calls) == 1

    (
        forwarded_context,
        method,
        path,
        query,
        forwarded_headers,
        body,
    ) = adapter.calls[0]

    assert forwarded_context is context
    assert method == request.method
    assert path == request.path
    assert query == request.query
    assert forwarded_headers == request.headers
    assert body == request.body
