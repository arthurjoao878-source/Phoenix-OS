from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from tests_support.tls_test_material import write_test_tls_material

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlaneNetworkPolicy,
    ControlPlaneProxyHeaderPolicy,
    ControlPlanePublicOrigin,
    ControlPlaneReader,
    ControlPlaneSecureHttpServer,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
)
from phoenix_os.inbound_events import (
    INBOUND_CONTENT_TYPE,
    INBOUND_KEY_VERSION_HEADER,
    INBOUND_NONCE_HEADER,
    INBOUND_REQUEST_ID_HEADER,
    INBOUND_SIGNATURE_HEADER,
    INBOUND_SOURCE_EVENT_ID_HEADER,
    INBOUND_TIMESTAMP_HEADER,
    InboundEventSource,
    InboundHmacPolicy,
    InboundHttpAdapter,
    InboundHttpRequest,
    InboundHttpResponse,
    InboundHttpRoute,
    inbound_http_path,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_BODY = b'{"schema_version":1}'


class _Handler:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(
        self,
        request: InboundHttpRequest,
        transport_context: object | None,
    ) -> InboundHttpResponse:
        del request, transport_context
        self.calls += 1
        return HTTPStatus.ACCEPTED, {"accepted": True}, {}


def _source() -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _adapter(handler: _Handler | None = None) -> InboundHttpAdapter:
    source = _source()
    return InboundHttpAdapter((InboundHttpRoute(source, handler or _Handler()),))


def _policy(
    port: int,
    *,
    allowed: tuple[str, ...] = ("127.0.0.0/8",),
    proxy: ControlPlaneProxyHeaderPolicy = ControlPlaneProxyHeaderPolicy.DISABLED,
    trusted: tuple[str, ...] = (),
    tls: ControlPlaneTlsPolicy | None = None,
) -> ControlPlaneNetworkPolicy:
    tls_policy = tls or ControlPlaneTlsPolicy()
    scheme = "https" if tls_policy.enabled else "http"
    return ControlPlaneNetworkPolicy(
        bind_host="127.0.0.1",
        port=port,
        public_origin=ControlPlanePublicOrigin(f"{scheme}://127.0.0.1:{port}"),
        tls=tls_policy,
        allowed_client_networks=allowed,
        trusted_proxy_networks=trusted,
        proxy_headers=proxy,
        secure_cookies=tls_policy.enabled,
    )


def _wire(
    port: int,
    *,
    host: str | None = None,
    extra: tuple[str, ...] = (),
    transfer_encoding: bool = False,
    duplicate_length: bool = False,
) -> bytes:
    source = _source()
    lines = [
        f"POST {inbound_http_path(source)} HTTP/1.1",
        f"Host: {host or f'127.0.0.1:{port}'}",
        f"Content-Type: {INBOUND_CONTENT_TYPE}",
        f"Content-Length: {len(_BODY)}",
        f"{INBOUND_REQUEST_ID_HEADER}: request-000000000001",
        f"{INBOUND_SOURCE_EVENT_ID_HEADER}: release-000000000001",
        f"{INBOUND_TIMESTAMP_HEADER}: 2026-07-25T12:00:00Z",
        f"{INBOUND_NONCE_HEADER}: nonce-000000000001",
        f"{INBOUND_SIGNATURE_HEADER}: hmac-sha256-v1={'0' * 64}",
        f"{INBOUND_KEY_VERSION_HEADER}: 1",
    ]
    if duplicate_length:
        lines.append(f"Content-Length: {len(_BODY)}")
    if transfer_encoding:
        lines.append("Transfer-Encoding: chunked")
    lines.extend(extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + _BODY


async def _request(
    server: ControlPlaneSecureHttpServer,
    payload: bytes,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    reader, writer = await asyncio.open_connection(
        server.host,
        cast(int, server.port),
        ssl=ssl_context,
        server_hostname=None,
    )
    writer.write(payload)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {
        name.lower(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])
    }
    return status, headers, json.loads(body)


def _server(
    policy: ControlPlaneNetworkPolicy,
    adapter: InboundHttpAdapter,
) -> ControlPlaneSecureHttpServer:
    return ControlPlaneSecureHttpServer(
        cast(ControlPlaneReader, object()),
        AdminTokenAuthenticator("control-plane-test-token-00000001"),
        network_policy=policy,
        inbound_http=adapter,
    )


@pytest.mark.asyncio
async def test_inbound_route_inherits_host_and_proxy_rejection() -> None:
    port = _free_port()
    handler = _Handler()
    server = _server(_policy(port), _adapter(handler))
    await server.start()
    try:
        wrong_host, _, wrong_payload = await _request(
            server,
            _wire(port, host="attacker.invalid"),
        )
        proxy_status, _, proxy_payload = await _request(
            server,
            _wire(port, extra=("X-Forwarded-For: 203.0.113.1",)),
        )
    finally:
        await server.stop()

    assert wrong_host == HTTPStatus.FORBIDDEN
    assert wrong_payload == {"error": "request_rejected"}
    assert proxy_status == HTTPStatus.FORBIDDEN
    assert proxy_payload == {"error": "request_rejected"}
    assert handler.calls == 0


@pytest.mark.asyncio
async def test_inbound_route_inherits_cidr_rejection() -> None:
    port = _free_port()
    handler = _Handler()
    server = _server(
        _policy(port, allowed=("127.0.0.2/32",)),
        _adapter(handler),
    )
    await server.start()
    try:
        status, _, payload = await _request(server, _wire(port))
    finally:
        await server.stop()

    assert status == HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert handler.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload_factory",
    [
        lambda port: _wire(port, transfer_encoding=True),
        lambda port: _wire(port, duplicate_length=True),
    ],
)
async def test_inbound_route_rejects_request_smuggling_before_dispatch(
    payload_factory: Callable[[int], bytes],
) -> None:
    port = _free_port()
    handler = _Handler()
    server = _server(_policy(port), _adapter(handler))
    await server.start()
    try:
        status, _, payload = await _request(
            server,
            payload_factory(port),
        )
    finally:
        await server.stop()

    assert status == HTTPStatus.BAD_REQUEST
    assert payload["error"] in {
        "request_body_not_supported",
        "invalid_content_length",
    }
    assert handler.calls == 0


@pytest.mark.asyncio
async def test_inbound_route_uses_existing_native_tls_listener(
    tmp_path: Path,
) -> None:
    certificate, private_key, _, _, _ = write_test_tls_material(tmp_path)
    if os.name != "nt":
        private_key.chmod(0o600)
    tls = ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.SERVER,
        certificate_file=str(certificate.resolve()),
        private_key_file=str(private_key.resolve()),
    )
    port = _free_port()
    handler = _Handler()
    server = _server(_policy(port, tls=tls), _adapter(handler))
    await server.start()
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    try:
        status, headers, payload = await _request(
            server,
            _wire(port),
            ssl_context=client,
        )
    finally:
        await server.stop()

    assert status == HTTPStatus.ACCEPTED
    assert payload == {"accepted": True}
    assert headers["cache-control"] == "no-store"
    assert handler.calls == 1
