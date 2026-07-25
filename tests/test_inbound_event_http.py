from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlaneHttpServer,
    ControlPlaneReader,
)
from phoenix_os.inbound_events import (
    INBOUND_CONTENT_TYPE,
    INBOUND_CORRELATION_ID_HEADER,
    INBOUND_HTTP_PREFIX,
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
    InboundHttpRoute,
    InboundServiceAccountPolicy,
    inbound_http_path,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_BODY = b'{"schema_version":1}'


def _source(
    *,
    service_account: bool = False,
    max_body_bytes: int = 262_144,
    max_header_bytes: int = 16_384,
) -> InboundEventSource:
    authentication = (
        InboundServiceAccountPolicy("inbound-source:release.events")
        if service_account
        else InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1))
    )
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=authentication,
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        max_body_bytes=max_body_bytes,
        max_header_bytes=max_header_bytes,
    )


class _Handler:
    def __init__(self) -> None:
        self.calls: list[tuple[InboundHttpRequest, object | None]] = []

    async def __call__(
        self,
        request: InboundHttpRequest,
        transport_context: object | None,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        self.calls.append((request, transport_context))
        return (
            HTTPStatus.ACCEPTED,
            {
                "schema_version": 1,
                "accepted": True,
            },
            {"X-Test": "accepted"},
        )


def _headers(*, service_account: bool = False) -> dict[str, tuple[str, ...]]:
    headers: dict[str, tuple[str, ...]] = {
        "host": ("127.0.0.1",),
        "content-type": (INBOUND_CONTENT_TYPE,),
        INBOUND_REQUEST_ID_HEADER.lower(): ("request-000000000001",),
        INBOUND_SOURCE_EVENT_ID_HEADER.lower(): ("release-000000000001",),
        INBOUND_TIMESTAMP_HEADER.lower(): ("2026-07-25T12:00:00Z",),
        INBOUND_NONCE_HEADER.lower(): ("nonce-000000000001",),
        INBOUND_CORRELATION_ID_HEADER.lower(): ("inbound-correlation",),
    }
    if service_account:
        headers["authorization"] = ("Bearer phx_example",)
    else:
        headers[INBOUND_SIGNATURE_HEADER.lower()] = ("hmac-sha256-v1=" + "0" * 64,)
        headers[INBOUND_KEY_VERSION_HEADER.lower()] = ("1",)
    return headers


@pytest.mark.asyncio
async def test_adapter_registers_only_exact_explicit_source_route() -> None:
    source = _source()
    handler = _Handler()
    adapter = InboundHttpAdapter((InboundHttpRoute(source, handler),))
    path = inbound_http_path(source)

    assert path == f"{INBOUND_HTTP_PREFIX}release.events"
    assert adapter.handles(path)
    assert not adapter.handles(f"{INBOUND_HTTP_PREFIX}other.events")
    assert adapter.body_limit(path) == source.max_body_bytes

    status, payload, headers = await adapter.dispatch(
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=_BODY,
        transport_context="network-context",
    )

    assert status is HTTPStatus.ACCEPTED
    assert payload["accepted"] is True
    assert headers["Cache-Control"] == "no-store"
    assert handler.calls[0][1] == "network-context"
    request = handler.calls[0][0]
    assert request.evidence.source_id == source.id
    assert request.evidence.request_id == "request-000000000001"
    assert request.evidence.source_event_id == "release-000000000001"
    assert request.evidence.correlation_id == "inbound-correlation"
    assert request.body == _BODY
    assert _BODY.decode() not in repr(request)
    assert "hmac-sha256-v1" not in repr(request)


@pytest.mark.asyncio
async def test_adapter_requires_post_without_query() -> None:
    source = _source()
    adapter = InboundHttpAdapter((InboundHttpRoute(source, _Handler()),))
    path = inbound_http_path(source)

    status, _, headers = await adapter.dispatch(
        method="GET",
        path=path,
        query={},
        headers=_headers(),
        body=_BODY,
        transport_context=None,
    )
    assert status is HTTPStatus.METHOD_NOT_ALLOWED
    assert headers["Allow"] == "POST"

    status, payload, _ = await adapter.dispatch(
        method="POST",
        path=path,
        query={"debug": ("1",)},
        headers=_headers(),
        body=_BODY,
        transport_context=None,
    )
    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_query"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda headers: headers.update({"content-type": ("application/json; charset=utf-8",)}),
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            lambda headers: headers.update({"content-encoding": ("gzip",)}),
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            lambda headers: headers.update({INBOUND_NONCE_HEADER.lower(): ("one", "two")}),
            HTTPStatus.BAD_REQUEST,
        ),
        (
            lambda headers: headers.update({"cookie": ("session=browser",)}),
            HTTPStatus.FORBIDDEN,
        ),
        (
            lambda headers: headers.update({"x-phoenix-inbound-unknown": ("ambiguous",)}),
            HTTPStatus.BAD_REQUEST,
        ),
    ],
)
async def test_adapter_rejects_ambiguous_media_and_security_headers(
    mutate: Callable[[dict[str, tuple[str, ...]]], None],
    expected: HTTPStatus,
) -> None:
    source = _source()
    adapter = InboundHttpAdapter((InboundHttpRoute(source, _Handler()),))
    headers = _headers()
    mutate(headers)

    status, _, response_headers = await adapter.dispatch(
        method="POST",
        path=inbound_http_path(source),
        query={},
        headers=headers,
        body=_BODY,
        transport_context=None,
    )

    assert status is expected
    assert response_headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_adapter_enforces_mutually_exclusive_authentication_modes() -> None:
    hmac_source = _source()
    service_source = _source(service_account=True)
    hmac_adapter = InboundHttpAdapter((InboundHttpRoute(hmac_source, _Handler()),))
    service_adapter = InboundHttpAdapter((InboundHttpRoute(service_source, _Handler()),))

    mixed_hmac = _headers()
    mixed_hmac["authorization"] = ("Bearer phx_example",)
    status, _, _ = await hmac_adapter.dispatch(
        method="POST",
        path=inbound_http_path(hmac_source),
        query={},
        headers=mixed_hmac,
        body=_BODY,
        transport_context=None,
    )
    assert status is HTTPStatus.BAD_REQUEST

    mixed_service = _headers(service_account=True)
    mixed_service[INBOUND_SIGNATURE_HEADER.lower()] = ("hmac-sha256-v1=" + "0" * 64,)
    status, _, _ = await service_adapter.dispatch(
        method="POST",
        path=inbound_http_path(service_source),
        query={},
        headers=mixed_service,
        body=_BODY,
        transport_context=None,
    )
    assert status is HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_adapter_enforces_source_body_and_header_limits() -> None:
    body_source = _source(max_body_bytes=8)
    body_adapter = InboundHttpAdapter((InboundHttpRoute(body_source, _Handler()),))
    status, _, _ = await body_adapter.dispatch(
        method="POST",
        path=inbound_http_path(body_source),
        query={},
        headers=_headers(),
        body=b"123456789",
        transport_context=None,
    )
    assert status is HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    header_source = _source(max_header_bytes=32)
    header_adapter = InboundHttpAdapter((InboundHttpRoute(header_source, _Handler()),))
    status, _, _ = await header_adapter.dispatch(
        method="POST",
        path=inbound_http_path(header_source),
        query={},
        headers=_headers(),
        body=b"{}",
        transport_context=None,
    )
    assert status is HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE


async def _raw_request(
    server: ControlPlaneHttpServer,
    request: bytes,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    import asyncio

    assert server.port is not None
    reader, writer = await asyncio.open_connection(server.host, server.port)
    writer.write(request)
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


def _wire_request(path: str, body: bytes = _BODY) -> bytes:
    headers = _headers()
    lines = [
        f"POST {path} HTTP/1.1",
        "Host: 127.0.0.1",
        f"Content-Type: {INBOUND_CONTENT_TYPE}",
        f"Content-Length: {len(body)}",
        f"{INBOUND_REQUEST_ID_HEADER}: {headers[INBOUND_REQUEST_ID_HEADER.lower()][0]}",
        (f"{INBOUND_SOURCE_EVENT_ID_HEADER}: {headers[INBOUND_SOURCE_EVENT_ID_HEADER.lower()][0]}"),
        f"{INBOUND_TIMESTAMP_HEADER}: {headers[INBOUND_TIMESTAMP_HEADER.lower()][0]}",
        f"{INBOUND_NONCE_HEADER}: {headers[INBOUND_NONCE_HEADER.lower()][0]}",
        f"{INBOUND_SIGNATURE_HEADER}: {headers[INBOUND_SIGNATURE_HEADER.lower()][0]}",
        f"{INBOUND_KEY_VERSION_HEADER}: {headers[INBOUND_KEY_VERSION_HEADER.lower()][0]}",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


@pytest.mark.asyncio
async def test_control_plane_server_exposes_only_composed_inbound_routes() -> None:
    source = _source()
    handler = _Handler()
    adapter = InboundHttpAdapter((InboundHttpRoute(source, handler),))
    server = ControlPlaneHttpServer(
        cast(ControlPlaneReader, object()),  # route returns before reader use
        AdminTokenAuthenticator("control-plane-test-token-00000001"),
        inbound_http=adapter,
    )
    await server.start()
    try:
        status, headers, payload = await _raw_request(
            server,
            _wire_request(inbound_http_path(source)),
        )
        assert status == HTTPStatus.ACCEPTED
        assert payload["accepted"] is True
        assert headers["cache-control"] == "no-store"
        assert len(handler.calls) == 1

        unknown_status, _, _ = await _raw_request(
            server,
            _wire_request(f"{INBOUND_HTTP_PREFIX}other.events"),
        )
        assert unknown_status == HTTPStatus.UNAUTHORIZED
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_control_plane_parser_uses_source_specific_body_limit() -> None:
    source = _source(max_body_bytes=8)
    adapter = InboundHttpAdapter((InboundHttpRoute(source, _Handler()),))
    server = ControlPlaneHttpServer(
        cast(ControlPlaneReader, object()),
        AdminTokenAuthenticator("control-plane-test-token-00000001"),
        inbound_http=adapter,
    )
    await server.start()
    try:
        status, _, payload = await _raw_request(
            server,
            _wire_request(inbound_http_path(source), b"123456789"),
        )
        assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        assert payload == {"error": "request_body_too_large"}
    finally:
        await server.stop()
