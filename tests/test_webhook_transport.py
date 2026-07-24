from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    WEBHOOK_ATTEMPT_HEADER,
    WEBHOOK_CONTENT_TYPE,
    WEBHOOK_CONTENT_TYPE_HEADER,
    WEBHOOK_ID_HEADER,
    WEBHOOK_KEY_VERSION_HEADER,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_TIMESTAMP_HEADER,
    WEBHOOK_USER_AGENT,
    WEBHOOK_USER_AGENT_HEADER,
    WebhookConnection,
    WebhookEgressPolicy,
    WebhookEndpoint,
    WebhookEndpointRejectedError,
    WebhookHttpStatusClass,
    WebhookSignatureScheme,
    WebhookSignedRequest,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookTransport,
    WebhookTransportConfig,
    WebhookTransportError,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000024")
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000025")
_PUBLIC_ADDRESS = "93.184.216.34"


class _FakeConnection:
    def __init__(self, response: bytes, *, read_limit: int) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
        self._reader.feed_data(response)
        self._reader.feed_eof()
        self.written = bytearray()
        self.closed = False

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


class _FakeResolver:
    def __init__(self, *results: tuple[str, ...]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        if not self._results:
            raise AssertionError("fake resolver has no result")
        await asyncio.sleep(0)
        return self._results.pop(0)


class _BlockingResolver:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del host, port
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("blocking resolver unexpectedly resumed")


class _FakeConnector:
    def __init__(self, *responses: bytes) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, int, bool, str | None, float, int]] = []
        self.connections: list[_FakeConnection] = []

    async def connect(
        self,
        address: str,
        port: int,
        *,
        tls: bool,
        server_hostname: str | None,
        connect_timeout: float,
        read_limit: int,
    ) -> WebhookConnection:
        self.calls.append((address, port, tls, server_hostname, connect_timeout, read_limit))
        if not self._responses:
            raise AssertionError("fake connector has no response")
        await asyncio.sleep(0)
        connection = _FakeConnection(self._responses.pop(0), read_limit=read_limit)
        self.connections.append(connection)
        return connection


class _ExplodingConnector:
    async def connect(
        self,
        address: str,
        port: int,
        *,
        tls: bool,
        server_hostname: str | None,
        connect_timeout: float,
        read_limit: int,
    ) -> WebhookConnection:
        del address, port, tls, server_hostname, connect_timeout, read_limit
        await asyncio.sleep(0)
        raise RuntimeError("private 10.0.0.9 token=must-not-leak")


def _subscription(
    endpoint: WebhookEndpoint | None = None,
    *,
    policy_name: str = "production.webhooks",
) -> WebhookSubscription:
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="transport-test",
        display_name="Transport Test",
        event_types=frozenset({"jobs.completed"}),
        endpoint=endpoint or WebhookEndpoint("https://hooks.example.com/phoenix"),
        signing=WebhookSigningPolicy(SecretRef("webhook-key", "integrations", 1)),
        egress_policy=policy_name,
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
    )


def _request(*, body: bytes = b'{"job_id":"job-1"}') -> WebhookSignedRequest:
    return WebhookSignedRequest(
        delivery_id=_DELIVERY_ID,
        subscription_id=_SUBSCRIPTION_ID,
        attempt=1,
        timestamp=_NOW,
        key_version=1,
        scheme=WebhookSignatureScheme.HMAC_SHA256_V1,
        body=body,
        headers={
            WEBHOOK_CONTENT_TYPE_HEADER: WEBHOOK_CONTENT_TYPE,
            WEBHOOK_USER_AGENT_HEADER: WEBHOOK_USER_AGENT,
            WEBHOOK_ID_HEADER: str(_DELIVERY_ID),
            WEBHOOK_TIMESTAMP_HEADER: "2026-07-24T12:00:00Z",
            WEBHOOK_SIGNATURE_HEADER: "hmac-sha256-v1=" + "0" * 64,
            WEBHOOK_KEY_VERSION_HEADER: "1",
            WEBHOOK_ATTEMPT_HEADER: "1",
        },
    )


def _policy(**changes: object) -> WebhookEgressPolicy:
    values: dict[str, object] = {"name": "production.webhooks"}
    values.update(changes)
    return WebhookEgressPolicy(**cast(Any, values))


def _response(
    status: int,
    reason: str,
    *,
    headers: tuple[tuple[str, str], ...] = (("Content-Length", "0"),),
    body: bytes = b"",
) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}".encode("ascii")]
    lines.extend(f"{name}: {value}".encode("ascii") for name, value in headers)
    return b"\r\n".join((*lines, b"", body))


@pytest.mark.asyncio
async def test_transport_pins_dns_address_and_builds_exact_request() -> None:
    resolver = _FakeResolver((_PUBLIC_ADDRESS,))
    connector = _FakeConnector(_response(204, "No Content"))
    transport = WebhookTransport(resolver=resolver, connector=connector)
    subscription = _subscription()
    request = _request()

    result = await transport.send(request, subscription, policy=_policy())

    assert result.successful is True
    assert result.status_code == 204
    assert result.status_class is WebhookHttpStatusClass.SUCCESSFUL
    assert connector.calls[0][:4] == (
        _PUBLIC_ADDRESS,
        443,
        True,
        "hooks.example.com",
    )
    written = bytes(connector.connections[0].written)
    assert written.startswith(b"POST /phoenix HTTP/1.1\r\n")
    assert b"Host: hooks.example.com\r\n" in written
    assert f"Content-Length: {len(request.body)}\r\n".encode("ascii") in written
    assert b"Accept-Encoding: identity\r\n" in written
    assert b"Connection: close\r\n" in written
    assert written.endswith(request.body)
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_transport_re_resolves_and_fails_closed_on_dns_rebinding() -> None:
    resolver = _FakeResolver(
        (_PUBLIC_ADDRESS,),
        (_PUBLIC_ADDRESS, "127.0.0.1"),
    )
    connector = _FakeConnector(_response(200, "OK"))
    transport = WebhookTransport(resolver=resolver, connector=connector)
    subscription = _subscription()

    assert (await transport.send(_request(), subscription, policy=_policy())).successful
    with pytest.raises(WebhookEndpointRejectedError) as raised:
        await transport.send(_request(), subscription, policy=_policy())

    assert raised.value.category == "destination_not_allowed"
    assert len(resolver.calls) == 2
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_transport_allows_explicit_private_https_network() -> None:
    resolver = _FakeResolver(("10.20.30.40",))
    connector = _FakeConnector(_response(200, "OK"))
    transport = WebhookTransport(resolver=resolver, connector=connector)
    policy = _policy(
        allowed_networks=("10.0.0.0/8",),
        allow_public_networks=False,
    )

    result = await transport.send(_request(), _subscription(), policy=policy)

    assert result.successful
    assert connector.calls[0][0] == "10.20.30.40"
    assert connector.calls[0][2] is True


@pytest.mark.asyncio
async def test_transport_allows_only_explicit_http_loopback_development() -> None:
    endpoint = WebhookEndpoint(
        "http://127.0.0.1/hooks",
        allow_insecure_loopback=True,
    )
    connector = _FakeConnector(_response(200, "OK"))
    resolver = _FakeResolver()
    transport = WebhookTransport(resolver=resolver, connector=connector)
    policy = _policy(
        allowed_ports=frozenset({80}),
        allow_public_networks=False,
        allow_insecure_loopback=True,
    )

    result = await transport.send(
        _request(),
        _subscription(endpoint),
        policy=policy,
    )

    assert result.successful
    assert resolver.calls == []
    assert connector.calls[0][:4] == ("127.0.0.1", 80, False, None)


@pytest.mark.asyncio
async def test_transport_rejects_policy_mismatch_and_disallowed_port() -> None:
    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,)),
        connector=_FakeConnector(_response(200, "OK")),
    )
    with pytest.raises(WebhookEndpointRejectedError) as mismatch:
        await transport.send(
            _request(),
            _subscription(),
            policy=WebhookEgressPolicy("other.webhooks"),
        )
    assert mismatch.value.category == "policy_mismatch"

    with pytest.raises(WebhookEndpointRejectedError) as port:
        await transport.send(
            _request(),
            _subscription(),
            policy=_policy(allowed_ports=frozenset({8443})),
        )
    assert port.value.category == "port_not_allowed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "reason", "successful", "retryable", "category"),
    [
        (302, "Found", False, False, "http_redirect"),
        (400, "Bad Request", False, False, "http_client_error"),
        (408, "Request Timeout", False, True, "http_client_retryable"),
        (429, "Too Many Requests", False, True, "http_client_retryable"),
        (503, "Unavailable", False, True, "http_server_error"),
    ],
)
async def test_transport_classifies_http_without_following_redirects(
    status: int,
    reason: str,
    successful: bool,
    retryable: bool,
    category: str,
) -> None:
    connector = _FakeConnector(
        _response(
            status,
            reason,
            headers=(("Content-Length", "0"), ("Location", "https://other.example/")),
        )
    )
    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,)),
        connector=connector,
    )

    result = await transport.send(_request(), _subscription(), policy=_policy())

    assert result.successful is successful
    assert result.retryable is retryable
    assert result.error_category == category
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_transport_rejects_oversized_response_headers() -> None:
    connector = _FakeConnector(
        _response(
            200,
            "OK",
            headers=(("X-Large", "x" * 80), ("Content-Length", "0")),
        )
    )
    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,)),
        connector=connector,
        config=WebhookTransportConfig(max_response_header_bytes=64),
    )

    with pytest.raises(WebhookTransportError) as raised:
        await transport.send(_request(), _subscription(), policy=_policy())

    assert raised.value.category == "response_headers_too_large"
    assert raised.value.retryable is False


@pytest.mark.asyncio
async def test_transport_rejects_oversized_content_length_and_chunked_body() -> None:
    responses = (
        _response(200, "OK", headers=(("Content-Length", "5"),), body=b"12345"),
        _response(
            200,
            "OK",
            headers=(("Transfer-Encoding", "chunked"),),
            body=b"5\r\n12345\r\n0\r\n\r\n",
        ),
    )
    connector = _FakeConnector(*responses)
    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,), (_PUBLIC_ADDRESS,)),
        connector=connector,
        config=WebhookTransportConfig(max_response_body_bytes=4),
    )

    for _ in responses:
        with pytest.raises(WebhookTransportError) as raised:
            await transport.send(_request(), _subscription(), policy=_policy())
        assert raised.value.category == "response_body_too_large"
        assert raised.value.retryable is False


@pytest.mark.asyncio
async def test_transport_rejects_ambiguous_or_malformed_response_framing() -> None:
    connector = _FakeConnector(
        _response(
            200,
            "OK",
            headers=(("Content-Length", "0"), ("Transfer-Encoding", "chunked")),
        ),
        b"NOT-HTTP\r\n\r\n",
    )
    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,), (_PUBLIC_ADDRESS,)),
        connector=connector,
    )

    with pytest.raises(WebhookTransportError) as ambiguous:
        await transport.send(_request(), _subscription(), policy=_policy())
    assert ambiguous.value.category == "ambiguous_response_framing"

    with pytest.raises(WebhookTransportError) as malformed:
        await transport.send(_request(), _subscription(), policy=_policy())
    assert malformed.value.category == "invalid_response"


@pytest.mark.asyncio
async def test_transport_timeout_is_safe_and_retryable() -> None:
    transport = WebhookTransport(
        resolver=_BlockingResolver(),
        connector=_FakeConnector(),
        config=WebhookTransportConfig(connect_timeout=0.01, total_timeout=0.01),
    )

    with pytest.raises(WebhookTransportError) as raised:
        await transport.send(_request(), _subscription(), policy=_policy())

    assert raised.value.category == "timeout"
    assert raised.value.retryable is True


@pytest.mark.asyncio
async def test_transport_preserves_cancellation() -> None:
    resolver = _BlockingResolver()
    transport = WebhookTransport(resolver=resolver, connector=_FakeConnector())
    task = asyncio.create_task(transport.send(_request(), _subscription(), policy=_policy()))
    await resolver.started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_transport_wraps_internal_failures_without_leaking_details() -> None:
    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,)),
        connector=_ExplodingConnector(),
    )

    with pytest.raises(WebhookTransportError) as raised:
        await transport.send(_request(), _subscription(), policy=_policy())

    rendered = f"{raised.value!r} {raised.value}"
    assert raised.value.category == "transport_failed"
    assert "must-not-leak" not in rendered
    assert "10.0.0.9" not in rendered


@pytest.mark.asyncio
async def test_transport_rejects_invalid_request_target_and_closed_work() -> None:
    with pytest.raises(ValueError, match="whitespace"):
        WebhookEndpoint("https://hooks.example.com/bad path")

    transport = WebhookTransport(
        resolver=_FakeResolver((_PUBLIC_ADDRESS,)),
        connector=_FakeConnector(_response(200, "OK")),
    )
    transport.close()
    transport.close()

    with pytest.raises(WebhookTransportError) as raised:
        await transport.send(_request(), _subscription(), policy=_policy())
    assert raised.value.category == "transport_closed"
    assert raised.value.retryable is False
