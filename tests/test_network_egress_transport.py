from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest

from phoenix_os.network_egress._admission import admit_network_destination
from phoenix_os.network_egress._errors import (
    NetworkDestinationRejectedError,
    NetworkTransportError,
)
from phoenix_os.network_egress._transport import (
    NetworkConnection,
    NetworkTransport,
)
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
    NetworkHttpRequest,
)
from phoenix_os.network_egress.profiles import (
    NetworkCredentialBinding,
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)
from phoenix_os.secrets import SecretRef


class _FakeConnection:
    def __init__(
        self,
        response: bytes,
        *,
        read_limit: int,
        drain_error: OSError | None = None,
    ) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
        self._reader.feed_data(response)
        self._reader.feed_eof()
        self._drain_error = drain_error
        self.written = bytearray()
        self.closed = False

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)
        if self._drain_error is not None:
            raise self._drain_error

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


class _FakeConnector:
    def __init__(
        self,
        responses: tuple[bytes, ...],
        *,
        failures: tuple[BaseException | None, ...] = (),
        drain_error: OSError | None = None,
    ) -> None:
        self._responses = list(responses)
        self._failures = list(failures)
        self._drain_error = drain_error
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
    ) -> NetworkConnection:
        self.calls.append((address, port, tls, server_hostname, connect_timeout, read_limit))
        await asyncio.sleep(0)
        if self._failures:
            failure = self._failures.pop(0)
            if failure is not None:
                raise failure
        if not self._responses:
            raise AssertionError("fake connector has no response")
        connection = _FakeConnection(
            self._responses.pop(0),
            read_limit=read_limit,
            drain_error=self._drain_error,
        )
        self.connections.append(connection)
        return connection


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


def _operation(**changes: object) -> NetworkEgressOperation:
    values: dict[str, object] = {
        "operation_id": NetworkEgressOperationId("read"),
        "method": NetworkHttpMethod.GET,
        "request_target": "/v1/data?fixed=1",
        "effect": NetworkOperationEffect.READ_ONLY,
        "limits": NetworkOperationLimits(
            max_request_body_bytes=0,
            max_response_body_bytes=64,
            max_response_headers=8,
            max_response_header_bytes=1024,
            max_resolved_addresses=4,
            connect_timeout_seconds=0.5,
            total_timeout_seconds=1.0,
        ),
        "exposed_response_headers": ("content-type", "location"),
    }
    values.update(changes)
    return NetworkEgressOperation(**cast(Any, values))


def _profile(
    operation: NetworkEgressOperation | None = None,
    **changes: object,
) -> NetworkEgressProfile:
    values: dict[str, object] = {
        "profile_id": NetworkEgressProfileId("example"),
        "generation": 7,
        "mode": NetworkDestinationMode.HOSTED_HTTPS,
        "host": "api.example.com",
        "operations": (operation or _operation(),),
    }
    values.update(changes)
    return NetworkEgressProfile(**cast(Any, values))


def _request(
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
    *,
    body: bytes = b"",
) -> NetworkHttpRequest:
    return NetworkHttpRequest(
        profile_id=profile.profile_id,
        operation_id=operation.operation_id,
        body=body,
    )


@pytest.mark.asyncio
async def test_open_session_pins_literal_tls_target_and_writes_nothing() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector((_response(204, "No Content"),))
    transport = NetworkTransport(connector=connector)

    session = await transport.open_session(profile, operation, admission)

    assert connector.calls[0][:4] == (
        "8.8.8.8",
        443,
        True,
        "api.example.com",
    )
    assert connector.connections[0].written == b""
    assert session.request_started is False
    await session.aclose()
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_connect_fallback_occurs_only_before_request_write() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("1.1.1.1", "8.8.8.8"))
    connector = _FakeConnector(
        (_response(200, "OK"),),
        failures=(OSError("first connect failed"), None),
    )
    transport = NetworkTransport(connector=connector)

    session = await transport.open_session(profile, operation, admission)

    assert [call[0] for call in connector.calls] == ["1.1.1.1", "8.8.8.8"]
    assert connector.connections[0].written == b""
    await session.aclose()


@pytest.mark.asyncio
async def test_exchange_builds_exact_server_owned_request_and_filters_response() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector(
        (
            _response(
                200,
                "OK",
                headers=(
                    ("Content-Type", "application/json"),
                    ("Location", "https://other.example/ignored"),
                    ("X-Secret", "must-not-expose"),
                    ("Content-Length", "2"),
                ),
                body=b"{}",
            ),
        )
    )
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    result = await session.exchange(_request(profile, operation))

    written = bytes(connector.connections[0].written)
    assert written.startswith(b"GET /v1/data?fixed=1 HTTP/1.1\r\n")
    assert b"Host: api.example.com\r\n" in written
    assert b"Content-Length: 0\r\n" in written
    assert b"Accept-Encoding: identity\r\n" in written
    assert b"Connection: close\r\n" in written
    assert result.status_code == 200
    assert result.body == b"{}"
    assert dict(result.headers) == {
        "content-type": "application/json",
        "location": "https://other.example/ignored",
    }
    assert len(connector.calls) == 1
    assert session.closed is True
    assert session.request_started is True


@pytest.mark.asyncio
async def test_redirect_is_returned_as_data_and_never_followed() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector(
        (
            _response(
                302,
                "Found",
                headers=(
                    ("Location", "https://127.0.0.1/admin"),
                    ("Content-Length", "0"),
                ),
            ),
        )
    )
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    result = await session.exchange(_request(profile, operation))

    assert result.status_code == 302
    assert result.headers["location"] == "https://127.0.0.1/admin"
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_no_reconnect_or_address_fallback_after_write_may_start() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("1.1.1.1", "8.8.8.8"))
    connector = _FakeConnector(
        (_response(200, "OK"), _response(200, "OK")),
        drain_error=OSError("send failed"),
    )
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    with pytest.raises(NetworkTransportError) as raised:
        await session.exchange(_request(profile, operation))

    assert raised.value.category == "io_failed"
    assert raised.value.request_started is True
    assert len(connector.calls) == 1
    assert session.closed is True


@pytest.mark.asyncio
async def test_session_is_one_shot_even_when_first_exchange_fails_before_write() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector((_response(200, "OK"),))
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )
    wrong = NetworkHttpRequest(
        profile_id=NetworkEgressProfileId("other"),
        operation_id=operation.operation_id,
    )

    with pytest.raises(NetworkDestinationRejectedError):
        await session.exchange(wrong)

    assert session.closed is True
    assert session.used is True
    assert session.request_started is False
    assert connector.connections[0].written == b""


@pytest.mark.asyncio
async def test_credential_material_is_server_bound_header_only() -> None:
    operation = _operation(
        operation_id=NetworkEgressOperationId("write"),
        method=NetworkHttpMethod.POST,
        effect=NetworkOperationEffect.REMOTE_EFFECT,
        limits=NetworkOperationLimits(
            max_request_body_bytes=32,
            max_response_body_bytes=64,
            max_response_headers=8,
            max_response_header_bytes=1024,
            max_resolved_addresses=4,
            connect_timeout_seconds=0.5,
            total_timeout_seconds=1.0,
        ),
        content_type="application/json",
    )
    credential = NetworkCredentialBinding(
        header_name="authorization",
        secret_ref=SecretRef("token", "network", 3),
        value_prefix="Bearer ",
    )
    profile = _profile(operation, credential=credential)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector((_response(204, "No Content"),))
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    await session.exchange(
        _request(profile, operation, body=b"{}"),
        credential_value=b"secret-token",
    )

    written = bytes(connector.connections[0].written)
    assert b"Authorization:" not in written
    assert b"authorization: Bearer secret-token\r\n" in written
    assert written.endswith(b"{}")


@pytest.mark.asyncio
async def test_invalid_credential_bytes_never_start_request_or_leak() -> None:
    operation = _operation()
    credential = NetworkCredentialBinding(
        header_name="authorization",
        secret_ref=SecretRef("token", "network", 3),
        value_prefix="Bearer ",
    )
    profile = _profile(operation, credential=credential)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector((_response(200, "OK"),))
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        await session.exchange(
            _request(profile, operation),
            credential_value=b"secret\r\nX-Evil: 1",
        )

    assert raised.value.category == "invalid_credential_material"
    assert "secret" not in str(raised.value)
    assert connector.connections[0].written == b""
    assert session.request_started is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "category"),
    [
        (
            _response(
                200,
                "OK",
                headers=(("Content-Length", "0"), ("Transfer-Encoding", "chunked")),
            ),
            "ambiguous_response_framing",
        ),
        (
            _response(
                200,
                "OK",
                headers=(("X-Test", "one"), ("X-Test", "two"), ("Content-Length", "0")),
            ),
            "duplicate_response_header",
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n",
            "protocol_switch_rejected",
        ),
    ],
)
async def test_response_parser_rejects_ambiguous_duplicate_or_upgrade(
    response: bytes,
    category: str,
) -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _FakeConnector((response,))
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    with pytest.raises(NetworkTransportError) as raised:
        await session.exchange(_request(profile, operation))

    assert raised.value.category == category
    assert raised.value.request_started is True


@pytest.mark.asyncio
async def test_response_body_limits_apply_to_content_length_and_chunked() -> None:
    operation = _operation(
        limits=NetworkOperationLimits(
            max_response_body_bytes=4,
            max_response_headers=8,
            max_response_header_bytes=1024,
            max_resolved_addresses=4,
            connect_timeout_seconds=0.5,
            total_timeout_seconds=1.0,
        )
    )
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))

    for response in (
        _response(200, "OK", headers=(("Content-Length", "5"),), body=b"12345"),
        _response(
            200,
            "OK",
            headers=(("Transfer-Encoding", "chunked"),),
            body=b"5\r\n12345\r\n0\r\n\r\n",
        ),
    ):
        connector = _FakeConnector((response,))
        session = await NetworkTransport(connector=connector).open_session(
            profile,
            operation,
            admission,
        )
        with pytest.raises(NetworkTransportError) as raised:
            await session.exchange(_request(profile, operation))
        assert raised.value.category == "response_body_too_large"


@pytest.mark.asyncio
async def test_chunk_extensions_and_trailers_are_rejected() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))

    cases = (
        (
            _response(
                200,
                "OK",
                headers=(("Transfer-Encoding", "chunked"),),
                body=b"1;ext=x\r\na\r\n0\r\n\r\n",
            ),
            "invalid_chunked_response",
        ),
        (
            _response(
                200,
                "OK",
                headers=(("Transfer-Encoding", "chunked"),),
                body=b"1\r\na\r\n0\r\nX-Trailer: nope\r\n\r\n",
            ),
            "response_trailers_rejected",
        ),
    )
    for response, category in cases:
        connector = _FakeConnector((response,))
        session = await NetworkTransport(connector=connector).open_session(
            profile,
            operation,
            admission,
        )
        with pytest.raises(NetworkTransportError) as raised:
            await session.exchange(_request(profile, operation))
        assert raised.value.category == category


@pytest.mark.asyncio
async def test_connection_teardown_wait_is_bounded() -> None:
    class _BlockingCloseConnection(_FakeConnection):
        async def wait_closed(self) -> None:
            await asyncio.Event().wait()

    class _BlockingCloseConnector:
        def __init__(self) -> None:
            self.connection: _BlockingCloseConnection | None = None

        async def connect(
            self,
            address: str,
            port: int,
            *,
            tls: bool,
            server_hostname: str | None,
            connect_timeout: float,
            read_limit: int,
        ) -> NetworkConnection:
            del address, port, tls, server_hostname, connect_timeout
            await asyncio.sleep(0)
            self.connection = _BlockingCloseConnection(
                _response(204, "No Content"),
                read_limit=read_limit,
            )
            return self.connection

    operation = _operation(
        limits=NetworkOperationLimits(
            max_response_body_bytes=64,
            max_response_headers=8,
            max_response_header_bytes=1024,
            max_resolved_addresses=4,
            connect_timeout_seconds=0.01,
            total_timeout_seconds=0.5,
        )
    )
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    connector = _BlockingCloseConnector()
    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    result = await asyncio.wait_for(
        session.exchange(_request(profile, operation)),
        timeout=0.2,
    )

    assert result.status_code == 204
    assert session.closed is True
    assert connector.connection is not None
    assert connector.connection.closed is True


@pytest.mark.asyncio
async def test_loopback_http_uses_no_tls_hostname() -> None:
    operation = _operation()
    profile = _profile(
        operation,
        mode=NetworkDestinationMode.LOOPBACK_HTTP,
        host="localhost",
        allow_public_networks=False,
    )
    admission = admit_network_destination(profile, operation, ("127.0.0.1",))
    connector = _FakeConnector((_response(204, "No Content"),))

    session = await NetworkTransport(connector=connector).open_session(
        profile,
        operation,
        admission,
    )

    assert connector.calls[0][:4] == ("127.0.0.1", 80, False, None)
    await session.aclose()


@pytest.mark.asyncio
async def test_forged_admission_identity_is_rejected_before_connect() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(profile, operation, ("8.8.8.8",))
    forged = admission.__class__(
        profile_id=admission.profile_id,
        generation=admission.generation + 1,
        operation_id=admission.operation_id,
        mode=admission.mode,
        host=admission.host,
        port=admission.port,
        addresses=admission.addresses,
    )
    connector = _FakeConnector((_response(200, "OK"),))

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        await NetworkTransport(connector=connector).open_session(
            profile,
            operation,
            forged,
        )

    assert raised.value.category == "admission_mismatch"
    assert connector.calls == []
