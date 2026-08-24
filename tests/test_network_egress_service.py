from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.authority import AuthorityIntent
from phoenix_os.network_egress._admission import NetworkResolver
from phoenix_os.network_egress._transport import (
    NetworkConnection,
    NetworkTransport,
)
from phoenix_os.network_egress.authorization import (
    NetworkEgressAuthorizationRejectedError,
    network_http_intent,
)
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
    NetworkHttpRequest,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)
from phoenix_os.network_egress.service import (
    NetworkEgressCancellationToken,
    NetworkEgressFailureKind,
    NetworkEgressRequestError,
    NetworkEgressService,
    NetworkEgressServiceLimits,
)
from phoenix_os.policy import PrincipalType, SecurityContext


class _Profiles:
    def __init__(self, profile: NetworkEgressProfile) -> None:
        self.current = profile

    def require_profile(self, profile_id: NetworkEgressProfileId) -> NetworkEgressProfile:
        if profile_id != self.current.profile_id:
            raise KeyError(profile_id)
        return self.current


class _Freshness:
    def __init__(self, *, reject_call: int | None = None) -> None:
        self.calls = 0
        self._reject_call = reject_call

    async def validate(self, context: SecurityContext) -> None:
        assert context.principal == "alice"
        self.calls += 1
        await asyncio.sleep(0)
        if self.calls == self._reject_call:
            raise RuntimeError("stale")


class _Authorizer:
    def __init__(self, *, reject_call: int | None = None) -> None:
        self.calls = 0
        self._reject_call = reject_call

    async def authorize(
        self,
        request: NetworkHttpRequest,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        context: SecurityContext,
    ) -> AuthorityIntent:
        assert context.principal == "alice"
        self.calls += 1
        await asyncio.sleep(0)
        if self.calls == self._reject_call:
            raise NetworkEgressAuthorizationRejectedError()
        return network_http_intent(request, profile, operation)


class _Resolver:
    def __init__(self) -> None:
        self.calls = 0

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        assert host == "api.example.com"
        assert port == 443
        assert max_addresses >= 1
        self.calls += 1
        await asyncio.sleep(0)
        return ("8.8.8.8",)


class _BlockingResolver:
    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        del host, port, max_addresses
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return ("8.8.8.8",)


class _SlowResolver:
    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        del host, port, max_addresses
        await asyncio.sleep(1)
        return ("8.8.8.8",)


class _Connection:
    def __init__(
        self,
        response: bytes,
        *,
        drain_delay: float = 0.0,
        drain_error: OSError | None = None,
    ) -> None:
        self._reader = asyncio.StreamReader(limit=8194)
        self._reader.feed_data(response)
        self._reader.feed_eof()
        self._drain_delay = drain_delay
        self._drain_error = drain_error
        self.written = bytearray()
        self.closed = False

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        if self._drain_delay:
            await asyncio.sleep(self._drain_delay)
        else:
            await asyncio.sleep(0)
        if self._drain_error is not None:
            raise self._drain_error

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


class _Connector:
    def __init__(
        self,
        *,
        response: bytes | None = None,
        drain_delay: float = 0.0,
        drain_error: OSError | None = None,
    ) -> None:
        self._response = _response() if response is None else response
        self._drain_delay = drain_delay
        self._drain_error = drain_error
        self.calls = 0
        self.connections: list[_Connection] = []

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
        assert address == "8.8.8.8"
        assert port == 443
        assert tls is True
        assert server_hostname == "api.example.com"
        assert connect_timeout > 0
        assert read_limit > 0
        self.calls += 1
        await asyncio.sleep(0)
        connection = _Connection(
            self._response,
            drain_delay=self._drain_delay,
            drain_error=self._drain_error,
        )
        self.connections.append(connection)
        return connection


class _BlockingConnector(_Connector):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

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
        del address, port, tls, server_hostname, connect_timeout, read_limit
        self.calls += 1
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        connection = _Connection(self._response)
        self.connections.append(connection)
        return connection


def _response() -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Hidden: secret\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n"
        b"{}"
    )


def _operation() -> NetworkEgressOperation:
    return NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("read"),
        method=NetworkHttpMethod.GET,
        request_target="/v1/data",
        effect=NetworkOperationEffect.READ_ONLY,
        limits=NetworkOperationLimits(
            max_request_body_bytes=0,
            max_response_body_bytes=64,
            max_response_headers=8,
            max_response_header_bytes=1024,
            max_resolved_addresses=4,
            connect_timeout_seconds=0.5,
            total_timeout_seconds=2.0,
        ),
        exposed_response_headers=("content-type",),
    )


def _profile() -> NetworkEgressProfile:
    return NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("example"),
        generation=7,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="api.example.com",
        operations=(_operation(),),
    )


def _request(profile: NetworkEgressProfile) -> NetworkHttpRequest:
    return NetworkHttpRequest(
        profile_id=profile.profile_id,
        operation_id=profile.operations[0].operation_id,
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
    )


def _service(
    profile: NetworkEgressProfile,
    *,
    resolver: NetworkResolver,
    connector: _Connector,
    freshness: _Freshness | None = None,
    authorizer: _Authorizer | None = None,
    limits: NetworkEgressServiceLimits | None = None,
) -> NetworkEgressService:
    return NetworkEgressService(
        profiles=_Profiles(profile),
        authorizer=_Authorizer() if authorizer is None else authorizer,
        freshness=_Freshness() if freshness is None else freshness,
        resolver=resolver,
        transport=NetworkTransport(connector=connector),
        limits=limits,
    )


@pytest.mark.asyncio
async def test_service_sends_only_after_second_fresh_authorization_and_filters_response() -> None:
    profile = _profile()
    resolver = _Resolver()
    connector = _Connector()
    freshness = _Freshness()
    authorizer = _Authorizer()
    service = _service(
        profile,
        resolver=resolver,
        connector=connector,
        freshness=freshness,
        authorizer=authorizer,
    )

    result = await service.request(_request(profile), _context())

    assert result.request_id is not None
    assert result.profile_id == profile.profile_id
    assert result.operation_id == profile.operations[0].operation_id
    assert result.status_code == 200
    assert result.body == b"{}"
    assert dict(result.headers) == {"content-type": "application/json"}
    assert freshness.calls == 2
    assert authorizer.calls == 2
    assert resolver.calls == 1
    assert connector.calls == 1
    assert bytes(connector.connections[0].written).startswith(b"GET /v1/data HTTP/1.1\r\n")


@pytest.mark.asyncio
async def test_saturation_rejects_immediately_without_request_queue() -> None:
    profile = _profile()
    resolver = _BlockingResolver()
    connector = _Connector()
    service = _service(
        profile,
        resolver=resolver,
        connector=connector,
        limits=NetworkEgressServiceLimits(max_concurrent_requests=1),
    )

    first = asyncio.create_task(service.request(_request(profile), _context()))
    await asyncio.wait_for(resolver.started.wait(), timeout=1)

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(profile), _context())

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert caught.value.request_started is False
    assert resolver.calls == 1
    assert connector.calls == 0

    resolver.release.set()
    await first


@pytest.mark.asyncio
async def test_cooperative_cancellation_during_dns_prevents_connect_and_send() -> None:
    profile = _profile()
    resolver = _BlockingResolver()
    connector = _Connector()
    token = NetworkEgressCancellationToken()
    service = _service(profile, resolver=resolver, connector=connector)

    attempt = asyncio.create_task(
        service.request(
            _request(profile),
            _context(),
            cancellation=token,
        )
    )
    await asyncio.wait_for(resolver.started.wait(), timeout=1)
    token.cancel()

    with pytest.raises(NetworkEgressRequestError) as caught:
        await attempt

    assert caught.value.kind is NetworkEgressFailureKind.CANCELLED
    assert caught.value.request_started is False
    assert connector.calls == 0


@pytest.mark.asyncio
async def test_deadline_during_dns_times_out_before_any_connection() -> None:
    profile = _profile()
    connector = _Connector()
    service = _service(profile, resolver=_SlowResolver(), connector=connector)

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(
            _request(profile),
            _context(),
            deadline=datetime.now(UTC) + timedelta(milliseconds=50),
        )

    assert caught.value.kind is NetworkEgressFailureKind.TIMED_OUT
    assert caught.value.request_started is False
    assert connector.calls == 0


@pytest.mark.asyncio
async def test_deadline_after_write_is_indeterminate_and_never_retries() -> None:
    profile = _profile()
    connector = _Connector(drain_delay=1.0)
    service = _service(profile, resolver=_Resolver(), connector=connector)

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(
            _request(profile),
            _context(),
            deadline=datetime.now(UTC) + timedelta(milliseconds=500),
        )

    assert caught.value.kind is NetworkEgressFailureKind.INDETERMINATE
    assert caught.value.request_started is True
    assert connector.calls == 1
    assert len(connector.connections) == 1
    assert connector.connections[0].written


@pytest.mark.asyncio
async def test_transport_failure_after_write_is_indeterminate_and_never_retries() -> None:
    profile = _profile()
    connector = _Connector(drain_error=OSError("peer reset"))
    service = _service(profile, resolver=_Resolver(), connector=connector)

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(profile), _context())

    assert caught.value.kind is NetworkEgressFailureKind.INDETERMINATE
    assert caught.value.request_started is True
    assert connector.calls == 1
    assert len(connector.connections) == 1


@pytest.mark.asyncio
async def test_final_policy_rejection_closes_pinned_session_without_writing() -> None:
    profile = _profile()
    connector = _Connector()
    authorizer = _Authorizer(reject_call=2)
    service = _service(
        profile,
        resolver=_Resolver(),
        connector=connector,
        authorizer=authorizer,
    )

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(profile), _context())

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert caught.value.request_started is False
    assert connector.calls == 1
    assert connector.connections[0].written == b""
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_service_rejects_naive_caller_deadline_at_the_public_boundary() -> None:
    profile = _profile()
    service = _service(profile, resolver=_Resolver(), connector=_Connector())

    with pytest.raises(ValueError, match="timezone-aware"):
        await service.request(
            _request(profile),
            _context(),
            deadline=datetime(2026, 1, 1),
        )


@pytest.mark.asyncio
async def test_external_task_cancellation_drains_pending_connect_before_slot_release() -> None:
    profile = _profile()
    connector = _BlockingConnector()
    service = _service(
        profile,
        resolver=_Resolver(),
        connector=connector,
        limits=NetworkEgressServiceLimits(max_concurrent_requests=1),
    )

    attempt = asyncio.create_task(service.request(_request(profile), _context()))
    await asyncio.wait_for(connector.started.wait(), timeout=1)
    attempt.cancel()

    with pytest.raises(asyncio.CancelledError):
        await attempt

    await asyncio.wait_for(connector.cancelled.wait(), timeout=1)
    assert connector.calls == 1
    assert connector.connections == []


@pytest.mark.asyncio
async def test_cooperative_cancel_and_connect_completion_never_leak_pinned_session() -> None:
    profile = _profile()
    connector = _BlockingConnector()
    token = NetworkEgressCancellationToken()
    service = _service(profile, resolver=_Resolver(), connector=connector)

    attempt = asyncio.create_task(
        service.request(
            _request(profile),
            _context(),
            cancellation=token,
        )
    )
    await asyncio.wait_for(connector.started.wait(), timeout=1)

    token.cancel()
    connector.release.set()

    with pytest.raises(NetworkEgressRequestError) as caught:
        await attempt

    assert caught.value.kind is NetworkEgressFailureKind.CANCELLED
    assert caught.value.request_started is False
    assert connector.calls == 1
    assert all(connection.written == b"" for connection in connector.connections)
    assert all(connection.closed for connection in connector.connections)
