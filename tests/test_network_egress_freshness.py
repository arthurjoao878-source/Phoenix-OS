from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta

import pytest

from phoenix_os.authority import AuthorityIntent
from phoenix_os.configuration import SecretValue
from phoenix_os.network_egress._transport import NetworkConnection, NetworkTransport
from phoenix_os.network_egress.authorization import network_http_intent
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
from phoenix_os.network_egress.service import (
    NetworkEgressFailureKind,
    NetworkEgressRequestError,
    NetworkEgressService,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretLease, SecretRef, SecretsManager


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
            raise RuntimeError("revoked")


class _Authorizer:
    def __init__(self) -> None:
        self.calls = 0

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
        return network_http_intent(request, profile, operation)


class _Resolver:
    def __init__(
        self,
        *,
        hook: Callable[[], None] | None = None,
    ) -> None:
        self.calls = 0
        self._hook = hook

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        del host, port, max_addresses
        self.calls += 1
        await asyncio.sleep(0)
        if self._hook is not None:
            self._hook()
        return ("8.8.8.8",)


class _Connection:
    def __init__(self) -> None:
        self._reader = asyncio.StreamReader(limit=8194)
        self._reader.feed_data(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
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


class _Connector:
    def __init__(
        self,
        *,
        hook: Callable[[], None] | None = None,
    ) -> None:
        self._hook = hook
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
        del address, port, tls, server_hostname, connect_timeout, read_limit
        self.calls += 1
        await asyncio.sleep(0)
        connection = _Connection()
        self.connections.append(connection)
        if self._hook is not None:
            self._hook()
        return connection


class _LeaseRevokingConnector(_Connector):
    def __init__(
        self,
        manager: _RecordingSecretsManager,
        context: SecurityContext,
    ) -> None:
        super().__init__()
        self._manager = manager
        self._context = context

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
        connection = await super().connect(
            address,
            port,
            tls=tls,
            server_hostname=server_hostname,
            connect_timeout=connect_timeout,
            read_limit=read_limit,
        )
        lease = self._manager.last_lease
        assert lease is not None
        revoked = await self._manager.revoke_lease(lease.id, self._context)
        assert revoked is True
        return connection


class _RecordingSecretsManager(SecretsManager):
    def __init__(self) -> None:
        super().__init__()
        self.last_lease: SecretLease | None = None
        self._lease_hook: Callable[[], None] | None = None

    def set_lease_hook(self, hook: Callable[[], None]) -> None:
        self._lease_hook = hook

    async def lease(
        self,
        ref: SecretRef,
        context: SecurityContext,
        *,
        ttl: timedelta | None = None,
    ) -> SecretLease:
        lease = await super().lease(ref, context, ttl=ttl)
        self.last_lease = lease
        if self._lease_hook is not None:
            self._lease_hook()
        return lease


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
    )


def _profile(
    *,
    generation: int = 7,
    credential: NetworkCredentialBinding | None = None,
) -> NetworkEgressProfile:
    return NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("example"),
        generation=generation,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="api.example.com",
        operations=(_operation(),),
        credential=credential,
    )


def _request(profile: NetworkEgressProfile) -> NetworkHttpRequest:
    return NetworkHttpRequest(
        profile_id=profile.profile_id,
        operation_id=profile.operations[0].operation_id,
    )


def _context(*, secret_permissions: bool = False) -> SecurityContext:
    permissions = (
        frozenset({"secret.create", "secret.read", "secret.lease.revoke"})
        if secret_permissions
        else frozenset()
    )
    return SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=permissions,
    )


def _service(
    profiles: _Profiles,
    *,
    resolver: _Resolver,
    connector: _Connector,
    freshness: _Freshness | None = None,
    secrets: SecretsManager | None = None,
) -> NetworkEgressService:
    return NetworkEgressService(
        profiles=profiles,
        authorizer=_Authorizer(),
        freshness=_Freshness() if freshness is None else freshness,
        secrets=secrets,
        resolver=resolver,
        transport=NetworkTransport(connector=connector),
    )


@pytest.mark.asyncio
async def test_profile_generation_swap_during_dns_fails_before_connect() -> None:
    original = _profile()
    profiles = _Profiles(original)
    resolver = _Resolver(hook=lambda: setattr(profiles, "current", replace(original, generation=8)))
    connector = _Connector()
    service = _service(profiles, resolver=resolver, connector=connector)

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(original), _context())

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert caught.value.request_started is False
    assert resolver.calls == 1
    assert connector.calls == 0


@pytest.mark.asyncio
async def test_profile_generation_swap_during_connect_closes_without_writing() -> None:
    original = _profile()
    profiles = _Profiles(original)
    connector = _Connector(
        hook=lambda: setattr(profiles, "current", replace(original, generation=8))
    )
    service = _service(profiles, resolver=_Resolver(), connector=connector)

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(original), _context())

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert caught.value.request_started is False
    assert connector.calls == 1
    assert connector.connections[0].written == b""
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_subject_revocation_after_connect_fails_before_request_bytes() -> None:
    original = _profile()
    profiles = _Profiles(original)
    freshness = _Freshness(reject_call=2)
    connector = _Connector()
    service = _service(
        profiles,
        resolver=_Resolver(),
        connector=connector,
        freshness=freshness,
    )

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(original), _context())

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert caught.value.request_started is False
    assert freshness.calls == 2
    assert connector.connections[0].written == b""
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_profile_swap_during_secret_lease_fails_before_dns() -> None:
    context = _context(secret_permissions=True)
    manager = _RecordingSecretsManager()
    metadata = await manager.create(
        SecretRef("api-token", "network"),
        SecretValue(b"test-secret"),
        context,
    )
    current = _profile(
        credential=NetworkCredentialBinding(
            header_name="authorization",
            secret_ref=metadata.ref,
            value_prefix="Bearer ",
        )
    )
    profiles = _Profiles(current)
    manager.set_lease_hook(lambda: setattr(profiles, "current", replace(current, generation=8)))
    resolver = _Resolver()
    connector = _Connector()
    service = _service(
        profiles,
        resolver=resolver,
        connector=connector,
        secrets=manager,
    )

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(current), context)

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert resolver.calls == 0
    assert connector.calls == 0
    await manager.close()


@pytest.mark.asyncio
async def test_revoked_secret_lease_after_connect_fails_without_exposing_secret() -> None:
    context = _context(secret_permissions=True)
    manager = _RecordingSecretsManager()
    metadata = await manager.create(
        SecretRef("api-token", "network"),
        SecretValue(b"test-secret"),
        context,
    )
    profile = _profile(
        credential=NetworkCredentialBinding(
            header_name="authorization",
            secret_ref=metadata.ref,
            value_prefix="Bearer ",
        )
    )
    profiles = _Profiles(profile)
    connector = _LeaseRevokingConnector(manager, context)
    service = _service(
        profiles,
        resolver=_Resolver(),
        connector=connector,
        secrets=manager,
    )

    with pytest.raises(NetworkEgressRequestError) as caught:
        await service.request(_request(profile), context)

    assert caught.value.kind is NetworkEgressFailureKind.REJECTED
    assert caught.value.request_started is False
    assert str(caught.value) == "network egress request rejected"
    assert "test-secret" not in repr(caught.value)
    assert connector.connections[0].written == b""
    assert connector.connections[0].closed is True
    await manager.close()


@pytest.mark.asyncio
async def test_exact_secret_is_revealed_only_for_final_transport_exchange() -> None:
    context = _context(secret_permissions=True)
    manager = _RecordingSecretsManager()
    metadata = await manager.create(
        SecretRef("api-token", "network"),
        SecretValue(b"test-secret"),
        context,
    )
    profile = _profile(
        credential=NetworkCredentialBinding(
            header_name="authorization",
            secret_ref=metadata.ref,
            value_prefix="Bearer ",
        )
    )
    profiles = _Profiles(profile)
    connector = _Connector()
    service = _service(
        profiles,
        resolver=_Resolver(),
        connector=connector,
        secrets=manager,
    )

    result = await service.request(_request(profile), context)

    written = bytes(connector.connections[0].written)
    assert b"authorization: Bearer test-secret\r\n" in written
    assert b"test-secret" not in result.body
    assert "test-secret" not in repr(profile)
    assert manager.last_lease is not None
    assert manager.last_lease.ref == metadata.ref
    await manager.close()
