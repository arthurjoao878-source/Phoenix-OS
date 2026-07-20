from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.assets import DashboardAssets
from phoenix_os.control_plane.durable_session_access import ControlPlaneDurableSessionAccessService
from phoenix_os.control_plane.durable_session_contracts import ControlPlaneDurableSessionPolicy
from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionCookiePolicy,
    ControlPlaneDurableSessionHttpBoundary,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneRemoteLoginRejectedError,
    ControlPlaneRemoteLoginThrottleClosedError,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentity,
    ControlPlaneClientIdentitySource,
)
from phoenix_os.control_plane.network_guard import (
    ControlPlaneNetworkRejectionReason,
    ControlPlaneNetworkRequestContext,
)
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry
from phoenix_os.control_plane.remote_security import (
    ControlPlaneRemoteAddressFamily,
    ControlPlaneRemoteAddressProtector,
    ControlPlaneRemoteAddressScope,
    ControlPlaneRemoteAudit,
    ControlPlaneRemoteAuditEvent,
    ControlPlaneRemoteAuthenticationService,
    ControlPlaneRemoteLoginBlockedError,
    ControlPlaneRemoteLoginBlockReason,
    ControlPlaneRemoteLoginThrottle,
    ControlPlaneRemoteLoginThrottlePolicy,
)
from phoenix_os.events import Event, EventBus

NOW = datetime(2026, 7, 19, 21, 0, tzinfo=UTC)
OPERATOR_ID = UUID(int=2204)
TOKEN = ControlPlaneOperatorToken("remote-operator-token-0123456789abcdef")
ORIGIN = "https://admin.example.com:8443"


class FakeMonotonicClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class DateClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class Secrets:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.counter = 0

    def __call__(self) -> str:
        self.counter += 1
        return f"{self.prefix}-{self.counter:048d}"


def direct(address: str = "8.8.8.8") -> ControlPlaneClientIdentity:
    return ControlPlaneClientIdentity(address=address, peer_address=address)


def forwarded(address: str = "2001:4860:4860::8888") -> ControlPlaneClientIdentity:
    return ControlPlaneClientIdentity(
        address=address,
        peer_address="10.0.0.10",
        source=ControlPlaneClientIdentitySource.FORWARDED,
        forwarded_chain=(address, "10.0.0.20"),
        trusted_proxy=True,
    )


def context(
    address: str = "8.8.8.8",
    *,
    origin: str | None = ORIGIN,
) -> ControlPlaneNetworkRequestContext:
    return ControlPlaneNetworkRequestContext(
        identity=direct(address),
        host="admin.example.com:8443",
        origin=origin,
    )


async def remote_service(
    *,
    throttle_policy: ControlPlaneRemoteLoginThrottlePolicy | None = None,
    events: EventBus | None = None,
    throttle_clock: FakeMonotonicClock | None = None,
) -> tuple[
    ControlPlaneRemoteAuthenticationService,
    ControlPlaneRemoteLoginThrottle,
    InMemoryControlPlaneDurableSessionRepository,
    ControlPlaneRemoteAudit,
]:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(
        ControlPlaneOperatorRecord(
            id=OPERATOR_ID,
            username="alice",
            display_name="Alice",
            role=ControlPlaneOperatorRole.MAINTAINER,
            token_digest=TOKEN.digest,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    repository = InMemoryControlPlaneDurableSessionRepository()
    date_clock = DateClock()
    access = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=repository,
        policy=ControlPlaneDurableSessionPolicy(
            absolute_ttl=timedelta(hours=1),
            idle_ttl=timedelta(minutes=20),
            rotation_interval=timedelta(minutes=10),
        ),
        clock=date_clock,
        token_factory=Secrets("remote-session"),
        csrf_factory=Secrets("remote-csrf"),
    )
    sessions = ControlPlaneDurableSessionHttpBoundary(
        authenticator=ControlPlaneOperatorAuthenticator(registry, clock=date_clock),
        access=access,
        repository=repository,
        cookie_policy=ControlPlaneDurableSessionCookiePolicy(secure=True),
        public_origin=ORIGIN,
    )
    throttle = ControlPlaneRemoteLoginThrottle(
        throttle_policy,
        clock=throttle_clock,
    )
    audit = ControlPlaneRemoteAudit(
        events,
        ControlPlaneRemoteAddressProtector(b"a" * 32),
    )
    return (
        ControlPlaneRemoteAuthenticationService(
            sessions=sessions,
            throttle=throttle,
            audit=audit,
        ),
        throttle,
        repository,
        audit,
    )


def test_dashboard_uses_same_origin_relative_requests_for_https_compatibility() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")
    assert asset is not None
    script = asset.body.decode("utf-8")

    assert 'credentials: "same-origin"' in script
    assert 'fetch("/v1/control-plane/' in script
    assert "http://" not in script
    assert "https://" not in script


@pytest.mark.parametrize("secret", [b"short", b"x" * 129])
def test_address_protector_rejects_unsafe_secrets(secret: bytes) -> None:
    with pytest.raises(ValueError, match="secret"):
        ControlPlaneRemoteAddressProtector(secret)


def test_safe_address_is_stable_protected_and_contains_no_raw_address() -> None:
    protector = ControlPlaneRemoteAddressProtector(b"a" * 32)
    first = protector.protect(direct("8.8.8.8"))
    second = protector.protect(direct("8.8.8.8"))

    assert first == second
    assert first.family is ControlPlaneRemoteAddressFamily.IPV4
    assert first.scope is ControlPlaneRemoteAddressScope.GLOBAL
    assert first.source is ControlPlaneClientIdentitySource.DIRECT
    assert len(first.fingerprint) == 64
    assert "8.8.8.8" not in repr(first)
    assert "8.8.8.8" not in repr(first.payload())


def test_safe_address_changes_for_address_and_secret() -> None:
    first = ControlPlaneRemoteAddressProtector(b"a" * 32).protect(direct("8.8.8.8"))
    other_address = ControlPlaneRemoteAddressProtector(b"a" * 32).protect(direct("1.1.1.1"))
    other_secret = ControlPlaneRemoteAddressProtector(b"b" * 32).protect(direct("8.8.8.8"))

    assert first.fingerprint != other_address.fingerprint
    assert first.fingerprint != other_secret.fingerprint


def test_safe_address_preserves_only_allowlisted_proxy_provenance() -> None:
    protected = ControlPlaneRemoteAddressProtector(b"a" * 32).protect(forwarded())

    assert protected.family is ControlPlaneRemoteAddressFamily.IPV6
    assert protected.source is ControlPlaneClientIdentitySource.FORWARDED
    assert protected.trusted_proxy
    rendered = repr(protected.payload())
    assert "2001:4860:4860::8888" not in rendered
    assert "10.0.0.10" not in rendered
    assert "10.0.0.20" not in rendered


@pytest.mark.parametrize(
    ("address", "scope"),
    [
        ("127.0.0.1", ControlPlaneRemoteAddressScope.LOOPBACK),
        ("10.0.0.1", ControlPlaneRemoteAddressScope.PRIVATE),
        ("169.254.1.1", ControlPlaneRemoteAddressScope.LINK_LOCAL),
        ("224.0.0.1", ControlPlaneRemoteAddressScope.MULTICAST),
        ("0.0.0.0", ControlPlaneRemoteAddressScope.UNSPECIFIED),
        ("8.8.8.8", ControlPlaneRemoteAddressScope.GLOBAL),
    ],
)
def test_safe_address_scope_is_allowlisted(
    address: str,
    scope: ControlPlaneRemoteAddressScope,
) -> None:
    protected = ControlPlaneRemoteAddressProtector(b"a" * 32).protect(direct(address))
    assert protected.scope is scope


@pytest.mark.parametrize(
    "changes",
    [
        {"client_attempts": 0},
        {"operator_attempts": 0},
        {"window": 0.0},
        {"window": float("nan")},
        {"client_capacity": 0},
        {"operator_capacity": 0},
    ],
)
def test_throttle_policy_rejects_invalid_bounds(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ControlPlaneRemoteLoginThrottlePolicy(**changes)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_client_throttle_blocks_after_limit_with_counter_only_snapshot() -> None:
    clock = FakeMonotonicClock()
    throttle = ControlPlaneRemoteLoginThrottle(
        ControlPlaneRemoteLoginThrottlePolicy(client_attempts=2),
        clock=clock,
    )
    identity = direct()

    await throttle.consume_client(identity)
    await throttle.consume_client(identity)
    with pytest.raises(ControlPlaneRemoteLoginBlockedError) as captured:
        await throttle.consume_client(identity)

    assert captured.value.reason is ControlPlaneRemoteLoginBlockReason.CLIENT
    snapshot = await throttle.snapshot()
    assert snapshot.client_attempts == 3
    assert snapshot.client_blocks == 1
    assert snapshot.tracked_clients == 1
    assert snapshot.last_block is ControlPlaneRemoteLoginBlockReason.CLIENT
    assert "8.8.8.8" not in repr(snapshot)


@pytest.mark.asyncio
async def test_operator_throttle_is_independent_from_client_limit() -> None:
    throttle = ControlPlaneRemoteLoginThrottle(
        ControlPlaneRemoteLoginThrottlePolicy(operator_attempts=1)
    )

    await throttle.consume_operator(OPERATOR_ID)
    with pytest.raises(ControlPlaneRemoteLoginBlockedError) as captured:
        await throttle.consume_operator(OPERATOR_ID)

    assert captured.value.reason is ControlPlaneRemoteLoginBlockReason.OPERATOR
    snapshot = await throttle.snapshot()
    assert snapshot.operator_attempts == 2
    assert snapshot.operator_blocks == 1
    assert snapshot.client_attempts == 0
    assert snapshot.last_block is ControlPlaneRemoteLoginBlockReason.OPERATOR


@pytest.mark.asyncio
async def test_throttle_capacity_fails_closed_and_recovers_after_window() -> None:
    clock = FakeMonotonicClock()
    throttle = ControlPlaneRemoteLoginThrottle(
        ControlPlaneRemoteLoginThrottlePolicy(
            window=10,
            client_capacity=1,
        ),
        clock=clock,
    )

    await throttle.consume_client(direct("8.8.8.8"))
    with pytest.raises(ControlPlaneRemoteLoginBlockedError) as captured:
        await throttle.consume_client(direct("1.1.1.1"))
    assert captured.value.reason is ControlPlaneRemoteLoginBlockReason.CAPACITY
    assert (await throttle.snapshot()).last_block is ControlPlaneRemoteLoginBlockReason.CAPACITY

    clock.advance(11)
    await throttle.consume_client(direct("1.1.1.1"))
    snapshot = await throttle.snapshot()
    assert snapshot.tracked_clients == 1
    assert snapshot.capacity_blocks == 1


@pytest.mark.asyncio
async def test_closed_throttle_fails_closed_and_drops_tracking_keys() -> None:
    throttle = ControlPlaneRemoteLoginThrottle()
    await throttle.consume_client(direct())

    await throttle.close()

    with pytest.raises(ControlPlaneRemoteLoginThrottleClosedError):
        await throttle.consume_client(direct())
    snapshot = await throttle.snapshot()
    assert snapshot.closed
    assert snapshot.tracked_clients == 0


@pytest.mark.asyncio
async def test_audit_payload_contains_only_safe_address_facts() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    audit = ControlPlaneRemoteAudit(
        bus,
        ControlPlaneRemoteAddressProtector(b"a" * 32),
    )
    identity = forwarded()

    await audit.connection_accepted(identity)
    await audit.authentication_succeeded(identity, OPERATOR_ID)
    await audit.connection_closed(identity)

    assert [event.name for event in received] == [
        ControlPlaneRemoteAuditEvent.CONNECTION_ACCEPTED.value,
        ControlPlaneRemoteAuditEvent.AUTHENTICATION_SUCCEEDED.value,
        ControlPlaneRemoteAuditEvent.CONNECTION_CLOSED.value,
    ]
    rendered = repr(tuple(event.payload for event in received))
    assert "2001:4860:4860::8888" not in rendered
    assert "10.0.0.10" not in rendered
    assert "10.0.0.20" not in rendered
    assert "forwarded_chain" not in rendered
    assert "operator_id" in received[1].payload
    snapshot = await audit.snapshot()
    assert snapshot.emitted == 3
    assert snapshot.dropped == 0


@pytest.mark.asyncio
async def test_allowlist_rejection_audit_needs_no_untrusted_identity() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    audit = ControlPlaneRemoteAudit(
        bus,
        ControlPlaneRemoteAddressProtector(b"a" * 32),
    )

    await audit.network_rejected(ControlPlaneNetworkRejectionReason.ALLOWLIST)

    assert received[0].payload == {
        "action": "network",
        "outcome": "rejected",
        "result": "allowlist",
    }


@pytest.mark.asyncio
async def test_closed_event_bus_drops_audit_without_raising() -> None:
    bus = EventBus()
    await bus.close()
    audit = ControlPlaneRemoteAudit(
        bus,
        ControlPlaneRemoteAddressProtector(b"a" * 32),
    )

    await audit.authentication_rejected(direct())

    snapshot = await audit.snapshot()
    assert snapshot.emitted == 0
    assert snapshot.dropped == 1
    assert snapshot.last_event is ControlPlaneRemoteAuditEvent.AUTHENTICATION_REJECTED


@pytest.mark.asyncio
async def test_remote_login_requires_exact_public_origin() -> None:
    service, throttle, repository, _ = await remote_service()

    with pytest.raises(ControlPlaneRemoteLoginRejectedError):
        await service.login(f"Bearer {TOKEN.value}", context(origin=None))

    assert (await throttle.snapshot()).client_attempts == 0
    assert (await repository.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_remote_login_issues_secure_cookie_after_both_admissions() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    service, throttle, repository, _ = await remote_service(events=bus)

    login = await service.login(f"Bearer {TOKEN.value}", context())

    set_cookie = dict(login.response_headers)["Set-Cookie"]
    assert "Secure" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert service.public_origin == ORIGIN
    snapshot = await throttle.snapshot()
    assert snapshot.client_attempts == 1
    assert snapshot.operator_attempts == 1
    assert (await repository.snapshot()).entries == 1
    assert received[-1].name == ControlPlaneRemoteAuditEvent.AUTHENTICATION_SUCCEEDED.value


@pytest.mark.asyncio
async def test_invalid_remote_credential_never_creates_a_session() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    service, throttle, repository, _ = await remote_service(events=bus)

    with pytest.raises(ControlPlaneRemoteLoginRejectedError) as captured:
        await service.login("Bearer invalid-credential-0123456789abcdef", context())

    assert str(captured.value) == "remote operator login rejected"
    snapshot = await throttle.snapshot()
    assert snapshot.client_attempts == 1
    assert snapshot.operator_attempts == 0
    assert (await repository.snapshot()).entries == 0
    assert received[-1].name == ControlPlaneRemoteAuditEvent.AUTHENTICATION_REJECTED.value


@pytest.mark.asyncio
async def test_client_login_limit_blocks_before_credential_authentication() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    service, throttle, repository, _ = await remote_service(
        throttle_policy=ControlPlaneRemoteLoginThrottlePolicy(client_attempts=1),
        events=bus,
    )

    with pytest.raises(ControlPlaneRemoteLoginRejectedError):
        await service.login("Bearer invalid-credential-0123456789abcdef", context())
    with pytest.raises(ControlPlaneRemoteLoginRejectedError):
        await service.login(f"Bearer {TOKEN.value}", context())

    snapshot = await throttle.snapshot()
    assert snapshot.client_blocks == 1
    assert snapshot.operator_attempts == 0
    assert (await repository.snapshot()).entries == 0
    assert received[-1].name == ControlPlaneRemoteAuditEvent.LOGIN_BLOCKED.value
    assert received[-1].payload["result"] == "client"


@pytest.mark.asyncio
async def test_operator_login_limit_applies_across_distinct_clients_before_issue() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    service, throttle, repository, _ = await remote_service(
        throttle_policy=ControlPlaneRemoteLoginThrottlePolicy(operator_attempts=1),
        events=bus,
    )

    await service.login(f"Bearer {TOKEN.value}", context("8.8.8.8"))
    with pytest.raises(ControlPlaneRemoteLoginRejectedError):
        await service.login(f"Bearer {TOKEN.value}", context("1.1.1.1"))

    snapshot = await throttle.snapshot()
    assert snapshot.client_attempts == 2
    assert snapshot.operator_attempts == 2
    assert snapshot.operator_blocks == 1
    assert (await repository.snapshot()).entries == 1
    assert received[-1].name == ControlPlaneRemoteAuditEvent.LOGIN_BLOCKED.value
    assert received[-1].payload["result"] == "operator"
    assert received[-1].payload["operator_id"] == str(OPERATOR_ID)


@pytest.mark.asyncio
async def test_remote_login_capacity_block_is_generic_and_audited() -> None:
    bus = EventBus()
    received: list[Event] = []
    await bus.subscribe("*", received.append)
    service, throttle, _, _ = await remote_service(
        throttle_policy=ControlPlaneRemoteLoginThrottlePolicy(client_capacity=1),
        events=bus,
    )

    with pytest.raises(ControlPlaneRemoteLoginRejectedError):
        await service.login("Bearer invalid-credential-0123456789abcdef", context("8.8.8.8"))
    with pytest.raises(ControlPlaneRemoteLoginRejectedError) as captured:
        await service.login(f"Bearer {TOKEN.value}", context("1.1.1.1"))

    assert str(captured.value) == "remote operator login rejected"
    assert (await throttle.snapshot()).capacity_blocks == 1
    assert received[-1].payload["result"] == "capacity"
