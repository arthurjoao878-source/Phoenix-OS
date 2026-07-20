from __future__ import annotations

from dataclasses import replace

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneNetworkGuardClosedError,
    ControlPlaneNetworkRejectedError,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentity,
    ControlPlaneExposureMode,
    ControlPlaneNetworkPolicy,
    ControlPlaneProxyHeaderPolicy,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
)
from phoenix_os.control_plane.network_guard import (
    DEFAULT_CONTROL_PLANE_CLIENT_RATE_CAPACITY,
    DEFAULT_CONTROL_PLANE_CLIENT_RATE_LIMIT,
    DEFAULT_CONTROL_PLANE_CLIENT_RATE_WINDOW,
    MAX_CONTROL_PLANE_CLIENT_RATE_CAPACITY,
    MAX_CONTROL_PLANE_CLIENT_RATE_LIMIT,
    MAX_CONTROL_PLANE_CLIENT_RATE_WINDOW,
    ControlPlaneClientRateLimitPolicy,
    ControlPlaneNetworkGuard,
    ControlPlaneNetworkGuardSnapshot,
    ControlPlaneNetworkRejectionReason,
    ControlPlaneNetworkRequestContext,
)


class FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.value = now

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def loopback_policy(**changes: object) -> ControlPlaneNetworkPolicy:
    values: dict[str, object] = {
        "exposure": ControlPlaneExposureMode.LOOPBACK,
        "bind_host": "127.0.0.1",
        "port": 8080,
        "public_origin": "http://localhost:8080",
        "allowed_client_networks": ("127.0.0.0/8", "::1/128"),
        "max_connections_per_client": 2,
    }
    values.update(changes)
    return ControlPlaneNetworkPolicy(**values)  # type: ignore[arg-type]


def remote_policy(
    *,
    proxy_headers: ControlPlaneProxyHeaderPolicy = ControlPlaneProxyHeaderPolicy.DISABLED,
    allowed: tuple[str, ...] = ("203.0.113.0/24", "2001:db8::/32"),
    trusted: tuple[str, ...] = (),
    max_connections: int = 2,
) -> ControlPlaneNetworkPolicy:
    return ControlPlaneNetworkPolicy(
        exposure=ControlPlaneExposureMode.REMOTE,
        bind_host="0.0.0.0",
        port=8443,
        public_origin="https://admin.example.com:8443",
        tls=ControlPlaneTlsPolicy(
            mode=ControlPlaneTlsMode.SERVER,
            certificate_file="/etc/phoenix/tls.crt",
            private_key_file="/etc/phoenix/tls.key",
        ),
        allowed_client_networks=allowed,
        trusted_proxy_networks=trusted,
        proxy_headers=proxy_headers,
        secure_cookies=True,
        max_connections_per_client=max_connections,
    )


def host(value: str = "localhost:8080") -> dict[str, tuple[str, ...]]:
    return {"host": (value,)}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requests", 0),
        ("requests", MAX_CONTROL_PLANE_CLIENT_RATE_LIMIT + 1),
        ("window", 0.0),
        ("window", MAX_CONTROL_PLANE_CLIENT_RATE_WINDOW + 1.0),
        ("capacity", 0),
        ("capacity", MAX_CONTROL_PLANE_CLIENT_RATE_CAPACITY + 1),
    ],
)
def test_rate_limit_policy_rejects_values_outside_bounds(field: str, value: int | float) -> None:
    values: dict[str, int | float] = {
        "requests": DEFAULT_CONTROL_PLANE_CLIENT_RATE_LIMIT,
        "window": DEFAULT_CONTROL_PLANE_CLIENT_RATE_WINDOW,
        "capacity": DEFAULT_CONTROL_PLANE_CLIENT_RATE_CAPACITY,
    }
    values[field] = value
    with pytest.raises(ValueError):
        ControlPlaneClientRateLimitPolicy(**values)  # type: ignore[arg-type]


def test_rate_limit_policy_defaults_are_bounded() -> None:
    policy = ControlPlaneClientRateLimitPolicy()
    assert policy.requests == 120
    assert policy.window == 60.0
    assert policy.capacity == 4096


def test_request_context_requires_canonical_host_and_origin() -> None:
    identity = ControlPlaneClientIdentity(address="127.0.0.1", peer_address="127.0.0.1")
    context = ControlPlaneNetworkRequestContext(
        identity=identity,
        host="localhost:8080",
        origin="http://localhost:8080",
    )
    assert context.identity is identity
    with pytest.raises(ValueError):
        replace(context, host="LOCALHOST:8080")
    with pytest.raises(ValueError):
        replace(context, origin="http://LOCALHOST:8080")


def test_guard_snapshot_rejects_inconsistent_counters() -> None:
    with pytest.raises(ValueError):
        ControlPlaneNetworkGuardSnapshot(
            closed=False,
            requests=1,
            accepted=1,
            rejected=1,
            host_rejections=1,
            origin_rejections=0,
            proxy_rejections=0,
            allowlist_rejections=0,
            rate_limit_rejections=0,
            connection_limit_rejections=0,
            active_connections=0,
            tracked_clients=0,
            rate_limit_capacity=1,
        )


@pytest.mark.asyncio
async def test_direct_loopback_request_is_authorized() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy())
    context = await guard.authorize_request("127.0.0.2", host())
    assert context.identity.address == "127.0.0.2"
    assert context.identity.peer_address == "127.0.0.2"
    assert context.host == "localhost:8080"
    assert context.origin is None
    snapshot = await guard.snapshot()
    assert snapshot.requests == snapshot.accepted == 1
    assert snapshot.rejected == 0


@pytest.mark.asyncio
async def test_host_normalizes_case_and_default_port() -> None:
    policy = loopback_policy(public_origin="http://localhost")
    guard = ControlPlaneNetworkGuard(policy)
    context = await guard.authorize_request("127.0.0.1", host("LOCALHOST:80"))
    assert context.host == "localhost"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "values",
    [
        (),
        ("localhost:8080", "localhost:8080"),
        ("example.com:8080",),
        (" localhost:8080",),
        ("localhost:8080/path",),
        ("user@localhost:8080",),
        ("local host:8080",),
        ("localhost:8080,example.com",),
        ("éxample.com:8080",),
        ("a" * 513,),
    ],
)
async def test_invalid_host_is_rejected(values: tuple[str, ...]) -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy())
    with pytest.raises(ControlPlaneNetworkRejectedError, match="network request rejected"):
        await guard.authorize_request("127.0.0.1", {"host": values})
    snapshot = await guard.snapshot()
    assert snapshot.last_rejection is ControlPlaneNetworkRejectionReason.HOST
    assert snapshot.host_rejections == 1


@pytest.mark.asyncio
async def test_exact_origin_is_optional_or_can_be_required() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy())
    context = await guard.authorize_request(
        "127.0.0.1",
        {"host": ("localhost:8080",), "origin": ("http://LOCALHOST:8080",)},
        require_origin=True,
    )
    assert context.origin == "http://localhost:8080"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "values",
    [
        (),
        ("http://localhost:8080", "http://localhost:8080"),
        ("http://example.com:8080",),
        ("null",),
        ("http://localhost:8080/path",),
        (" http://localhost:8080",),
    ],
)
async def test_required_invalid_origin_is_rejected(values: tuple[str, ...]) -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy())
    headers = host()
    if values:
        headers["origin"] = values
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("127.0.0.1", headers, require_origin=True)
    snapshot = await guard.snapshot()
    assert snapshot.origin_rejections == 1


@pytest.mark.asyncio
async def test_direct_client_outside_allowlist_is_rejected() -> None:
    guard = ControlPlaneNetworkGuard(remote_policy())
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("198.51.100.8", host("admin.example.com:8443"))
    snapshot = await guard.snapshot()
    assert snapshot.allowlist_rejections == 1


@pytest.mark.asyncio
async def test_proxy_header_is_rejected_when_proxy_support_is_disabled() -> None:
    guard = ControlPlaneNetworkGuard(remote_policy())
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.9",)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("203.0.113.8", headers)
    assert (await guard.snapshot()).proxy_rejections == 1


@pytest.mark.asyncio
async def test_proxy_header_is_rejected_from_untrusted_peer() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.9",)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("192.0.2.10", headers)


@pytest.mark.asyncio
async def test_both_proxy_header_formats_are_rejected() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.FORWARDED,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers.update(
        {
            "forwarded": ("for=203.0.113.9",),
            "x-forwarded-for": ("203.0.113.9",),
        }
    )
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("10.0.0.2", headers)


@pytest.mark.asyncio
async def test_unconfigured_proxy_header_format_is_rejected() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.FORWARDED,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.9",)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("10.0.0.2", headers)


@pytest.mark.asyncio
async def test_duplicate_proxy_header_values_are_rejected() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.9", "203.0.113.10")
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("10.0.0.2", headers)


@pytest.mark.asyncio
async def test_x_forwarded_for_resolves_client_from_trusted_proxy() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.9",)
    context = await guard.authorize_request("10.0.0.2", headers)
    assert context.identity.address == "203.0.113.9"
    assert context.identity.forwarded_chain == ("203.0.113.9",)
    assert context.identity.trusted_proxy is True


@pytest.mark.asyncio
async def test_untrusted_left_xff_values_are_not_used_as_client_identity() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
            allowed=("198.51.100.0/24",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.99, 198.51.100.8",)
    context = await guard.authorize_request("10.0.0.2", headers)
    assert context.identity.address == "198.51.100.8"
    assert context.identity.forwarded_chain == ("198.51.100.8",)


@pytest.mark.asyncio
async def test_xff_preserves_trusted_intermediate_proxy_suffix() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("203.0.113.9, 10.0.0.3",)
    context = await guard.authorize_request("10.0.0.2", headers)
    assert context.identity.forwarded_chain == ("203.0.113.9", "10.0.0.3")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("for=203.0.113.9", "203.0.113.9"),
        ("for=203.0.113.9:443;proto=https", "203.0.113.9"),
        ('for="[2001:db8::9]:443";proto=https', "2001:db8::9"),
        ("by=10.0.0.2;for=203.0.113.9;host=admin.example.com", "203.0.113.9"),
    ],
)
async def test_forwarded_header_resolves_supported_ip_forms(header: str, expected: str) -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.FORWARDED,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["forwarded"] = (header,)
    context = await guard.authorize_request("10.0.0.2", headers)
    assert context.identity.address == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header",
    [
        "for=unknown",
        "for=_hidden",
        "proto=https",
        "for=203.0.113.9;for=203.0.113.10",
        'for="[2001:db8::9]',
        "for=example.com",
        "for=203.0.113.9,",
        "for=203.0.113.9;;proto=https",
    ],
)
async def test_malformed_forwarded_header_is_rejected(header: str) -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.FORWARDED,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["forwarded"] = (header,)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("10.0.0.2", headers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header",
    [
        "",
        "example.com",
        "203.0.113.9,",
        "203.0.113.9:443",
        "203.0.113.9,,203.0.113.10",
        "203.0.113.9%eth0",
    ],
)
async def test_malformed_xff_header_is_rejected(header: str) -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = (header,)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("10.0.0.2", headers)


@pytest.mark.asyncio
async def test_forwarded_client_must_match_client_allowlist() -> None:
    guard = ControlPlaneNetworkGuard(
        remote_policy(
            proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
            trusted=("10.0.0.0/8",),
        )
    )
    headers = host("admin.example.com:8443")
    headers["x-forwarded-for"] = ("198.51.100.8",)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("10.0.0.2", headers)
    assert (await guard.snapshot()).allowlist_rejections == 1


@pytest.mark.asyncio
async def test_rate_limit_rejects_request_at_exact_limit() -> None:
    clock = FakeClock()
    guard = ControlPlaneNetworkGuard(
        loopback_policy(),
        rate_limit=ControlPlaneClientRateLimitPolicy(requests=2, window=10, capacity=2),
        clock=clock,
    )
    await guard.authorize_request("127.0.0.1", host())
    await guard.authorize_request("127.0.0.1", host())
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("127.0.0.1", host())
    snapshot = await guard.snapshot()
    assert snapshot.accepted == 2
    assert snapshot.rate_limit_rejections == 1


@pytest.mark.asyncio
async def test_rate_limit_window_expires_deterministically() -> None:
    clock = FakeClock()
    guard = ControlPlaneNetworkGuard(
        loopback_policy(),
        rate_limit=ControlPlaneClientRateLimitPolicy(requests=1, window=10, capacity=2),
        clock=clock,
    )
    await guard.authorize_request("127.0.0.1", host())
    clock.advance(10)
    await guard.authorize_request("127.0.0.1", host())
    assert (await guard.snapshot()).accepted == 2


@pytest.mark.asyncio
async def test_rate_limit_tracking_capacity_fails_closed() -> None:
    guard = ControlPlaneNetworkGuard(
        loopback_policy(),
        rate_limit=ControlPlaneClientRateLimitPolicy(requests=2, window=10, capacity=1),
        clock=FakeClock(),
    )
    await guard.authorize_request("127.0.0.1", host())
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("127.0.0.2", host())
    snapshot = await guard.snapshot()
    assert snapshot.tracked_clients == 1
    assert snapshot.rate_limit_rejections == 1


@pytest.mark.asyncio
async def test_rate_limit_capacity_is_reclaimed_after_window() -> None:
    clock = FakeClock()
    guard = ControlPlaneNetworkGuard(
        loopback_policy(),
        rate_limit=ControlPlaneClientRateLimitPolicy(requests=1, window=10, capacity=1),
        clock=clock,
    )
    await guard.authorize_request("127.0.0.1", host())
    clock.advance(10)
    await guard.authorize_request("127.0.0.2", host())
    assert (await guard.snapshot()).tracked_clients == 1


@pytest.mark.asyncio
async def test_per_client_connection_limit_and_release() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy(max_connections_per_client=1))
    context = await guard.authorize_request("127.0.0.1", host())
    lease = await guard.acquire_connection(context.identity)
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.acquire_connection(context.identity)
    assert (await guard.snapshot()).active_connections == 1
    await lease.close()
    await lease.close()
    assert (await guard.snapshot()).active_connections == 0


@pytest.mark.asyncio
async def test_connection_lease_async_context_releases_slot() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy(max_connections_per_client=1))
    context = await guard.authorize_request("127.0.0.1", host())
    async with await guard.acquire_connection(context.identity) as lease:
        assert lease.address == "127.0.0.1"
        assert lease.closed is False
    assert lease.closed is True
    assert (await guard.snapshot()).active_connections == 0


@pytest.mark.asyncio
async def test_connection_limits_are_independent_per_client() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy(max_connections_per_client=1))
    first = await guard.authorize_request("127.0.0.1", host())
    second = await guard.authorize_request("127.0.0.2", host())
    first_lease = await guard.acquire_connection(first.identity)
    second_lease = await guard.acquire_connection(second.identity)
    assert (await guard.snapshot()).active_connections == 2
    await first_lease.close()
    await second_lease.close()


@pytest.mark.asyncio
async def test_close_rejects_new_requests_and_connections() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy())
    identity = ControlPlaneClientIdentity(address="127.0.0.1", peer_address="127.0.0.1")
    await guard.close()
    with pytest.raises(ControlPlaneNetworkGuardClosedError):
        await guard.authorize_request("127.0.0.1", host())
    with pytest.raises(ControlPlaneNetworkGuardClosedError):
        await guard.acquire_connection(identity)
    assert (await guard.snapshot()).closed is True


@pytest.mark.asyncio
async def test_snapshot_contains_only_bounded_safe_counters() -> None:
    guard = ControlPlaneNetworkGuard(loopback_policy())
    with pytest.raises(ControlPlaneNetworkRejectedError):
        await guard.authorize_request("127.0.0.1", host("attacker.invalid"))
    snapshot = await guard.snapshot()
    rendered = repr(snapshot)
    assert "attacker.invalid" not in rendered
    assert snapshot.requests == snapshot.rejected == snapshot.host_rejections == 1
    assert snapshot.last_rejection is ControlPlaneNetworkRejectionReason.HOST
