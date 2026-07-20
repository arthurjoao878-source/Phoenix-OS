from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from phoenix_os.control_plane.network_contracts import (
    MAX_CONTROL_PLANE_CONNECTIONS_PER_CLIENT,
    MAX_CONTROL_PLANE_PROXY_HOPS,
    ControlPlaneClientIdentity,
    ControlPlaneClientIdentitySource,
    ControlPlaneExposureMode,
    ControlPlaneNetworkConfigurationError,
    ControlPlaneNetworkPolicy,
    ControlPlaneProxyHeaderPolicy,
    ControlPlanePublicOrigin,
    ControlPlaneTlsMinimumVersion,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
    ControlPlaneTlsPolicySnapshot,
)


def _server_tls() -> ControlPlaneTlsPolicy:
    return ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.SERVER,
        certificate_file="/etc/phoenix/tls/server.crt",
        private_key_file="/etc/phoenix/tls/server.key",
    )


def _remote_policy(**overrides: object) -> ControlPlaneNetworkPolicy:
    values: dict[str, object] = {
        "exposure": ControlPlaneExposureMode.REMOTE,
        "bind_host": "0.0.0.0",
        "port": 8443,
        "public_origin": "https://phoenix.example.test:8443",
        "tls": _server_tls(),
        "allowed_client_networks": ("10.0.0.0/8", "2001:db8::/32"),
        "secure_cookies": True,
    }
    values.update(overrides)
    return ControlPlaneNetworkPolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "canonical", "port", "loopback"),
    [
        ("http://127.0.0.1/", "http://127.0.0.1", 80, True),
        ("https://LOCALHOST:443", "https://localhost", 443, True),
        ("https://Example.COM:8443", "https://example.com:8443", 8443, False),
        ("https://[2001:db8::1]:9443", "https://[2001:db8::1]:9443", 9443, False),
    ],
)
def test_public_origin_is_canonical(
    raw: str,
    canonical: str,
    port: int,
    loopback: bool,
) -> None:
    origin = ControlPlanePublicOrigin(raw)
    assert str(origin) == canonical
    assert origin.port == port
    assert origin.loopback is loopback


@pytest.mark.parametrize(
    "value",
    [
        "",
        " https://example.com",
        "ftp://example.com",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?query=1",
        "https://example.com#fragment",
        "https://example.com:0",
        "https://example.com:65536",
        "https://bad_host.example",
        "https://[fe80::1%25eth0]",
    ],
)
def test_public_origin_rejects_ambiguous_values(value: str) -> None:
    with pytest.raises(ControlPlaneNetworkConfigurationError):
        ControlPlanePublicOrigin(value)


def test_tls_disabled_is_safe_default() -> None:
    policy = ControlPlaneTlsPolicy()
    assert policy.mode is ControlPlaneTlsMode.DISABLED
    assert policy.enabled is False
    assert policy.mutual_tls is False
    assert policy.snapshot() == ControlPlaneTlsPolicySnapshot(
        mode=ControlPlaneTlsMode.DISABLED,
        minimum_version=ControlPlaneTlsMinimumVersion.TLS_1_2,
        mutual_tls=False,
    )


def test_server_tls_accepts_windows_absolute_paths_and_redacts_key() -> None:
    policy = ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.SERVER,
        certificate_file=r"C:\Phoenix\tls\server.crt",
        private_key_file=r"C:\Phoenix\tls\server.key",
        minimum_version=ControlPlaneTlsMinimumVersion.TLS_1_3,
    )
    assert policy.enabled
    assert policy.minimum_version is ControlPlaneTlsMinimumVersion.TLS_1_3
    assert "server.key" not in repr(policy)


def test_mutual_tls_requires_all_material() -> None:
    policy = ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.MUTUAL,
        certificate_file="/tls/server.crt",
        private_key_file="/tls/server.key",
        client_ca_file="/tls/client-ca.crt",
    )
    assert policy.mutual_tls
    assert policy.snapshot().mutual_tls


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "disabled", "certificate_file": "/tls/cert"},
        {"mode": "server", "certificate_file": "/tls/cert"},
        {
            "mode": "server",
            "certificate_file": "/tls/cert",
            "private_key_file": "/tls/key",
            "client_ca_file": "/tls/ca",
        },
        {
            "mode": "mutual",
            "certificate_file": "/tls/cert",
            "private_key_file": "/tls/key",
        },
        {
            "mode": "server",
            "certificate_file": "relative/cert",
            "private_key_file": "/tls/key",
        },
        {
            "mode": "server",
            "certificate_file": "/tls/cert",
            "private_key_file": " /tls/key",
        },
    ],
)
def test_tls_policy_rejects_incomplete_or_ambiguous_material(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ControlPlaneNetworkConfigurationError):
        ControlPlaneTlsPolicy(**kwargs)  # type: ignore[arg-type]


def test_loopback_policy_defaults_fail_closed() -> None:
    policy = ControlPlaneNetworkPolicy()
    assert policy.exposure is ControlPlaneExposureMode.LOOPBACK
    assert policy.bind_host == "127.0.0.1"
    assert str(policy.public_origin) == "http://127.0.0.1"
    assert policy.allows_client("127.0.0.1")
    assert policy.allows_client("::1")
    assert not policy.allows_client("10.0.0.1")
    assert not policy.trusts_proxy("127.0.0.1")


def test_remote_policy_accepts_explicit_tls_and_allowlists() -> None:
    policy = _remote_policy()
    assert policy.exposure is ControlPlaneExposureMode.REMOTE
    assert policy.allowed_client_networks == ("10.0.0.0/8", "2001:db8::/32")
    assert policy.allows_client("10.23.4.5")
    assert policy.allows_client("2001:db8::5")
    assert not policy.allows_client("192.168.1.1")
    snapshot = policy.snapshot()
    assert snapshot.tls.mode is ControlPlaneTlsMode.SERVER
    assert snapshot.allowed_client_networks == 2
    assert snapshot.trusted_proxy_networks == 0


def test_remote_policy_accepts_explicit_forwarded_proxy_policy() -> None:
    policy = _remote_policy(
        trusted_proxy_networks=("10.255.0.0/16",),
        proxy_headers=ControlPlaneProxyHeaderPolicy.FORWARDED,
    )
    assert policy.trusts_proxy("10.255.2.3")
    assert not policy.trusts_proxy("10.254.2.3")


@pytest.mark.parametrize(
    "overrides",
    [
        {"port": 0},
        {"public_origin": "http://phoenix.example.test:8443"},
        {"public_origin": "https://localhost:8443"},
        {"tls": ControlPlaneTlsPolicy()},
        {"secure_cookies": False},
        {"bind_host": "phoenix.example.test"},
        {"allowed_client_networks": ()},
        {"allowed_client_networks": ("10.0.0.1/8",)},
        {"allowed_client_networks": ("10.0.0.0/8", "10.0.0.0/8")},
        {"trusted_proxy_networks": ("10.0.0.0/8",)},
        {"proxy_headers": "forwarded"},
        {"max_connections_per_client": 0},
        {"max_connections_per_client": MAX_CONTROL_PLANE_CONNECTIONS_PER_CLIENT + 1},
    ],
)
def test_remote_policy_rejects_unsafe_configuration(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ControlPlaneNetworkConfigurationError):
        _remote_policy(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"bind_host": "0.0.0.0"},
        {"public_origin": "http://example.test"},
        {"allowed_client_networks": ("0.0.0.0/0",)},
        {
            "public_origin": "https://localhost",
            "tls": _server_tls(),
            "secure_cookies": False,
        },
        {
            "public_origin": "http://localhost",
            "tls": _server_tls(),
            "secure_cookies": True,
        },
    ],
)
def test_loopback_policy_rejects_remote_or_inconsistent_configuration(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ControlPlaneNetworkConfigurationError):
        ControlPlaneNetworkPolicy(**overrides)  # type: ignore[arg-type]


def test_direct_client_identity_is_canonical_and_allowed() -> None:
    identity = ControlPlaneClientIdentity("127.0.0.1", "127.0.0.1")
    assert identity.source is ControlPlaneClientIdentitySource.DIRECT
    assert identity.loopback
    assert identity.allowed_by(ControlPlaneNetworkPolicy())


def test_forwarded_identity_is_allowed_only_for_matching_trusted_policy() -> None:
    policy = _remote_policy(
        trusted_proxy_networks=("192.0.2.0/24",),
        proxy_headers=ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR,
    )
    identity = ControlPlaneClientIdentity(
        address="10.1.2.3",
        peer_address="192.0.2.10",
        source=ControlPlaneClientIdentitySource.X_FORWARDED_FOR,
        forwarded_chain=("10.1.2.3", "198.51.100.7"),
        trusted_proxy=True,
    )
    assert identity.allowed_by(policy)
    mismatched = _remote_policy(
        trusted_proxy_networks=("192.0.2.0/24",),
        proxy_headers=ControlPlaneProxyHeaderPolicy.FORWARDED,
    )
    assert not identity.allowed_by(mismatched)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"address": "127.0.0.2", "peer_address": "127.0.0.1"},
        {
            "address": "10.0.0.1",
            "peer_address": "192.0.2.1",
            "source": "forwarded",
            "forwarded_chain": (),
            "trusted_proxy": True,
        },
        {
            "address": "10.0.0.1",
            "peer_address": "192.0.2.1",
            "source": "forwarded",
            "forwarded_chain": ("10.0.0.2",),
            "trusted_proxy": True,
        },
        {
            "address": "10.0.0.1",
            "peer_address": "192.0.2.1",
            "source": "forwarded",
            "forwarded_chain": ("10.0.0.1",),
            "trusted_proxy": False,
        },
        {
            "address": "10.0.0.1",
            "peer_address": "192.0.2.1",
            "source": "forwarded",
            "forwarded_chain": tuple("10.0.0.1" for _ in range(MAX_CONTROL_PLANE_PROXY_HOPS + 1)),
            "trusted_proxy": True,
        },
        {"address": "010.0.0.1", "peer_address": "010.0.0.1"},
        {"address": "fe80::1%eth0", "peer_address": "fe80::1%eth0"},
    ],
)
def test_client_identity_rejects_untrusted_or_ambiguous_provenance(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ControlPlaneNetworkConfigurationError):
        ControlPlaneClientIdentity(**kwargs)  # type: ignore[arg-type]


def test_contracts_are_immutable() -> None:
    policy = ControlPlaneNetworkPolicy()
    with pytest.raises(FrozenInstanceError):
        policy.port = 8080  # type: ignore[misc]
