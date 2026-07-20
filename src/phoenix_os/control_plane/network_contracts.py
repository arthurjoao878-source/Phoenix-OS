"""Immutable contracts for secure Phoenix control-plane network exposure."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

MAX_CONTROL_PLANE_PROXY_HOPS = 32
MAX_CONTROL_PLANE_CONNECTIONS_PER_CLIENT = 1024

_DNS_NAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class ControlPlaneNetworkConfigurationError(ValueError):
    """Raised when a network-exposure contract fails closed validation."""


class ControlPlaneExposureMode(StrEnum):
    """Supported socket exposure modes for the control plane."""

    LOOPBACK = "loopback"
    REMOTE = "remote"


class ControlPlaneTlsMode(StrEnum):
    """Native TLS authentication modes for the control-plane listener."""

    DISABLED = "disabled"
    SERVER = "server"
    MUTUAL = "mutual"


class ControlPlaneTlsMinimumVersion(StrEnum):
    """Allowlisted minimum TLS protocol versions."""

    TLS_1_2 = "tls1.2"
    TLS_1_3 = "tls1.3"


class ControlPlaneProxyHeaderPolicy(StrEnum):
    """Exactly one allowlisted source for proxy client-address metadata."""

    DISABLED = "disabled"
    FORWARDED = "forwarded"
    X_FORWARDED_FOR = "x-forwarded-for"


class ControlPlaneClientIdentitySource(StrEnum):
    """Provenance of a validated client address."""

    DIRECT = "direct"
    FORWARDED = "forwarded"
    X_FORWARDED_FOR = "x-forwarded-for"


@dataclass(frozen=True, slots=True)
class ControlPlanePublicOrigin:
    """Canonical browser origin used for Host, cookie, and CSRF binding."""

    value: str

    def __post_init__(self) -> None:
        raw = self.value.strip()
        if raw != self.value or not raw:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin must not contain surrounding whitespace"
            )
        try:
            parsed = urlsplit(raw)
            port = parsed.port
        except ValueError as exception:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin contains an invalid port"
            ) from exception
        if parsed.scheme not in {"http", "https"}:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin must use http or https"
            )
        if parsed.username is not None or parsed.password is not None:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin must not contain user information"
            )
        if parsed.hostname is None:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin requires a hostname"
            )
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin must not contain a path, query, or fragment"
            )
        host = _normalize_origin_host(parsed.hostname)
        canonical_port = _canonical_origin_port(parsed.scheme, port)
        authority = _format_authority(host, canonical_port)
        object.__setattr__(self, "value", f"{parsed.scheme}://{authority}")

    @property
    def scheme(self) -> str:
        return urlsplit(self.value).scheme

    @property
    def host(self) -> str:
        host = urlsplit(self.value).hostname
        if host is None:  # pragma: no cover - protected by construction
            raise AssertionError("validated origin lost its hostname")
        return host

    @property
    def port(self) -> int:
        parsed = urlsplit(self.value)
        if parsed.port is not None:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @property
    def tls(self) -> bool:
        return self.scheme == "https"

    @property
    def loopback(self) -> bool:
        if self.host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ControlPlaneTlsPolicySnapshot:
    """Non-sensitive TLS policy facts safe for health snapshots."""

    mode: ControlPlaneTlsMode
    minimum_version: ControlPlaneTlsMinimumVersion
    mutual_tls: bool

    def __post_init__(self) -> None:
        mode = ControlPlaneTlsMode(self.mode)
        minimum = ControlPlaneTlsMinimumVersion(self.minimum_version)
        if self.mutual_tls is not (mode is ControlPlaneTlsMode.MUTUAL):
            raise ControlPlaneNetworkConfigurationError(
                "control-plane TLS snapshot mutual flag is inconsistent"
            )
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "minimum_version", minimum)


@dataclass(frozen=True, slots=True)
class ControlPlaneTlsPolicy:
    """Validated native TLS material references without key contents."""

    mode: ControlPlaneTlsMode = ControlPlaneTlsMode.DISABLED
    certificate_file: str | None = None
    private_key_file: str | None = field(default=None, repr=False)
    client_ca_file: str | None = None
    minimum_version: ControlPlaneTlsMinimumVersion = ControlPlaneTlsMinimumVersion.TLS_1_2

    def __post_init__(self) -> None:
        mode = ControlPlaneTlsMode(self.mode)
        minimum = ControlPlaneTlsMinimumVersion(self.minimum_version)
        certificate = _normalize_optional_absolute_path(
            self.certificate_file,
            "TLS certificate",
        )
        private_key = _normalize_optional_absolute_path(
            self.private_key_file,
            "TLS private key",
        )
        client_ca = _normalize_optional_absolute_path(
            self.client_ca_file,
            "TLS client CA",
        )
        if mode is ControlPlaneTlsMode.DISABLED:
            if any(value is not None for value in (certificate, private_key, client_ca)):
                raise ControlPlaneNetworkConfigurationError(
                    "disabled control-plane TLS must not reference certificate material"
                )
        elif mode is ControlPlaneTlsMode.SERVER:
            if certificate is None or private_key is None:
                raise ControlPlaneNetworkConfigurationError(
                    "server TLS requires certificate and private-key files"
                )
            if client_ca is not None:
                raise ControlPlaneNetworkConfigurationError(
                    "server TLS must not configure a client CA; use mutual TLS"
                )
        elif certificate is None or private_key is None or client_ca is None:
            raise ControlPlaneNetworkConfigurationError(
                "mutual TLS requires certificate, private-key, and client-CA files"
            )
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "minimum_version", minimum)
        object.__setattr__(self, "certificate_file", certificate)
        object.__setattr__(self, "private_key_file", private_key)
        object.__setattr__(self, "client_ca_file", client_ca)

    @property
    def enabled(self) -> bool:
        return self.mode is not ControlPlaneTlsMode.DISABLED

    @property
    def mutual_tls(self) -> bool:
        return self.mode is ControlPlaneTlsMode.MUTUAL

    def snapshot(self) -> ControlPlaneTlsPolicySnapshot:
        return ControlPlaneTlsPolicySnapshot(
            mode=self.mode,
            minimum_version=self.minimum_version,
            mutual_tls=self.mutual_tls,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneNetworkPolicySnapshot:
    """Non-sensitive validated network facts for diagnostics."""

    exposure: ControlPlaneExposureMode
    bind_host: str
    port: int
    public_origin: str
    tls: ControlPlaneTlsPolicySnapshot
    secure_cookies: bool
    allowed_client_networks: int
    trusted_proxy_networks: int
    proxy_headers: ControlPlaneProxyHeaderPolicy
    max_connections_per_client: int

    def __post_init__(self) -> None:
        exposure = ControlPlaneExposureMode(self.exposure)
        proxy_headers = ControlPlaneProxyHeaderPolicy(self.proxy_headers)
        _normalize_ip_address(self.bind_host, "snapshot bind host")
        ControlPlanePublicOrigin(self.public_origin)
        if self.port < 0 or self.port > 65535:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane network snapshot port is invalid"
            )
        if self.allowed_client_networks <= 0 or self.trusted_proxy_networks < 0:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane network snapshot counters are invalid"
            )
        if not 1 <= self.max_connections_per_client <= MAX_CONTROL_PLANE_CONNECTIONS_PER_CLIENT:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane per-client connection limit is invalid"
            )
        object.__setattr__(self, "exposure", exposure)
        object.__setattr__(self, "proxy_headers", proxy_headers)


@dataclass(frozen=True, slots=True)
class ControlPlaneNetworkPolicy:
    """Fail-closed exposure, TLS, origin, allowlist, and proxy policy."""

    exposure: ControlPlaneExposureMode = ControlPlaneExposureMode.LOOPBACK
    bind_host: str = "127.0.0.1"
    port: int = 0
    public_origin: ControlPlanePublicOrigin | str = "http://127.0.0.1"
    tls: ControlPlaneTlsPolicy = field(default_factory=ControlPlaneTlsPolicy)
    allowed_client_networks: tuple[str, ...] = ("127.0.0.0/8", "::1/128")
    trusted_proxy_networks: tuple[str, ...] = ()
    proxy_headers: ControlPlaneProxyHeaderPolicy = ControlPlaneProxyHeaderPolicy.DISABLED
    secure_cookies: bool = False
    max_connections_per_client: int = 16

    def __post_init__(self) -> None:
        exposure = ControlPlaneExposureMode(self.exposure)
        bind_host = _normalize_ip_address(self.bind_host, "bind host")
        origin = (
            self.public_origin
            if isinstance(self.public_origin, ControlPlanePublicOrigin)
            else ControlPlanePublicOrigin(self.public_origin)
        )
        tls = self.tls
        if not isinstance(tls, ControlPlaneTlsPolicy):
            raise ControlPlaneNetworkConfigurationError(
                "control-plane TLS policy must use ControlPlaneTlsPolicy"
            )
        allowed = _normalize_networks(self.allowed_client_networks, "allowed client")
        trusted = (
            ()
            if not self.trusted_proxy_networks
            else _normalize_networks(self.trusted_proxy_networks, "trusted proxy")
        )
        proxy_headers = ControlPlaneProxyHeaderPolicy(self.proxy_headers)
        if self.port < 0 or self.port > 65535:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane port must be between 0 and 65535"
            )
        if exposure is ControlPlaneExposureMode.REMOTE and self.port == 0:
            raise ControlPlaneNetworkConfigurationError(
                "remote control-plane exposure requires an explicit nonzero port"
            )
        if not 1 <= self.max_connections_per_client <= MAX_CONTROL_PLANE_CONNECTIONS_PER_CLIENT:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane max_connections_per_client must be between 1 and 1024"
            )
        if tls.enabled is not origin.tls:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public-origin scheme must match native TLS policy"
            )
        if self.secure_cookies is not origin.tls:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane Secure-cookie policy must match the public origin scheme"
            )
        if proxy_headers is ControlPlaneProxyHeaderPolicy.DISABLED:
            if trusted:
                raise ControlPlaneNetworkConfigurationError(
                    "trusted proxies require an enabled proxy-header policy"
                )
        elif not trusted:
            raise ControlPlaneNetworkConfigurationError(
                "enabled proxy headers require explicit trusted proxy networks"
            )
        if exposure is ControlPlaneExposureMode.LOOPBACK:
            if not ipaddress.ip_address(bind_host).is_loopback:
                raise ControlPlaneNetworkConfigurationError(
                    "loopback exposure requires a literal loopback bind address"
                )
            if not origin.loopback:
                raise ControlPlaneNetworkConfigurationError(
                    "loopback exposure requires a loopback public origin"
                )
            if any(not network.is_loopback for network in _parsed_networks(allowed)):
                raise ControlPlaneNetworkConfigurationError(
                    "loopback exposure may allow only loopback client networks"
                )
        else:
            if not tls.enabled or not origin.tls or not self.secure_cookies:
                raise ControlPlaneNetworkConfigurationError(
                    "remote exposure requires native TLS, HTTPS, and Secure cookies"
                )
            if origin.loopback:
                raise ControlPlaneNetworkConfigurationError(
                    "remote exposure requires a non-loopback public origin"
                )
        object.__setattr__(self, "exposure", exposure)
        object.__setattr__(self, "bind_host", bind_host)
        object.__setattr__(self, "public_origin", origin)
        object.__setattr__(self, "allowed_client_networks", allowed)
        object.__setattr__(self, "trusted_proxy_networks", trusted)
        object.__setattr__(self, "proxy_headers", proxy_headers)

    def allows_client(self, address: str) -> bool:
        candidate = ipaddress.ip_address(_normalize_ip_address(address, "client address"))
        return any(
            candidate in network for network in _parsed_networks(self.allowed_client_networks)
        )

    def trusts_proxy(self, address: str) -> bool:
        candidate = ipaddress.ip_address(_normalize_ip_address(address, "proxy address"))
        return any(
            candidate in network for network in _parsed_networks(self.trusted_proxy_networks)
        )

    def snapshot(self) -> ControlPlaneNetworkPolicySnapshot:
        return ControlPlaneNetworkPolicySnapshot(
            exposure=self.exposure,
            bind_host=self.bind_host,
            port=self.port,
            public_origin=str(self.public_origin),
            tls=self.tls.snapshot(),
            secure_cookies=self.secure_cookies,
            allowed_client_networks=len(self.allowed_client_networks),
            trusted_proxy_networks=len(self.trusted_proxy_networks),
            proxy_headers=self.proxy_headers,
            max_connections_per_client=self.max_connections_per_client,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneClientIdentity:
    """Canonical client identity after direct or trusted-proxy resolution."""

    address: str
    peer_address: str
    source: ControlPlaneClientIdentitySource = ControlPlaneClientIdentitySource.DIRECT
    forwarded_chain: tuple[str, ...] = ()
    trusted_proxy: bool = False

    def __post_init__(self) -> None:
        address = _normalize_ip_address(self.address, "client address")
        peer = _normalize_ip_address(self.peer_address, "peer address")
        source = ControlPlaneClientIdentitySource(self.source)
        chain = tuple(
            _normalize_ip_address(item, "forwarded client address") for item in self.forwarded_chain
        )
        if len(chain) > MAX_CONTROL_PLANE_PROXY_HOPS:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane forwarded chain exceeds the supported hop limit"
            )
        if source is ControlPlaneClientIdentitySource.DIRECT:
            if chain or self.trusted_proxy or address != peer:
                raise ControlPlaneNetworkConfigurationError(
                    "direct client identity must equal the peer and contain no proxy metadata"
                )
        else:
            if not self.trusted_proxy or not chain:
                raise ControlPlaneNetworkConfigurationError(
                    "forwarded client identity requires a trusted proxy and a nonempty chain"
                )
            if chain[0] != address:
                raise ControlPlaneNetworkConfigurationError(
                    "forwarded client identity must match the first forwarded address"
                )
        object.__setattr__(self, "address", address)
        object.__setattr__(self, "peer_address", peer)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "forwarded_chain", chain)

    @property
    def loopback(self) -> bool:
        return ipaddress.ip_address(self.address).is_loopback

    def allowed_by(self, policy: ControlPlaneNetworkPolicy) -> bool:
        if self.source is not ControlPlaneClientIdentitySource.DIRECT:
            if policy.proxy_headers.value != self.source.value:
                return False
            if not policy.trusts_proxy(self.peer_address):
                return False
        return policy.allows_client(self.address)


def _normalize_origin_host(value: str) -> str:
    host = value.strip().lower()
    if not host or "%" in host:
        raise ControlPlaneNetworkConfigurationError(
            "control-plane public origin contains an invalid hostname"
        )
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        if host == "localhost":
            return host
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exception:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin hostname cannot be normalized"
            ) from exception
        if _DNS_NAME_PATTERN.fullmatch(ascii_host) is None:
            raise ControlPlaneNetworkConfigurationError(
                "control-plane public origin contains an invalid DNS hostname"
            ) from None
        return ascii_host


def _canonical_origin_port(scheme: str, port: int | None) -> int | None:
    if port is None:
        return None
    if port <= 0 or port > 65535:
        raise ControlPlaneNetworkConfigurationError(
            "control-plane public origin port must be between 1 and 65535"
        )
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return None
    return port


def _format_authority(host: str, port: int | None) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        authority = host
    else:
        authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return authority if port is None else f"{authority}:{port}"


def _normalize_optional_absolute_path(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if normalized != value or not normalized or "\x00" in normalized:
        raise ControlPlaneNetworkConfigurationError(f"control-plane {label} path is invalid")
    if not (PurePosixPath(normalized).is_absolute() or PureWindowsPath(normalized).is_absolute()):
        raise ControlPlaneNetworkConfigurationError(f"control-plane {label} path must be absolute")
    return normalized


def _normalize_ip_address(value: str, label: str) -> str:
    normalized = value.strip()
    if normalized != value or not normalized or "%" in normalized:
        raise ControlPlaneNetworkConfigurationError(
            f"control-plane {label} must be a canonical IP literal"
        )
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError as exception:
        raise ControlPlaneNetworkConfigurationError(
            f"control-plane {label} must be an IP literal"
        ) from exception
    if normalized.lower() != address.compressed.lower():
        raise ControlPlaneNetworkConfigurationError(
            f"control-plane {label} must use canonical IP notation"
        )
    return address.compressed


def _normalize_networks(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not values:
        raise ControlPlaneNetworkConfigurationError(
            f"control-plane {label} networks must not be empty"
        )
    normalized: list[str] = []
    for value in values:
        candidate = value.strip()
        if candidate != value or not candidate or "%" in candidate:
            raise ControlPlaneNetworkConfigurationError(f"control-plane {label} network is invalid")
        try:
            network = ipaddress.ip_network(candidate, strict=True)
        except ValueError as exception:
            raise ControlPlaneNetworkConfigurationError(
                f"control-plane {label} networks must use canonical CIDR notation"
            ) from exception
        normalized.append(network.with_prefixlen)
    if len(normalized) != len(set(normalized)):
        raise ControlPlaneNetworkConfigurationError(
            f"control-plane {label} networks must be unique"
        )
    return tuple(
        sorted(
            normalized,
            key=lambda item: (
                ipaddress.ip_network(item).version,
                int(ipaddress.ip_network(item).network_address),
                ipaddress.ip_network(item).prefixlen,
            ),
        )
    )


def _parsed_networks(
    values: tuple[str, ...],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(value, strict=True) for value in values)
