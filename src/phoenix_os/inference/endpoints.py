"""Fail-closed endpoint admission without ambient HTTP clients or proxies."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

from phoenix_os.inference.errors import (
    InferenceEndpointRejectedError,
    InferenceEndpointRejectionCode,
)

MAX_MODEL_ENDPOINT_URL_LENGTH = 2_048
MAX_MODEL_ENDPOINT_NETWORKS = 64
MAX_MODEL_ENDPOINT_PORTS = 32
MAX_MODEL_RESOLVED_ADDRESSES = 32

type _IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type _IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ModelEndpointMode(StrEnum):
    HOSTED_HTTPS = "hosted_https"
    LOOPBACK_HTTP = "loopback_http"


@dataclass(frozen=True, slots=True)
class ModelEndpointPolicy:
    """Canonical endpoint and finite destination allowlist for one provider."""

    url: str
    mode: ModelEndpointMode = ModelEndpointMode.HOSTED_HTTPS
    allowed_ports: frozenset[int] = field(default_factory=frozenset)
    allowed_networks: tuple[str, ...] = ()
    allow_public_networks: bool | None = None
    max_resolved_addresses: int = 16

    def __post_init__(self) -> None:
        mode = ModelEndpointMode(self.mode)
        normalized_url = _normalize_endpoint_url(self.url, mode=mode)
        parsed = urlsplit(normalized_url)
        port = _endpoint_port(parsed.scheme, parsed.port)

        ports = frozenset(self.allowed_ports)
        if not ports:
            ports = frozenset({443 if mode is ModelEndpointMode.HOSTED_HTTPS else 80})
        if any(type(item) is not int for item in ports):
            raise TypeError("model endpoint ports must be integers")
        if not ports or len(ports) > MAX_MODEL_ENDPOINT_PORTS:
            raise ValueError("model endpoint policy has an invalid port count")
        if any(item <= 0 or item > 65_535 for item in ports):
            raise ValueError("model endpoint ports must be between 1 and 65535")
        if port not in ports:
            raise ValueError("model endpoint port is not allowlisted")

        networks = _normalize_networks(self.allowed_networks)
        allow_public = self.allow_public_networks
        if allow_public is None:
            allow_public = mode is ModelEndpointMode.HOSTED_HTTPS
        if not isinstance(allow_public, bool):
            raise TypeError("allow_public_networks must be a boolean")
        if mode is ModelEndpointMode.LOOPBACK_HTTP:
            if allow_public:
                raise ValueError("loopback endpoint cannot allow public networks")
            if networks:
                raise ValueError("loopback endpoint cannot configure non-loopback networks")

        if isinstance(self.max_resolved_addresses, bool) or not isinstance(
            self.max_resolved_addresses, int
        ):
            raise TypeError("max_resolved_addresses must be an integer")
        if not 1 <= self.max_resolved_addresses <= MAX_MODEL_RESOLVED_ADDRESSES:
            raise ValueError("max_resolved_addresses is outside supported bounds")

        object.__setattr__(self, "url", normalized_url)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "allowed_ports", ports)
        object.__setattr__(self, "allowed_networks", networks)
        object.__setattr__(self, "allow_public_networks", allow_public)

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @property
    def host(self) -> str:
        host = urlsplit(self.url).hostname
        if host is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("validated model endpoint has no host")
        return host

    @property
    def port(self) -> int:
        parsed = urlsplit(self.url)
        return _endpoint_port(parsed.scheme, parsed.port)

    @property
    def request_target(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def follow_redirects(self) -> bool:
        return False

    @property
    def use_proxy(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class ResolvedModelEndpoint:
    """Pinned literal destinations admitted for exactly one canonical endpoint."""

    policy: ModelEndpointPolicy
    addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ModelEndpointPolicy):
            raise TypeError("policy must be ModelEndpointPolicy")
        if not self.addresses:
            raise ValueError("resolved endpoint requires addresses")
        parsed = tuple(ipaddress.ip_address(item).compressed for item in self.addresses)
        if len(parsed) != len(set(parsed)):
            raise ValueError("resolved endpoint addresses must be unique")
        object.__setattr__(self, "addresses", parsed)

    @property
    def tls(self) -> bool:
        return self.policy.mode is ModelEndpointMode.HOSTED_HTTPS

    @property
    def server_hostname(self) -> str | None:
        return self.policy.host if self.tls else None

    @property
    def follow_redirects(self) -> bool:
        return False

    @property
    def use_proxy(self) -> bool:
        return False


def admit_model_endpoint(
    policy: ModelEndpointPolicy,
    resolved_addresses: Sequence[str],
) -> ResolvedModelEndpoint:
    """Validate all DNS answers and return only pinned literal destinations."""

    if not isinstance(policy, ModelEndpointPolicy):
        raise TypeError("policy must be ModelEndpointPolicy")
    if isinstance(resolved_addresses, (str, bytes)):
        raise TypeError("resolved_addresses must be a sequence of address strings")
    supplied = tuple(resolved_addresses)
    if not supplied:
        raise InferenceEndpointRejectedError(InferenceEndpointRejectionCode.DNS_NO_ADDRESSES)
    if len(supplied) > policy.max_resolved_addresses:
        raise InferenceEndpointRejectedError(InferenceEndpointRejectionCode.TOO_MANY_ADDRESSES)

    addresses: set[_IpAddress] = set()
    for item in supplied:
        if not isinstance(item, str):
            raise TypeError("resolved addresses must be strings")
        try:
            addresses.add(_effective_address(ipaddress.ip_address(item)))
        except ValueError as exception:
            raise InferenceEndpointRejectedError(
                InferenceEndpointRejectionCode.INVALID_ADDRESS
            ) from exception
    if not addresses:
        raise InferenceEndpointRejectedError(InferenceEndpointRejectionCode.DNS_NO_ADDRESSES)
    if len(addresses) > policy.max_resolved_addresses:
        raise InferenceEndpointRejectedError(InferenceEndpointRejectionCode.TOO_MANY_ADDRESSES)

    networks = tuple(ipaddress.ip_network(item) for item in policy.allowed_networks)
    for address in addresses:
        effective = _effective_address(address)
        if policy.mode is ModelEndpointMode.LOOPBACK_HTTP:
            if not effective.is_loopback:
                raise InferenceEndpointRejectedError(
                    InferenceEndpointRejectionCode.LOOPBACK_RESOLUTION_MISMATCH
                )
            continue

        explicit = any(
            effective.version == network.version and effective in network for network in networks
        )
        public = bool(policy.allow_public_networks) and effective.is_global
        if not (explicit or public):
            raise InferenceEndpointRejectedError(
                InferenceEndpointRejectionCode.DESTINATION_NOT_ALLOWED
            )

    ordered = tuple(item.compressed for item in sorted(addresses, key=_address_sort_key))
    return ResolvedModelEndpoint(policy=policy, addresses=ordered)


def _normalize_endpoint_url(value: str, *, mode: ModelEndpointMode) -> str:
    if not isinstance(value, str):
        raise TypeError("model endpoint url must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_MODEL_ENDPOINT_URL_LENGTH:
        raise ValueError("model endpoint url size is outside supported bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("model endpoint url contains control characters")

    parsed = urlsplit(normalized)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("model endpoint url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("model endpoint url must not contain query or fragment")
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("model endpoint url requires scheme and host")
    scheme = parsed.scheme.lower()
    expected = "https" if mode is ModelEndpointMode.HOSTED_HTTPS else "http"
    if scheme != expected:
        raise ValueError(f"{mode.value} requires {expected}")

    host = parsed.hostname.lower()
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exception:
        raise ValueError("model endpoint host must be ASCII") from exception
    if "%" in host:
        raise ValueError("model endpoint host must not contain a zone identifier")
    try:
        port = parsed.port
    except ValueError as exception:
        raise ValueError("model endpoint port is invalid") from exception

    path = parsed.path or "/"
    if not path.startswith("/"):
        raise ValueError("model endpoint path must be absolute")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise ValueError("model endpoint path contains control characters")

    rendered_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = rendered_host if port in {None, default_port} else f"{rendered_host}:{port}"
    return urlunsplit((scheme, netloc, path, "", ""))


def _normalize_networks(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError("allowed_networks must be a tuple")
    if len(values) > MAX_MODEL_ENDPOINT_NETWORKS:
        raise ValueError("model endpoint policy contains too many networks")
    normalized: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise TypeError("model endpoint networks must be strings")
        try:
            network = ipaddress.ip_network(item.strip(), strict=True)
        except ValueError as exception:
            raise ValueError("model endpoint network is invalid") from exception
        normalized.add(network.with_prefixlen)
    return tuple(sorted(normalized, key=_network_sort_key))


def _endpoint_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def _effective_address(address: _IpAddress) -> _IpAddress:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _address_sort_key(address: _IpAddress) -> tuple[int, int]:
    effective = _effective_address(address)
    return effective.version, int(effective)


def _network_sort_key(value: str) -> tuple[int, int, int]:
    network = ipaddress.ip_network(value)
    return network.version, int(network.network_address), network.prefixlen
