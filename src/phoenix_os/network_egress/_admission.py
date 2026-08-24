"""DNS resolution and fail-closed literal destination admission for RFC-0034."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from phoenix_os.network_egress._errors import (
    NetworkDestinationRejectedError,
    NetworkTransportError,
)
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
)

type _IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_AUTO_PUBLIC_DENY_NETWORKS_V4 = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)

_AUTO_PUBLIC_DENY_NETWORKS_V6 = (
    ipaddress.IPv6Network("::/96"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("2001::/23"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("2002::/16"),
    ipaddress.IPv6Network("3fff::/20"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fec0::/10"),
    ipaddress.IPv6Network("ff00::/8"),
)


class NetworkResolver(Protocol):
    """Resolve one canonical server-owned host into bounded literal address strings."""

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]: ...


class AsyncioNetworkResolver:
    """System DNS adapter that returns only normalized unique IP literals."""

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        if isinstance(max_addresses, bool) or not isinstance(max_addresses, int):
            raise TypeError("max_addresses must be an integer")
        if max_addresses <= 0:
            raise ValueError("max_addresses must be positive")

        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        if len(records) > max_addresses:
            raise NetworkDestinationRejectedError("too_many_addresses")

        addresses: set[str] = set()
        for family, _kind, _protocol, _canonical, sockaddr in records:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            value = sockaddr[0]
            if not isinstance(value, str):
                continue
            address = _parse_literal(value)
            addresses.add(address.compressed)

        if not addresses:
            raise NetworkTransportError("dns_no_addresses", request_started=False)
        if len(addresses) > max_addresses:
            raise NetworkDestinationRejectedError("too_many_addresses")
        return tuple(sorted(addresses, key=_address_sort_key))


@dataclass(frozen=True, slots=True)
class NetworkDestinationAdmission:
    """Exact immutable destination pins for one profile generation and operation."""

    profile_id: NetworkEgressProfileId
    generation: int
    operation_id: NetworkEgressOperationId
    mode: NetworkDestinationMode
    host: str
    port: int
    addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, NetworkEgressProfileId):
            raise TypeError("profile_id must be NetworkEgressProfileId")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int):
            raise TypeError("generation must be an integer")
        if self.generation <= 0:
            raise ValueError("generation must be positive")
        if not isinstance(self.operation_id, NetworkEgressOperationId):
            raise TypeError("operation_id must be NetworkEgressOperationId")
        mode = NetworkDestinationMode(self.mode)
        if not isinstance(self.host, str) or not self.host:
            raise ValueError("host must be a canonical non-empty string")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("port must be an integer")
        if not 1 <= self.port <= 65_535:
            raise ValueError("port is outside supported bounds")
        if not isinstance(self.addresses, tuple):
            raise TypeError("addresses must be a tuple")
        if not self.addresses:
            raise ValueError("destination admission requires at least one address")

        normalized: list[str] = []
        for item in self.addresses:
            if not isinstance(item, str):
                raise TypeError("destination addresses must be strings")
            address = _parse_literal(item)
            if _hard_forbidden(address):
                raise ValueError("destination admission contains a forbidden address")
            normalized.append(address.compressed)
        if len(normalized) != len(set(normalized)):
            raise ValueError("destination admission addresses must be unique")

        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "addresses", tuple(normalized))


def _require_profile_operation(
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
) -> None:
    if not isinstance(profile, NetworkEgressProfile):
        raise TypeError("profile must be NetworkEgressProfile")
    if not isinstance(operation, NetworkEgressOperation):
        raise TypeError("operation must be NetworkEgressOperation")
    try:
        configured = profile.require_operation(operation.operation_id)
    except KeyError as exception:
        raise NetworkDestinationRejectedError("operation_mismatch") from exception
    if configured != operation:
        raise NetworkDestinationRejectedError("operation_mismatch")


def admit_network_destination(
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
    resolved_addresses: Sequence[str],
) -> NetworkDestinationAdmission:
    """Validate the complete DNS answer set and return immutable literal pins."""

    _require_profile_operation(profile, operation)
    if isinstance(resolved_addresses, (str, bytes)):
        raise TypeError("resolved_addresses must be a sequence of strings")
    supplied = tuple(resolved_addresses)
    if not supplied:
        raise NetworkTransportError("dns_no_addresses", request_started=False)
    if len(supplied) > operation.limits.max_resolved_addresses:
        raise NetworkDestinationRejectedError("too_many_addresses")

    parsed: set[_IpAddress] = set()
    for item in supplied:
        if not isinstance(item, str):
            raise TypeError("resolved addresses must be strings")
        address = _parse_literal(item)
        if _hard_forbidden(address):
            raise NetworkDestinationRejectedError("destination_not_allowed")
        parsed.add(address)

    if not parsed:
        raise NetworkTransportError("dns_no_addresses", request_started=False)
    if len(parsed) > operation.limits.max_resolved_addresses:
        raise NetworkDestinationRejectedError("too_many_addresses")

    networks = tuple(ipaddress.ip_network(value) for value in profile.allowed_networks)
    for address in parsed:
        if profile.mode is NetworkDestinationMode.LOOPBACK_HTTP:
            if not address.is_loopback:
                raise NetworkDestinationRejectedError("loopback_resolution_mismatch")
            continue

        explicit = any(
            address.version == network.version and address in network for network in networks
        )
        public = bool(profile.allow_public_networks) and _public_unicast(address)
        if not (explicit or public):
            raise NetworkDestinationRejectedError("destination_not_allowed")

    ordered = tuple(item.compressed for item in sorted(parsed, key=_ip_sort_key))
    port = profile.port
    if port is None:  # pragma: no cover - NetworkEgressProfile invariant
        raise RuntimeError("validated network profile has no port")
    return NetworkDestinationAdmission(
        profile_id=profile.profile_id,
        generation=profile.generation,
        operation_id=operation.operation_id,
        mode=profile.mode,
        host=profile.host,
        port=port,
        addresses=ordered,
    )


async def resolve_and_admit_network_destination(
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
    *,
    resolver: NetworkResolver | None = None,
) -> NetworkDestinationAdmission:
    """Resolve once, validate every answer, and pin the exact admitted literals."""

    _require_profile_operation(profile, operation)
    selected_resolver = AsyncioNetworkResolver() if resolver is None else resolver

    try:
        literal = _parse_literal(profile.host)
    except NetworkDestinationRejectedError:
        literal = None

    supplied: tuple[str, ...]
    if literal is not None:
        supplied = (literal.compressed,)
    else:
        port = profile.port
        if port is None:  # pragma: no cover - NetworkEgressProfile invariant
            raise RuntimeError("validated network profile has no port")
        try:
            async with asyncio.timeout(operation.limits.total_timeout_seconds):
                supplied = await selected_resolver.resolve(
                    profile.host,
                    port,
                    max_addresses=operation.limits.max_resolved_addresses,
                )
        except asyncio.CancelledError:
            raise
        except NetworkDestinationRejectedError:
            raise
        except NetworkTransportError:
            raise
        except TimeoutError as exception:
            raise NetworkTransportError(
                "dns_timeout",
                request_started=False,
            ) from exception
        except OSError as exception:
            raise NetworkTransportError(
                "dns_failed",
                request_started=False,
            ) from exception
        except Exception as exception:
            raise NetworkTransportError(
                "dns_failed",
                request_started=False,
            ) from exception

    return admit_network_destination(profile, operation, supplied)


def _parse_literal(value: str) -> _IpAddress:
    if "%" in value:
        raise NetworkDestinationRejectedError("invalid_resolved_address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exception:
        raise NetworkDestinationRejectedError("invalid_resolved_address") from exception
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _hard_forbidden(address: _IpAddress) -> bool:
    return address.is_unspecified or address.is_multicast


def _public_unicast(address: _IpAddress) -> bool:
    denied = (
        _AUTO_PUBLIC_DENY_NETWORKS_V4
        if isinstance(address, ipaddress.IPv4Address)
        else _AUTO_PUBLIC_DENY_NETWORKS_V6
    )
    if any(address in network for network in denied):
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.is_site_local:
        return False
    return (
        address.is_global
        and not address.is_private
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_multicast
        and not address.is_loopback
        and not address.is_link_local
    )


def _address_sort_key(value: str) -> tuple[int, int]:
    return _ip_sort_key(_parse_literal(value))


def _ip_sort_key(address: _IpAddress) -> tuple[int, int]:
    return address.version, int(address)
