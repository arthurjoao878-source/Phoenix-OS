"""Fail-closed browser destination admission for RFC-0035 S5."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from phoenix_os.browser_automation.contracts import BrowserProfileId
from phoenix_os.browser_automation.errors import (
    BrowserAutomationAdapterError,
    BrowserAutomationError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationRejectedError,
)
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserOrigin,
    BrowserProfile,
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


@runtime_checkable
class BrowserNetworkResolver(Protocol):
    """Reviewed resolver for one exact server-derived browser origin."""

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        """Return bounded literal addresses without granting browser authority."""
        ...


@dataclass(frozen=True, slots=True)
class BrowserDestinationAdmission:
    """Immutable literal destination pins for one exact browser profile generation."""

    profile_id: BrowserProfileId
    profile_generation: int
    origin: BrowserOrigin
    addresses: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, BrowserProfileId):
            raise TypeError("profile_id must be BrowserProfileId")
        if isinstance(self.profile_generation, bool) or not isinstance(
            self.profile_generation, int
        ):
            raise TypeError("profile_generation must be an integer")
        if not 1 <= self.profile_generation <= 2_147_483_647:
            raise ValueError("profile_generation is outside supported bounds")
        if not isinstance(self.origin, BrowserOrigin):
            raise TypeError("origin must be BrowserOrigin")
        if not isinstance(self.addresses, tuple):
            raise TypeError("addresses must be a tuple")
        if not self.addresses:
            raise ValueError("destination admission requires at least one address")

        normalized: list[_IpAddress] = []
        for item in self.addresses:
            if not isinstance(item, str):
                raise TypeError("destination addresses must be strings")
            address = _parse_literal(item)
            if _hard_forbidden(address):
                raise ValueError("destination admission contains a forbidden address")
            if self.origin.mode is BrowserDestinationMode.LOOPBACK_HTTP and not address.is_loopback:
                raise ValueError("loopback HTTP destination admission requires loopback addresses")
            normalized.append(address)

        if len(normalized) != len(set(normalized)):
            raise ValueError("destination admission addresses must be unique")

        ordered = tuple(address.compressed for address in sorted(normalized, key=_ip_sort_key))
        object.__setattr__(self, "addresses", ordered)

    @property
    def tls_server_name(self) -> str | None:
        """Preserve the canonical hostname required for hosted TLS verification."""

        if self.origin.mode is BrowserDestinationMode.HOSTED_HTTPS:
            return self.origin.host
        return None


def admit_browser_destination(
    profile: BrowserProfile,
    origin: BrowserOrigin,
    resolved_addresses: Sequence[str],
) -> BrowserDestinationAdmission:
    """Validate every resolved address and return exact immutable destination pins."""

    _require_profile_origin(profile, origin)

    if isinstance(resolved_addresses, (str, bytes)):
        raise TypeError("resolved_addresses must be a sequence of strings")

    supplied = tuple(resolved_addresses)
    if not supplied:
        raise BrowserAutomationRejectedError()
    if len(supplied) > profile.limits.max_resolved_addresses:
        raise BrowserAutomationLimitExceededError()

    parsed: set[_IpAddress] = set()
    for item in supplied:
        if not isinstance(item, str):
            raise TypeError("resolved addresses must be strings")
        address = _parse_literal(item)
        if _hard_forbidden(address):
            raise BrowserAutomationRejectedError()
        parsed.add(address)

    if not parsed:
        raise BrowserAutomationRejectedError()
    if len(parsed) > profile.limits.max_resolved_addresses:
        raise BrowserAutomationLimitExceededError()

    explicit_networks = tuple(
        ipaddress.ip_network(value) for value in profile.network_policy.allowed_networks
    )

    for address in parsed:
        if origin.mode is BrowserDestinationMode.LOOPBACK_HTTP:
            if not address.is_loopback:
                raise BrowserAutomationRejectedError()
            continue

        explicitly_allowed = any(
            address.version == network.version and address in network
            for network in explicit_networks
        )
        publicly_allowed = profile.network_policy.allow_public_networks and _public_unicast(address)
        if not (explicitly_allowed or publicly_allowed):
            raise BrowserAutomationRejectedError()

    ordered = tuple(address.compressed for address in sorted(parsed, key=_ip_sort_key))
    return BrowserDestinationAdmission(
        profile_id=profile.profile_id,
        profile_generation=profile.generation,
        origin=origin,
        addresses=ordered,
    )


async def resolve_and_admit_browser_destination(
    profile: BrowserProfile,
    origin: BrowserOrigin,
    *,
    resolver: BrowserNetworkResolver,
) -> BrowserDestinationAdmission:
    """Resolve through the reviewed resolver and admit the complete answer set."""

    _require_profile_origin(profile, origin)
    if not isinstance(resolver, BrowserNetworkResolver):
        raise TypeError("resolver must implement BrowserNetworkResolver")

    try:
        port = origin.port
        if port is None:  # pragma: no cover - BrowserOrigin invariant
            raise RuntimeError("validated browser origin has no port")
        supplied = await resolver.resolve(
            origin.host,
            port,
            max_addresses=profile.limits.max_resolved_addresses,
        )
    except asyncio.CancelledError:
        raise
    except BrowserAutomationError:
        raise
    except Exception:
        raise BrowserAutomationAdapterError() from None

    return admit_browser_destination(profile, origin, supplied)


def _require_profile_origin(profile: BrowserProfile, origin: BrowserOrigin) -> None:
    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")
    if not isinstance(origin, BrowserOrigin):
        raise TypeError("origin must be BrowserOrigin")
    if origin not in profile.allowed_origins:
        raise BrowserAutomationRejectedError()


def _parse_literal(value: str) -> _IpAddress:
    if not isinstance(value, str):
        raise TypeError("resolved address must be a string")
    if not value or "%" in value:
        raise BrowserAutomationRejectedError()
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise BrowserAutomationRejectedError() from None

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


def _ip_sort_key(address: _IpAddress) -> tuple[int, int]:
    return address.version, int(address)
