"""Fail-closed remote client resolution and bounded abuse controls."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, Self

from phoenix_os.control_plane.errors import (
    ControlPlaneNetworkGuardClosedError,
    ControlPlaneNetworkRejectedError,
)
from phoenix_os.control_plane.network_contracts import (
    MAX_CONTROL_PLANE_PROXY_HOPS,
    ControlPlaneClientIdentity,
    ControlPlaneClientIdentitySource,
    ControlPlaneNetworkPolicy,
    ControlPlaneProxyHeaderPolicy,
    ControlPlanePublicOrigin,
)

DEFAULT_CONTROL_PLANE_CLIENT_RATE_LIMIT = 120
DEFAULT_CONTROL_PLANE_CLIENT_RATE_WINDOW = 60.0
DEFAULT_CONTROL_PLANE_CLIENT_RATE_CAPACITY = 4096
MAX_CONTROL_PLANE_CLIENT_RATE_LIMIT = 100_000
MAX_CONTROL_PLANE_CLIENT_RATE_WINDOW = 3600.0
MAX_CONTROL_PLANE_CLIENT_RATE_CAPACITY = 100_000
MAX_CONTROL_PLANE_NETWORK_HEADER_BYTES = 4096
MAX_CONTROL_PLANE_HOST_BYTES = 512

_HEADER_NAME_PATTERN = re.compile(r"[!#$%&'*+.^_`|~0-9a-z-]{1,64}\Z")
_PARAMETER_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


class ControlPlaneNetworkRejectionReason(StrEnum):
    """Allowlisted internal reason categories without request content."""

    HOST = "host"
    ORIGIN = "origin"
    PROXY = "proxy"
    ALLOWLIST = "allowlist"
    RATE_LIMIT = "rate-limit"
    CONNECTION_LIMIT = "connection-limit"


class ControlPlaneNetworkClock(Protocol):
    """Monotonic time source used by per-client request limits."""

    def now(self) -> float: ...


class _SystemNetworkClock:
    def now(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class ControlPlaneClientRateLimitPolicy:
    """Bounded fixed-window request policy keyed by canonical client IP."""

    requests: int = DEFAULT_CONTROL_PLANE_CLIENT_RATE_LIMIT
    window: float = DEFAULT_CONTROL_PLANE_CLIENT_RATE_WINDOW
    capacity: int = DEFAULT_CONTROL_PLANE_CLIENT_RATE_CAPACITY

    def __post_init__(self) -> None:
        if not 1 <= self.requests <= MAX_CONTROL_PLANE_CLIENT_RATE_LIMIT:
            raise ValueError("control-plane client request limit is outside supported bounds")
        if (
            not math.isfinite(self.window)
            or not 0 < self.window <= MAX_CONTROL_PLANE_CLIENT_RATE_WINDOW
        ):
            raise ValueError("control-plane client rate window is outside supported bounds")
        if not 1 <= self.capacity <= MAX_CONTROL_PLANE_CLIENT_RATE_CAPACITY:
            raise ValueError("control-plane client rate capacity is outside supported bounds")


@dataclass(frozen=True, slots=True)
class ControlPlaneNetworkRequestContext:
    """Validated network facts attached to one accepted HTTP request."""

    identity: ControlPlaneClientIdentity
    host: str
    origin: str | None

    def __post_init__(self) -> None:
        host = self.host.strip().lower()
        if not host or host != self.host:
            raise ValueError("validated control-plane Host must be canonical")
        if self.origin is not None:
            origin = str(ControlPlanePublicOrigin(self.origin))
            if origin != self.origin:
                raise ValueError("validated control-plane Origin must be canonical")
        object.__setattr__(self, "host", host)


@dataclass(frozen=True, slots=True)
class ControlPlaneNetworkGuardSnapshot:
    """Non-sensitive request, rejection, and connection counters."""

    closed: bool
    requests: int
    accepted: int
    rejected: int
    host_rejections: int
    origin_rejections: int
    proxy_rejections: int
    allowlist_rejections: int
    rate_limit_rejections: int
    connection_limit_rejections: int
    active_connections: int
    tracked_clients: int
    rate_limit_capacity: int
    last_rejection: ControlPlaneNetworkRejectionReason | None = None

    def __post_init__(self) -> None:
        counters = (
            self.requests,
            self.accepted,
            self.rejected,
            self.host_rejections,
            self.origin_rejections,
            self.proxy_rejections,
            self.allowlist_rejections,
            self.rate_limit_rejections,
            self.connection_limit_rejections,
            self.active_connections,
            self.tracked_clients,
        )
        if any(value < 0 for value in counters):
            raise ValueError("control-plane network guard counters cannot be negative")
        request_rejections = (
            self.host_rejections
            + self.origin_rejections
            + self.proxy_rejections
            + self.allowlist_rejections
            + self.rate_limit_rejections
        )
        if self.accepted + request_rejections != self.requests:
            raise ValueError("control-plane network request counters are inconsistent")
        rejection_total = (
            self.host_rejections
            + self.origin_rejections
            + self.proxy_rejections
            + self.allowlist_rejections
            + self.rate_limit_rejections
            + self.connection_limit_rejections
        )
        if rejection_total != self.rejected:
            raise ValueError("control-plane network rejection counters are inconsistent")
        if not 1 <= self.rate_limit_capacity <= MAX_CONTROL_PLANE_CLIENT_RATE_CAPACITY:
            raise ValueError("control-plane network rate-limit capacity is invalid")
        if self.tracked_clients > self.rate_limit_capacity:
            raise ValueError("tracked control-plane clients exceed configured capacity")
        rejection = (
            None
            if self.last_rejection is None
            else ControlPlaneNetworkRejectionReason(self.last_rejection)
        )
        object.__setattr__(self, "last_rejection", rejection)


class ControlPlaneClientConnectionLease:
    """One idempotently releasable per-client connection reservation."""

    __slots__ = ("_address", "_closed", "_guard")

    def __init__(self, guard: ControlPlaneNetworkGuard, address: str) -> None:
        self._guard = guard
        self._address = address
        self._closed = False

    @property
    def address(self) -> str:
        return self._address

    @property
    def closed(self) -> bool:
        return self._closed

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._guard._release_connection(self._address)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        await self.close()


class ControlPlaneNetworkGuard:
    """Validate Host, Origin, proxy provenance, allowlists, and client limits."""

    def __init__(
        self,
        policy: ControlPlaneNetworkPolicy,
        *,
        rate_limit: ControlPlaneClientRateLimitPolicy | None = None,
        clock: ControlPlaneNetworkClock | None = None,
    ) -> None:
        self._policy = policy
        self._rate_limit = rate_limit or ControlPlaneClientRateLimitPolicy()
        self._clock = clock or _SystemNetworkClock()
        self._closed = False
        self._requests = 0
        self._accepted = 0
        self._rejections = {reason: 0 for reason in ControlPlaneNetworkRejectionReason}
        self._last_rejection: ControlPlaneNetworkRejectionReason | None = None
        self._rate_buckets: dict[str, deque[float]] = {}
        self._active_by_client: dict[str, int] = {}
        self._active_connections = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def policy(self) -> ControlPlaneNetworkPolicy:
        return self._policy

    async def authorize_request(
        self,
        peer_address: str,
        headers: Mapping[str, str | tuple[str, ...]],
        *,
        require_origin: bool = False,
    ) -> ControlPlaneNetworkRequestContext:
        """Resolve and admit one HTTP request or fail with a generic rejection."""

        try:
            normalized = _normalize_headers(headers)
            host = _validate_host(self._policy, normalized)
            origin = _validate_origin(self._policy, normalized, required=require_origin)
            identity = _resolve_identity(self._policy, peer_address, normalized)
            if not identity.allowed_by(self._policy):
                raise _NetworkRejection(ControlPlaneNetworkRejectionReason.ALLOWLIST)
            await self._consume_request(identity.address)
        except _NetworkRejection as exception:
            await self._record_rejection(exception.reason)
            raise ControlPlaneNetworkRejectedError(
                "control-plane network request rejected"
            ) from None
        async with self._lock:
            if self._closed:
                raise ControlPlaneNetworkGuardClosedError("control-plane network guard is closed")
            self._requests += 1
            self._accepted += 1
        return ControlPlaneNetworkRequestContext(identity=identity, host=host, origin=origin)

    async def acquire_connection(
        self,
        identity: ControlPlaneClientIdentity,
    ) -> ControlPlaneClientConnectionLease:
        """Reserve one connection slot for an already validated client identity."""

        address = identity.address
        async with self._lock:
            if self._closed:
                raise ControlPlaneNetworkGuardClosedError("control-plane network guard is closed")
            active = self._active_by_client.get(address, 0)
            if active >= self._policy.max_connections_per_client:
                self._rejections[ControlPlaneNetworkRejectionReason.CONNECTION_LIMIT] += 1
                self._last_rejection = ControlPlaneNetworkRejectionReason.CONNECTION_LIMIT
                raise ControlPlaneNetworkRejectedError(
                    "control-plane network request rejected"
                ) from None
            self._active_by_client[address] = active + 1
            self._active_connections += 1
        return ControlPlaneClientConnectionLease(self, address)

    async def snapshot(self) -> ControlPlaneNetworkGuardSnapshot:
        async with self._lock:
            self._purge_expired_buckets(self._clock.now())
            rejection_total = sum(self._rejections.values())
            return ControlPlaneNetworkGuardSnapshot(
                closed=self._closed,
                requests=self._requests,
                accepted=self._accepted,
                rejected=rejection_total,
                host_rejections=self._rejections[ControlPlaneNetworkRejectionReason.HOST],
                origin_rejections=self._rejections[ControlPlaneNetworkRejectionReason.ORIGIN],
                proxy_rejections=self._rejections[ControlPlaneNetworkRejectionReason.PROXY],
                allowlist_rejections=self._rejections[ControlPlaneNetworkRejectionReason.ALLOWLIST],
                rate_limit_rejections=self._rejections[
                    ControlPlaneNetworkRejectionReason.RATE_LIMIT
                ],
                connection_limit_rejections=self._rejections[
                    ControlPlaneNetworkRejectionReason.CONNECTION_LIMIT
                ],
                active_connections=self._active_connections,
                tracked_clients=len(self._rate_buckets),
                rate_limit_capacity=self._rate_limit.capacity,
                last_rejection=self._last_rejection,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._rate_buckets.clear()

    async def _consume_request(self, address: str) -> None:
        now = self._clock.now()
        if not math.isfinite(now):
            raise RuntimeError("control-plane network clock returned a non-finite value")
        async with self._lock:
            if self._closed:
                raise ControlPlaneNetworkGuardClosedError("control-plane network guard is closed")
            self._purge_expired_buckets(now)
            bucket = self._rate_buckets.get(address)
            if bucket is None:
                if len(self._rate_buckets) >= self._rate_limit.capacity:
                    raise _NetworkRejection(ControlPlaneNetworkRejectionReason.RATE_LIMIT)
                bucket = deque()
                self._rate_buckets[address] = bucket
            cutoff = now - self._rate_limit.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._rate_limit.requests:
                raise _NetworkRejection(ControlPlaneNetworkRejectionReason.RATE_LIMIT)
            bucket.append(now)

    async def _record_rejection(self, reason: ControlPlaneNetworkRejectionReason) -> None:
        async with self._lock:
            if self._closed:
                raise ControlPlaneNetworkGuardClosedError("control-plane network guard is closed")
            self._requests += 1
            self._rejections[reason] += 1
            self._last_rejection = reason

    async def _release_connection(self, address: str) -> None:
        async with self._lock:
            active = self._active_by_client.get(address)
            if active is None or active <= 0:
                raise RuntimeError("control-plane connection lease accounting is inconsistent")
            if active == 1:
                del self._active_by_client[address]
            else:
                self._active_by_client[address] = active - 1
            self._active_connections -= 1

    def _purge_expired_buckets(self, now: float) -> None:
        cutoff = now - self._rate_limit.window
        expired: list[str] = []
        for address, bucket in self._rate_buckets.items():
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                expired.append(address)
        for address in expired:
            del self._rate_buckets[address]


@dataclass(frozen=True, slots=True)
class _NetworkRejection(Exception):
    reason: ControlPlaneNetworkRejectionReason


def _normalize_headers(
    headers: Mapping[str, str | tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    normalized: dict[str, tuple[str, ...]] = {}
    for raw_name, raw_values in headers.items():
        if raw_name != raw_name.strip():
            raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
        name = raw_name.lower()
        if _HEADER_NAME_PATTERN.fullmatch(name) is None:
            raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
        values = (raw_values,) if isinstance(raw_values, str) else tuple(raw_values)
        if name in normalized:
            raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
        checked: list[str] = []
        for value in values:
            if not isinstance(value, str):
                raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
            if len(value.encode("utf-8")) > MAX_CONTROL_PLANE_NETWORK_HEADER_BYTES:
                raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
            if "\r" in value or "\n" in value or "\x00" in value:
                raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
            checked.append(value)
        normalized[name] = tuple(checked)
    return normalized


def _validate_host(
    policy: ControlPlaneNetworkPolicy,
    headers: Mapping[str, tuple[str, ...]],
) -> str:
    values = headers.get("host", ())
    if len(values) != 1:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.HOST)
    raw = values[0]
    if (
        not raw
        or raw != raw.strip()
        or len(raw.encode("ascii", errors="ignore")) != len(raw)
        or len(raw) > MAX_CONTROL_PLANE_HOST_BYTES
        or any(
            character.isspace() or ord(character) < 33 or ord(character) == 127 for character in raw
        )
        or any(character in raw for character in "/\\@,#?")
    ):
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.HOST)
    public_origin = policy.public_origin
    if not isinstance(public_origin, ControlPlanePublicOrigin):  # pragma: no cover
        raise AssertionError("validated network policy lost its public-origin contract")
    try:
        candidate = ControlPlanePublicOrigin(f"{public_origin.scheme}://{raw}")
    except ValueError:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.HOST) from None
    if candidate != public_origin:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.HOST)
    return candidate.value.split("://", 1)[1]


def _validate_origin(
    policy: ControlPlaneNetworkPolicy,
    headers: Mapping[str, tuple[str, ...]],
    *,
    required: bool,
) -> str | None:
    values = headers.get("origin", ())
    if not values:
        if required:
            raise _NetworkRejection(ControlPlaneNetworkRejectionReason.ORIGIN)
        return None
    if len(values) != 1:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.ORIGIN)
    raw = values[0]
    if not raw or raw != raw.strip() or len(raw.encode("utf-8")) > MAX_CONTROL_PLANE_HOST_BYTES:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.ORIGIN)
    try:
        candidate = ControlPlanePublicOrigin(raw)
    except ValueError:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.ORIGIN) from None
    public_origin = policy.public_origin
    if not isinstance(public_origin, ControlPlanePublicOrigin):  # pragma: no cover
        raise AssertionError("validated network policy lost its public-origin contract")
    if candidate != public_origin:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.ORIGIN)
    return str(candidate)


def _resolve_identity(
    policy: ControlPlaneNetworkPolicy,
    peer_address: str,
    headers: Mapping[str, tuple[str, ...]],
) -> ControlPlaneClientIdentity:
    try:
        peer = ipaddress.ip_address(peer_address.strip()).compressed
    except ValueError:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY) from None
    forwarded = headers.get("forwarded", ())
    x_forwarded_for = headers.get("x-forwarded-for", ())
    if forwarded and x_forwarded_for:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
    supplied_policy = (
        ControlPlaneProxyHeaderPolicy.FORWARDED
        if forwarded
        else ControlPlaneProxyHeaderPolicy.X_FORWARDED_FOR
        if x_forwarded_for
        else ControlPlaneProxyHeaderPolicy.DISABLED
    )
    if supplied_policy is ControlPlaneProxyHeaderPolicy.DISABLED:
        return ControlPlaneClientIdentity(address=peer, peer_address=peer)
    if policy.proxy_headers is ControlPlaneProxyHeaderPolicy.DISABLED:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
    if supplied_policy is not policy.proxy_headers or not policy.trusts_proxy(peer):
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
    values = forwarded if forwarded else x_forwarded_for
    if len(values) != 1:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY)
    try:
        chain = (
            _parse_forwarded(values[0])
            if supplied_policy is ControlPlaneProxyHeaderPolicy.FORWARDED
            else _parse_x_forwarded_for(values[0])
        )
    except ValueError:
        raise _NetworkRejection(ControlPlaneNetworkRejectionReason.PROXY) from None
    resolved = _resolve_trusted_suffix(policy, peer, chain)
    source = (
        ControlPlaneClientIdentitySource.FORWARDED
        if supplied_policy is ControlPlaneProxyHeaderPolicy.FORWARDED
        else ControlPlaneClientIdentitySource.X_FORWARDED_FOR
    )
    return ControlPlaneClientIdentity(
        address=resolved[0],
        peer_address=peer,
        source=source,
        forwarded_chain=resolved,
        trusted_proxy=True,
    )


def _resolve_trusted_suffix(
    policy: ControlPlaneNetworkPolicy,
    peer: str,
    chain: tuple[str, ...],
) -> tuple[str, ...]:
    if not chain or len(chain) > MAX_CONTROL_PLANE_PROXY_HOPS:
        raise ValueError("forwarded chain length is invalid")
    downstream = peer
    start = len(chain) - 1
    for index in range(len(chain) - 1, -1, -1):
        if not policy.trusts_proxy(downstream):
            break
        start = index
        downstream = chain[index]
        if not policy.trusts_proxy(downstream):
            break
    return chain[start:]


def _parse_x_forwarded_for(value: str) -> tuple[str, ...]:
    parts = value.split(",")
    if not parts or len(parts) > MAX_CONTROL_PLANE_PROXY_HOPS:
        raise ValueError("X-Forwarded-For chain length is invalid")
    return tuple(_parse_ip_literal(part.strip(), allow_ipv4_port=False) for part in parts)


def _parse_forwarded(value: str) -> tuple[str, ...]:
    elements = _split_quoted(value, ",")
    if not elements or len(elements) > MAX_CONTROL_PLANE_PROXY_HOPS:
        raise ValueError("Forwarded chain length is invalid")
    chain: list[str] = []
    for element in elements:
        parameters = _split_quoted(element, ";")
        seen: set[str] = set()
        forwarded_for: str | None = None
        for parameter in parameters:
            if "=" not in parameter:
                raise ValueError("Forwarded parameter is malformed")
            raw_name, raw_value = parameter.split("=", 1)
            name = raw_name.strip().lower()
            if _PARAMETER_NAME_PATTERN.fullmatch(name) is None or name in seen:
                raise ValueError("Forwarded parameter name is invalid")
            seen.add(name)
            decoded = _decode_forwarded_value(raw_value.strip())
            if not decoded:
                raise ValueError("Forwarded parameter value is empty")
            if name == "for":
                forwarded_for = _parse_forwarded_node(decoded)
        if forwarded_for is None:
            raise ValueError("Forwarded element requires exactly one for parameter")
        chain.append(forwarded_for)
    return tuple(chain)


def _split_quoted(value: str, delimiter: str) -> tuple[str, ...]:
    if not value or len(value.encode("utf-8")) > MAX_CONTROL_PLANE_NETWORK_HEADER_BYTES:
        raise ValueError("proxy header is empty or too large")
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quoted and character == "\\":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if character == delimiter and not quoted:
            part = value[start:index].strip()
            if not part:
                raise ValueError("proxy header contains an empty element")
            parts.append(part)
            start = index + 1
    if quoted or escaped:
        raise ValueError("proxy header contains an unterminated quoted string")
    tail = value[start:].strip()
    if not tail:
        raise ValueError("proxy header contains an empty trailing element")
    parts.append(tail)
    return tuple(parts)


def _decode_forwarded_value(value: str) -> str:
    if not value:
        raise ValueError("Forwarded value is empty")
    if value[0] != '"':
        if '"' in value or "\\" in value or any(character.isspace() for character in value):
            raise ValueError("unquoted Forwarded value is invalid")
        return value
    if len(value) < 2 or value[-1] != '"':
        raise ValueError("quoted Forwarded value is invalid")
    decoded: list[str] = []
    escaped = False
    for character in value[1:-1]:
        if escaped:
            if character not in {'"', "\\"}:
                raise ValueError("Forwarded quoted escape is invalid")
            decoded.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"' or ord(character) < 32 or ord(character) == 127:
            raise ValueError("Forwarded quoted value contains invalid characters")
        else:
            decoded.append(character)
    if escaped:
        raise ValueError("Forwarded quoted value ends with an escape")
    return "".join(decoded)


def _parse_forwarded_node(value: str) -> str:
    lowered = value.lower()
    if lowered == "unknown" or value.startswith("_"):
        raise ValueError("Forwarded node must be an IP literal")
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1:
            raise ValueError("Forwarded IPv6 node is malformed")
        address = value[1:closing]
        suffix = value[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            raise ValueError("Forwarded IPv6 port is malformed")
        return _parse_ip_literal(address, allow_ipv4_port=False)
    return _parse_ip_literal(value, allow_ipv4_port=True)


def _parse_ip_literal(value: str, *, allow_ipv4_port: bool) -> str:
    candidate = value.strip()
    if not candidate or "%" in candidate:
        raise ValueError("client address is invalid")
    if allow_ipv4_port and candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            if not 1 <= int(port) <= 65535:
                raise ValueError("client port is invalid")
            candidate = host
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        raise ValueError("client address must be an IP literal") from None
