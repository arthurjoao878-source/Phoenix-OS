"""Immutable server-owned browser profiles and navigation targets for RFC-0035."""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from urllib.parse import urljoin, urlsplit

from phoenix_os.browser_automation.contracts import (
    MAX_BROWSER_ELEMENT_NAME_CHARS,
    MAX_BROWSER_ELEMENT_VALUE_CHARS,
    MAX_BROWSER_FILL_TEXT_BYTES,
    MAX_BROWSER_FILL_TEXT_CHARS,
    MAX_BROWSER_SNAPSHOT_ELEMENTS,
    MAX_BROWSER_SNAPSHOT_TEXT_BYTES,
    MAX_BROWSER_SNAPSHOT_TEXT_CHARS,
    MAX_BROWSER_SNAPSHOT_TITLE_CHARS,
    BrowserAdapterId,
    BrowserNavigationTargetId,
    BrowserProfileId,
)

MAX_BROWSER_PROFILE_COUNT = 256
MAX_BROWSER_PROFILE_ORIGINS = 64
MAX_BROWSER_PROFILE_TARGETS = 256
MAX_BROWSER_PROFILE_NETWORKS = 64
MAX_BROWSER_REQUEST_TARGET_LENGTH = 2_048
MAX_BROWSER_REDIRECT_LOCATION_LENGTH = 4_096
MAX_BROWSER_RESOLVED_ADDRESSES = 32
MAX_BROWSER_REDIRECTS = 16
MAX_BROWSER_COOKIE_COUNT = 512
MAX_BROWSER_COOKIE_BYTES = 262_144
MAX_BROWSER_SESSION_TTL_SECONDS = 86_400.0
MAX_BROWSER_OPERATION_TIMEOUT_SECONDS = 300.0
MAX_BROWSER_CONCURRENT_SESSIONS = 128

_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class BrowserDestinationMode(StrEnum):
    """Finite reviewed origin modes; v0.35.0 supports HTTPS or explicit loopback HTTP."""

    HOSTED_HTTPS = "hosted_https"
    LOOPBACK_HTTP = "loopback_http"


def _positive_int(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")
    return value


def _non_negative_int(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")
    return value


def _finite_positive_float(value: float, *, label: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} must be numeric")
    rendered = float(value)
    if not math.isfinite(rendered) or not 0 < rendered <= maximum:
        raise ValueError(f"{label} is outside supported bounds")
    return rendered


def _normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("browser origin host must be a string")
    host = value.strip().lower()
    if not host or len(host) > 253:
        raise ValueError("browser origin host size is outside supported bounds")
    if any(ord(character) < 33 or ord(character) > 126 for character in host):
        raise ValueError("browser origin host must use visible ASCII")
    if "%" in host:
        raise ValueError("browser origin host must not contain a zone identifier")

    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass

    if host.endswith("."):
        raise ValueError("browser origin host must not contain a trailing dot")
    labels = host.split(".")
    if any(_HOST_LABEL_PATTERN.fullmatch(label) is None for label in labels):
        raise ValueError("browser origin host is not a canonical DNS name")
    return host


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalize_networks(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError("allowed_networks must be a tuple")
    if len(values) > MAX_BROWSER_PROFILE_NETWORKS:
        raise ValueError("browser network policy contains too many explicit networks")

    normalized: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise TypeError("allowed_networks must contain strings")
        try:
            network = ipaddress.ip_network(item.strip(), strict=True)
        except ValueError as exception:
            raise ValueError(
                "browser network policy contains an invalid explicit network"
            ) from exception
        normalized.add(network.with_prefixlen)
    return tuple(
        sorted(
            normalized,
            key=lambda value: (
                ipaddress.ip_network(value).version,
                int(ipaddress.ip_network(value).network_address),
                ipaddress.ip_network(value).prefixlen,
            ),
        )
    )


def _normalize_request_target(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("browser navigation request target must be a string")
    target = value
    if not target or len(target) > MAX_BROWSER_REQUEST_TARGET_LENGTH:
        raise ValueError("browser navigation request target size is outside supported bounds")
    if any(ord(character) < 33 or ord(character) > 126 for character in target):
        raise ValueError(
            "browser navigation request target must use visible ASCII; "
            "encode spaces and non-ASCII bytes with percent escapes"
        )
    if not target.startswith("/") or target.startswith("//"):
        raise ValueError("browser navigation request target must use HTTP origin-form")
    if "#" in target or "\\" in target:
        raise ValueError("browser navigation request target contains a forbidden delimiter")

    path = target.split("?", 1)[0]
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("browser navigation request target contains dot segments")

    escapes = re.findall(r"%[^%]{0,2}", target)
    for escape in escapes:
        if _PERCENT_ESCAPE_PATTERN.fullmatch(escape) is None:
            raise ValueError("browser navigation request target contains an invalid percent escape")
    lowered = target.lower()
    for encoded in ("%2f", "%5c", "%2e"):
        if encoded in lowered:
            raise ValueError("browser navigation request target contains encoded path delimiters")
    return target


@dataclass(frozen=True, slots=True, order=True)
class BrowserOrigin:
    """Exact server-owned `(scheme, host, port)` origin admitted by one browser profile."""

    mode: BrowserDestinationMode
    host: str
    port: int | None = None

    def __post_init__(self) -> None:
        mode = BrowserDestinationMode(self.mode)
        host = _normalize_host(self.host)
        port = self.port
        if port is None:
            port = 443 if mode is BrowserDestinationMode.HOSTED_HTTPS else 80
        port = _positive_int(port, label="browser origin port", maximum=65_535)

        if mode is BrowserDestinationMode.LOOPBACK_HTTP and not _is_loopback_host(host):
            raise ValueError("loopback HTTP browser origin requires a loopback host")

        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)

    @property
    def scheme(self) -> str:
        return "https" if self.mode is BrowserDestinationMode.HOSTED_HTTPS else "http"

    @property
    def canonical(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default_port else f":{self.port}"
        rendered_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{rendered_host}{suffix}"


@dataclass(frozen=True, slots=True)
class BrowserNetworkPolicy:
    """Server-owned destination policy used later by browser DNS/IP admission."""

    allow_public_networks: bool = True
    allowed_networks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.allow_public_networks, bool):
            raise TypeError("allow_public_networks must be a boolean")
        object.__setattr__(self, "allowed_networks", _normalize_networks(self.allowed_networks))


@dataclass(frozen=True, slots=True)
class BrowserNavigationTarget:
    """One immutable server-owned initial navigation target."""

    target_id: BrowserNavigationTargetId
    origin: BrowserOrigin
    request_target: str

    def __post_init__(self) -> None:
        if not isinstance(self.target_id, BrowserNavigationTargetId):
            raise TypeError("target_id must be BrowserNavigationTargetId")
        if not isinstance(self.origin, BrowserOrigin):
            raise TypeError("origin must be BrowserOrigin")
        object.__setattr__(self, "request_target", _normalize_request_target(self.request_target))


@dataclass(frozen=True, slots=True)
class BrowserNavigationRequest:
    """One exact top-level request rooted in one server-owned initial target."""

    target_id: BrowserNavigationTargetId
    origin: BrowserOrigin
    request_target: str
    redirect_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.target_id, BrowserNavigationTargetId):
            raise TypeError("target_id must be BrowserNavigationTargetId")
        if not isinstance(self.origin, BrowserOrigin):
            raise TypeError("origin must be BrowserOrigin")
        redirect_count = _non_negative_int(
            self.redirect_count,
            label="browser navigation redirect count",
            maximum=MAX_BROWSER_REDIRECTS,
        )
        object.__setattr__(self, "request_target", _normalize_request_target(self.request_target))
        object.__setattr__(self, "redirect_count", redirect_count)

    @classmethod
    def from_target(cls, target: BrowserNavigationTarget) -> BrowserNavigationRequest:
        if not isinstance(target, BrowserNavigationTarget):
            raise TypeError("target must be BrowserNavigationTarget")
        return cls(
            target_id=target.target_id,
            origin=target.origin,
            request_target=target.request_target,
            redirect_count=0,
        )

    @property
    def absolute_url(self) -> str:
        return f"{self.origin.canonical}{self.request_target}"


class BrowserRequestMethod(StrEnum):
    """Finite top-level request methods permitted for click-derived effects."""

    GET = "GET"
    POST = "POST"


@dataclass(frozen=True, slots=True)
class BrowserClickRequest:
    """Exact top-level request derived from one prepared click effect."""

    origin: BrowserOrigin
    request_target: str
    method: BrowserRequestMethod = BrowserRequestMethod.GET
    body_digest: str | None = None
    redirect_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.origin, BrowserOrigin):
            raise TypeError("origin must be BrowserOrigin")
        method = BrowserRequestMethod(self.method)
        redirect_count = _non_negative_int(
            self.redirect_count,
            label="browser click redirect count",
            maximum=MAX_BROWSER_REDIRECTS,
        )
        body_digest = self.body_digest
        if body_digest is not None:
            if not isinstance(body_digest, str):
                raise TypeError("body_digest must be a string or None")
            if _SHA256_DIGEST_PATTERN.fullmatch(body_digest) is None:
                raise ValueError("body_digest must be an exact SHA-256 digest")
        if method is BrowserRequestMethod.GET and body_digest is not None:
            raise ValueError("GET browser click request cannot carry a body digest")
        if method is BrowserRequestMethod.POST and body_digest is None:
            raise ValueError("POST browser click request requires an exact body digest")
        object.__setattr__(self, "request_target", _normalize_request_target(self.request_target))
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "redirect_count", redirect_count)

    @property
    def absolute_url(self) -> str:
        return f"{self.origin.canonical}{self.request_target}"


@dataclass(frozen=True, slots=True)
class BrowserProfileLimits:
    """Finite server-owned limits for one v0.35.0 browser profile."""

    max_snapshot_title_chars: int = 1_024
    max_snapshot_text_chars: int = 131_072
    max_snapshot_text_bytes: int = 524_288
    max_snapshot_elements: int = 512
    max_element_name_chars: int = 1_024
    max_element_value_chars: int = 4_096
    max_fill_text_chars: int = 32_768
    max_fill_text_bytes: int = 131_072
    max_cookies: int = 128
    max_cookie_bytes: int = 65_536
    max_resolved_addresses: int = 16
    max_redirects: int = 5
    session_ttl_seconds: float = 900.0
    operation_timeout_seconds: float = 30.0
    max_concurrent_sessions: int = 8

    def __post_init__(self) -> None:
        _positive_int(
            self.max_snapshot_title_chars,
            label="max_snapshot_title_chars",
            maximum=MAX_BROWSER_SNAPSHOT_TITLE_CHARS,
        )
        _positive_int(
            self.max_snapshot_text_chars,
            label="max_snapshot_text_chars",
            maximum=MAX_BROWSER_SNAPSHOT_TEXT_CHARS,
        )
        _positive_int(
            self.max_snapshot_text_bytes,
            label="max_snapshot_text_bytes",
            maximum=MAX_BROWSER_SNAPSHOT_TEXT_BYTES,
        )
        _positive_int(
            self.max_snapshot_elements,
            label="max_snapshot_elements",
            maximum=MAX_BROWSER_SNAPSHOT_ELEMENTS,
        )
        _positive_int(
            self.max_element_name_chars,
            label="max_element_name_chars",
            maximum=MAX_BROWSER_ELEMENT_NAME_CHARS,
        )
        _positive_int(
            self.max_element_value_chars,
            label="max_element_value_chars",
            maximum=MAX_BROWSER_ELEMENT_VALUE_CHARS,
        )
        _positive_int(
            self.max_fill_text_chars,
            label="max_fill_text_chars",
            maximum=MAX_BROWSER_FILL_TEXT_CHARS,
        )
        _positive_int(
            self.max_fill_text_bytes,
            label="max_fill_text_bytes",
            maximum=MAX_BROWSER_FILL_TEXT_BYTES,
        )
        _positive_int(self.max_cookies, label="max_cookies", maximum=MAX_BROWSER_COOKIE_COUNT)
        _positive_int(
            self.max_cookie_bytes,
            label="max_cookie_bytes",
            maximum=MAX_BROWSER_COOKIE_BYTES,
        )
        _positive_int(
            self.max_resolved_addresses,
            label="max_resolved_addresses",
            maximum=MAX_BROWSER_RESOLVED_ADDRESSES,
        )
        _non_negative_int(
            self.max_redirects,
            label="max_redirects",
            maximum=MAX_BROWSER_REDIRECTS,
        )
        session_ttl = _finite_positive_float(
            self.session_ttl_seconds,
            label="session_ttl_seconds",
            maximum=MAX_BROWSER_SESSION_TTL_SECONDS,
        )
        operation_timeout = _finite_positive_float(
            self.operation_timeout_seconds,
            label="operation_timeout_seconds",
            maximum=MAX_BROWSER_OPERATION_TIMEOUT_SECONDS,
        )
        _positive_int(
            self.max_concurrent_sessions,
            label="max_concurrent_sessions",
            maximum=MAX_BROWSER_CONCURRENT_SESSIONS,
        )
        if self.max_snapshot_text_bytes < self.max_snapshot_text_chars:
            raise ValueError("max_snapshot_text_bytes cannot be less than max_snapshot_text_chars")
        if self.max_fill_text_bytes < self.max_fill_text_chars:
            raise ValueError("max_fill_text_bytes cannot be less than max_fill_text_chars")
        if operation_timeout > session_ttl:
            raise ValueError("operation timeout cannot exceed browser session TTL")
        object.__setattr__(self, "session_ttl_seconds", session_ttl)
        object.__setattr__(self, "operation_timeout_seconds", operation_timeout)


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    """Immutable server-owned browser scope with no generic browser escape hatches."""

    profile_id: BrowserProfileId
    generation: int
    adapter_id: BrowserAdapterId
    allowed_origins: tuple[BrowserOrigin, ...]
    initial_targets: tuple[BrowserNavigationTarget, ...]
    network_policy: BrowserNetworkPolicy = field(default_factory=BrowserNetworkPolicy)
    limits: BrowserProfileLimits = field(default_factory=BrowserProfileLimits)

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, BrowserProfileId):
            raise TypeError("profile_id must be BrowserProfileId")
        generation = _positive_int(
            self.generation,
            label="browser profile generation",
            maximum=2_147_483_647,
        )
        if not isinstance(self.adapter_id, BrowserAdapterId):
            raise TypeError("adapter_id must be BrowserAdapterId")
        if not isinstance(self.network_policy, BrowserNetworkPolicy):
            raise TypeError("network_policy must be BrowserNetworkPolicy")
        if not isinstance(self.limits, BrowserProfileLimits):
            raise TypeError("limits must be BrowserProfileLimits")

        origins = tuple(self.allowed_origins)
        if not origins:
            raise ValueError("browser profile requires at least one allowed origin")
        if len(origins) > MAX_BROWSER_PROFILE_ORIGINS:
            raise ValueError("browser profile contains too many allowed origins")
        if any(not isinstance(origin, BrowserOrigin) for origin in origins):
            raise TypeError("allowed_origins must contain BrowserOrigin values")
        if len(origins) != len(set(origins)):
            raise ValueError("browser profile contains duplicate allowed origins")
        if (
            all(origin.mode is BrowserDestinationMode.LOOPBACK_HTTP for origin in origins)
            and self.network_policy.allow_public_networks
        ):
            raise ValueError("loopback-only browser profile cannot allow public networks")

        targets = tuple(self.initial_targets)
        if not targets:
            raise ValueError("browser profile requires at least one initial navigation target")
        if len(targets) > MAX_BROWSER_PROFILE_TARGETS:
            raise ValueError("browser profile contains too many initial navigation targets")
        if any(not isinstance(target, BrowserNavigationTarget) for target in targets):
            raise TypeError("initial_targets must contain BrowserNavigationTarget values")
        target_ids = tuple(target.target_id for target in targets)
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("browser profile contains duplicate navigation target ids")
        if any(target.origin not in origins for target in targets):
            raise ValueError("browser navigation target origin is not in the profile allowlist")

        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "allowed_origins", origins)
        object.__setattr__(self, "initial_targets", targets)

    @property
    def javascript_enabled(self) -> bool:
        return False

    @property
    def subresources_enabled(self) -> bool:
        return False

    @property
    def downloads_enabled(self) -> bool:
        return False

    @property
    def uploads_enabled(self) -> bool:
        return False

    @property
    def persistent_storage_enabled(self) -> bool:
        return False

    @property
    def max_pages_per_session(self) -> int:
        return 1

    def require_target(self, target_id: BrowserNavigationTargetId) -> BrowserNavigationTarget:
        if not isinstance(target_id, BrowserNavigationTargetId):
            raise TypeError("target_id must be BrowserNavigationTargetId")
        for target in self.initial_targets:
            if target.target_id == target_id:
                return target
        raise KeyError(f"unknown browser navigation target: {target_id}")


def derive_browser_redirect_request(
    profile: BrowserProfile,
    current: BrowserNavigationRequest,
    location: str,
) -> BrowserNavigationRequest:
    """Canonicalize one untrusted HTTP redirect without accepting response-granted authority."""

    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")
    if not isinstance(current, BrowserNavigationRequest):
        raise TypeError("current must be BrowserNavigationRequest")
    if not isinstance(location, str):
        raise TypeError("redirect location must be a string")

    try:
        configured = profile.require_target(current.target_id)
    except KeyError:
        raise ValueError("redirect root target is not configured") from None
    if current.origin not in profile.allowed_origins:
        raise ValueError("current navigation origin is not allowed")
    if current.redirect_count == 0 and (
        current.origin != configured.origin or current.request_target != configured.request_target
    ):
        raise ValueError("initial navigation request does not match its server-owned target")
    if current.redirect_count >= profile.limits.max_redirects:
        raise ValueError("browser redirect limit exceeded")

    raw = location
    if not raw or len(raw) > MAX_BROWSER_REDIRECT_LOCATION_LENGTH:
        raise ValueError("browser redirect location size is outside supported bounds")
    if any(ord(character) < 33 or ord(character) > 126 for character in raw):
        raise ValueError("browser redirect location must use visible ASCII")
    if "#" in raw or "\\" in raw:
        raise ValueError("browser redirect location contains a forbidden delimiter")

    raw_parts = urlsplit(raw)
    raw_path = raw_parts.path
    if any(segment in {".", ".."} for segment in raw_path.split("/")):
        raise ValueError("browser redirect location contains dot segments")
    lowered = raw.lower()
    for encoded in ("%2f", "%5c", "%2e"):
        if encoded in lowered:
            raise ValueError("browser redirect location contains encoded path delimiters")

    absolute = urljoin(current.absolute_url, raw)
    parsed = urlsplit(absolute)
    if parsed.fragment:
        raise ValueError("browser redirect location cannot contain a fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("browser redirect location cannot contain user information")
    if parsed.hostname is None:
        raise ValueError("browser redirect location requires a host")

    scheme = parsed.scheme.lower()
    if scheme == "https":
        mode = BrowserDestinationMode.HOSTED_HTTPS
    elif scheme == "http":
        mode = BrowserDestinationMode.LOOPBACK_HTTP
    else:
        raise ValueError("browser redirect location uses an unsupported scheme")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("browser redirect location contains an invalid port") from None

    origin = BrowserOrigin(mode, parsed.hostname, port)
    if origin not in profile.allowed_origins:
        raise ValueError("browser redirect origin is not in the exact profile allowlist")

    path = parsed.path or "/"
    request_target = path
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    return BrowserNavigationRequest(
        target_id=current.target_id,
        origin=origin,
        request_target=request_target,
        redirect_count=current.redirect_count + 1,
    )


def derive_browser_click_redirect_request(
    profile: BrowserProfile,
    current: BrowserClickRequest,
    location: str,
    status_code: int,
) -> BrowserClickRequest:
    """Derive one exact click redirect request and fail closed on ambiguous method changes."""

    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")
    if not isinstance(current, BrowserClickRequest):
        raise TypeError("current must be BrowserClickRequest")
    if not isinstance(location, str):
        raise TypeError("redirect location must be a string")
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise TypeError("redirect status_code must be an integer")
    if status_code not in {301, 302, 303, 307, 308}:
        raise ValueError("unsupported browser redirect status")
    if current.origin not in profile.allowed_origins:
        raise ValueError("current click origin is not allowed")
    if current.redirect_count >= profile.limits.max_redirects:
        raise ValueError("browser redirect limit exceeded")

    raw = location
    if not raw or len(raw) > MAX_BROWSER_REDIRECT_LOCATION_LENGTH:
        raise ValueError("browser redirect location size is outside supported bounds")
    if any(ord(character) < 33 or ord(character) > 126 for character in raw):
        raise ValueError("browser redirect location must use visible ASCII")
    if "#" in raw or "\\" in raw:
        raise ValueError("browser redirect location contains a forbidden delimiter")

    raw_parts = urlsplit(raw)
    raw_path = raw_parts.path
    if any(segment in {".", ".."} for segment in raw_path.split("/")):
        raise ValueError("browser redirect location contains dot segments")
    lowered = raw.lower()
    for encoded in ("%2f", "%5c", "%2e"):
        if encoded in lowered:
            raise ValueError("browser redirect location contains encoded path delimiters")

    absolute = urljoin(current.absolute_url, raw)
    parsed = urlsplit(absolute)
    if parsed.fragment:
        raise ValueError("browser redirect location cannot contain a fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("browser redirect location cannot contain user information")
    if parsed.hostname is None:
        raise ValueError("browser redirect location requires a host")

    scheme = parsed.scheme.lower()
    if scheme == "https":
        mode = BrowserDestinationMode.HOSTED_HTTPS
    elif scheme == "http":
        mode = BrowserDestinationMode.LOOPBACK_HTTP
    else:
        raise ValueError("browser redirect location uses an unsupported scheme")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("browser redirect location contains an invalid port") from None

    origin = BrowserOrigin(mode, parsed.hostname, port)
    if origin not in profile.allowed_origins:
        raise ValueError("browser redirect origin is not in the exact profile allowlist")
    path = parsed.path or "/"
    request_target = path if not parsed.query else f"{path}?{parsed.query}"

    if current.method is BrowserRequestMethod.GET:
        method = BrowserRequestMethod.GET
        body_digest = None
    elif status_code == 303:
        method = BrowserRequestMethod.GET
        body_digest = None
    elif status_code in {307, 308}:
        method = BrowserRequestMethod.POST
        body_digest = current.body_digest
    else:
        raise ValueError("ambiguous POST redirect method transition is not supported")

    return BrowserClickRequest(
        origin=origin,
        request_target=request_target,
        method=method,
        body_digest=body_digest,
        redirect_count=current.redirect_count + 1,
    )


class BrowserProfileCatalog:
    """Finite immutable lookup for server-owned browser profiles."""

    def __init__(self, profiles: tuple[BrowserProfile, ...]) -> None:
        supplied = tuple(profiles)
        if not supplied:
            raise ValueError("enabled browser automation requires at least one profile")
        if len(supplied) > MAX_BROWSER_PROFILE_COUNT:
            raise ValueError("browser profile count exceeds the supported maximum")

        by_id: dict[BrowserProfileId, BrowserProfile] = {}
        for profile in supplied:
            if not isinstance(profile, BrowserProfile):
                raise TypeError("profiles must contain BrowserProfile values")
            if profile.profile_id in by_id:
                raise ValueError("browser profile catalog contains duplicate profile ids")
            by_id[profile.profile_id] = profile

        self._profiles: Mapping[BrowserProfileId, BrowserProfile] = MappingProxyType(by_id)

    @property
    def profile_ids(self) -> tuple[BrowserProfileId, ...]:
        return tuple(self._profiles)

    def require_profile(self, profile_id: BrowserProfileId) -> BrowserProfile:
        if not isinstance(profile_id, BrowserProfileId):
            raise TypeError("profile_id must be BrowserProfileId")
        try:
            return self._profiles[profile_id]
        except KeyError as exception:
            raise KeyError(f"unknown browser profile: {profile_id}") from exception
