"""Server-owned immutable profiles for controlled Phoenix network egress."""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType

from phoenix_os.network_egress.contracts import (
    MAX_NETWORK_HEADER_NAME_LENGTH,
    MAX_NETWORK_REQUEST_BODY_BYTES,
    MAX_NETWORK_RESPONSE_BODY_BYTES,
    MAX_NETWORK_RESPONSE_HEADERS,
    NetworkEgressOperationId,
    NetworkEgressProfileId,
)
from phoenix_os.secrets import SecretRef

MAX_NETWORK_PROFILE_COUNT = 256
MAX_NETWORK_PROFILE_OPERATIONS = 256
MAX_NETWORK_PROFILE_NETWORKS = 64
MAX_NETWORK_RESOLVED_ADDRESSES = 32
MAX_NETWORK_REQUEST_TARGET_LENGTH = 2_048
MAX_NETWORK_MEDIA_TYPE_LENGTH = 256
MAX_NETWORK_EXPOSED_RESPONSE_HEADERS = 64
MAX_NETWORK_CREDENTIAL_PREFIX_LENGTH = 128
MAX_NETWORK_CONNECT_TIMEOUT_SECONDS = 60.0
MAX_NETWORK_TOTAL_TIMEOUT_SECONDS = 300.0
MAX_NETWORK_RESPONSE_HEADER_BYTES = 65_536

_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_HTTP_TOKEN_PATTERN = re.compile(r"^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$")
_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_FORBIDDEN_CREDENTIAL_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
    }
)
_FORBIDDEN_EXPOSED_RESPONSE_HEADERS = frozenset(
    {
        "authentication-info",
        "proxy-authenticate",
        "set-cookie",
        "set-cookie2",
    }
)


class NetworkDestinationMode(StrEnum):
    HOSTED_HTTPS = "hosted_https"
    LOOPBACK_HTTP = "loopback_http"


class NetworkHttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class NetworkOperationEffect(StrEnum):
    READ_ONLY = "read_only"
    REMOTE_EFFECT = "remote_effect"


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
        raise TypeError("network profile host must be a string")
    host = value.strip().lower()
    if not host or len(host) > 253:
        raise ValueError("network profile host size is outside supported bounds")
    if any(ord(character) < 33 or ord(character) > 126 for character in host):
        raise ValueError("network profile host must be visible ASCII")
    if "%" in host:
        raise ValueError("network profile host must not contain a zone identifier")

    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass

    if host.endswith("."):
        raise ValueError("network profile host must not contain a trailing dot")
    labels = host.split(".")
    if any(_HOST_LABEL_PATTERN.fullmatch(label) is None for label in labels):
        raise ValueError("network profile host is not a canonical DNS name")
    return host


def _normalize_request_target(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("network operation request target must be a string")
    target = value
    if not target or len(target) > MAX_NETWORK_REQUEST_TARGET_LENGTH:
        raise ValueError("network operation request target size is outside supported bounds")
    if any(ord(character) < 33 or ord(character) > 126 for character in target):
        raise ValueError(
            "network operation request target must use visible ASCII; "
            "encode spaces and non-ASCII bytes with percent escapes"
        )
    if not target.startswith("/") or target.startswith("//"):
        raise ValueError("network operation request target must use HTTP origin-form")
    if "#" in target or "\\" in target:
        raise ValueError("network operation request target contains a forbidden delimiter")

    path = target.split("?", 1)[0]
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("network operation request target contains dot segments")

    escapes = re.findall(r"%[^%]{0,2}", target)
    for escape in escapes:
        if _PERCENT_ESCAPE_PATTERN.fullmatch(escape) is None:
            raise ValueError("network operation request target contains an invalid percent escape")
    lowered = target.lower()
    for encoded in ("%2f", "%5c", "%2e"):
        if encoded in lowered:
            raise ValueError("network operation request target contains encoded path delimiters")
    return target


def _normalize_media_type(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string or None")
    if not value or len(value) > MAX_NETWORK_MEDIA_TYPE_LENGTH:
        raise ValueError(f"{label} size is outside supported bounds")
    if any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise ValueError(f"{label} must use printable ASCII only")

    segments = value.split(";")
    media = segments[0].strip(" ")
    if media.count("/") != 1:
        raise ValueError(f"{label} is invalid")
    media_type, media_subtype = media.split("/", 1)
    if (
        _HTTP_TOKEN_PATTERN.fullmatch(media_type) is None
        or _HTTP_TOKEN_PATTERN.fullmatch(media_subtype) is None
    ):
        raise ValueError(f"{label} is invalid")

    normalized = f"{media_type.lower()}/{media_subtype.lower()}"
    for segment in segments[1:]:
        parameter = segment.strip(" ")
        if parameter.count("=") != 1:
            raise ValueError(f"{label} is invalid")
        name, item = (part.strip(" ") for part in parameter.split("=", 1))
        if (
            _HTTP_TOKEN_PATTERN.fullmatch(name) is None
            or _HTTP_TOKEN_PATTERN.fullmatch(item) is None
        ):
            raise ValueError(f"{label} is invalid")
        normalized += f"; {name.lower()}={item}"

    return normalized


def _normalize_header_name(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if not normalized or len(normalized) > MAX_NETWORK_HEADER_NAME_LENGTH:
        raise ValueError(f"{label} size is outside supported bounds")
    if _HEADER_NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} is invalid")
    return normalized


def _normalize_networks(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError("allowed_networks must be a tuple")
    if len(values) > MAX_NETWORK_PROFILE_NETWORKS:
        raise ValueError("network profile contains too many explicit networks")

    normalized: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise TypeError("allowed_networks must contain strings")
        try:
            network = ipaddress.ip_network(item.strip(), strict=True)
        except ValueError as exception:
            raise ValueError("network profile contains an invalid explicit network") from exception
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


@dataclass(frozen=True, slots=True)
class NetworkOperationLimits:
    """Finite limits for one controlled HTTP operation."""

    max_request_body_bytes: int = 0
    max_response_body_bytes: int = 1_048_576
    max_response_headers: int = 64
    max_response_header_bytes: int = 32_768
    max_resolved_addresses: int = 16
    connect_timeout_seconds: float = 5.0
    total_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        _non_negative_int(
            self.max_request_body_bytes,
            label="max_request_body_bytes",
            maximum=MAX_NETWORK_REQUEST_BODY_BYTES,
        )
        _non_negative_int(
            self.max_response_body_bytes,
            label="max_response_body_bytes",
            maximum=MAX_NETWORK_RESPONSE_BODY_BYTES,
        )
        _positive_int(
            self.max_response_headers,
            label="max_response_headers",
            maximum=MAX_NETWORK_RESPONSE_HEADERS,
        )
        _positive_int(
            self.max_response_header_bytes,
            label="max_response_header_bytes",
            maximum=MAX_NETWORK_RESPONSE_HEADER_BYTES,
        )
        _positive_int(
            self.max_resolved_addresses,
            label="max_resolved_addresses",
            maximum=MAX_NETWORK_RESOLVED_ADDRESSES,
        )
        connect = _finite_positive_float(
            self.connect_timeout_seconds,
            label="connect_timeout_seconds",
            maximum=MAX_NETWORK_CONNECT_TIMEOUT_SECONDS,
        )
        total = _finite_positive_float(
            self.total_timeout_seconds,
            label="total_timeout_seconds",
            maximum=MAX_NETWORK_TOTAL_TIMEOUT_SECONDS,
        )
        if connect > total:
            raise ValueError("connect timeout cannot exceed total timeout")
        object.__setattr__(self, "connect_timeout_seconds", connect)
        object.__setattr__(self, "total_timeout_seconds", total)

    @property
    def connect_timeout(self) -> timedelta:
        return timedelta(seconds=self.connect_timeout_seconds)

    @property
    def total_timeout(self) -> timedelta:
        return timedelta(seconds=self.total_timeout_seconds)


@dataclass(frozen=True, slots=True)
class NetworkCredentialBinding:
    """Server-owned binding from one HTTP header to one exact secret version."""

    header_name: str
    secret_ref: SecretRef
    value_prefix: str = ""

    def __post_init__(self) -> None:
        header_name = _normalize_header_name(self.header_name, label="credential header name")
        if header_name in _FORBIDDEN_CREDENTIAL_HEADERS:
            raise ValueError("credential header name is reserved by the transport")
        if not isinstance(self.secret_ref, SecretRef):
            raise TypeError("secret_ref must be SecretRef")
        if self.secret_ref.version is None:
            raise ValueError("network credential binding requires an exact secret version")
        if not isinstance(self.value_prefix, str):
            raise TypeError("credential value prefix must be a string")
        if len(self.value_prefix) > MAX_NETWORK_CREDENTIAL_PREFIX_LENGTH:
            raise ValueError("credential value prefix exceeds the supported maximum")
        if any(ord(character) < 32 or ord(character) > 126 for character in self.value_prefix):
            raise ValueError("credential value prefix must use printable ASCII only")
        object.__setattr__(self, "header_name", header_name)


@dataclass(frozen=True, slots=True)
class NetworkEgressOperation:
    """One exact server-owned HTTP operation inside an egress profile."""

    operation_id: NetworkEgressOperationId
    method: NetworkHttpMethod
    request_target: str
    effect: NetworkOperationEffect
    limits: NetworkOperationLimits = field(default_factory=NetworkOperationLimits)
    accept: str | None = None
    content_type: str | None = None
    exposed_response_headers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, NetworkEgressOperationId):
            raise TypeError("operation_id must be NetworkEgressOperationId")
        method = NetworkHttpMethod(self.method)
        effect = NetworkOperationEffect(self.effect)
        target = _normalize_request_target(self.request_target)
        if effect is NetworkOperationEffect.READ_ONLY and method not in {
            NetworkHttpMethod.GET,
            NetworkHttpMethod.HEAD,
        }:
            raise ValueError(
                "read-only network effect classification is valid only for GET or HEAD"
            )
        if not isinstance(self.limits, NetworkOperationLimits):
            raise TypeError("limits must be NetworkOperationLimits")
        if method in {NetworkHttpMethod.GET, NetworkHttpMethod.HEAD}:
            if self.limits.max_request_body_bytes != 0:
                raise ValueError("GET and HEAD operations cannot permit request bodies")
        accept = _normalize_media_type(self.accept, label="accept")
        content_type = _normalize_media_type(self.content_type, label="content_type")
        if self.limits.max_request_body_bytes == 0 and content_type is not None:
            raise ValueError("bodyless network operation cannot define content_type")

        supplied_headers = tuple(self.exposed_response_headers)
        if len(supplied_headers) > MAX_NETWORK_EXPOSED_RESPONSE_HEADERS:
            raise ValueError("too many exposed response headers")
        normalized_headers: list[str] = []
        for header in supplied_headers:
            name = _normalize_header_name(header, label="exposed response header")
            if name in _FORBIDDEN_EXPOSED_RESPONSE_HEADERS:
                raise ValueError("sensitive response header cannot be exposed")
            normalized_headers.append(name)
        if len(normalized_headers) != len(set(normalized_headers)):
            raise ValueError("exposed response headers contain duplicates")

        object.__setattr__(self, "method", method)
        object.__setattr__(self, "effect", effect)
        object.__setattr__(self, "request_target", target)
        object.__setattr__(self, "accept", accept)
        object.__setattr__(self, "content_type", content_type)
        object.__setattr__(self, "exposed_response_headers", tuple(normalized_headers))


@dataclass(frozen=True, slots=True)
class NetworkEgressProfile:
    """Immutable server-owned destination and operation allowlist."""

    profile_id: NetworkEgressProfileId
    generation: int
    mode: NetworkDestinationMode
    host: str
    operations: tuple[NetworkEgressOperation, ...]
    port: int | None = None
    allow_public_networks: bool | None = None
    allowed_networks: tuple[str, ...] = ()
    credential: NetworkCredentialBinding | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, NetworkEgressProfileId):
            raise TypeError("profile_id must be NetworkEgressProfileId")
        generation = _positive_int(
            self.generation,
            label="network profile generation",
            maximum=2_147_483_647,
        )
        mode = NetworkDestinationMode(self.mode)
        host = _normalize_host(self.host)

        port = self.port
        if port is None:
            port = 443 if mode is NetworkDestinationMode.HOSTED_HTTPS else 80
        port = _positive_int(port, label="network profile port", maximum=65_535)

        allow_public = self.allow_public_networks
        if allow_public is None:
            allow_public = mode is NetworkDestinationMode.HOSTED_HTTPS
        if not isinstance(allow_public, bool):
            raise TypeError("allow_public_networks must be a boolean")

        networks = _normalize_networks(self.allowed_networks)
        if mode is NetworkDestinationMode.LOOPBACK_HTTP:
            if allow_public:
                raise ValueError("loopback profile cannot allow public networks")
            if networks:
                raise ValueError("loopback profile cannot define explicit networks")

        operations = tuple(self.operations)
        if not operations:
            raise ValueError("network profile requires at least one operation")
        if len(operations) > MAX_NETWORK_PROFILE_OPERATIONS:
            raise ValueError("network profile contains too many operations")
        if any(not isinstance(item, NetworkEgressOperation) for item in operations):
            raise TypeError("operations must contain NetworkEgressOperation values")
        operation_ids = tuple(item.operation_id for item in operations)
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("network profile contains duplicate operation ids")

        if self.credential is not None and not isinstance(
            self.credential,
            NetworkCredentialBinding,
        ):
            raise TypeError("credential must be NetworkCredentialBinding or None")

        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "allow_public_networks", allow_public)
        object.__setattr__(self, "allowed_networks", networks)
        object.__setattr__(self, "operations", operations)

    def require_operation(self, operation_id: NetworkEgressOperationId) -> NetworkEgressOperation:
        if not isinstance(operation_id, NetworkEgressOperationId):
            raise TypeError("operation_id must be NetworkEgressOperationId")
        for operation in self.operations:
            if operation.operation_id == operation_id:
                return operation
        raise KeyError(f"unknown network egress operation: {operation_id}")


class NetworkEgressProfileCatalog:
    """Finite immutable lookup for server-owned network egress profiles."""

    def __init__(self, profiles: tuple[NetworkEgressProfile, ...]) -> None:
        supplied = tuple(profiles)
        if not supplied:
            raise ValueError("enabled network egress requires at least one profile")
        if len(supplied) > MAX_NETWORK_PROFILE_COUNT:
            raise ValueError("network egress profile count exceeds the supported maximum")

        by_id: dict[NetworkEgressProfileId, NetworkEgressProfile] = {}
        for profile in supplied:
            if not isinstance(profile, NetworkEgressProfile):
                raise TypeError("profiles must contain NetworkEgressProfile values")
            if profile.profile_id in by_id:
                raise ValueError("network egress profile catalog contains duplicate profile ids")
            by_id[profile.profile_id] = profile

        self._profiles: Mapping[NetworkEgressProfileId, NetworkEgressProfile] = MappingProxyType(
            by_id
        )

    @property
    def profile_ids(self) -> tuple[NetworkEgressProfileId, ...]:
        return tuple(self._profiles)

    def require_profile(self, profile_id: NetworkEgressProfileId) -> NetworkEgressProfile:
        if not isinstance(profile_id, NetworkEgressProfileId):
            raise TypeError("profile_id must be NetworkEgressProfileId")
        try:
            return self._profiles[profile_id]
        except KeyError as exception:
            raise KeyError(f"unknown network egress profile: {profile_id}") from exception

    def require_operation(
        self,
        profile_id: NetworkEgressProfileId,
        operation_id: NetworkEgressOperationId,
    ) -> NetworkEgressOperation:
        return self.require_profile(profile_id).require_operation(operation_id)
