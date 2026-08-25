"""Immutable public contracts for controlled Phoenix network egress."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID, uuid4

MAX_NETWORK_IDENTIFIER_LENGTH = 128
MAX_NETWORK_REQUEST_BODY_BYTES = 1_048_576
MAX_NETWORK_RESPONSE_BODY_BYTES = 8_388_608
MAX_NETWORK_RESPONSE_HEADERS = 256
MAX_NETWORK_HEADER_NAME_LENGTH = 128
MAX_NETWORK_HEADER_VALUE_LENGTH = 8_192

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if len(normalized) > MAX_NETWORK_IDENTIFIER_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _freeze_body(value: bytes, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be bytes")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds the global maximum")
    return value


def _normalize_header_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("response header name must be a string")
    normalized = value.strip().lower()
    if not normalized or len(normalized) > MAX_NETWORK_HEADER_NAME_LENGTH:
        raise ValueError("response header name size is outside supported bounds")
    if _HEADER_NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError("response header name is invalid")
    return normalized


def _freeze_response_headers(values: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(values, Mapping):
        raise TypeError("response headers must be a mapping")
    if len(values) > MAX_NETWORK_RESPONSE_HEADERS:
        raise ValueError("response headers exceed the global maximum")

    frozen: dict[str, str] = {}
    for key, value in values.items():
        name = _normalize_header_name(key)
        if not isinstance(value, str):
            raise TypeError("response header values must be strings")
        normalized_value = value.strip()
        if len(normalized_value) > MAX_NETWORK_HEADER_VALUE_LENGTH:
            raise ValueError("response header value exceeds the global maximum")
        if "\r" in normalized_value or "\n" in normalized_value or "\x00" in normalized_value:
            raise ValueError("response header value contains forbidden control data")
        if name in frozen:
            raise ValueError("response headers contain duplicate normalized names")
        frozen[name] = normalized_value
    return MappingProxyType(frozen)


@dataclass(frozen=True, slots=True, order=True)
class NetworkEgressProfileId:
    """Stable server-owned identity for one configured egress profile."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="network egress profile id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class NetworkEgressOperationId:
    """Stable server-owned identity for one operation in an egress profile."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="network egress operation id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class NetworkHttpRequest:
    """Bounded caller data selecting only a server-owned profile and operation."""

    profile_id: NetworkEgressProfileId
    operation_id: NetworkEgressOperationId
    body: bytes = field(default=b"", repr=False)
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, NetworkEgressProfileId):
            raise TypeError("profile_id must be NetworkEgressProfileId")
        if not isinstance(self.operation_id, NetworkEgressOperationId):
            raise TypeError("operation_id must be NetworkEgressOperationId")
        object.__setattr__(
            self,
            "body",
            _freeze_body(
                self.body,
                label="network request body",
                maximum=MAX_NETWORK_REQUEST_BODY_BYTES,
            ),
        )
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        _require_aware(self.created_at, label="created_at")

    @property
    def body_digest(self) -> str:
        """Stable exact-body digest used by later intent binding."""

        return f"sha256:{hashlib.sha256(self.body).hexdigest()}"


@dataclass(frozen=True, slots=True)
class NetworkHttpResponse:
    """Bounded untrusted response data after profile-controlled filtering."""

    request_id: UUID
    profile_id: NetworkEgressProfileId
    operation_id: NetworkEgressOperationId
    status_code: int
    body: bytes = field(default=b"", repr=False)
    headers: Mapping[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        if not isinstance(self.profile_id, NetworkEgressProfileId):
            raise TypeError("profile_id must be NetworkEgressProfileId")
        if not isinstance(self.operation_id, NetworkEgressOperationId):
            raise TypeError("operation_id must be NetworkEgressOperationId")
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise TypeError("status_code must be an integer")
        if not 200 <= self.status_code <= 599:
            raise ValueError("status_code must be a final HTTP status")
        object.__setattr__(
            self,
            "body",
            _freeze_body(
                self.body,
                label="network response body",
                maximum=MAX_NETWORK_RESPONSE_BODY_BYTES,
            ),
        )
        object.__setattr__(self, "headers", _freeze_response_headers(self.headers))
        _require_aware(self.created_at, label="created_at")
