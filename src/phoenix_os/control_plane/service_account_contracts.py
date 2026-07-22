"""Immutable contracts for service accounts and scoped API tokens."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import ip_network
from typing import Protocol
from uuid import UUID

DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE = 50
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE = 200
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY = 10_000
MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT = 32
MAX_CONTROL_PLANE_API_TOKEN_LIFETIME = timedelta(days=366)
MAX_CONTROL_PLANE_API_TOKEN_ROTATION_OVERLAP = timedelta(hours=24)
MAX_CONTROL_PLANE_API_TOKEN_CLIENT_NETWORKS = 32

_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{2,63}\Z")
_SCOPE_PATTERN = re.compile(r"[a-z][a-z0-9._-]{2,127}\Z")
_RESOURCE_PATTERN = re.compile(r"[A-Za-z0-9*][A-Za-z0-9._:/*-]{0,255}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_PATTERN = re.compile(r"phx_sa_[A-Za-z0-9_-]{40,152}\Z")


class ControlPlaneServiceAccountStatus(StrEnum):
    """Administrative state for one machine identity."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"

    @property
    def authenticatable(self) -> bool:
        return self is self.ACTIVE


class ControlPlaneApiTokenStatus(StrEnum):
    """Persisted lifecycle state for one API token."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"

    @property
    def authenticatable(self) -> bool:
        return self is self.ACTIVE


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneApiToken:
    """One-time bearer whose plaintext must never be persisted."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.value != self.value.strip():
            raise ValueError("API token must not contain surrounding whitespace")

        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("API token must contain ASCII characters only") from exception

        if _TOKEN_PATTERN.fullmatch(self.value) is None:
            raise ValueError(
                "API token must use the phx_sa_ prefix and contain 40 to 152 URL-safe characters"
            )

    @property
    def digest(self) -> str:
        """Return the stable SHA-256 persistence representation."""

        return hashlib.sha256(self.value.encode("ascii")).hexdigest()

    def __repr__(self) -> str:
        return "ControlPlaneApiToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenRestriction:
    """Optional network and mutual-TLS token restrictions."""

    allowed_client_networks: tuple[str, ...] = ()
    mutual_tls_certificate_sha256: str | None = None

    def __post_init__(self) -> None:
        networks = _normalize_networks(self.allowed_client_networks)

        fingerprint = self.mutual_tls_certificate_sha256

        if fingerprint is not None:
            fingerprint = _normalize_digest(
                fingerprint,
                label="mutual TLS certificate fingerprint",
            )

        object.__setattr__(
            self,
            "allowed_client_networks",
            networks,
        )
        object.__setattr__(
            self,
            "mutual_tls_certificate_sha256",
            fingerprint,
        )

    @property
    def restricted(self) -> bool:
        return bool(self.allowed_client_networks or self.mutual_tls_certificate_sha256)


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountRecord:
    """Versioned machine identity without plaintext credentials."""

    id: UUID
    name: str
    display_name: str
    created_at: datetime
    updated_at: datetime
    status: ControlPlaneServiceAccountStatus = ControlPlaneServiceAccountStatus.ACTIVE
    disabled_at: datetime | None = None
    revoked_at: datetime | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        name = _normalize_name(self.name)
        display_name = _normalize_display_name(
            self.display_name,
            label="service account",
        )
        status = ControlPlaneServiceAccountStatus(self.status)

        if self.schema_version != 1:
            raise ValueError("unsupported service-account schema version")

        if self.revision <= 0:
            raise ValueError("service-account revision must be positive")

        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")

        if self.updated_at < self.created_at:
            raise ValueError("service-account updated_at cannot precede created_at")

        if self.disabled_at is not None:
            _require_aware(
                self.disabled_at,
                "disabled_at",
            )

            if self.disabled_at < self.created_at:
                raise ValueError("service-account disabled_at cannot precede created_at")

        if self.revoked_at is not None:
            _require_aware(
                self.revoked_at,
                "revoked_at",
            )

            if self.revoked_at < self.created_at:
                raise ValueError("service-account revoked_at cannot precede created_at")

        if status is ControlPlaneServiceAccountStatus.ACTIVE:
            if self.disabled_at is not None or self.revoked_at is not None:
                raise ValueError("active service account cannot contain inactive timestamps")

        elif status is ControlPlaneServiceAccountStatus.DISABLED:
            if self.disabled_at is None or self.revoked_at is not None:
                raise ValueError("disabled service account requires only disabled_at")

        elif self.revoked_at is None:
            raise ValueError("revoked service account requires revoked_at")

        object.__setattr__(self, "name", name)
        object.__setattr__(
            self,
            "display_name",
            display_name,
        )
        object.__setattr__(self, "status", status)


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenMetadata:
    """Credential-safe metadata for one scoped API token."""

    id: UUID
    service_account_id: UUID
    label: str
    token_digest: str = field(repr=False)
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    updated_at: datetime
    resources: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))
    restriction: ControlPlaneApiTokenRestriction = field(
        default_factory=ControlPlaneApiTokenRestriction
    )
    status: ControlPlaneApiTokenStatus = ControlPlaneApiTokenStatus.ACTIVE
    revoked_at: datetime | None = None
    rotated_from: UUID | None = None
    token_version: int = 1
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        label = _normalize_display_name(
            self.label,
            label="API token",
        )
        digest = _normalize_digest(
            self.token_digest,
            label="API token digest",
        )
        scopes = _normalize_scopes(self.scopes)
        resources = _normalize_resources(self.resources)
        status = ControlPlaneApiTokenStatus(self.status)

        if not isinstance(
            self.restriction,
            ControlPlaneApiTokenRestriction,
        ):
            raise TypeError("API token restriction must be ControlPlaneApiTokenRestriction")

        if self.schema_version != 1:
            raise ValueError("unsupported API-token schema version")

        if self.token_version <= 0:
            raise ValueError("API token version must be positive")

        if self.revision <= 0:
            raise ValueError("API token revision must be positive")

        if self.rotated_from == self.id:
            raise ValueError("API token cannot rotate from itself")

        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        _require_aware(self.updated_at, "updated_at")

        if self.expires_at <= self.issued_at:
            raise ValueError("API token expires_at must follow issued_at")

        lifetime = self.expires_at - self.issued_at

        if lifetime > MAX_CONTROL_PLANE_API_TOKEN_LIFETIME:
            raise ValueError("API token lifetime exceeds supported maximum")

        if self.updated_at < self.issued_at:
            raise ValueError("API token updated_at cannot precede issued_at")

        if self.revoked_at is not None:
            _require_aware(
                self.revoked_at,
                "revoked_at",
            )

            if self.revoked_at < self.issued_at:
                raise ValueError("API token revoked_at cannot precede issued_at")

            if self.updated_at < self.revoked_at:
                raise ValueError("API token updated_at cannot precede revoked_at")

        if status is ControlPlaneApiTokenStatus.ACTIVE:
            if self.revoked_at is not None:
                raise ValueError("active API token cannot contain revoked_at")

            if self.updated_at >= self.expires_at:
                raise ValueError("active API token cannot already be expired")

        elif status is ControlPlaneApiTokenStatus.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked API token requires revoked_at")

        else:
            if self.revoked_at is not None:
                raise ValueError("expired API token cannot contain revoked_at")

            if self.updated_at < self.expires_at:
                raise ValueError("expired API token requires updated_at at or after expires_at")

        object.__setattr__(self, "label", label)
        object.__setattr__(
            self,
            "token_digest",
            digest,
        )
        object.__setattr__(self, "scopes", scopes)
        object.__setattr__(
            self,
            "resources",
            resources,
        )
        object.__setattr__(self, "status", status)

    def authenticatable_at(
        self,
        when: datetime,
    ) -> bool:
        """Return whether this token can authenticate at an instant."""

        _require_aware(when, "when")

        return self.status.authenticatable and when < self.expires_at


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenRotation:
    """Atomic immediate or bounded-overlap API-token rotation."""

    predecessor: ControlPlaneApiTokenMetadata
    successor: ControlPlaneApiTokenMetadata
    schema_version: int = 1

    def __post_init__(self) -> None:
        predecessor = self.predecessor
        successor = self.successor
        rotation_at = successor.issued_at

        if predecessor.status not in {
            ControlPlaneApiTokenStatus.ACTIVE,
            ControlPlaneApiTokenStatus.REVOKED,
        }:
            raise ValueError("rotated API-token predecessor must be active or revoked")

        if successor.status is not ControlPlaneApiTokenStatus.ACTIVE:
            raise ValueError("rotated API-token successor must be active")

        if predecessor.service_account_id != successor.service_account_id:
            raise ValueError("API-token rotation must remain within one service account")

        if successor.rotated_from != predecessor.id:
            raise ValueError("API-token successor must reference its predecessor")

        if successor.token_version != predecessor.token_version + 1:
            raise ValueError("API-token successor version must increment exactly once")

        if predecessor.updated_at != rotation_at:
            raise ValueError("API-token predecessor must be updated at rotation")

        if successor.updated_at != rotation_at:
            raise ValueError("new API-token successor must be updated at issuance")

        if hmac.compare_digest(
            predecessor.token_digest,
            successor.token_digest,
        ):
            raise ValueError("API-token rotation requires a fresh secret")

        if predecessor.status is ControlPlaneApiTokenStatus.REVOKED:
            if predecessor.revoked_at != rotation_at:
                raise ValueError("immediate API-token rotation requires revocation at issuance")

        else:
            if predecessor.revoked_at is not None:
                raise ValueError("overlapping predecessor cannot contain revoked_at")

            if not (
                rotation_at
                < predecessor.expires_at
                <= rotation_at + MAX_CONTROL_PLANE_API_TOKEN_ROTATION_OVERLAP
            ):
                raise ValueError("API-token rotation overlap exceeds the supported bound")

        if self.schema_version != 1:
            raise ValueError("unsupported API-token rotation schema version")

    @property
    def overlapping(self) -> bool:
        """Return whether the predecessor remains temporarily valid."""

        return self.predecessor.status is ControlPlaneApiTokenStatus.ACTIVE

    @property
    def overlap_expires_at(
        self,
    ) -> datetime | None:
        """Return the predecessor overlap deadline."""

        if not self.overlapping:
            return None

        return self.predecessor.expires_at


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountRegistrySnapshot:
    """Non-sensitive bounded registry counters."""

    closed: bool
    accounts: int
    active_accounts: int
    disabled_accounts: int
    revoked_accounts: int
    tokens: int
    active_tokens: int
    revoked_tokens: int
    expired_tokens: int
    account_capacity: int
    max_tokens_per_account: int

    def __post_init__(self) -> None:
        counters = (
            self.accounts,
            self.active_accounts,
            self.disabled_accounts,
            self.revoked_accounts,
            self.tokens,
            self.active_tokens,
            self.revoked_tokens,
            self.expired_tokens,
        )

        if any(value < 0 for value in counters):
            raise ValueError("service-account counters cannot be negative")

        if not (1 <= self.account_capacity <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY):
            raise ValueError("service-account capacity is outside bounds")

        if not (1 <= self.max_tokens_per_account <= MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT):
            raise ValueError("API-token capacity is outside bounds")

        if self.accounts > self.account_capacity:
            raise ValueError("service-account count exceeds capacity")

        account_status_total = self.active_accounts + self.disabled_accounts + self.revoked_accounts

        if account_status_total != self.accounts:
            raise ValueError("service-account status counts are inconsistent")

        token_status_total = self.active_tokens + self.revoked_tokens + self.expired_tokens

        if token_status_total != self.tokens:
            raise ValueError("API-token status counts are inconsistent")

        maximum_tokens = self.accounts * self.max_tokens_per_account

        if self.tokens > maximum_tokens:
            raise ValueError("API-token count exceeds per-account capacity")


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountPageRequest:
    """Validated offset pagination for accounts and token metadata."""

    offset: int = 0
    limit: int = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("service-account page offset cannot be negative")
        if self.limit <= 0 or self.limit > MAX_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE:
            raise ValueError(
                "service-account page limit must be between 1 and "
                f"{MAX_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE}"
            )


DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST = ControlPlaneServiceAccountPageRequest()


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountPageInfo:
    """Stable pagination metadata for repository reads."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.returned < 0 or self.total < 0:
            raise ValueError("service-account page counters cannot be negative")

        if self.limit <= 0 or self.limit > MAX_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE:
            raise ValueError("service-account page limit is outside bounds")

        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("service-account page returned count is inconsistent")

        expected = self.offset + self.returned

        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("service-account page requires next_offset")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("service-account page next_offset is inconsistent")

    @classmethod
    def from_slice(
        cls,
        request: ControlPlaneServiceAccountPageRequest,
        *,
        returned: int,
        total: int,
    ) -> ControlPlaneServiceAccountPageInfo:
        next_offset = request.offset + returned

        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=(next_offset if next_offset < total else None),
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountPage:
    """Deterministically ordered service-account page."""

    items: tuple[ControlPlaneServiceAccountRecord, ...]
    page: ControlPlaneServiceAccountPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("service-account page count must match items")

        ids = tuple(item.id for item in self.items)
        names = tuple(item.name for item in self.items)

        if len(ids) != len(set(ids)) or len(names) != len(set(names)):
            raise ValueError("service-account page items must be unique")


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenPage:
    """Deterministically ordered API-token metadata page."""

    items: tuple[ControlPlaneApiTokenMetadata, ...]
    page: ControlPlaneServiceAccountPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("API-token page count must match items")

        ids = tuple(item.id for item in self.items)
        digests = tuple(item.token_digest for item in self.items)

        if len(ids) != len(set(ids)) or len(digests) != len(set(digests)):
            raise ValueError("API-token page items must be unique")


class ControlPlaneServiceAccountRepository(Protocol):
    """Persistence boundary for service accounts and API tokens."""

    @property
    def closed(self) -> bool: ...

    def add_account(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> Awaitable[None]: ...

    def get_account(
        self,
        service_account_id: UUID,
    ) -> Awaitable[ControlPlaneServiceAccountRecord | None]: ...

    def get_account_by_name(
        self,
        name: str,
    ) -> Awaitable[ControlPlaneServiceAccountRecord | None]: ...

    def list_accounts(
        self,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> Awaitable[ControlPlaneServiceAccountPage]: ...

    def replace_account(
        self,
        record: ControlPlaneServiceAccountRecord,
        *,
        expected_revision: int,
    ) -> Awaitable[ControlPlaneServiceAccountRecord]: ...

    def add_token(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> Awaitable[None]: ...

    def get_token(
        self,
        token_id: UUID,
    ) -> Awaitable[ControlPlaneApiTokenMetadata | None]: ...

    def get_token_by_digest(
        self,
        token_digest: str,
    ) -> Awaitable[ControlPlaneApiTokenMetadata | None]: ...

    def list_tokens(
        self,
        service_account_id: UUID,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> Awaitable[ControlPlaneApiTokenPage]: ...

    def replace_token(
        self,
        metadata: ControlPlaneApiTokenMetadata,
        *,
        expected_revision: int,
    ) -> Awaitable[ControlPlaneApiTokenMetadata]: ...

    def delete_terminal_token(
        self,
        token_id: UUID,
        *,
        expected_revision: int,
    ) -> Awaitable[None]: ...

    def rotate_token(
        self,
        predecessor: ControlPlaneApiTokenMetadata,
        successor: ControlPlaneApiTokenMetadata,
        *,
        expected_revision: int,
    ) -> Awaitable[ControlPlaneApiTokenRotation]: ...

    def snapshot(
        self,
    ) -> Awaitable[ControlPlaneServiceAccountRegistrySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def _normalize_name(value: str) -> str:
    normalized = value.strip().lower()

    if _NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError("service-account name must match [a-z][a-z0-9_.-]{2,63}")

    return normalized


def _normalize_display_name(
    value: str,
    *,
    label: str,
) -> str:
    normalized = value.strip()

    if not normalized or len(normalized) > 128:
        raise ValueError(f"{label} display name must contain between 1 and 128 characters")

    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"{label} display name must not contain control characters")

    return normalized


def _normalize_digest(
    value: str,
    *,
    label: str,
) -> str:
    normalized = value.strip().lower()

    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a SHA-256 hexadecimal digest")

    return normalized


def _normalize_scopes(
    values: frozenset[str],
) -> frozenset[str]:
    scopes = frozenset(value.strip().lower() for value in values)

    if not scopes:
        raise ValueError("API token requires at least one scope")

    if any(_SCOPE_PATTERN.fullmatch(value) is None for value in scopes):
        raise ValueError("API token scopes contain unsupported characters")

    return scopes


def _normalize_resources(
    values: frozenset[str],
) -> frozenset[str]:
    resources = frozenset(value.strip() for value in values)

    if not resources:
        raise ValueError("API token requires at least one resource")

    if any(_RESOURCE_PATTERN.fullmatch(value) is None for value in resources):
        raise ValueError("API token resources contain unsupported characters")

    return resources


def _normalize_networks(
    values: tuple[str, ...],
) -> tuple[str, ...]:
    if len(values) > MAX_CONTROL_PLANE_API_TOKEN_CLIENT_NETWORKS:
        raise ValueError("API token contains too many client networks")

    networks = []

    for value in values:
        supplied = value.strip()

        try:
            network = ip_network(
                supplied,
                strict=True,
            )
        except ValueError as exception:
            raise ValueError(
                "API token client networks must use canonical CIDR notation"
            ) from exception

        if supplied != network.with_prefixlen:
            raise ValueError("API token client networks must use canonical CIDR notation")

        networks.append(network)

    canonical = [network.with_prefixlen for network in networks]

    if len(canonical) != len(set(canonical)):
        raise ValueError("API token client networks must be unique")

    ordered = sorted(
        networks,
        key=lambda item: (
            item.version,
            int(item.network_address),
            item.prefixlen,
        ),
    )

    return tuple(item.with_prefixlen for item in ordered)


def _require_aware(
    value: datetime,
    label: str,
) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
