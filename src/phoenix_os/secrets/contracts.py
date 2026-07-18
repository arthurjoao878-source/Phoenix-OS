"""Immutable contracts for Phoenix secrets vault and key-management boundaries."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.configuration import SecretValue

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


def _normalize(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized or _NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid {label}: {value!r}")
    return normalized


def _freeze_text_mapping(values: Mapping[str, str]) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for key, value in values.items():
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if not normalized_key or not normalized_value:
            raise ValueError("metadata keys and values must not be blank")
        result[normalized_key] = normalized_value
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class KeyRef:
    """Provider-neutral reference to a wrapping key and optional immutable version."""

    name: str
    provider: str = "default"
    version: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize(self.name, "key name"))
        object.__setattr__(self, "provider", _normalize(self.provider, "key provider"))
        if self.version is not None and self.version <= 0:
            raise ValueError("key version must be positive")

    @property
    def canonical(self) -> str:
        suffix = "" if self.version is None else f"#{self.version}"
        return f"{self.provider}/{self.name}{suffix}"


@dataclass(frozen=True, slots=True)
class SecretRef:
    """Stable reference to a secret name and optionally one immutable version."""

    name: str
    namespace: str = "default"
    version: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize(self.name, "secret name"))
        object.__setattr__(self, "namespace", _normalize(self.namespace, "secret namespace"))
        if self.version is not None and self.version <= 0:
            raise ValueError("secret version must be positive")

    @property
    def canonical(self) -> str:
        return f"{self.namespace}/{self.name}"

    @property
    def resource(self) -> str:
        return f"secret:{self.canonical}"

    def at(self, version: int) -> SecretRef:
        return SecretRef(self.name, self.namespace, version)

    def __str__(self) -> str:
        suffix = "" if self.version is None else f"#{self.version}"
        return f"{self.canonical}{suffix}"


class SecretStatus(StrEnum):
    """Lifecycle state of one immutable secret version."""

    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class SecretMetadata:
    """Non-sensitive metadata for one secret version."""

    ref: SecretRef
    created_by: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: SecretStatus = SecretStatus.ACTIVE
    rotated_from: int | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    protection_key: KeyRef | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.ref.version is None:
            raise ValueError("secret metadata requires an exact version")
        creator = self.created_by.strip()
        if not creator:
            raise ValueError("created_by must not be blank")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.rotated_from is not None and self.rotated_from <= 0:
            raise ValueError("rotated_from must be positive")
        if self.status is SecretStatus.REVOKED and self.revoked_at is None:
            raise ValueError("revoked secrets require revoked_at")
        if self.revoked_at is not None and self.revoked_at.tzinfo is None:
            raise ValueError("revoked_at must be timezone-aware")
        reason = None if self.revocation_reason is None else self.revocation_reason.strip()
        if self.revocation_reason is not None and not reason:
            raise ValueError("revocation_reason must not be blank")
        object.__setattr__(self, "created_by", creator)
        object.__setattr__(self, "revocation_reason", reason)
        object.__setattr__(self, "attributes", _freeze_text_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class StoredSecret:
    """Store boundary object; material remains redacted by SecretValue."""

    metadata: SecretMetadata
    value: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.value, SecretValue):
            raise TypeError("stored secret value must be SecretValue")


@dataclass(frozen=True, slots=True)
class SecretLeasePolicy:
    """Limits applied to temporary secret material leases."""

    default_ttl: timedelta = timedelta(minutes=5)
    max_ttl: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        if self.default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive")
        if self.max_ttl <= timedelta(0):
            raise ValueError("max_ttl must be positive")
        if self.default_ttl > self.max_ttl:
            raise ValueError("default_ttl cannot exceed max_ttl")


class SecretLeaseStatus(StrEnum):
    """Lifecycle state of a temporary material lease."""

    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class SecretLease:
    """Short-lived grant containing redacted secret material."""

    ref: SecretRef
    principal: str
    value: SecretValue = field(repr=False)
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=5))
    status: SecretLeaseStatus = SecretLeaseStatus.ACTIVE
    id: UUID = field(default_factory=uuid4)
    correlation_id: str | None = None
    causation_id: UUID | None = None

    def __post_init__(self) -> None:
        if self.ref.version is None:
            raise ValueError("secret leases require an exact version")
        if not self.principal.strip():
            raise ValueError("lease principal must not be blank")
        if not isinstance(self.value, SecretValue):
            raise TypeError("lease value must be SecretValue")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("lease timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("lease expires_at must be after issued_at")
        if self.correlation_id is not None and not self.correlation_id.strip():
            raise ValueError("correlation_id must not be blank")
        object.__setattr__(self, "principal", self.principal.strip())
        if self.correlation_id is not None:
            object.__setattr__(self, "correlation_id", self.correlation_id.strip())

    def valid_at(self, moment: datetime) -> bool:
        if moment.tzinfo is None:
            raise ValueError("moment must be timezone-aware")
        return self.status is SecretLeaseStatus.ACTIVE and moment < self.expires_at


@dataclass(frozen=True, slots=True)
class SecretStoreSnapshot:
    """Non-sensitive point-in-time state of a secret store."""

    closed: bool
    names: int
    versions: int
    active_versions: int
    revoked_versions: int


@dataclass(frozen=True, slots=True)
class SecretsSnapshot:
    """Non-sensitive manager diagnostics."""

    closed: bool
    leases: int
    active_leases: int
    issued_leases: int
    revoked_leases: int
    denied_operations: int


class SecretStore(Protocol):
    """Provider-neutral asynchronous storage boundary for secret material."""

    @property
    def closed(self) -> bool: ...

    def put(
        self,
        ref: SecretRef,
        value: SecretValue,
        *,
        created_by: str,
        attributes: Mapping[str, str] | None = None,
        protection_key: KeyRef | None = None,
    ) -> Awaitable[StoredSecret]: ...

    def get(self, ref: SecretRef) -> Awaitable[StoredSecret | None]: ...

    def list(self, *, namespace: str | None = None) -> Awaitable[tuple[SecretMetadata, ...]]: ...

    def revoke(
        self,
        ref: SecretRef,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> Awaitable[SecretMetadata | None]: ...

    def snapshot(self) -> Awaitable[SecretStoreSnapshot]: ...

    def close(self) -> Awaitable[None]: ...


class SecretProtector(Protocol):
    """External cryptographic boundary; algorithms and keys stay outside the core."""

    def seal(self, value: bytes, *, key: KeyRef) -> bytes | Awaitable[bytes]: ...

    def open(self, value: bytes, *, key: KeyRef) -> bytes | Awaitable[bytes]: ...
