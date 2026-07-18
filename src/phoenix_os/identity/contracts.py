"""Immutable contracts for Phoenix identity, authentication, and sessions."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.configuration.contracts import SecretValue
from phoenix_os.policy import PrincipalType, SecurityContext

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _normalize_name(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized or _NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid {label}: {value!r}")
    return normalized


def _freeze_strings(values: frozenset[str]) -> frozenset[str]:
    result = frozenset(value.strip().lower() for value in values)
    if "" in result:
        raise ValueError("string sets must not contain blank values")
    return result


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
class AuthenticationCredential:
    """Provider-specific credential whose secret is redacted by default."""

    scheme: str
    secret: SecretValue = field(repr=False)
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scheme", _normalize_name(self.scheme, "credential scheme"))
        if not isinstance(self.secret, SecretValue):
            raise TypeError("credential secret must be a SecretValue")
        object.__setattr__(self, "attributes", _freeze_text_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class AuthenticationRequest:
    """One immutable request delivered to an authentication provider."""

    provider: str
    credential: AuthenticationCredential = field(repr=False)
    metadata: Mapping[str, str] = field(default_factory=dict)
    correlation_id: str | None = None
    causation_id: UUID | None = None
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _normalize_name(self.provider, "provider name"))
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.correlation_id is not None:
            normalized = self.correlation_id.strip()
            if not normalized:
                raise ValueError("correlation_id must not be blank")
            object.__setattr__(self, "correlation_id", normalized)
        object.__setattr__(self, "metadata", _freeze_text_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class Identity:
    """Authenticated subject returned by a trusted provider."""

    subject: str
    principal_type: PrincipalType = PrincipalType.USER
    provider: str = "local"
    display_name: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    attributes: Mapping[str, str] = field(default_factory=dict)
    authenticated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        subject = self.subject.strip()
        if not subject:
            raise ValueError("identity subject must not be blank")
        if self.principal_type is PrincipalType.ANONYMOUS:
            raise ValueError("authenticated identities cannot be anonymous")
        if self.authenticated_at.tzinfo is None:
            raise ValueError("authenticated_at must be timezone-aware")
        display_name = None if self.display_name is None else self.display_name.strip()
        if self.display_name is not None and not display_name:
            raise ValueError("display_name must not be blank")
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "provider", _normalize_name(self.provider, "provider name"))
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "roles", _freeze_strings(self.roles))
        object.__setattr__(self, "permissions", _freeze_strings(self.permissions))
        object.__setattr__(self, "scopes", _freeze_strings(self.scopes))
        object.__setattr__(self, "attributes", _freeze_text_mapping(self.attributes))

    def security_context(
        self,
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
        confirmed: bool = False,
        session_id: UUID | None = None,
    ) -> SecurityContext:
        """Translate this authenticated identity into the central policy model."""

        attributes = dict(self.attributes)
        attributes["identity_provider"] = self.provider
        if session_id is not None:
            attributes["session_id"] = str(session_id)
        return SecurityContext(
            principal=self.subject,
            principal_type=self.principal_type,
            authenticated=True,
            roles=self.roles,
            permissions=self.permissions,
            scopes=self.scopes,
            attributes=attributes,
            correlation_id=correlation_id,
            causation_id=causation_id,
            confirmed=confirmed,
        )


class SessionStatus(StrEnum):
    """Persistent lifecycle state of an authentication session."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    """Limits applied when issuing and refreshing sessions."""

    absolute_ttl: timedelta = timedelta(hours=8)
    idle_ttl: timedelta | None = timedelta(minutes=30)
    max_sessions_per_identity: int = 8
    touch_interval: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if self.absolute_ttl <= timedelta(0):
            raise ValueError("absolute_ttl must be positive")
        if self.idle_ttl is not None and self.idle_ttl <= timedelta(0):
            raise ValueError("idle_ttl must be positive")
        if self.max_sessions_per_identity <= 0:
            raise ValueError("max_sessions_per_identity must be positive")
        if self.touch_interval < timedelta(0):
            raise ValueError("touch_interval cannot be negative")


@dataclass(frozen=True, slots=True)
class Session:
    """Public session metadata that never contains the bearer token."""

    id: UUID
    identity: Identity
    issued_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime | None = None
    idle_ttl: timedelta | None = None
    status: SessionStatus = SessionStatus.ACTIVE
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        timestamps = (self.issued_at, self.expires_at, self.last_seen_at)
        if any(value.tzinfo is None for value in timestamps):
            raise ValueError("session timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        if self.last_seen_at < self.issued_at:
            raise ValueError("last_seen_at cannot be earlier than issued_at")
        if self.idle_ttl is not None and self.idle_ttl <= timedelta(0):
            raise ValueError("idle_ttl must be positive")
        if self.idle_expires_at is not None:
            if self.idle_expires_at.tzinfo is None:
                raise ValueError("idle_expires_at must be timezone-aware")
            if self.idle_expires_at <= self.last_seen_at:
                raise ValueError("idle_expires_at must be later than last_seen_at")
            if self.idle_ttl is None:
                raise ValueError("idle_expires_at requires idle_ttl")
        elif self.idle_ttl is not None:
            raise ValueError("idle_ttl requires idle_expires_at")
        if self.status is SessionStatus.REVOKED and self.revoked_at is None:
            raise ValueError("revoked sessions require revoked_at")
        if self.revoked_at is not None and self.revoked_at.tzinfo is None:
            raise ValueError("revoked_at must be timezone-aware")
        reason = None if self.revocation_reason is None else self.revocation_reason.strip()
        if self.revocation_reason is not None and not reason:
            raise ValueError("revocation_reason must not be blank")
        object.__setattr__(self, "revocation_reason", reason)
        object.__setattr__(self, "metadata", _freeze_text_mapping(self.metadata))

    def valid_at(self, moment: datetime) -> bool:
        """Return whether this session is active at the supplied instant."""

        if moment.tzinfo is None:
            raise ValueError("moment must be timezone-aware")
        if self.status is not SessionStatus.ACTIVE or moment >= self.expires_at:
            return False
        return self.idle_expires_at is None or moment < self.idle_expires_at

    def security_context(
        self,
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
        confirmed: bool = False,
    ) -> SecurityContext:
        return self.identity.security_context(
            correlation_id=correlation_id,
            causation_id=causation_id,
            confirmed=confirmed,
            session_id=self.id,
        )


@dataclass(frozen=True, slots=True)
class SessionGrant:
    """Newly issued session and its one-time bearer token."""

    session: Session
    token: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.token, SecretValue):
            raise TypeError("session token must be a SecretValue")


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Repository record containing only a one-way token digest."""

    session: Session
    token_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        normalized = self.token_digest.strip().lower()
        if _DIGEST_PATTERN.fullmatch(normalized) is None:
            raise ValueError("token_digest must be a 64-character hexadecimal SHA-256 digest")
        object.__setattr__(self, "token_digest", normalized)


@dataclass(frozen=True, slots=True)
class ProviderRegistration:
    """Opaque provider registration handle."""

    id: UUID
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_name(self.name, "provider name"))


@dataclass(frozen=True, slots=True)
class AuthenticationSnapshot:
    """Point-in-time authentication manager counters."""

    closed: bool
    providers: tuple[str, ...]
    sessions: int
    active_sessions: int
    authentications: int
    failures: int
    revocations: int


class AuthenticationProvider(Protocol):
    """Provider boundary; external protocols remain outside the core."""

    def authenticate(self, request: AuthenticationRequest) -> Awaitable[Identity] | Identity: ...


class SessionRepository(Protocol):
    """Persistence boundary for hashed session records."""

    @property
    def closed(self) -> bool: ...

    def save(self, record: SessionRecord) -> Awaitable[None]: ...

    def get(self, session_id: UUID) -> Awaitable[SessionRecord | None]: ...

    def find_by_digest(self, token_digest: str) -> Awaitable[SessionRecord | None]: ...

    def list_for_subject(self, subject: str) -> Awaitable[tuple[SessionRecord, ...]]: ...

    def list_all(self) -> Awaitable[tuple[SessionRecord, ...]]: ...

    def close(self) -> Awaitable[None]: ...
