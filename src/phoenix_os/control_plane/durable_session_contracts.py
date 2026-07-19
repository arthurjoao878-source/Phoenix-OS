"""Immutable contracts for durable local-operator control-plane sessions."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

DEFAULT_DURABLE_SESSION_PAGE_SIZE = 50
MAX_DURABLE_SESSION_PAGE_SIZE = 200
MAX_DURABLE_SESSION_CAPACITY = 100_000
DEFAULT_DURABLE_SESSIONS_PER_OPERATOR = 8
MAX_DURABLE_SESSIONS_PER_OPERATOR = 64
DEFAULT_DURABLE_SESSION_ABSOLUTE_TTL = timedelta(hours=8)
MAX_DURABLE_SESSION_ABSOLUTE_TTL = timedelta(hours=24)
DEFAULT_DURABLE_SESSION_IDLE_TTL = timedelta(minutes=30)
MAX_DURABLE_SESSION_IDLE_TTL = timedelta(hours=8)
DEFAULT_DURABLE_SESSION_ROTATION_INTERVAL = timedelta(minutes=15)
MAX_DURABLE_SESSION_ROTATION_INTERVAL = timedelta(hours=12)
DEFAULT_DURABLE_SESSION_TERMINAL_RETENTION = timedelta(days=7)
MAX_DURABLE_SESSION_TERMINAL_RETENTION = timedelta(days=90)

_USERNAME_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{2,63}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SESSION_SECRET_PATTERN = re.compile(r"[A-Za-z0-9._~-]{32,128}\Z")


class ControlPlaneDurableSessionStatus(StrEnum):
    """Persisted lifecycle state for one local-operator session."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    ROTATED = "rotated"

    @property
    def terminal(self) -> bool:
        return self is not self.ACTIVE


class ControlPlaneDurableSessionTerminationReason(StrEnum):
    """Credential-free reason explaining a terminal durable session."""

    LOGOUT = "logout"
    ADMINISTRATIVE = "administrative"
    OPERATOR_INACTIVE = "operator-inactive"
    CREDENTIAL_ROTATED = "credential-rotated"
    ROLE_CHANGED = "role-changed"
    PERMISSIONS_CHANGED = "permissions-changed"
    ABSOLUTE_TIMEOUT = "absolute-timeout"
    IDLE_TIMEOUT = "idle-timeout"
    TOKEN_ROTATED = "token-rotated"

    @property
    def expiration(self) -> bool:
        return self in {self.ABSOLUTE_TIMEOUT, self.IDLE_TIMEOUT}


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneDurableSessionToken:
    """One-time session token redacted from string representations."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_secret(self.value, label="durable session token")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.value.encode("ascii")).hexdigest()

    def __repr__(self) -> str:
        return "ControlPlaneDurableSessionToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneDurableCsrfSecret:
    """One-time CSRF secret redacted from string representations."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_secret(self.value, label="durable session CSRF secret")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.value.encode("ascii")).hexdigest()

    def __repr__(self) -> str:
        return "ControlPlaneDurableCsrfSecret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionPolicy:
    """Bounded expiration, rotation, retention, and concurrency policy."""

    absolute_ttl: timedelta = DEFAULT_DURABLE_SESSION_ABSOLUTE_TTL
    idle_ttl: timedelta = DEFAULT_DURABLE_SESSION_IDLE_TTL
    rotation_interval: timedelta = DEFAULT_DURABLE_SESSION_ROTATION_INTERVAL
    terminal_retention: timedelta = DEFAULT_DURABLE_SESSION_TERMINAL_RETENTION
    max_sessions_per_operator: int = DEFAULT_DURABLE_SESSIONS_PER_OPERATOR
    schema_version: int = 1

    def __post_init__(self) -> None:
        _validate_duration(
            self.absolute_ttl,
            label="absolute TTL",
            maximum=MAX_DURABLE_SESSION_ABSOLUTE_TTL,
        )
        _validate_duration(
            self.idle_ttl,
            label="idle TTL",
            maximum=MAX_DURABLE_SESSION_IDLE_TTL,
        )
        _validate_duration(
            self.rotation_interval,
            label="rotation interval",
            maximum=MAX_DURABLE_SESSION_ROTATION_INTERVAL,
        )
        _validate_duration(
            self.terminal_retention,
            label="terminal retention",
            maximum=MAX_DURABLE_SESSION_TERMINAL_RETENTION,
        )
        if self.idle_ttl > self.absolute_ttl:
            raise ValueError("durable session idle TTL cannot exceed absolute TTL")
        if self.rotation_interval > self.absolute_ttl:
            raise ValueError("durable session rotation interval cannot exceed absolute TTL")
        if (
            self.max_sessions_per_operator <= 0
            or self.max_sessions_per_operator > MAX_DURABLE_SESSIONS_PER_OPERATOR
        ):
            raise ValueError("durable session per-operator limit is outside supported bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session policy schema version")

    def absolute_expiry(self, issued_at: datetime) -> datetime:
        _require_aware(issued_at, "issued_at")
        return issued_at + self.absolute_ttl

    def idle_expiry(self, last_seen_at: datetime, *, absolute_expires_at: datetime) -> datetime:
        _require_aware(last_seen_at, "last_seen_at")
        _require_aware(absolute_expires_at, "absolute_expires_at")
        return min(last_seen_at + self.idle_ttl, absolute_expires_at)

    def rotation_due_at(self, issued_at: datetime, *, absolute_expires_at: datetime) -> datetime:
        _require_aware(issued_at, "issued_at")
        _require_aware(absolute_expires_at, "absolute_expires_at")
        return min(issued_at + self.rotation_interval, absolute_expires_at)


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRecord:
    """Digest-only durable session record safe for persistence and history."""

    id: UUID
    operator_id: UUID
    username: str
    token_digest: str = field(repr=False)
    csrf_digest: str = field(repr=False)
    operator_revision: int
    operator_token_version: int
    generation: int
    issued_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    idle_expires_at: datetime
    rotate_after: datetime
    status: ControlPlaneDurableSessionStatus = ControlPlaneDurableSessionStatus.ACTIVE
    terminated_at: datetime | None = None
    termination_reason: ControlPlaneDurableSessionTerminationReason | None = None
    predecessor_session_id: UUID | None = None
    successor_session_id: UUID | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        username = _normalize_username(self.username)
        token_digest = _normalize_digest(self.token_digest, label="token digest")
        csrf_digest = _normalize_digest(self.csrf_digest, label="CSRF digest")
        status = ControlPlaneDurableSessionStatus(self.status)
        reason = (
            None
            if self.termination_reason is None
            else ControlPlaneDurableSessionTerminationReason(self.termination_reason)
        )
        if token_digest == csrf_digest:
            raise ValueError("durable session token and CSRF digests must be distinct")
        if self.operator_revision <= 0:
            raise ValueError("durable session operator revision must be positive")
        if self.operator_token_version <= 0:
            raise ValueError("durable session operator token version must be positive")
        if self.generation <= 0:
            raise ValueError("durable session generation must be positive")
        if self.revision <= 0:
            raise ValueError("durable session revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session record schema version")
        for label, value in (
            ("issued_at", self.issued_at),
            ("last_seen_at", self.last_seen_at),
            ("absolute_expires_at", self.absolute_expires_at),
            ("idle_expires_at", self.idle_expires_at),
            ("rotate_after", self.rotate_after),
        ):
            _require_aware(value, label)
        if self.last_seen_at < self.issued_at:
            raise ValueError("durable session last_seen_at cannot precede issuance")
        if self.absolute_expires_at <= self.issued_at:
            raise ValueError("durable session absolute expiry must follow issuance")
        if self.absolute_expires_at - self.issued_at > MAX_DURABLE_SESSION_ABSOLUTE_TTL:
            raise ValueError("durable session absolute lifetime exceeds the supported maximum")
        if self.idle_expires_at <= self.last_seen_at:
            raise ValueError("durable session idle expiry must follow last activity")
        if self.idle_expires_at > self.absolute_expires_at:
            raise ValueError("durable session idle expiry cannot exceed absolute expiry")
        if self.rotate_after <= self.issued_at:
            raise ValueError("durable session rotation time must follow issuance")
        if self.rotate_after > self.absolute_expires_at:
            raise ValueError("durable session rotation time cannot exceed absolute expiry")
        if self.generation == 1 and self.predecessor_session_id is not None:
            raise ValueError("first durable session generation cannot have a predecessor")
        if self.generation > 1 and self.predecessor_session_id is None:
            raise ValueError("rotated durable session generation requires a predecessor")
        if self.predecessor_session_id == self.id or self.successor_session_id == self.id:
            raise ValueError("durable session lineage cannot reference itself")

        if status is ControlPlaneDurableSessionStatus.ACTIVE:
            if self.terminated_at is not None or reason is not None:
                raise ValueError("active durable session cannot contain termination facts")
            if self.successor_session_id is not None:
                raise ValueError("active durable session cannot contain a successor")
        else:
            if self.terminated_at is None or reason is None:
                raise ValueError("terminal durable session requires termination facts")
            _require_aware(self.terminated_at, "terminated_at")
            if self.terminated_at < self.issued_at:
                raise ValueError("durable session termination cannot precede issuance")
            if status is ControlPlaneDurableSessionStatus.ROTATED:
                if reason is not ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED:
                    raise ValueError("rotated durable session requires token-rotated reason")
                if self.successor_session_id is None:
                    raise ValueError("rotated durable session requires a successor")
            else:
                if self.successor_session_id is not None:
                    raise ValueError("non-rotated durable session cannot contain a successor")
                if reason is ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED:
                    raise ValueError("token-rotated reason requires rotated session status")
                if status is ControlPlaneDurableSessionStatus.EXPIRED and not reason.expiration:
                    raise ValueError("expired durable session requires an expiration reason")
                if status is ControlPlaneDurableSessionStatus.REVOKED and reason.expiration:
                    raise ValueError("revoked durable session cannot use an expiration reason")

        object.__setattr__(self, "username", username)
        object.__setattr__(self, "token_digest", token_digest)
        object.__setattr__(self, "csrf_digest", csrf_digest)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "termination_reason", reason)

    @classmethod
    def issue(
        cls,
        *,
        operator_id: UUID,
        username: str,
        token: ControlPlaneDurableSessionToken,
        csrf_secret: ControlPlaneDurableCsrfSecret,
        operator_revision: int,
        operator_token_version: int,
        issued_at: datetime,
        policy: ControlPlaneDurableSessionPolicy | None = None,
        session_id: UUID | None = None,
        generation: int = 1,
        predecessor_session_id: UUID | None = None,
        absolute_expires_at: datetime | None = None,
    ) -> ControlPlaneDurableSessionRecord:
        """Create one active record without retaining either plaintext secret."""

        _require_aware(issued_at, "issued_at")
        resolved_policy = ControlPlaneDurableSessionPolicy() if policy is None else policy
        absolute_expiry = (
            resolved_policy.absolute_expiry(issued_at)
            if absolute_expires_at is None
            else absolute_expires_at
        )
        _require_aware(absolute_expiry, "absolute_expires_at")
        return cls(
            id=uuid4() if session_id is None else session_id,
            operator_id=operator_id,
            username=username,
            token_digest=token.digest,
            csrf_digest=csrf_secret.digest,
            operator_revision=operator_revision,
            operator_token_version=operator_token_version,
            generation=generation,
            issued_at=issued_at,
            last_seen_at=issued_at,
            absolute_expires_at=absolute_expiry,
            idle_expires_at=resolved_policy.idle_expiry(
                issued_at,
                absolute_expires_at=absolute_expiry,
            ),
            rotate_after=resolved_policy.rotation_due_at(
                issued_at,
                absolute_expires_at=absolute_expiry,
            ),
            predecessor_session_id=predecessor_session_id,
        )

    def expiration_reason_at(
        self,
        now: datetime,
    ) -> ControlPlaneDurableSessionTerminationReason | None:
        _require_aware(now, "now")
        if self.status.terminal:
            return None
        if now >= self.absolute_expires_at:
            return ControlPlaneDurableSessionTerminationReason.ABSOLUTE_TIMEOUT
        if now >= self.idle_expires_at:
            return ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT
        return None

    def active_at(self, now: datetime) -> bool:
        return self.status is ControlPlaneDurableSessionStatus.ACTIVE and (
            self.expiration_reason_at(now) is None
        )

    def rotation_due_at(self, now: datetime) -> bool:
        _require_aware(now, "now")
        return self.active_at(now) and now >= self.rotate_after


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionPageRequest:
    """Bounded deterministic pagination with optional exact filters."""

    offset: int = 0
    limit: int = DEFAULT_DURABLE_SESSION_PAGE_SIZE
    operator_id: UUID | None = None
    status: ControlPlaneDurableSessionStatus | None = None

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("durable session offset cannot be negative")
        if self.limit <= 0 or self.limit > MAX_DURABLE_SESSION_PAGE_SIZE:
            raise ValueError(
                f"durable session limit must be between 1 and {MAX_DURABLE_SESSION_PAGE_SIZE}"
            )
        if self.status is not None:
            object.__setattr__(self, "status", ControlPlaneDurableSessionStatus(self.status))


DEFAULT_DURABLE_SESSION_PAGE_REQUEST = ControlPlaneDurableSessionPageRequest()


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionPageInfo:
    """Stable metadata for one durable-session page."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.returned < 0 or self.total < 0:
            raise ValueError("durable session page counters cannot be negative")
        if self.limit <= 0 or self.limit > MAX_DURABLE_SESSION_PAGE_SIZE:
            raise ValueError("durable session page limit is outside supported bounds")
        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("durable session returned count is inconsistent")
        expected = self.offset + self.returned
        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("durable session page requires next_offset")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("durable session next_offset is inconsistent")

    @classmethod
    def from_slice(
        cls,
        request: ControlPlaneDurableSessionPageRequest,
        *,
        returned: int,
        total: int,
    ) -> ControlPlaneDurableSessionPageInfo:
        next_offset = request.offset + returned
        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=next_offset if next_offset < total else None,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionPage:
    """Deterministically ordered digest-only durable-session records."""

    items: tuple[ControlPlaneDurableSessionRecord, ...]
    page: ControlPlaneDurableSessionPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("durable session page count must match items")
        identities = tuple(item.id for item in self.items)
        if len(identities) != len(set(identities)):
            raise ValueError("durable session page items must be unique")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRotation:
    """Atomic result for one old-token to new-token rotation."""

    previous: ControlPlaneDurableSessionRecord
    successor: ControlPlaneDurableSessionRecord

    def __post_init__(self) -> None:
        if self.previous.status is not ControlPlaneDurableSessionStatus.ROTATED:
            raise ValueError("durable session rotation previous record must be rotated")
        if self.successor.status is not ControlPlaneDurableSessionStatus.ACTIVE:
            raise ValueError("durable session rotation successor must be active")
        if self.previous.successor_session_id != self.successor.id:
            raise ValueError("durable session rotation lineage is inconsistent")
        if self.successor.predecessor_session_id != self.previous.id:
            raise ValueError("durable session rotation reverse lineage is inconsistent")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionSnapshot:
    """Credential-free counters for one bounded durable-session repository."""

    closed: bool
    entries: int
    active: int
    revoked: int
    expired: int
    rotated: int
    capacity: int
    max_sessions_per_operator: int

    def __post_init__(self) -> None:
        values = (self.entries, self.active, self.revoked, self.expired, self.rotated)
        if any(value < 0 for value in values):
            raise ValueError("durable session counters cannot be negative")
        if self.capacity <= 0 or self.capacity > MAX_DURABLE_SESSION_CAPACITY:
            raise ValueError("durable session capacity is outside supported bounds")
        if self.entries > self.capacity:
            raise ValueError("durable session entries cannot exceed capacity")
        if sum(values[1:]) != self.entries:
            raise ValueError("durable session status counts must equal entries")
        if (
            self.max_sessions_per_operator <= 0
            or self.max_sessions_per_operator > MAX_DURABLE_SESSIONS_PER_OPERATOR
        ):
            raise ValueError("durable session per-operator limit is outside supported bounds")


class ControlPlaneDurableSessionRepository(Protocol):
    """Asynchronous persistence boundary for durable operator sessions."""

    @property
    def closed(self) -> bool: ...

    def add(self, record: ControlPlaneDurableSessionRecord) -> Awaitable[None]: ...

    def get(self, session_id: UUID) -> Awaitable[ControlPlaneDurableSessionRecord | None]: ...

    def get_by_token_digest(
        self,
        token_digest: str,
    ) -> Awaitable[ControlPlaneDurableSessionRecord | None]: ...

    def list_page(
        self,
        request: ControlPlaneDurableSessionPageRequest = DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    ) -> Awaitable[ControlPlaneDurableSessionPage]: ...

    def list_active_for_operator(
        self,
        operator_id: UUID,
        *,
        limit: int = MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ) -> Awaitable[tuple[ControlPlaneDurableSessionRecord, ...]]: ...

    def touch(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        seen_at: datetime,
        idle_expires_at: datetime,
    ) -> Awaitable[ControlPlaneDurableSessionRecord]: ...

    def terminate(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        status: ControlPlaneDurableSessionStatus,
        reason: ControlPlaneDurableSessionTerminationReason,
        terminated_at: datetime,
    ) -> Awaitable[ControlPlaneDurableSessionRecord]: ...

    def rotate(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        successor: ControlPlaneDurableSessionRecord,
        rotated_at: datetime,
    ) -> Awaitable[ControlPlaneDurableSessionRotation]: ...

    def delete_terminal(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
    ) -> Awaitable[None]: ...

    def snapshot(self) -> Awaitable[ControlPlaneDurableSessionSnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def _validate_secret(value: str, *, label: str) -> None:
    if value != value.strip() or _SESSION_SECRET_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} has an invalid format")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exception:
        raise ValueError(f"{label} must contain ASCII characters only") from exception


def _normalize_username(value: str) -> str:
    normalized = value.strip().lower()
    if _USERNAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError("durable session username must match [a-z][a-z0-9_.-]{2,63}")
    return normalized


def _normalize_digest(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"durable session {label} must be a SHA-256 hexadecimal digest")
    return normalized


def _validate_duration(value: timedelta, *, label: str, maximum: timedelta) -> None:
    if value <= timedelta(0) or value > maximum:
        raise ValueError(f"durable session {label} is outside supported bounds")


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
