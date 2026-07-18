"""Immutable contracts for the Phoenix audit ledger and security journal."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID, uuid4

from phoenix_os.observability.redaction import RedactionPolicy

if TYPE_CHECKING:
    from phoenix_os.secrets.contracts import KeyRef

AUDIT_GENESIS_DIGEST = "0" * 64
_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
_ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_.:*?/-]*$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_REDACTION = RedactionPolicy()


def _normalize_identifier(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized or _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid {label}: {value!r}")
    return normalized


def _normalize_action(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or _ACTION_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid audit action: {value!r}")
    return normalized


def _normalize_text(value: str, label: str, *, lower: bool = False) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be blank")
    return normalized.lower() if lower else normalized


def _normalize_digest(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if _DIGEST_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 hexadecimal digest")
    return normalized


def _normalize_string_set(
    values: frozenset[str],
    label: str,
    *,
    lower: bool = False,
) -> frozenset[str]:
    normalized = frozenset(_normalize_text(item, label, lower=lower) for item in values)
    if len(normalized) != len(values):
        raise ValueError(f"{label} values must be unique after normalization")
    return normalized


class AuditCategory(StrEnum):
    """Stable categories used to investigate security-relevant facts."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CAPABILITY = "capability"
    CONFIGURATION = "configuration"
    IDENTITY = "identity"
    JOB = "job"
    WORKFLOW = "workflow"
    PLUGIN = "plugin"
    RUNTIME = "runtime"
    SECRETS = "secrets"
    STATE = "state"
    SYSTEM = "system"
    OTHER = "other"


class AuditOutcome(StrEnum):
    """Portable result of the operation represented by an audit fact."""

    SUCCEEDED = "succeeded"
    DENIED = "denied"
    RESTRICTED = "restricted"
    FAILED = "failed"
    UNKNOWN = "unknown"


class AuditSeverity(StrEnum):
    """Security-oriented importance independent of a logging framework."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One immutable and recursively redacted security fact before sequencing."""

    name: str
    source: str
    category: AuditCategory
    action: str
    resource: str
    actor: str
    outcome: AuditOutcome = AuditOutcome.SUCCEEDED
    severity: AuditSeverity = AuditSeverity.INFO
    details: Mapping[str, object] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    causation_id: UUID | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_identifier(self.name, "audit event name"))
        object.__setattr__(self, "source", _normalize_identifier(self.source, "audit source"))
        object.__setattr__(self, "category", AuditCategory(self.category))
        object.__setattr__(self, "action", _normalize_action(self.action))
        object.__setattr__(self, "resource", _normalize_text(self.resource, "audit resource"))
        object.__setattr__(self, "actor", _normalize_text(self.actor, "audit actor"))
        object.__setattr__(self, "outcome", AuditOutcome(self.outcome))
        object.__setattr__(self, "severity", AuditSeverity(self.severity))
        object.__setattr__(self, "details", _DEFAULT_REDACTION.redact(self.details))
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.correlation_id is not None:
            object.__setattr__(
                self,
                "correlation_id",
                _normalize_text(self.correlation_id, "correlation_id"),
            )


@dataclass(frozen=True, slots=True)
class AuditSeal:
    """External signature metadata attached to one record digest."""

    key: KeyRef
    algorithm: str
    signature: bytes = field(repr=False)

    def __post_init__(self) -> None:
        algorithm = _normalize_text(self.algorithm, "signature algorithm", lower=True)
        signature = bytes(self.signature)
        if not signature:
            raise ValueError("audit signature must not be empty")
        object.__setattr__(self, "algorithm", algorithm)
        object.__setattr__(self, "signature", signature)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One immutable sequenced record in a hash-linked audit ledger."""

    event: AuditEvent
    sequence: int
    recorded_at: datetime
    previous_digest: str
    digest: str
    seal: AuditSeal | None = None

    def __post_init__(self) -> None:
        if self.sequence <= 0:
            raise ValueError("audit sequence must be positive")
        if self.recorded_at.tzinfo is None:
            raise ValueError("recorded_at must be timezone-aware")
        object.__setattr__(
            self,
            "previous_digest",
            _normalize_digest(self.previous_digest, "previous_digest"),
        )
        object.__setattr__(self, "digest", _normalize_digest(self.digest, "digest"))


@dataclass(frozen=True, slots=True)
class AuditQuery:
    """Bounded deterministic filters for ascending audit inspection."""

    start_sequence: int = 1
    end_sequence: int | None = None
    limit: int = 100
    categories: frozenset[AuditCategory] = field(default_factory=frozenset)
    outcomes: frozenset[AuditOutcome] = field(default_factory=frozenset)
    sources: frozenset[str] = field(default_factory=frozenset)
    actors: frozenset[str] = field(default_factory=frozenset)
    actions: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.start_sequence <= 0:
            raise ValueError("start_sequence must be positive")
        if self.end_sequence is not None and self.end_sequence < self.start_sequence:
            raise ValueError("end_sequence cannot be lower than start_sequence")
        if self.limit <= 0 or self.limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        object.__setattr__(
            self,
            "categories",
            frozenset(AuditCategory(item) for item in self.categories),
        )
        object.__setattr__(
            self,
            "outcomes",
            frozenset(AuditOutcome(item) for item in self.outcomes),
        )
        object.__setattr__(
            self,
            "sources",
            frozenset(_normalize_identifier(item, "audit source") for item in self.sources),
        )
        object.__setattr__(
            self,
            "actors",
            _normalize_string_set(self.actors, "audit actor"),
        )
        object.__setattr__(
            self,
            "actions",
            frozenset(_normalize_action(item) for item in self.actions),
        )

    def matches(self, record: AuditRecord) -> bool:
        """Return whether one record satisfies this exact query."""

        if record.sequence < self.start_sequence:
            return False
        if self.end_sequence is not None and record.sequence > self.end_sequence:
            return False
        event = record.event
        if self.categories and event.category not in self.categories:
            return False
        if self.outcomes and event.outcome not in self.outcomes:
            return False
        if self.sources and event.source not in self.sources:
            return False
        if self.actors and event.actor not in self.actors:
            return False
        return not self.actions or event.action in self.actions


@dataclass(frozen=True, slots=True)
class AuditVerification:
    """Result of deterministic hash-chain and optional signature verification."""

    valid: bool
    checked_records: int
    head_digest: str
    first_sequence: int | None = None
    last_sequence: int | None = None
    failure_sequence: int | None = None
    reason: str | None = None
    signatures_checked: int = 0

    def __post_init__(self) -> None:
        if self.checked_records < 0:
            raise ValueError("checked_records cannot be negative")
        if self.signatures_checked < 0 or self.signatures_checked > self.checked_records:
            raise ValueError("signatures_checked must be within checked record count")
        object.__setattr__(self, "head_digest", _normalize_digest(self.head_digest, "head_digest"))
        if self.checked_records == 0:
            if self.first_sequence is not None or self.last_sequence is not None:
                raise ValueError("empty verification cannot have sequence bounds")
        elif self.first_sequence is None or self.last_sequence is None:
            raise ValueError("non-empty verification requires sequence bounds")
        if self.valid:
            if self.failure_sequence is not None or self.reason is not None:
                raise ValueError("valid verification cannot contain failure details")
        else:
            if self.failure_sequence is None or self.reason is None or not self.reason.strip():
                raise ValueError("invalid verification requires a failure sequence and reason")
            object.__setattr__(self, "reason", self.reason.strip())


@dataclass(frozen=True, slots=True)
class AuditStoreSnapshot:
    """Point-in-time non-sensitive state of an audit store."""

    closed: bool
    records: int
    head_sequence: int | None
    head_digest: str
    signed_records: int

    def __post_init__(self) -> None:
        if self.records < 0 or self.signed_records < 0 or self.signed_records > self.records:
            raise ValueError("invalid audit store counts")
        if self.records == 0 and self.head_sequence is not None:
            raise ValueError("empty audit store cannot have a head sequence")
        if self.records > 0 and self.head_sequence is None:
            raise ValueError("non-empty audit store requires a head sequence")
        object.__setattr__(self, "head_digest", _normalize_digest(self.head_digest, "head_digest"))


@dataclass(frozen=True, slots=True)
class AuditLedgerSnapshot:
    """Non-sensitive manager diagnostics."""

    closed: bool
    records: int
    head_sequence: int | None
    head_digest: str
    signed_records: int
    appended: int
    reads: int
    verifications: int
    verification_failures: int
    denied_operations: int


@dataclass(frozen=True, slots=True)
class SecurityJournalSnapshot:
    """Point-in-time Security Journal lifecycle and capture counters."""

    started: bool
    captured: int
    ignored: int
    failures: int


class AuditSigner(Protocol):
    """External signature boundary; key material and algorithms stay outside the core."""

    def sign(self, digest: bytes, *, key: KeyRef) -> bytes | Awaitable[bytes]: ...

    def verify(
        self,
        digest: bytes,
        signature: bytes,
        *,
        key: KeyRef,
    ) -> bool | Awaitable[bool]: ...


class AuditStore(Protocol):
    """Provider-neutral asynchronous append-only audit storage boundary."""

    @property
    def closed(self) -> bool: ...

    def append(self, event: AuditEvent, *, recorded_at: datetime) -> Awaitable[AuditRecord]: ...

    def read(self, query: AuditQuery) -> Awaitable[tuple[AuditRecord, ...]]: ...

    def verify(self) -> Awaitable[AuditVerification]: ...

    def snapshot(self) -> Awaitable[AuditStoreSnapshot]: ...

    def close(self) -> Awaitable[None]: ...
