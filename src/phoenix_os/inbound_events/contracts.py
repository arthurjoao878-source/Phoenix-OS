"""Immutable contracts for secure durable inbound events."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, cast
from uuid import UUID

from phoenix_os.secrets import SecretRef

MAX_INBOUND_SOURCE_NAME_LENGTH = 64
MAX_INBOUND_DISPLAY_NAME_LENGTH = 128
MAX_INBOUND_EVENT_TYPE_LENGTH = 128
MAX_INBOUND_EVENT_TYPES_PER_SOURCE = 64
MAX_INBOUND_RAW_BODY_BYTES = 1_048_576
MAX_INBOUND_NORMALIZED_PAYLOAD_BYTES = 1_048_576
MAX_INBOUND_HEADER_BYTES = 65_536
MAX_INBOUND_JSON_DEPTH = 16
MAX_INBOUND_JSON_ITEMS = 4_096
MAX_INBOUND_JSON_MAPPING_ITEMS = 1_024
MAX_INBOUND_JSON_SEQUENCE_ITEMS = 1_024
MAX_INBOUND_JSON_STRING_LENGTH = 65_536
MAX_INBOUND_IDENTIFIER_LENGTH = 256
MAX_INBOUND_CORRELATION_ID_LENGTH = 128
MAX_INBOUND_SOURCE_CAPACITY = 10_000
MAX_INBOUND_EVENT_CAPACITY = 100_000
MAX_INBOUND_REPLAY_CAPACITY = 500_000
MAX_INBOUND_PUBLICATION_ATTEMPTS = 20
MAX_INBOUND_RETRY_DELAY = timedelta(days=1)
MAX_INBOUND_REPLAY_RETENTION = timedelta(days=30)
MAX_INBOUND_TIMESTAMP_SKEW = timedelta(minutes=15)
MAX_INBOUND_SIGNING_LEASE_TTL = timedelta(minutes=5)
DEFAULT_INBOUND_PAGE_SIZE = 50
MAX_INBOUND_PAGE_SIZE = 200

_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{2,63}\Z")
_EVENT_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9._-]{2,127}\Z")
_FIELD_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_SCOPE_PATTERN = re.compile(r"[a-z][a-z0-9._-]{2,127}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_ERROR_CATEGORY_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")


type InboundJsonData = Mapping[str, object]


class InboundEventSourceStatus(StrEnum):
    """Administrative lifecycle state for one inbound source."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"

    @property
    def accepting(self) -> bool:
        return self is self.ACTIVE


class InboundAuthenticationMode(StrEnum):
    """Mutually exclusive authentication modes for one inbound source."""

    HMAC_SHA256 = "hmac_sha256"
    SERVICE_ACCOUNT = "service_account"


class InboundHmacScheme(StrEnum):
    """Versioned HMAC schemes supported by inbound sources."""

    HMAC_SHA256_V1 = "hmac-sha256-v1"


class InboundPublicationStatus(StrEnum):
    """Durable lifecycle state for one accepted event."""

    PENDING = "pending"
    PUBLISHING = "publishing"
    RETRYING = "retrying"
    PUBLISHED = "published"
    DEAD_LETTER = "dead_letter"
    DISCARDED = "discarded"

    @property
    def terminal(self) -> bool:
        return self in {self.PUBLISHED, self.DEAD_LETTER, self.DISCARDED}

    @property
    def schedulable(self) -> bool:
        return self in {self.PENDING, self.RETRYING}


class InboundPublicationOutcome(StrEnum):
    """Safe outcome classification for one publication attempt."""

    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    TERMINAL_FAILURE = "terminal_failure"


class InboundReplayKind(StrEnum):
    """Source-scoped replay evidence classes."""

    REQUEST_ID = "request_id"
    NONCE = "nonce"
    SOURCE_EVENT_ID = "source_event_id"


@dataclass(frozen=True, slots=True)
class InboundHmacPolicy:
    """Exact versioned secret references for inbound HMAC verification."""

    secret_ref: SecretRef
    scheme: InboundHmacScheme = InboundHmacScheme.HMAC_SHA256_V1
    lease_ttl: timedelta = timedelta(seconds=30)
    predecessor_secret_ref: SecretRef | None = None
    predecessor_valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.secret_ref, SecretRef):
            raise TypeError("inbound HMAC secret must be a SecretRef")
        if self.secret_ref.version is None:
            raise ValueError("inbound HMAC secret requires an exact version")
        if self.lease_ttl <= timedelta(0):
            raise ValueError("inbound HMAC lease ttl must be positive")
        if self.lease_ttl > MAX_INBOUND_SIGNING_LEASE_TTL:
            raise ValueError("inbound HMAC lease ttl exceeds the supported maximum")

        predecessor = self.predecessor_secret_ref
        valid_until = self.predecessor_valid_until
        if predecessor is None:
            if valid_until is not None:
                raise ValueError("predecessor_valid_until requires a predecessor secret")
        else:
            if not isinstance(predecessor, SecretRef):
                raise TypeError("inbound HMAC predecessor must be a SecretRef")
            if predecessor.version is None:
                raise ValueError("inbound HMAC predecessor requires an exact version")
            if predecessor.canonical != self.secret_ref.canonical:
                raise ValueError("inbound HMAC predecessor must reference the same secret")
            if predecessor.version == self.secret_ref.version:
                raise ValueError("inbound HMAC predecessor must use another version")
            if valid_until is None:
                raise ValueError("inbound HMAC predecessor requires predecessor_valid_until")
            _require_aware(valid_until, "predecessor_valid_until")

        object.__setattr__(self, "scheme", InboundHmacScheme(self.scheme))

    @property
    def mode(self) -> InboundAuthenticationMode:
        return InboundAuthenticationMode.HMAC_SHA256

    @property
    def key_version(self) -> int:
        version = self.secret_ref.version
        if version is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("validated inbound HMAC policy has no key version")
        return version


@dataclass(frozen=True, slots=True)
class InboundServiceAccountPolicy:
    """Exact RFC-0023 action and resource required for one source."""

    resource: str
    required_action: str = "inbound_event.submit"

    def __post_init__(self) -> None:
        action = _normalize_scope(self.required_action)
        resource = _normalize_resource(self.resource)
        if action != "inbound_event.submit":
            raise ValueError("inbound service-account action must be inbound_event.submit")
        object.__setattr__(self, "required_action", action)
        object.__setattr__(self, "resource", resource)

    @property
    def mode(self) -> InboundAuthenticationMode:
        return InboundAuthenticationMode.SERVICE_ACCOUNT


type InboundAuthenticationPolicy = InboundHmacPolicy | InboundServiceAccountPolicy


@dataclass(frozen=True, slots=True)
class InboundPublicationRetryPolicy:
    """Deterministic bounded retry policy for Event Bus publication."""

    max_attempts: int = 5
    initial_delay: timedelta = timedelta(seconds=1)
    multiplier: float = 2.0
    max_delay: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        if self.max_attempts <= 0 or self.max_attempts > MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("inbound publication max_attempts is outside supported bounds")
        if self.initial_delay <= timedelta(0):
            raise ValueError("inbound publication initial_delay must be positive")
        if self.max_delay < self.initial_delay:
            raise ValueError("inbound publication max_delay cannot precede initial_delay")
        if self.max_delay > MAX_INBOUND_RETRY_DELAY:
            raise ValueError("inbound publication max_delay exceeds the supported maximum")
        if not math.isfinite(self.multiplier) or not 1 <= self.multiplier <= 10:
            raise ValueError("inbound publication multiplier must be finite and between 1 and 10")

    def delay_after(self, completed_attempts: int) -> timedelta:
        """Return the bounded delay after one retryable completed attempt."""

        if completed_attempts <= 0 or completed_attempts >= self.max_attempts:
            raise ValueError("completed_attempts must identify a retryable attempt")
        seconds = self.initial_delay.total_seconds()
        maximum = self.max_delay.total_seconds()
        for _ in range(completed_attempts - 1):
            if seconds >= maximum / self.multiplier:
                return self.max_delay
            seconds *= self.multiplier
        return timedelta(seconds=seconds)


@dataclass(frozen=True, slots=True)
class InboundEventSchema:
    """Reviewed external schema and its bounded internal event mapping."""

    event_type: str
    event_schema_version: int
    internal_event_type: str
    required_fields: frozenset[str] = field(default_factory=frozenset)
    optional_fields: frozenset[str] = field(default_factory=frozenset)
    max_raw_body_bytes: int = 262_144
    max_normalized_payload_bytes: int = 262_144
    max_json_depth: int = 12
    max_mapping_items: int = 256
    max_sequence_items: int = 256
    max_string_length: int = 16_384
    reject_unknown_fields: bool = True
    schema_version: int = 1

    def __post_init__(self) -> None:
        event_type = _normalize_event_type(self.event_type)
        internal_event_type = _normalize_event_type(self.internal_event_type)
        if self.event_schema_version <= 0:
            raise ValueError("inbound event schema version must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound event schema contract version")
        if not isinstance(self.required_fields, frozenset):
            raise TypeError("inbound required_fields must be a frozenset")
        if not isinstance(self.optional_fields, frozenset):
            raise TypeError("inbound optional_fields must be a frozenset")
        required = frozenset(_normalize_field(value) for value in self.required_fields)
        optional = frozenset(_normalize_field(value) for value in self.optional_fields)
        if required & optional:
            raise ValueError("inbound required and optional fields must be disjoint")
        if len(required | optional) > MAX_INBOUND_JSON_MAPPING_ITEMS:
            raise ValueError("inbound schema declares too many fields")
        if not 1 <= self.max_raw_body_bytes <= MAX_INBOUND_RAW_BODY_BYTES:
            raise ValueError("inbound max_raw_body_bytes is outside supported bounds")
        if not 1 <= self.max_normalized_payload_bytes <= MAX_INBOUND_NORMALIZED_PAYLOAD_BYTES:
            raise ValueError("inbound max_normalized_payload_bytes is outside supported bounds")
        if not 1 <= self.max_json_depth <= MAX_INBOUND_JSON_DEPTH:
            raise ValueError("inbound max_json_depth is outside supported bounds")
        if not 1 <= self.max_mapping_items <= MAX_INBOUND_JSON_MAPPING_ITEMS:
            raise ValueError("inbound max_mapping_items is outside supported bounds")
        if not 1 <= self.max_sequence_items <= MAX_INBOUND_JSON_SEQUENCE_ITEMS:
            raise ValueError("inbound max_sequence_items is outside supported bounds")
        if not 1 <= self.max_string_length <= MAX_INBOUND_JSON_STRING_LENGTH:
            raise ValueError("inbound max_string_length is outside supported bounds")
        if type(self.reject_unknown_fields) is not bool:
            raise TypeError("inbound reject_unknown_fields must be bool")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "internal_event_type", internal_event_type)
        object.__setattr__(self, "required_fields", required)
        object.__setattr__(self, "optional_fields", optional)

    @property
    def allowed_fields(self) -> frozenset[str]:
        return self.required_fields | self.optional_fields


class InboundEventNormalizer(Protocol):
    """Reviewed normalizer for one registered external event schema."""

    @property
    def schema(self) -> InboundEventSchema: ...

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object] | Awaitable[Mapping[str, object]]: ...


@dataclass(frozen=True, slots=True)
class InboundEventSource:
    """Durable source configuration without plaintext credentials."""

    id: UUID
    name: str
    display_name: str
    authentication: InboundAuthenticationPolicy
    event_types: frozenset[str]
    created_at: datetime
    updated_at: datetime
    created_by: str
    max_body_bytes: int = 262_144
    max_header_bytes: int = 16_384
    timestamp_skew: timedelta = timedelta(minutes=5)
    replay_retention: timedelta = timedelta(days=1)
    max_concurrency: int = 8
    requests_per_minute: int = 120
    retry: InboundPublicationRetryPolicy = field(default_factory=InboundPublicationRetryPolicy)
    status: InboundEventSourceStatus = InboundEventSourceStatus.ACTIVE
    disabled_at: datetime | None = None
    revoked_at: datetime | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        name = _normalize_name(self.name, label="inbound source")
        display_name = _normalize_display_name(self.display_name, label="inbound source")
        created_by = _normalize_display_name(self.created_by, label="inbound source creator")
        if not isinstance(self.authentication, (InboundHmacPolicy, InboundServiceAccountPolicy)):
            raise TypeError("inbound source authentication policy is invalid")
        if not isinstance(self.event_types, frozenset):
            raise TypeError("inbound source event_types must be a frozenset")
        event_types = frozenset(_normalize_event_type(value) for value in self.event_types)
        if not event_types:
            raise ValueError("inbound source requires at least one event type")
        if len(event_types) > MAX_INBOUND_EVENT_TYPES_PER_SOURCE:
            raise ValueError("inbound source contains too many event types")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("inbound source updated_at cannot precede created_at")
        if not 1 <= self.max_body_bytes <= MAX_INBOUND_RAW_BODY_BYTES:
            raise ValueError("inbound source max_body_bytes is outside supported bounds")
        if not 1 <= self.max_header_bytes <= MAX_INBOUND_HEADER_BYTES:
            raise ValueError("inbound source max_header_bytes is outside supported bounds")
        if self.timestamp_skew <= timedelta(0) or self.timestamp_skew > MAX_INBOUND_TIMESTAMP_SKEW:
            raise ValueError("inbound source timestamp_skew is outside supported bounds")
        if self.replay_retention < self.timestamp_skew:
            raise ValueError(
                "inbound source replay_retention cannot be shorter than timestamp_skew"
            )
        if self.replay_retention > MAX_INBOUND_REPLAY_RETENTION:
            raise ValueError("inbound source replay_retention exceeds the supported maximum")
        if not 1 <= self.max_concurrency <= 1_024:
            raise ValueError("inbound source max_concurrency is outside supported bounds")
        if not 1 <= self.requests_per_minute <= 1_000_000:
            raise ValueError("inbound source requests_per_minute is outside supported bounds")
        if not isinstance(self.retry, InboundPublicationRetryPolicy):
            raise TypeError("inbound source retry must be InboundPublicationRetryPolicy")
        if self.revision <= 0:
            raise ValueError("inbound source revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound source schema version")

        status = InboundEventSourceStatus(self.status)
        disabled_at = self.disabled_at
        revoked_at = self.revoked_at
        if disabled_at is not None:
            _require_aware(disabled_at, "disabled_at")
            if disabled_at < self.created_at or self.updated_at < disabled_at:
                raise ValueError("inbound source disabled_at is outside its lifecycle")
        if revoked_at is not None:
            _require_aware(revoked_at, "revoked_at")
            if revoked_at < self.created_at or self.updated_at < revoked_at:
                raise ValueError("inbound source revoked_at is outside its lifecycle")
        if status is InboundEventSourceStatus.ACTIVE:
            if disabled_at is not None or revoked_at is not None:
                raise ValueError("active inbound source cannot contain inactive timestamps")
        elif status is InboundEventSourceStatus.DISABLED:
            if disabled_at is None or revoked_at is not None:
                raise ValueError("disabled inbound source requires only disabled_at")
        elif revoked_at is None:
            raise ValueError("revoked inbound source requires revoked_at")

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "event_types", event_types)
        object.__setattr__(self, "created_by", created_by)
        object.__setattr__(self, "status", status)

    @property
    def accepting(self) -> bool:
        return self.status.accepting


@dataclass(frozen=True, slots=True, repr=False)
class InboundRequestEvidence:
    """Transient authentication and replay evidence; never persisted as a record."""

    source_id: UUID
    request_id: str
    source_event_id: str
    nonce: str = field(repr=False)
    timestamp: datetime
    body_sha256: str
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _normalize_identifier(self.request_id, "request id"))
        object.__setattr__(
            self,
            "source_event_id",
            _normalize_identifier(self.source_event_id, "source event id"),
        )
        object.__setattr__(self, "nonce", _normalize_identifier(self.nonce, "nonce"))
        _require_aware(self.timestamp, "timestamp")
        object.__setattr__(
            self,
            "body_sha256",
            _normalize_sha256(self.body_sha256, label="inbound request body digest"),
        )
        if self.correlation_id is not None:
            object.__setattr__(
                self,
                "correlation_id",
                _normalize_correlation_id(self.correlation_id),
            )

    def __repr__(self) -> str:
        return (
            "InboundRequestEvidence("
            f"source_id={self.source_id!r}, request_id=<redacted>, "
            f"source_event_id={self.source_event_id!r}, nonce=<redacted>, "
            f"timestamp={self.timestamp!r}, body_sha256={self.body_sha256!r}, "
            f"correlation_id={self.correlation_id!r})"
        )


@dataclass(frozen=True, slots=True)
class InboundPublicationAttempt:
    """Safe immutable facts for one completed publication attempt."""

    accepted_event_id: UUID
    number: int
    scheduled_at: datetime
    started_at: datetime
    finished_at: datetime
    outcome: InboundPublicationOutcome
    retry_scheduled: bool = False
    next_attempt_at: datetime | None = None
    error_category: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not 1 <= self.number <= MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("inbound publication attempt number is outside supported bounds")
        _require_aware(self.scheduled_at, "scheduled_at")
        _require_aware(self.started_at, "started_at")
        _require_aware(self.finished_at, "finished_at")
        if self.started_at < self.scheduled_at:
            raise ValueError("inbound publication started_at cannot precede scheduled_at")
        if self.finished_at < self.started_at:
            raise ValueError("inbound publication finished_at cannot precede started_at")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound publication attempt schema version")
        outcome = InboundPublicationOutcome(self.outcome)
        error_category = self.error_category
        if error_category is not None:
            error_category = _normalize_error_category(error_category)
        next_attempt_at = self.next_attempt_at
        if next_attempt_at is not None:
            _require_aware(next_attempt_at, "next_attempt_at")
            if next_attempt_at <= self.finished_at:
                raise ValueError("inbound next_attempt_at must follow finished_at")
        if outcome is InboundPublicationOutcome.SUCCEEDED:
            if error_category is not None:
                raise ValueError("successful inbound publication cannot contain an error category")
            if self.retry_scheduled or next_attempt_at is not None:
                raise ValueError("successful inbound publication cannot schedule a retry")
        else:
            if error_category is None:
                raise ValueError("failed inbound publication requires an error category")
            if self.retry_scheduled != (next_attempt_at is not None):
                raise ValueError("inbound publication retry metadata is inconsistent")
            if outcome is InboundPublicationOutcome.TERMINAL_FAILURE and self.retry_scheduled:
                raise ValueError("terminal inbound publication cannot schedule a retry")
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "error_category", error_category)


@dataclass(frozen=True, slots=True, repr=False)
class InboundAcceptedEvent:
    """Durable normalized event without raw request or authentication material."""

    id: UUID
    receipt_id: UUID
    source_id: UUID
    source_event_id: str
    external_event_type: str
    external_schema_version: int
    internal_event_type: str
    occurred_at: datetime
    accepted_at: datetime
    updated_at: datetime
    normalized_payload: InboundJsonData
    normalized_payload_sha256: str
    status: InboundPublicationStatus = InboundPublicationStatus.PENDING
    correlation_id: str | None = None
    attempts: tuple[InboundPublicationAttempt, ...] = ()
    current_attempt: int | None = None
    publishing_at: datetime | None = None
    next_attempt_at: datetime | None = None
    terminal_at: datetime | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        source_event_id = _normalize_identifier(self.source_event_id, "source event id")
        external_event_type = _normalize_event_type(self.external_event_type)
        internal_event_type = _normalize_event_type(self.internal_event_type)
        if self.external_schema_version <= 0:
            raise ValueError("inbound external schema version must be positive")
        _require_aware(self.occurred_at, "occurred_at")
        _require_aware(self.accepted_at, "accepted_at")
        _require_aware(self.updated_at, "updated_at")
        if self.accepted_at < self.occurred_at:
            raise ValueError("inbound accepted_at cannot precede occurred_at")
        if self.updated_at < self.accepted_at:
            raise ValueError("inbound updated_at cannot precede accepted_at")
        if not isinstance(self.normalized_payload, Mapping):
            raise TypeError("inbound normalized_payload must be a mapping")
        budget = [MAX_INBOUND_JSON_ITEMS]
        normalized = _normalize_json(
            self.normalized_payload,
            path="$.normalized_payload",
            depth=0,
            budget=budget,
        )
        if not isinstance(normalized, dict):  # pragma: no cover - mapping input invariant
            raise TypeError("inbound normalized_payload must normalize to a mapping")
        canonical = _canonical_json_bytes(normalized)
        if not canonical or len(canonical) > MAX_INBOUND_NORMALIZED_PAYLOAD_BYTES:
            raise ValueError("inbound normalized payload size is outside supported bounds")
        digest = _normalize_sha256(
            self.normalized_payload_sha256,
            label="inbound normalized payload digest",
        )
        if digest != hashlib.sha256(canonical).hexdigest():
            raise ValueError("inbound normalized payload digest does not match payload")
        if self.correlation_id is not None:
            object.__setattr__(
                self,
                "correlation_id",
                _normalize_correlation_id(self.correlation_id),
            )
        attempts = tuple(self.attempts)
        if len(attempts) > MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("inbound accepted event contains too many attempts")
        for expected, attempt in enumerate(attempts, start=1):
            if not isinstance(attempt, InboundPublicationAttempt):
                raise TypeError("inbound attempts must be InboundPublicationAttempt values")
            if attempt.accepted_event_id != self.id:
                raise ValueError("inbound publication attempt belongs to another event")
            if attempt.number != expected:
                raise ValueError("inbound publication attempts must be contiguous and ordered")
        if self.revision <= 0:
            raise ValueError("inbound accepted event revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound accepted event schema version")
        status = InboundPublicationStatus(self.status)
        _validate_event_lifecycle(
            status=status,
            attempts=attempts,
            current_attempt=self.current_attempt,
            publishing_at=self.publishing_at,
            next_attempt_at=self.next_attempt_at,
            terminal_at=self.terminal_at,
            accepted_at=self.accepted_at,
            updated_at=self.updated_at,
        )
        object.__setattr__(self, "source_event_id", source_event_id)
        object.__setattr__(self, "external_event_type", external_event_type)
        object.__setattr__(self, "internal_event_type", internal_event_type)
        object.__setattr__(self, "normalized_payload", _freeze_json_mapping(normalized))
        object.__setattr__(self, "normalized_payload_sha256", digest)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(self, "status", status)

    def __repr__(self) -> str:
        return (
            "InboundAcceptedEvent("
            f"id={self.id!r}, receipt_id={self.receipt_id!r}, source_id={self.source_id!r}, "
            f"source_event_id={self.source_event_id!r}, "
            f"external_event_type={self.external_event_type!r}, status={self.status!r}, "
            f"attempts={len(self.attempts)}, normalized_payload=<redacted>)"
        )

    @property
    def completed_attempts(self) -> int:
        return len(self.attempts)


@dataclass(frozen=True, slots=True)
class InboundEventReceipt:
    """Stable safe receipt created with one durably accepted event."""

    id: UUID
    accepted_event_id: UUID
    source_id: UUID
    source_event_id: str
    external_event_type: str
    external_schema_version: int
    accepted_at: datetime
    correlation_id: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_event_id",
            _normalize_identifier(self.source_event_id, "source event id"),
        )
        object.__setattr__(
            self,
            "external_event_type",
            _normalize_event_type(self.external_event_type),
        )
        if self.external_schema_version <= 0:
            raise ValueError("inbound receipt external schema version must be positive")
        _require_aware(self.accepted_at, "accepted_at")
        if self.correlation_id is not None:
            object.__setattr__(
                self,
                "correlation_id",
                _normalize_correlation_id(self.correlation_id),
            )
        if self.schema_version != 1:
            raise ValueError("unsupported inbound receipt schema version")


@dataclass(frozen=True, slots=True)
class InboundReplayReservation:
    """Durable source-scoped digest reservation without raw replay evidence."""

    source_id: UUID
    kind: InboundReplayKind
    evidence_digest: str
    accepted_event_id: UUID
    created_at: datetime
    expires_at: datetime
    normalized_payload_sha256: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        kind = InboundReplayKind(self.kind)
        digest = _normalize_sha256(self.evidence_digest, label="inbound replay evidence digest")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("inbound replay reservation must expire after creation")
        if self.expires_at - self.created_at > MAX_INBOUND_REPLAY_RETENTION:
            raise ValueError("inbound replay reservation retention exceeds the supported maximum")
        payload_digest = self.normalized_payload_sha256
        if kind is InboundReplayKind.SOURCE_EVENT_ID:
            if payload_digest is None:
                raise ValueError("source-event replay reservation requires a payload digest")
            payload_digest = _normalize_sha256(
                payload_digest,
                label="inbound replay normalized payload digest",
            )
        elif payload_digest is not None:
            raise ValueError("request and nonce replay reservations cannot contain payload digests")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound replay reservation schema version")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "evidence_digest", digest)
        object.__setattr__(self, "normalized_payload_sha256", payload_digest)

    @property
    def key(self) -> tuple[UUID, InboundReplayKind, str]:
        return (self.source_id, self.kind, self.evidence_digest)


@dataclass(frozen=True, slots=True)
class InboundAcceptance:
    """Atomic accepted-event, receipt, and replay reservation bundle."""

    event: InboundAcceptedEvent
    receipt: InboundEventReceipt
    replay_reservations: tuple[InboundReplayReservation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.event, InboundAcceptedEvent):
            raise TypeError("inbound acceptance event is invalid")
        if not isinstance(self.receipt, InboundEventReceipt):
            raise TypeError("inbound acceptance receipt is invalid")
        reservations = tuple(self.replay_reservations)
        if self.receipt.id != self.event.receipt_id:
            raise ValueError("inbound acceptance receipt identity does not match event")
        if self.receipt.accepted_event_id != self.event.id:
            raise ValueError("inbound acceptance receipt references another event")
        if self.receipt.source_id != self.event.source_id:
            raise ValueError("inbound acceptance receipt references another source")
        if self.receipt.source_event_id != self.event.source_event_id:
            raise ValueError("inbound acceptance receipt source event does not match")
        if self.receipt.external_event_type != self.event.external_event_type:
            raise ValueError("inbound acceptance receipt event type does not match")
        if self.receipt.external_schema_version != self.event.external_schema_version:
            raise ValueError("inbound acceptance receipt schema version does not match")
        if self.receipt.accepted_at != self.event.accepted_at:
            raise ValueError("inbound acceptance receipt timestamp does not match")
        kinds: set[InboundReplayKind] = set()
        for reservation in reservations:
            if not isinstance(reservation, InboundReplayReservation):
                raise TypeError("inbound replay reservations contain an invalid value")
            if reservation.source_id != self.event.source_id:
                raise ValueError("inbound replay reservation references another source")
            if reservation.accepted_event_id != self.event.id:
                raise ValueError("inbound replay reservation references another event")
            if reservation.kind in kinds:
                raise ValueError("inbound acceptance contains duplicate replay reservation kinds")
            kinds.add(reservation.kind)
            if reservation.kind is InboundReplayKind.SOURCE_EVENT_ID:
                if reservation.normalized_payload_sha256 != self.event.normalized_payload_sha256:
                    raise ValueError("source-event reservation payload digest does not match event")
        if kinds != set(InboundReplayKind):
            raise ValueError(
                "inbound acceptance requires request, nonce, and source-event reservations"
            )
        object.__setattr__(self, "replay_reservations", reservations)


def _validate_idempotent_replay_reservations(
    event: InboundAcceptedEvent,
    reservations: tuple[InboundReplayReservation, InboundReplayReservation],
) -> tuple[InboundReplayReservation, InboundReplayReservation]:
    if not isinstance(event, InboundAcceptedEvent):
        raise TypeError("idempotent replay requires an accepted event")
    if not isinstance(reservations, tuple) or len(reservations) != 2:
        raise TypeError("idempotent replay requires request and nonce reservations")
    kinds: set[InboundReplayKind] = set()
    for reservation in reservations:
        if not isinstance(reservation, InboundReplayReservation):
            raise TypeError("idempotent replay contains an invalid reservation")
        if reservation.source_id != event.source_id:
            raise ValueError("idempotent replay reservation references another source")
        if reservation.accepted_event_id != event.id:
            raise ValueError("idempotent replay reservation references another event")
        if reservation.kind not in {
            InboundReplayKind.REQUEST_ID,
            InboundReplayKind.NONCE,
        }:
            raise ValueError("idempotent replay accepts only request and nonce evidence")
        if reservation.kind in kinds:
            raise ValueError("idempotent replay reservation kinds must be unique")
        kinds.add(reservation.kind)
    if kinds != {InboundReplayKind.REQUEST_ID, InboundReplayKind.NONCE}:
        raise ValueError("idempotent replay requires request and nonce evidence")
    return reservations


@dataclass(frozen=True, slots=True)
class InboundPageRequest:
    """Validated offset pagination for inbound repositories."""

    offset: int = 0
    limit: int = DEFAULT_INBOUND_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("inbound page offset cannot be negative")
        if not 1 <= self.limit <= MAX_INBOUND_PAGE_SIZE:
            raise ValueError(f"inbound page limit must be between 1 and {MAX_INBOUND_PAGE_SIZE}")


DEFAULT_INBOUND_PAGE_REQUEST = InboundPageRequest()


@dataclass(frozen=True, slots=True)
class InboundPageInfo:
    """Safe deterministic pagination metadata."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if min(self.offset, self.returned, self.total) < 0:
            raise ValueError("inbound page counters cannot be negative")
        if not 1 <= self.limit <= MAX_INBOUND_PAGE_SIZE:
            raise ValueError("inbound page limit is outside bounds")
        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("inbound page returned count is inconsistent")
        expected = self.offset + self.returned
        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("inbound page requires next_offset")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("inbound page next_offset is inconsistent")

    @classmethod
    def from_slice(
        cls,
        request: InboundPageRequest,
        *,
        returned: int,
        total: int,
    ) -> InboundPageInfo:
        next_offset = request.offset + returned
        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=next_offset if next_offset < total else None,
        )


@dataclass(frozen=True, slots=True)
class InboundSourcePage:
    items: tuple[InboundEventSource, ...]
    page: InboundPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("inbound source page count must match items")


@dataclass(frozen=True, slots=True)
class InboundEventPage:
    items: tuple[InboundAcceptedEvent, ...]
    page: InboundPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("inbound event page count must match items")


@dataclass(frozen=True, slots=True)
class InboundReplayPage:
    items: tuple[InboundReplayReservation, ...]
    page: InboundPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("inbound replay page count must match items")


@dataclass(frozen=True, slots=True)
class InboundSourceRepositorySnapshot:
    closed: bool
    sources: int
    active: int
    disabled: int
    revoked: int
    capacity: int

    def __post_init__(self) -> None:
        if min(self.sources, self.active, self.disabled, self.revoked) < 0:
            raise ValueError("inbound source counters cannot be negative")
        if not 1 <= self.capacity <= MAX_INBOUND_SOURCE_CAPACITY:
            raise ValueError("inbound source capacity is outside bounds")
        if self.sources > self.capacity:
            raise ValueError("inbound source count exceeds capacity")
        if self.active + self.disabled + self.revoked != self.sources:
            raise ValueError("inbound source status counts are inconsistent")


@dataclass(frozen=True, slots=True)
class InboundEventRepositorySnapshot:
    closed: bool
    events: int
    pending: int
    publishing: int
    retrying: int
    published: int
    dead_letter: int
    discarded: int
    attempts: int
    capacity: int

    def __post_init__(self) -> None:
        values = (
            self.events,
            self.pending,
            self.publishing,
            self.retrying,
            self.published,
            self.dead_letter,
            self.discarded,
            self.attempts,
        )
        if any(value < 0 for value in values):
            raise ValueError("inbound event counters cannot be negative")
        if not 1 <= self.capacity <= MAX_INBOUND_EVENT_CAPACITY:
            raise ValueError("inbound event capacity is outside bounds")
        if self.events > self.capacity:
            raise ValueError("inbound event count exceeds capacity")
        states = (
            self.pending
            + self.publishing
            + self.retrying
            + self.published
            + self.dead_letter
            + self.discarded
        )
        if states != self.events:
            raise ValueError("inbound event status counts are inconsistent")
        if self.attempts > self.events * MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("inbound attempt count exceeds event bounds")


@dataclass(frozen=True, slots=True)
class InboundReplayRepositorySnapshot:
    closed: bool
    reservations: int
    request_ids: int
    nonces: int
    source_events: int
    capacity: int

    def __post_init__(self) -> None:
        if min(self.reservations, self.request_ids, self.nonces, self.source_events) < 0:
            raise ValueError("inbound replay counters cannot be negative")
        if not 1 <= self.capacity <= MAX_INBOUND_REPLAY_CAPACITY:
            raise ValueError("inbound replay capacity is outside bounds")
        if self.reservations > self.capacity:
            raise ValueError("inbound replay count exceeds capacity")
        if self.request_ids + self.nonces + self.source_events != self.reservations:
            raise ValueError("inbound replay kind counts are inconsistent")


class InboundSourceRepository(Protocol):
    @property
    def closed(self) -> bool: ...

    def add(self, source: InboundEventSource) -> Awaitable[None]: ...

    def get(self, source_id: UUID) -> Awaitable[InboundEventSource | None]: ...

    def get_by_name(self, name: str) -> Awaitable[InboundEventSource | None]: ...

    def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> Awaitable[InboundSourcePage]: ...

    def replace(
        self,
        source: InboundEventSource,
        *,
        expected_revision: int,
    ) -> Awaitable[InboundEventSource]: ...

    def snapshot(self) -> Awaitable[InboundSourceRepositorySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


class InboundEventRepository(Protocol):
    @property
    def closed(self) -> bool: ...

    def accept(self, acceptance: InboundAcceptance) -> Awaitable[None]: ...

    def reserve_idempotent_replay(
        self,
        accepted_event_id: UUID,
        reservations: tuple[InboundReplayReservation, InboundReplayReservation],
    ) -> Awaitable[None]: ...

    def get(self, accepted_event_id: UUID) -> Awaitable[InboundAcceptedEvent | None]: ...

    def get_receipt(self, receipt_id: UUID) -> Awaitable[InboundEventReceipt | None]: ...

    def get_by_source_event_digest(
        self,
        source_id: UUID,
        source_event_digest: str,
    ) -> Awaitable[InboundAcceptedEvent | None]: ...

    def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> Awaitable[InboundEventPage]: ...

    def replace(
        self,
        event: InboundAcceptedEvent,
        *,
        expected_revision: int,
    ) -> Awaitable[InboundAcceptedEvent]: ...

    def snapshot(self) -> Awaitable[InboundEventRepositorySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


class InboundReplayRepository(Protocol):
    @property
    def closed(self) -> bool: ...

    def get(
        self,
        source_id: UUID,
        kind: InboundReplayKind,
        evidence_digest: str,
    ) -> Awaitable[InboundReplayReservation | None]: ...

    def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> Awaitable[InboundReplayPage]: ...

    def prune_expired(self, *, now: datetime) -> Awaitable[int]: ...

    def snapshot(self) -> Awaitable[InboundReplayRepositorySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def canonical_inbound_json_bytes(value: Mapping[str, object]) -> bytes:
    """Return deterministic JSON bytes for already normalized inbound data."""

    if not isinstance(value, Mapping):
        raise TypeError("inbound canonical JSON value must be a mapping")
    budget = [MAX_INBOUND_JSON_ITEMS]
    normalized = _normalize_json(value, path="$", depth=0, budget=budget)
    if not isinstance(normalized, dict):  # pragma: no cover - mapping input invariant
        raise TypeError("inbound canonical JSON value must normalize to a mapping")
    return _canonical_json_bytes(normalized)


def inbound_evidence_digest(source_id: UUID, kind: InboundReplayKind, value: str) -> str:
    """Return a source-scoped digest for replay evidence without retaining raw input."""

    normalized_kind = InboundReplayKind(kind)
    normalized_value = _normalize_identifier(value, normalized_kind.value.replace("_", " "))
    canonical = (
        f"inbound-replay-v1\n{source_id}\n{normalized_kind.value}\n{normalized_value}"
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _validate_event_lifecycle(
    *,
    status: InboundPublicationStatus,
    attempts: tuple[InboundPublicationAttempt, ...],
    current_attempt: int | None,
    publishing_at: datetime | None,
    next_attempt_at: datetime | None,
    terminal_at: datetime | None,
    accepted_at: datetime,
    updated_at: datetime,
) -> None:
    if publishing_at is not None:
        _require_aware(publishing_at, "publishing_at")
        if publishing_at < accepted_at or updated_at < publishing_at:
            raise ValueError("inbound publishing_at is outside its lifecycle")
    if next_attempt_at is not None:
        _require_aware(next_attempt_at, "next_attempt_at")
        if next_attempt_at < updated_at:
            raise ValueError("inbound next_attempt_at cannot precede updated_at")
    if terminal_at is not None:
        _require_aware(terminal_at, "terminal_at")
        if terminal_at < accepted_at or updated_at < terminal_at:
            raise ValueError("inbound terminal_at is outside its lifecycle")
    if status is InboundPublicationStatus.PENDING:
        if attempts or current_attempt is not None or publishing_at is not None:
            raise ValueError("pending inbound event cannot contain attempt state")
        if next_attempt_at is None or terminal_at is not None:
            raise ValueError("pending inbound event requires only next_attempt_at")
        return
    if status is InboundPublicationStatus.PUBLISHING:
        if current_attempt != len(attempts) + 1:
            raise ValueError("publishing inbound event has an invalid attempt number")
        if current_attempt > MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("publishing inbound event exceeds attempt bounds")
        if publishing_at is None or next_attempt_at is not None or terminal_at is not None:
            raise ValueError("publishing inbound event has inconsistent lifecycle metadata")
        return
    if current_attempt is not None or publishing_at is not None:
        raise ValueError("non-running inbound event cannot contain publishing metadata")
    if status is InboundPublicationStatus.RETRYING:
        if not attempts or attempts[-1].outcome is not InboundPublicationOutcome.RETRYABLE_FAILURE:
            raise ValueError("retrying inbound event requires a retryable attempt")
        if next_attempt_at is None or terminal_at is not None:
            raise ValueError("retrying inbound event has inconsistent retry metadata")
        return
    if next_attempt_at is not None or terminal_at is None:
        raise ValueError("terminal inbound event has inconsistent lifecycle metadata")
    if status is InboundPublicationStatus.DISCARDED:
        return
    if not attempts:
        raise ValueError("terminal published or dead-letter event requires an attempt")
    last = attempts[-1]
    if terminal_at < last.finished_at:
        raise ValueError("inbound terminal_at cannot precede the final attempt")
    if status is InboundPublicationStatus.PUBLISHED:
        if last.outcome is not InboundPublicationOutcome.SUCCEEDED:
            raise ValueError("published inbound event requires a successful final attempt")
    elif status is InboundPublicationStatus.DEAD_LETTER:
        if last.outcome is not InboundPublicationOutcome.RETRYABLE_FAILURE:
            raise ValueError("dead-letter inbound event requires a retryable final failure")
        if last.retry_scheduled:
            raise ValueError("dead-letter inbound event cannot retain a scheduled retry")


def _normalize_name(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if (
        len(normalized) > MAX_INBOUND_SOURCE_NAME_LENGTH
        or _NAME_PATTERN.fullmatch(normalized) is None
    ):
        raise ValueError(f"{label} contains unsupported characters")
    return normalized


def _normalize_event_type(value: str) -> str:
    normalized = value.strip().lower()
    if (
        len(normalized) > MAX_INBOUND_EVENT_TYPE_LENGTH
        or _EVENT_TYPE_PATTERN.fullmatch(normalized) is None
    ):
        raise ValueError("inbound event type contains unsupported characters")
    return normalized


def _normalize_field(value: str) -> str:
    normalized = value.strip().lower()
    if _FIELD_PATTERN.fullmatch(normalized) is None:
        raise ValueError("inbound schema field contains unsupported characters")
    return normalized


def _normalize_scope(value: str) -> str:
    normalized = value.strip().lower()
    if _SCOPE_PATTERN.fullmatch(normalized) is None:
        raise ValueError("inbound service-account action contains unsupported characters")
    return normalized


def _normalize_resource(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or len(normalized) > 256:
        raise ValueError("inbound service-account resource length is outside supported bounds")
    if any(ord(character) < 33 or ord(character) == 127 for character in normalized):
        raise ValueError("inbound service-account resource contains unsupported characters")
    return normalized


def _normalize_display_name(value: str, *, label: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > MAX_INBOUND_DISPLAY_NAME_LENGTH:
        raise ValueError(f"{label} display value length is outside supported bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"{label} display value contains control characters")
    return normalized


def _normalize_identifier(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_INBOUND_IDENTIFIER_LENGTH:
        raise ValueError(f"inbound {label} length is outside supported bounds")
    if any(ord(character) < 33 or ord(character) == 127 for character in normalized):
        raise ValueError(f"inbound {label} contains unsupported characters")
    return normalized


def _normalize_sha256(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _normalize_error_category(value: str) -> str:
    normalized = value.strip().lower()
    if _ERROR_CATEGORY_PATTERN.fullmatch(normalized) is None:
        raise ValueError("inbound error category contains unsupported characters")
    return normalized


def _normalize_correlation_id(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_INBOUND_CORRELATION_ID_LENGTH:
        raise ValueError("inbound correlation id length is outside supported bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("inbound correlation id contains control characters")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"inbound {label} must be timezone-aware")


def _canonical_json_bytes(value: Mapping[str, object] | dict[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exception:  # pragma: no cover - normalized invariant
        raise ValueError("inbound payload is not JSON-compatible") from exception


def _normalize_json(
    value: object,
    *,
    path: str,
    depth: int,
    budget: list[int],
) -> object:
    if depth > MAX_INBOUND_JSON_DEPTH:
        raise ValueError(f"inbound JSON depth exceeds bounds at {path}")
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("inbound JSON item count exceeds bounds")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"inbound JSON contains a non-finite number at {path}")
        return value
    if isinstance(value, str):
        if len(value) > MAX_INBOUND_JSON_STRING_LENGTH:
            raise ValueError(f"inbound JSON string exceeds bounds at {path}")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_INBOUND_JSON_MAPPING_ITEMS:
            raise ValueError(f"inbound JSON mapping exceeds bounds at {path}")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"inbound JSON mapping keys must be strings at {path}")
            if key in result:
                raise ValueError(f"inbound JSON mapping contains duplicate keys at {path}")
            if len(key) > MAX_INBOUND_JSON_STRING_LENGTH:
                raise ValueError(f"inbound JSON key exceeds bounds at {path}")
            result[key] = _normalize_json(
                item,
                path=f"{path}.{key}",
                depth=depth + 1,
                budget=budget,
            )
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_INBOUND_JSON_SEQUENCE_ITEMS:
            raise ValueError(f"inbound JSON sequence exceeds bounds at {path}")
        return [
            _normalize_json(
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                budget=budget,
            )
            for index, item in enumerate(value)
        ]
    raise ValueError(f"inbound JSON contains an unsupported value at {path}")


def _freeze_json_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, object], value)
        return _freeze_json_mapping(mapping)
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value
