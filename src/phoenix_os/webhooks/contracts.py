"""Immutable foundational contracts for durable signed webhooks."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from types import MappingProxyType
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit
from uuid import UUID

from phoenix_os.events import Event
from phoenix_os.secrets import SecretRef

MAX_WEBHOOK_ENDPOINT_URL_LENGTH = 2_048
MAX_WEBHOOK_EVENT_TYPE_LENGTH = 128
MAX_WEBHOOK_EVENT_TYPES_PER_SUBSCRIPTION = 64
MAX_WEBHOOK_FILTER_FIELDS_PER_EVENT = 32
MAX_WEBHOOK_FILTER_VALUES_PER_FIELD = 128
MAX_WEBHOOK_FILTER_VALUE_LENGTH = 256
MAX_WEBHOOK_JSON_DEPTH = 16
MAX_WEBHOOK_JSON_ITEMS = 4_096
MAX_WEBHOOK_JSON_MAPPING_ITEMS = 1_024
MAX_WEBHOOK_JSON_SEQUENCE_ITEMS = 1_024
MAX_WEBHOOK_JSON_STRING_LENGTH = 65_536
MAX_WEBHOOK_PAYLOAD_BYTES = 1_048_576
MAX_WEBHOOK_EGRESS_NETWORKS = 64
MAX_WEBHOOK_EGRESS_PORTS = 32
MAX_WEBHOOK_RETRY_ATTEMPTS = 20
MAX_WEBHOOK_RETRY_DELAY = timedelta(days=1)
MAX_WEBHOOK_SIGNING_LEASE_TTL = timedelta(minutes=5)
DEFAULT_WEBHOOK_PAGE_SIZE = 50
MAX_WEBHOOK_PAGE_SIZE = 200
MAX_WEBHOOK_SUBSCRIPTION_CAPACITY = 10_000
MAX_WEBHOOK_DISPLAY_NAME_LENGTH = 128
MAX_WEBHOOK_DELIVERY_CAPACITY = 100_000
MAX_WEBHOOK_DELIVERY_BODY_BYTES = 1_114_112
MAX_WEBHOOK_SAFE_ERROR_CATEGORY_LENGTH = 64
MAX_WEBHOOK_CORRELATION_ID_LENGTH = 128

_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{2,63}\Z")
_EVENT_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9._-]{2,127}\Z")
_FILTER_FIELD_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_ERROR_CATEGORY_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")


type WebhookPayloadData = Mapping[str, object]
type WebhookResourceFilters = Mapping[str, Mapping[str, frozenset[str]]]


class WebhookSubscriptionStatus(StrEnum):
    """Administrative state for one webhook subscription."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"

    @property
    def deliverable(self) -> bool:
        return self is self.ACTIVE


class WebhookDeliveryStatus(StrEnum):
    """Durable lifecycle state for one webhook delivery."""

    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    RETRYING = "retrying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {
            self.SUCCEEDED,
            self.FAILED,
            self.DEAD_LETTER,
            self.CANCELLED,
        }

    @property
    def schedulable(self) -> bool:
        return self in {self.PENDING, self.RETRYING}


class WebhookAttemptOutcome(StrEnum):
    """Safe classification for one completed outbound attempt."""

    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    TERMINAL_FAILURE = "terminal_failure"

    @property
    def succeeded(self) -> bool:
        return self is self.SUCCEEDED


class WebhookSignatureScheme(StrEnum):
    """Versioned request-signature schemes supported by Phoenix OS."""

    HMAC_SHA256_V1 = "hmac-sha256-v1"


class WebhookHttpStatusClass(StrEnum):
    """Bounded HTTP response classification without retaining response content."""

    INFORMATIONAL = "1xx"
    SUCCESSFUL = "2xx"
    REDIRECTION = "3xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"


@dataclass(frozen=True, slots=True)
class WebhookEndpoint:
    """Canonical outbound endpoint without embedded credentials or query secrets."""

    url: str
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        normalized = _normalize_endpoint_url(
            self.url,
            allow_insecure_loopback=self.allow_insecure_loopback,
        )
        object.__setattr__(self, "url", normalized)

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @property
    def host(self) -> str:
        host = urlsplit(self.url).hostname
        if host is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("validated webhook endpoint has no host")
        return host

    @property
    def port(self) -> int:
        parsed = urlsplit(self.url)
        if parsed.port is not None:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @property
    def loopback_development(self) -> bool:
        return self.scheme == "http"


@dataclass(frozen=True, slots=True)
class WebhookEgressPolicy:
    """Named bounded destination policy evaluated before every connection."""

    name: str
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({443}))
    allowed_networks: tuple[str, ...] = ()
    allow_public_networks: bool = True
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        name = _normalize_name(self.name, label="webhook egress policy")
        ports = frozenset(self.allowed_ports)
        networks = _normalize_networks(self.allowed_networks)

        if any(type(port) is not int for port in ports):
            raise TypeError("webhook egress policy ports must be integers")
        if not ports or len(ports) > MAX_WEBHOOK_EGRESS_PORTS:
            raise ValueError("webhook egress policy requires between 1 and 32 ports")
        if any(port <= 0 or port > 65_535 for port in ports):
            raise ValueError("webhook egress policy ports must be between 1 and 65535")
        if self.allow_insecure_loopback and 80 not in ports:
            raise ValueError("loopback development mode requires port 80 to be allowlisted")

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "allowed_ports", ports)
        object.__setattr__(self, "allowed_networks", networks)


@dataclass(frozen=True, slots=True)
class WebhookSigningPolicy:
    """Versioned secret reference and bounded lease used for request signing."""

    secret_ref: SecretRef
    scheme: WebhookSignatureScheme = WebhookSignatureScheme.HMAC_SHA256_V1
    lease_ttl: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if not isinstance(self.secret_ref, SecretRef):
            raise TypeError("webhook signing secret must be a SecretRef")
        if self.secret_ref.version is None:
            raise ValueError("webhook signing secret requires an exact version")
        if self.lease_ttl <= timedelta(0):
            raise ValueError("webhook signing lease ttl must be positive")
        if self.lease_ttl > MAX_WEBHOOK_SIGNING_LEASE_TTL:
            raise ValueError("webhook signing lease ttl exceeds the supported maximum")
        object.__setattr__(self, "scheme", WebhookSignatureScheme(self.scheme))

    @property
    def key_version(self) -> int:
        version = self.secret_ref.version
        if version is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("validated signing policy has no key version")
        return version


@dataclass(frozen=True, slots=True)
class WebhookRetryPolicy:
    """Deterministic bounded exponential retry policy."""

    max_attempts: int = 5
    initial_delay: timedelta = timedelta(seconds=5)
    multiplier: float = 2.0
    max_delay: timedelta = timedelta(hours=1)
    jitter_ratio: float = 0.1

    def __post_init__(self) -> None:
        if self.max_attempts <= 0 or self.max_attempts > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook retry max_attempts is outside supported bounds")
        if self.initial_delay <= timedelta(0):
            raise ValueError("webhook retry initial_delay must be positive")
        if self.max_delay < self.initial_delay:
            raise ValueError("webhook retry max_delay cannot precede initial_delay")
        if self.max_delay > MAX_WEBHOOK_RETRY_DELAY:
            raise ValueError("webhook retry max_delay exceeds the supported maximum")
        if not math.isfinite(self.multiplier) or self.multiplier < 1 or self.multiplier > 10:
            raise ValueError("webhook retry multiplier must be finite and between 1 and 10")
        if not math.isfinite(self.jitter_ratio) or not 0 <= self.jitter_ratio <= 0.5:
            raise ValueError("webhook retry jitter_ratio must be finite and between 0 and 0.5")

    def base_delay_after(self, completed_attempts: int) -> timedelta:
        """Return the bounded pre-jitter delay after a completed attempt."""

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
class WebhookEventType:
    """Allowlisted event type and its safe serializer constraints."""

    name: str
    schema_version: int = 1
    resource_filter_fields: frozenset[str] = field(default_factory=frozenset)
    max_payload_bytes: int = 262_144

    def __post_init__(self) -> None:
        name = _normalize_event_type(self.name)
        if not isinstance(self.resource_filter_fields, frozenset):
            raise TypeError("webhook resource_filter_fields must be a frozenset")
        fields = frozenset(_normalize_filter_field(value) for value in self.resource_filter_fields)

        if self.schema_version <= 0:
            raise ValueError("webhook event schema_version must be positive")
        if len(fields) > MAX_WEBHOOK_FILTER_FIELDS_PER_EVENT:
            raise ValueError("webhook event type contains too many resource-filter fields")
        if self.max_payload_bytes <= 0 or self.max_payload_bytes > MAX_WEBHOOK_PAYLOAD_BYTES:
            raise ValueError("webhook event max_payload_bytes is outside supported bounds")

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "resource_filter_fields", fields)

    @property
    def supports_filters(self) -> bool:
        return bool(self.resource_filter_fields)


@dataclass(frozen=True, slots=True)
class WebhookPayload:
    """Deeply immutable JSON-compatible output from a reviewed serializer."""

    event_type: WebhookEventType
    data: WebhookPayloadData = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, WebhookEventType):
            raise TypeError("webhook payload event_type must be WebhookEventType")
        if not isinstance(self.data, Mapping):
            raise TypeError("webhook payload data must be a mapping")

        budget = [MAX_WEBHOOK_JSON_ITEMS]
        normalized = _normalize_json(
            self.data,
            path="$.payload",
            depth=0,
            budget=budget,
        )
        if not isinstance(normalized, dict):  # pragma: no cover - mapping input invariant
            raise TypeError("webhook payload data must normalize to a mapping")
        object.__setattr__(self, "data", _freeze_json_mapping(normalized))


class WebhookPayloadSerializer(Protocol):
    """Reviewed serializer for one explicitly registered Event Bus event type."""

    @property
    def event_type(self) -> WebhookEventType: ...

    def serialize(self, event: Event) -> WebhookPayload | Awaitable[WebhookPayload]: ...


@dataclass(frozen=True, slots=True)
class WebhookEventRegistration:
    """Opaque handle returned by webhook event registration."""

    id: UUID
    name: str


@dataclass(frozen=True, slots=True)
class WebhookSubscription:
    """Versioned durable subscription without plaintext signing material."""

    id: UUID
    name: str
    display_name: str
    event_types: frozenset[str]
    endpoint: WebhookEndpoint
    signing: WebhookSigningPolicy
    egress_policy: str
    created_at: datetime
    updated_at: datetime
    created_by: str
    retry: WebhookRetryPolicy = field(default_factory=WebhookRetryPolicy)
    resource_filters: WebhookResourceFilters = field(default_factory=dict)
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE
    disabled_at: datetime | None = None
    revoked_at: datetime | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        name = _normalize_name(self.name, label="webhook subscription")
        display_name = _normalize_display_name(
            self.display_name,
            label="webhook subscription",
        )
        created_by = _normalize_display_name(
            self.created_by,
            label="webhook subscription creator",
        )
        if not isinstance(self.event_types, frozenset):
            raise TypeError("webhook subscription event_types must be a frozenset")
        event_types = frozenset(_normalize_event_type(value) for value in self.event_types)
        if not event_types:
            raise ValueError("webhook subscription requires at least one event type")
        if len(event_types) != len(self.event_types):
            raise ValueError("webhook subscription event types must be unique after normalization")
        if len(event_types) > MAX_WEBHOOK_EVENT_TYPES_PER_SUBSCRIPTION:
            raise ValueError("webhook subscription contains too many event types")
        if not isinstance(self.endpoint, WebhookEndpoint):
            raise TypeError("webhook subscription endpoint must be WebhookEndpoint")
        if not isinstance(self.signing, WebhookSigningPolicy):
            raise TypeError("webhook subscription signing must be WebhookSigningPolicy")
        if not isinstance(self.retry, WebhookRetryPolicy):
            raise TypeError("webhook subscription retry must be WebhookRetryPolicy")
        egress_policy = _normalize_name(
            self.egress_policy,
            label="webhook egress policy",
        )
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("webhook subscription updated_at cannot precede created_at")
        if self.revision <= 0:
            raise ValueError("webhook subscription revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported webhook subscription schema version")

        status = WebhookSubscriptionStatus(self.status)
        disabled_at = self.disabled_at
        revoked_at = self.revoked_at
        if disabled_at is not None:
            _require_aware(disabled_at, "disabled_at")
            if disabled_at < self.created_at or self.updated_at < disabled_at:
                raise ValueError("webhook subscription disabled_at is outside its lifecycle")
        if revoked_at is not None:
            _require_aware(revoked_at, "revoked_at")
            if revoked_at < self.created_at or self.updated_at < revoked_at:
                raise ValueError("webhook subscription revoked_at is outside its lifecycle")

        if status is WebhookSubscriptionStatus.ACTIVE:
            if disabled_at is not None or revoked_at is not None:
                raise ValueError("active webhook subscription cannot contain inactive timestamps")
        elif status is WebhookSubscriptionStatus.DISABLED:
            if disabled_at is None or revoked_at is not None:
                raise ValueError("disabled webhook subscription requires only disabled_at")
        elif revoked_at is None:
            raise ValueError("revoked webhook subscription requires revoked_at")

        filters = normalize_webhook_resource_filters(
            self.resource_filters,
            event_types=event_types,
        )
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "event_types", event_types)
        object.__setattr__(self, "egress_policy", egress_policy)
        object.__setattr__(self, "created_by", created_by)
        object.__setattr__(self, "resource_filters", filters)
        object.__setattr__(self, "status", status)

    @property
    def deliverable(self) -> bool:
        """Return whether this subscription may create or send deliveries."""

        return self.status.deliverable


@dataclass(frozen=True, slots=True)
class WebhookAttempt:
    """Safe immutable facts for one completed outbound delivery attempt."""

    delivery_id: UUID
    number: int
    scheduled_at: datetime
    started_at: datetime
    finished_at: datetime
    outcome: WebhookAttemptOutcome
    status_class: WebhookHttpStatusClass | None = None
    retry_scheduled: bool = False
    next_attempt_at: datetime | None = None
    error_category: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.number <= 0 or self.number > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook attempt number is outside supported bounds")
        _require_aware(self.scheduled_at, "scheduled_at")
        _require_aware(self.started_at, "started_at")
        _require_aware(self.finished_at, "finished_at")
        if self.started_at < self.scheduled_at:
            raise ValueError("webhook attempt started_at cannot precede scheduled_at")
        if self.finished_at < self.started_at:
            raise ValueError("webhook attempt finished_at cannot precede started_at")
        if self.schema_version != 1:
            raise ValueError("unsupported webhook attempt schema version")

        outcome = WebhookAttemptOutcome(self.outcome)
        status_class = self.status_class
        if status_class is not None:
            status_class = WebhookHttpStatusClass(status_class)

        error_category = self.error_category
        if error_category is not None:
            error_category = _normalize_error_category(error_category)

        next_attempt_at = self.next_attempt_at
        if next_attempt_at is not None:
            _require_aware(next_attempt_at, "next_attempt_at")
            if next_attempt_at <= self.finished_at:
                raise ValueError("webhook next_attempt_at must follow finished_at")

        if outcome is WebhookAttemptOutcome.SUCCEEDED:
            if status_class is not WebhookHttpStatusClass.SUCCESSFUL:
                raise ValueError("successful webhook attempt requires a 2xx status class")
            if error_category is not None:
                raise ValueError("successful webhook attempt cannot contain an error category")
            if self.retry_scheduled or next_attempt_at is not None:
                raise ValueError("successful webhook attempt cannot schedule a retry")
        else:
            if status_class is WebhookHttpStatusClass.SUCCESSFUL:
                raise ValueError("failed webhook attempt cannot contain a 2xx status class")
            if error_category is None:
                raise ValueError("failed webhook attempt requires an error category")
            if self.retry_scheduled != (next_attempt_at is not None):
                raise ValueError("webhook retry metadata is inconsistent")
            if outcome is WebhookAttemptOutcome.TERMINAL_FAILURE and self.retry_scheduled:
                raise ValueError("terminal webhook attempt cannot schedule a retry")

        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "status_class", status_class)
        object.__setattr__(self, "error_category", error_category)


@dataclass(frozen=True, slots=True, repr=False)
class WebhookDelivery:
    """Versioned durable delivery with one immutable canonical request body."""

    id: UUID
    subscription_id: UUID
    event_type: str
    deduplication_key: str
    canonical_body: bytes = field(repr=False)
    body_sha256: str
    occurred_at: datetime
    created_at: datetime
    updated_at: datetime
    status: WebhookDeliveryStatus = WebhookDeliveryStatus.PENDING
    source_event_id: UUID | None = None
    correlation_id: str | None = None
    attempts: tuple[WebhookAttempt, ...] = ()
    current_attempt: int | None = None
    in_flight_at: datetime | None = None
    next_attempt_at: datetime | None = None
    terminal_at: datetime | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        event_type = _normalize_event_type(self.event_type)
        deduplication_key = _normalize_sha256(
            self.deduplication_key,
            label="webhook delivery deduplication key",
        )
        if type(self.canonical_body) is not bytes:
            raise TypeError("webhook canonical body must be bytes")
        if not self.canonical_body or len(self.canonical_body) > MAX_WEBHOOK_DELIVERY_BODY_BYTES:
            raise ValueError("webhook canonical body size is outside supported bounds")
        body_sha256 = _normalize_sha256(
            self.body_sha256,
            label="webhook delivery body digest",
        )
        actual_digest = hashlib.sha256(self.canonical_body).hexdigest()
        if body_sha256 != actual_digest:
            raise ValueError("webhook delivery body digest does not match canonical body")

        _require_aware(self.occurred_at, "occurred_at")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.created_at < self.occurred_at:
            raise ValueError("webhook delivery created_at cannot precede occurred_at")
        if self.updated_at < self.created_at:
            raise ValueError("webhook delivery updated_at cannot precede created_at")
        if self.revision <= 0:
            raise ValueError("webhook delivery revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported webhook delivery schema version")

        correlation_id = self.correlation_id
        if correlation_id is not None:
            correlation_id = _normalize_correlation_id(correlation_id)

        attempts = tuple(self.attempts)
        if len(attempts) > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook delivery contains too many attempts")
        for expected_number, attempt in enumerate(attempts, start=1):
            if not isinstance(attempt, WebhookAttempt):
                raise TypeError("webhook delivery attempts must be WebhookAttempt values")
            if attempt.delivery_id != self.id:
                raise ValueError("webhook attempt belongs to another delivery")
            if attempt.number != expected_number:
                raise ValueError("webhook delivery attempts must be contiguous and ordered")

        status = WebhookDeliveryStatus(self.status)
        _validate_delivery_lifecycle(
            status=status,
            attempts=attempts,
            current_attempt=self.current_attempt,
            in_flight_at=self.in_flight_at,
            next_attempt_at=self.next_attempt_at,
            terminal_at=self.terminal_at,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "deduplication_key", deduplication_key)
        object.__setattr__(self, "body_sha256", body_sha256)
        object.__setattr__(self, "correlation_id", correlation_id)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(self, "status", status)

    def __repr__(self) -> str:
        return (
            "WebhookDelivery("
            f"id={self.id!r}, subscription_id={self.subscription_id!r}, "
            f"event_type={self.event_type!r}, status={self.status!r}, "
            f"attempts={len(self.attempts)}, canonical_body=<redacted>)"
        )

    @property
    def completed_attempts(self) -> int:
        return len(self.attempts)


@dataclass(frozen=True, slots=True)
class WebhookPageRequest:
    """Validated offset pagination for webhook repositories."""

    offset: int = 0
    limit: int = DEFAULT_WEBHOOK_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("webhook page offset cannot be negative")
        if self.limit <= 0 or self.limit > MAX_WEBHOOK_PAGE_SIZE:
            raise ValueError(f"webhook page limit must be between 1 and {MAX_WEBHOOK_PAGE_SIZE}")


DEFAULT_WEBHOOK_PAGE_REQUEST = WebhookPageRequest()


@dataclass(frozen=True, slots=True)
class WebhookPageInfo:
    """Safe deterministic pagination metadata."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if min(self.offset, self.returned, self.total) < 0:
            raise ValueError("webhook page counters cannot be negative")
        if self.limit <= 0 or self.limit > MAX_WEBHOOK_PAGE_SIZE:
            raise ValueError("webhook page limit is outside bounds")
        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("webhook page returned count is inconsistent")
        expected = self.offset + self.returned
        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("webhook page requires next_offset")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("webhook page next_offset is inconsistent")

    @classmethod
    def from_slice(
        cls,
        request: WebhookPageRequest,
        *,
        returned: int,
        total: int,
    ) -> WebhookPageInfo:
        next_offset = request.offset + returned
        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=next_offset if next_offset < total else None,
        )


@dataclass(frozen=True, slots=True)
class WebhookSubscriptionPage:
    """Deterministically ordered webhook-subscription page."""

    items: tuple[WebhookSubscription, ...]
    page: WebhookPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("webhook subscription page count must match items")
        ids = tuple(item.id for item in self.items)
        names = tuple(item.name for item in self.items)
        if len(ids) != len(set(ids)) or len(names) != len(set(names)):
            raise ValueError("webhook subscription page items must be unique")


@dataclass(frozen=True, slots=True)
class WebhookSubscriptionRepositorySnapshot:
    """Non-sensitive bounded subscription repository counters."""

    closed: bool
    subscriptions: int
    active: int
    disabled: int
    revoked: int
    capacity: int

    def __post_init__(self) -> None:
        if min(self.subscriptions, self.active, self.disabled, self.revoked) < 0:
            raise ValueError("webhook subscription counters cannot be negative")
        if not 1 <= self.capacity <= MAX_WEBHOOK_SUBSCRIPTION_CAPACITY:
            raise ValueError("webhook subscription capacity is outside bounds")
        if self.subscriptions > self.capacity:
            raise ValueError("webhook subscription count exceeds capacity")
        if self.active + self.disabled + self.revoked != self.subscriptions:
            raise ValueError("webhook subscription status counts are inconsistent")


class WebhookSubscriptionRepository(Protocol):
    """Persistence boundary for durable webhook subscriptions."""

    @property
    def closed(self) -> bool: ...

    def add(self, subscription: WebhookSubscription) -> Awaitable[None]: ...

    def get(self, subscription_id: UUID) -> Awaitable[WebhookSubscription | None]: ...

    def get_by_name(self, name: str) -> Awaitable[WebhookSubscription | None]: ...

    def list(
        self,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> Awaitable[WebhookSubscriptionPage]: ...

    def replace(
        self,
        subscription: WebhookSubscription,
        *,
        expected_revision: int,
    ) -> Awaitable[WebhookSubscription]: ...

    def snapshot(self) -> Awaitable[WebhookSubscriptionRepositorySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


@dataclass(frozen=True, slots=True)
class WebhookDeliveryPage:
    """Deterministically ordered webhook-delivery page."""

    items: tuple[WebhookDelivery, ...]
    page: WebhookPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("webhook delivery page count must match items")
        ids = tuple(item.id for item in self.items)
        keys = tuple(item.deduplication_key for item in self.items)
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("webhook delivery page items must be unique")


@dataclass(frozen=True, slots=True)
class WebhookDeliveryRepositorySnapshot:
    """Non-sensitive bounded delivery repository counters."""

    closed: bool
    deliveries: int
    pending: int
    in_flight: int
    retrying: int
    succeeded: int
    failed: int
    dead_letter: int
    cancelled: int
    attempts: int
    capacity: int

    def __post_init__(self) -> None:
        counts = (
            self.deliveries,
            self.pending,
            self.in_flight,
            self.retrying,
            self.succeeded,
            self.failed,
            self.dead_letter,
            self.cancelled,
            self.attempts,
        )
        if any(value < 0 for value in counts):
            raise ValueError("webhook delivery counters cannot be negative")
        if not 1 <= self.capacity <= MAX_WEBHOOK_DELIVERY_CAPACITY:
            raise ValueError("webhook delivery capacity is outside bounds")
        if self.deliveries > self.capacity:
            raise ValueError("webhook delivery count exceeds capacity")
        states = (
            self.pending
            + self.in_flight
            + self.retrying
            + self.succeeded
            + self.failed
            + self.dead_letter
            + self.cancelled
        )
        if states != self.deliveries:
            raise ValueError("webhook delivery status counts are inconsistent")
        if self.attempts > self.deliveries * MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook attempt count exceeds delivery bounds")


class WebhookDeliveryRepository(Protocol):
    """Persistence boundary for durable webhook deliveries and attempts."""

    @property
    def closed(self) -> bool: ...

    def add(self, delivery: WebhookDelivery) -> Awaitable[None]: ...

    def get(self, delivery_id: UUID) -> Awaitable[WebhookDelivery | None]: ...

    def get_by_deduplication_key(
        self,
        deduplication_key: str,
    ) -> Awaitable[WebhookDelivery | None]: ...

    def list(
        self,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> Awaitable[WebhookDeliveryPage]: ...

    def replace(
        self,
        delivery: WebhookDelivery,
        *,
        expected_revision: int,
    ) -> Awaitable[WebhookDelivery]: ...

    def snapshot(self) -> Awaitable[WebhookDeliveryRepositorySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def _validate_delivery_lifecycle(
    *,
    status: WebhookDeliveryStatus,
    attempts: tuple[WebhookAttempt, ...],
    current_attempt: int | None,
    in_flight_at: datetime | None,
    next_attempt_at: datetime | None,
    terminal_at: datetime | None,
    created_at: datetime,
    updated_at: datetime,
) -> None:
    if in_flight_at is not None:
        _require_aware(in_flight_at, "in_flight_at")
        if in_flight_at < created_at or updated_at < in_flight_at:
            raise ValueError("webhook delivery in_flight_at is outside its lifecycle")
    if next_attempt_at is not None:
        _require_aware(next_attempt_at, "next_attempt_at")
        if next_attempt_at < updated_at:
            raise ValueError("webhook delivery next_attempt_at cannot precede updated_at")
    if terminal_at is not None:
        _require_aware(terminal_at, "terminal_at")
        if terminal_at < created_at or updated_at < terminal_at:
            raise ValueError("webhook delivery terminal_at is outside its lifecycle")

    if status is WebhookDeliveryStatus.PENDING:
        if attempts or current_attempt is not None or in_flight_at is not None:
            raise ValueError("pending webhook delivery cannot contain attempt state")
        if next_attempt_at is None or terminal_at is not None:
            raise ValueError("pending webhook delivery requires only next_attempt_at")
        return

    if status is WebhookDeliveryStatus.IN_FLIGHT:
        if current_attempt != len(attempts) + 1:
            raise ValueError("in-flight webhook delivery has an invalid attempt number")
        if current_attempt > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("in-flight webhook delivery exceeds attempt bounds")
        if in_flight_at is None or next_attempt_at is not None or terminal_at is not None:
            raise ValueError("in-flight webhook delivery has inconsistent lifecycle metadata")
        return

    if current_attempt is not None or in_flight_at is not None:
        raise ValueError("non-running webhook delivery cannot contain in-flight metadata")

    if status is WebhookDeliveryStatus.RETRYING:
        if not attempts or attempts[-1].outcome is not WebhookAttemptOutcome.RETRYABLE_FAILURE:
            raise ValueError("retrying webhook delivery requires a retryable attempt")
        if not attempts[-1].retry_scheduled or next_attempt_at != attempts[-1].next_attempt_at:
            raise ValueError("retrying webhook delivery retry metadata is inconsistent")
        if terminal_at is not None:
            raise ValueError("retrying webhook delivery cannot be terminal")
        return

    if status is WebhookDeliveryStatus.CANCELLED:
        if next_attempt_at is not None or terminal_at is None:
            raise ValueError("cancelled webhook delivery requires terminal metadata")
        return

    if not attempts or next_attempt_at is not None or terminal_at is None:
        raise ValueError("terminal webhook delivery has inconsistent lifecycle metadata")

    last = attempts[-1]
    if terminal_at < last.finished_at:
        raise ValueError("webhook delivery terminal_at cannot precede its final attempt")
    if status is WebhookDeliveryStatus.SUCCEEDED:
        if last.outcome is not WebhookAttemptOutcome.SUCCEEDED:
            raise ValueError("successful webhook delivery requires a successful final attempt")
    elif status is WebhookDeliveryStatus.FAILED:
        if last.outcome is not WebhookAttemptOutcome.TERMINAL_FAILURE:
            raise ValueError("failed webhook delivery requires a terminal failure")
    elif status is WebhookDeliveryStatus.DEAD_LETTER:
        if last.outcome is not WebhookAttemptOutcome.RETRYABLE_FAILURE or last.retry_scheduled:
            raise ValueError("dead-letter webhook delivery requires exhausted retryable failure")


def _normalize_sha256(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _normalize_error_category(value: str) -> str:
    normalized = value.strip().lower()
    if (
        len(normalized) > MAX_WEBHOOK_SAFE_ERROR_CATEGORY_LENGTH
        or _ERROR_CATEGORY_PATTERN.fullmatch(normalized) is None
    ):
        raise ValueError("webhook error category contains unsupported characters")
    return normalized


def _normalize_correlation_id(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_WEBHOOK_CORRELATION_ID_LENGTH:
        raise ValueError("webhook correlation id length is outside supported bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("webhook correlation id must not contain control characters")
    return normalized


def normalize_webhook_resource_filters(
    values: WebhookResourceFilters,
    *,
    event_types: frozenset[str],
) -> WebhookResourceFilters:
    """Validate and deeply freeze per-event resource filters."""

    normalized_event_types = frozenset(_normalize_event_type(value) for value in event_types)
    result: dict[str, Mapping[str, frozenset[str]]] = {}

    for event_name, fields in values.items():
        normalized_event = _normalize_event_type(event_name)
        if normalized_event in result:
            raise ValueError("webhook resource filters contain duplicate event types")
        if normalized_event not in normalized_event_types:
            raise ValueError("webhook resource filters reference an unsubscribed event type")
        if not isinstance(fields, Mapping):
            raise TypeError("webhook resource-filter fields must be a mapping")
        if len(fields) > MAX_WEBHOOK_FILTER_FIELDS_PER_EVENT:
            raise ValueError("webhook resource filters contain too many fields")

        normalized_fields: dict[str, frozenset[str]] = {}
        for field_name, supplied_values in fields.items():
            normalized_field = _normalize_filter_field(field_name)
            if normalized_field in normalized_fields:
                raise ValueError("webhook resource filters contain duplicate fields")
            if not isinstance(supplied_values, frozenset):
                raise TypeError("webhook resource-filter values must be a frozenset")
            normalized_values = frozenset(
                _normalize_filter_value(value) for value in supplied_values
            )
            if not normalized_values:
                raise ValueError("webhook resource-filter values must not be empty")
            if len(normalized_values) > MAX_WEBHOOK_FILTER_VALUES_PER_FIELD:
                raise ValueError("webhook resource filter contains too many values")
            normalized_fields[normalized_field] = normalized_values

        result[normalized_event] = MappingProxyType(normalized_fields)

    return MappingProxyType(result)


def _normalize_endpoint_url(
    value: str,
    *,
    allow_insecure_loopback: bool,
) -> str:
    if value != value.strip():
        raise ValueError("webhook endpoint must not contain surrounding whitespace")
    if not value or len(value) > MAX_WEBHOOK_ENDPOINT_URL_LENGTH:
        raise ValueError("webhook endpoint length is outside supported bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("webhook endpoint must not contain control characters")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exception:
        raise ValueError("webhook endpoint must use an ASCII URL") from exception
    if "\\" in value:
        raise ValueError("webhook endpoint must not contain backslashes")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"https", "http"}:
        raise ValueError("webhook endpoint must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("webhook endpoint must not contain user information")
    if parsed.fragment:
        raise ValueError("webhook endpoint must not contain a fragment")
    if parsed.query:
        raise ValueError("webhook endpoint query parameters are not supported")
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("webhook endpoint requires a host")
    if "%" in hostname:
        raise ValueError("webhook endpoint must not contain an address zone identifier")

    try:
        port = parsed.port
    except ValueError as exception:
        raise ValueError("webhook endpoint contains an invalid port") from exception

    host, address = _normalize_host(hostname)
    path = parsed.path or "/"
    if any(character.isspace() for character in path):
        raise ValueError("webhook endpoint path must not contain whitespace")
    if not path.startswith("/"):
        raise ValueError("webhook endpoint path must be absolute")

    if scheme == "http":
        if not allow_insecure_loopback:
            raise ValueError("HTTP webhook endpoints require explicit loopback development mode")
        if address is None or not address.is_loopback:
            raise ValueError("HTTP webhook endpoints require a literal loopback address")
    elif allow_insecure_loopback:
        raise ValueError("loopback development mode is valid only for HTTP endpoints")

    default_port = 443 if scheme == "https" else 80
    effective_port = default_port if port is None else port
    if effective_port <= 0 or effective_port > 65_535:
        raise ValueError("webhook endpoint port must be between 1 and 65535")

    authority = _format_authority(host, address, port, default_port)
    normalized = SplitResult(
        scheme=scheme,
        netloc=authority,
        path=path,
        query="",
        fragment="",
    )
    return urlunsplit(normalized)


def _normalize_host(
    value: str,
) -> tuple[str, IPv4Address | IPv6Address | None]:
    supplied = value.lower().rstrip(".")
    if not supplied:
        raise ValueError("webhook endpoint requires a host")

    try:
        address = ip_address(supplied)
    except ValueError:
        if len(supplied) > 253:
            raise ValueError("webhook endpoint host is too long") from None
        labels = supplied.split(".")
        if any(
            not label
            or len(label) > 63
            or label[0] == "-"
            or label[-1] == "-"
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ):
            raise ValueError("webhook endpoint host is not a canonical DNS name") from None
        return supplied, None
    return address.compressed, address


def _format_authority(
    host: str,
    address: IPv4Address | IPv6Address | None,
    port: int | None,
    default_port: int,
) -> str:
    formatted_host = f"[{host}]" if isinstance(address, IPv6Address) else host
    if port is None or port == default_port:
        return formatted_host
    return f"{formatted_host}:{port}"


def _normalize_networks(values: tuple[str, ...]) -> tuple[str, ...]:
    if len(values) > MAX_WEBHOOK_EGRESS_NETWORKS:
        raise ValueError("webhook egress policy contains too many networks")

    networks = []
    for value in values:
        supplied = value.strip()
        try:
            network = ip_network(supplied, strict=True)
        except ValueError as exception:
            raise ValueError(
                "webhook egress policy networks must use canonical CIDR notation"
            ) from exception
        if supplied != network.with_prefixlen:
            raise ValueError("webhook egress policy networks must use canonical CIDR notation")
        networks.append(network)

    canonical = [network.with_prefixlen for network in networks]
    if len(canonical) != len(set(canonical)):
        raise ValueError("webhook egress policy networks must be unique")

    ordered = sorted(
        networks,
        key=lambda item: (
            item.version,
            int(item.network_address),
            item.prefixlen,
        ),
    )
    return tuple(item.with_prefixlen for item in ordered)


def _normalize_json(
    value: object,
    *,
    path: str,
    depth: int,
    budget: list[int],
) -> object:
    if depth > MAX_WEBHOOK_JSON_DEPTH:
        raise ValueError(f"webhook payload exceeds maximum nesting depth at {path}")

    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("webhook payload exceeds maximum item count")

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"webhook payload contains a non-finite number at {path}")
        return value
    if isinstance(value, str):
        if len(value) > MAX_WEBHOOK_JSON_STRING_LENGTH:
            raise ValueError(f"webhook payload string is too long at {path}")
        if any(ord(character) == 0 for character in value):
            raise ValueError(f"webhook payload strings must not contain NUL at {path}")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_WEBHOOK_JSON_MAPPING_ITEMS:
            raise ValueError(f"webhook payload mapping has too many entries at {path}")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"webhook payload mapping keys must be strings at {path}")
            if not key or len(key) > 256:
                raise ValueError(f"webhook payload mapping key has invalid length at {path}")
            if any(ord(character) < 32 or ord(character) == 127 for character in key):
                raise ValueError(
                    f"webhook payload mapping key contains control characters at {path}"
                )
            result[key] = _normalize_json(
                item,
                path=f"{path}.{key}",
                depth=depth + 1,
                budget=budget,
            )
        return result
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        if len(value) > MAX_WEBHOOK_JSON_SEQUENCE_ITEMS:
            raise ValueError(f"webhook payload sequence has too many entries at {path}")
        return [
            _normalize_json(
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                budget=budget,
            )
            for index, item in enumerate(value)
        ]
    raise ValueError(f"unsupported webhook payload type {type(value).__name__} at {path}")


def _freeze_json_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return _freeze_json_mapping(value)
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _normalize_display_name(value: str, *, label: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_WEBHOOK_DISPLAY_NAME_LENGTH:
        raise ValueError(
            f"{label} must contain between 1 and {MAX_WEBHOOK_DISPLAY_NAME_LENGTH} characters"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"{label} must not contain control characters")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _normalize_name(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} name must match [a-z][a-z0-9_.-]{{2,63}}")
    return normalized


def _normalize_event_type(value: str) -> str:
    normalized = value.strip().lower()
    if _EVENT_TYPE_PATTERN.fullmatch(normalized) is None:
        raise ValueError("webhook event type contains unsupported characters")
    return normalized


def _normalize_filter_field(value: str) -> str:
    normalized = value.strip().lower()
    if _FILTER_FIELD_PATTERN.fullmatch(normalized) is None:
        raise ValueError("webhook resource-filter field contains unsupported characters")
    return normalized


def _normalize_filter_value(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_WEBHOOK_FILTER_VALUE_LENGTH:
        raise ValueError("webhook resource-filter value length is outside supported bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("webhook resource-filter value must not contain control characters")
    return normalized
