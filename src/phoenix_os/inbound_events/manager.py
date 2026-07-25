"""Protected administration for durable inbound sources and accepted events."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from phoenix_os.audit import (
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.inbound_events.contracts import (
    DEFAULT_INBOUND_PAGE_REQUEST,
    MAX_INBOUND_PUBLICATION_ATTEMPTS,
    InboundAcceptedEvent,
    InboundAuthenticationMode,
    InboundAuthenticationPolicy,
    InboundEventPage,
    InboundEventReceipt,
    InboundEventRepository,
    InboundEventRepositorySnapshot,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundPageInfo,
    InboundPageRequest,
    InboundPublicationAttempt,
    InboundPublicationOutcome,
    InboundPublicationRetryPolicy,
    InboundPublicationStatus,
    InboundReplayRepository,
    InboundReplayRepositorySnapshot,
    InboundSourcePage,
    InboundSourceRepository,
    InboundSourceRepositorySnapshot,
)
from phoenix_os.inbound_events.errors import (
    InboundEventNotFoundError,
    InboundManagerAccessDeniedError,
    InboundManagerClosedError,
    InboundSourceConflictError,
    InboundSourceNotFoundError,
)
from phoenix_os.inbound_events.recovery import (
    INBOUND_REDRIVE_PERMISSION,
    InboundPublicationRecovery,
    InboundRecoverySnapshot,
    InboundRedriveResult,
)
from phoenix_os.inbound_events.schema import (
    InboundSchemaRegistry,
    InboundSchemaRegistrySnapshot,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef

INBOUND_SOURCES_READ_PERMISSION = "inbound_event.source.read"
INBOUND_SOURCES_CREATE_PERMISSION = "inbound_event.source.create"
INBOUND_SOURCES_UPDATE_PERMISSION = "inbound_event.source.update"
INBOUND_SOURCES_AUTHENTICATION_PERMISSION = "inbound_event.source.authentication.update"
INBOUND_SOURCES_DISABLE_PERMISSION = "inbound_event.source.disable"
INBOUND_SOURCES_ENABLE_PERMISSION = "inbound_event.source.enable"
INBOUND_SOURCES_REVOKE_PERMISSION = "inbound_event.source.revoke"
INBOUND_SOURCES_ROTATE_PERMISSION = "inbound_event.source.rotate"
INBOUND_EVENTS_READ_PERMISSION = "inbound_event.event.read"
INBOUND_RECEIPTS_READ_PERMISSION = "inbound_event.receipt.read"
INBOUND_HEALTH_READ_PERMISSION = "inbound_event.health.read"

type InboundManagerClock = Callable[[], datetime]
type InboundSourceIdFactory = Callable[[], UUID]


@dataclass(frozen=True, slots=True)
class InboundManagerConfig:
    """Explicit administration composition settings."""

    machine_administration_enabled: bool = False
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.machine_administration_enabled) is not bool:
            raise TypeError("machine_administration_enabled must be bool")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound manager config version")


@dataclass(frozen=True, slots=True)
class InboundAuthenticationView:
    """Credential-free authentication metadata."""

    mode: InboundAuthenticationMode
    scheme: str | None = None
    key_version: int | None = None
    predecessor_key_version: int | None = None
    predecessor_valid_until: datetime | None = None
    service_account_resource: str | None = None
    required_action: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        mode = InboundAuthenticationMode(self.mode)
        if mode is InboundAuthenticationMode.HMAC_SHA256:
            if self.scheme is None or self.key_version is None:
                raise ValueError("inbound HMAC view requires scheme and key version")
            if self.service_account_resource is not None or self.required_action is not None:
                raise ValueError("inbound HMAC view cannot contain service-account metadata")
            if self.predecessor_key_version is None:
                if self.predecessor_valid_until is not None:
                    raise ValueError("predecessor validity requires a predecessor key version")
            else:
                if self.predecessor_valid_until is None:
                    raise ValueError("predecessor key version requires bounded validity")
                _require_aware(
                    self.predecessor_valid_until,
                    "inbound predecessor validity",
                )
        else:
            if self.service_account_resource is None or self.required_action is None:
                raise ValueError("service-account view requires resource and action")
            if any(
                value is not None
                for value in (
                    self.scheme,
                    self.key_version,
                    self.predecessor_key_version,
                    self.predecessor_valid_until,
                )
            ):
                raise ValueError("service-account view cannot contain HMAC metadata")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound authentication view version")
        object.__setattr__(self, "mode", mode)

    @classmethod
    def from_policy(
        cls,
        policy: InboundAuthenticationPolicy,
    ) -> InboundAuthenticationView:
        if isinstance(policy, InboundHmacPolicy):
            predecessor = policy.predecessor_secret_ref
            return cls(
                mode=policy.mode,
                scheme=policy.scheme.value,
                key_version=policy.key_version,
                predecessor_key_version=(None if predecessor is None else predecessor.version),
                predecessor_valid_until=policy.predecessor_valid_until,
            )
        return cls(
            mode=policy.mode,
            service_account_resource=policy.resource,
            required_action=policy.required_action,
        )


@dataclass(frozen=True, slots=True)
class InboundRetryView:
    """Safe finite publication retry metadata."""

    max_attempts: int
    initial_delay_seconds: float
    multiplier: float
    max_delay_seconds: float

    @classmethod
    def from_policy(
        cls,
        policy: InboundPublicationRetryPolicy,
    ) -> InboundRetryView:
        return cls(
            max_attempts=policy.max_attempts,
            initial_delay_seconds=policy.initial_delay.total_seconds(),
            multiplier=policy.multiplier,
            max_delay_seconds=policy.max_delay.total_seconds(),
        )


@dataclass(frozen=True, slots=True)
class InboundSourceView:
    """Allowlisted source metadata without secret references."""

    id: UUID
    name: str
    display_name: str
    authentication: InboundAuthenticationView
    event_types: tuple[str, ...]
    created_at: datetime
    updated_at: datetime
    created_by: str
    max_body_bytes: int
    max_header_bytes: int
    timestamp_skew_seconds: float
    replay_retention_seconds: float
    max_concurrency: int
    requests_per_minute: int
    retry: InboundRetryView
    status: InboundEventSourceStatus
    disabled_at: datetime | None
    revoked_at: datetime | None
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if tuple(sorted(self.event_types)) != self.event_types:
            raise ValueError("inbound source view event types must be sorted")
        if self.revision <= 0:
            raise ValueError("inbound source view revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound source view version")
        object.__setattr__(self, "status", InboundEventSourceStatus(self.status))

    @classmethod
    def from_source(cls, source: InboundEventSource) -> InboundSourceView:
        return cls(
            id=source.id,
            name=source.name,
            display_name=source.display_name,
            authentication=InboundAuthenticationView.from_policy(source.authentication),
            event_types=tuple(sorted(source.event_types)),
            created_at=source.created_at,
            updated_at=source.updated_at,
            created_by=source.created_by,
            max_body_bytes=source.max_body_bytes,
            max_header_bytes=source.max_header_bytes,
            timestamp_skew_seconds=source.timestamp_skew.total_seconds(),
            replay_retention_seconds=source.replay_retention.total_seconds(),
            max_concurrency=source.max_concurrency,
            requests_per_minute=source.requests_per_minute,
            retry=InboundRetryView.from_policy(source.retry),
            status=source.status,
            disabled_at=source.disabled_at,
            revoked_at=source.revoked_at,
            revision=source.revision,
        )


@dataclass(frozen=True, slots=True)
class InboundAttemptView:
    """Safe completed publication-attempt facts."""

    number: int
    scheduled_at: datetime
    started_at: datetime
    finished_at: datetime
    outcome: InboundPublicationOutcome
    retry_scheduled: bool
    next_attempt_at: datetime | None
    error_category: str | None

    @classmethod
    def from_attempt(
        cls,
        attempt: InboundPublicationAttempt,
    ) -> InboundAttemptView:
        return cls(
            number=attempt.number,
            scheduled_at=attempt.scheduled_at,
            started_at=attempt.started_at,
            finished_at=attempt.finished_at,
            outcome=attempt.outcome,
            retry_scheduled=attempt.retry_scheduled,
            next_attempt_at=attempt.next_attempt_at,
            error_category=attempt.error_category,
        )


@dataclass(frozen=True, slots=True)
class InboundEventView:
    """Payload-free accepted-event metadata and bounded attempt history."""

    id: UUID
    receipt_id: UUID
    source_id: UUID
    external_event_type: str
    external_schema_version: int
    internal_event_type: str
    occurred_at: datetime
    accepted_at: datetime
    updated_at: datetime
    correlation_id: str | None
    status: InboundPublicationStatus
    attempts: tuple[InboundAttemptView, ...]
    current_attempt: int | None
    publishing_at: datetime | None
    next_attempt_at: datetime | None
    terminal_at: datetime | None
    redrive_eligible: bool
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if len(self.attempts) > MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("inbound event view contains too many attempts")
        if self.revision <= 0:
            raise ValueError("inbound event view revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound event view version")
        object.__setattr__(self, "status", InboundPublicationStatus(self.status))

    @classmethod
    def from_event(cls, event: InboundAcceptedEvent) -> InboundEventView:
        return cls(
            id=event.id,
            receipt_id=event.receipt_id,
            source_id=event.source_id,
            external_event_type=event.external_event_type,
            external_schema_version=event.external_schema_version,
            internal_event_type=event.internal_event_type,
            occurred_at=event.occurred_at,
            accepted_at=event.accepted_at,
            updated_at=event.updated_at,
            correlation_id=event.correlation_id,
            status=event.status,
            attempts=tuple(InboundAttemptView.from_attempt(item) for item in event.attempts),
            current_attempt=event.current_attempt,
            publishing_at=event.publishing_at,
            next_attempt_at=event.next_attempt_at,
            terminal_at=event.terminal_at,
            redrive_eligible=(
                event.status is InboundPublicationStatus.DEAD_LETTER
                and event.completed_attempts < MAX_INBOUND_PUBLICATION_ATTEMPTS
            ),
            revision=event.revision,
        )


@dataclass(frozen=True, slots=True)
class InboundReceiptView:
    """RFC-approved stable receipt metadata."""

    receipt_id: UUID
    accepted_event_id: UUID
    source_id: UUID
    source_event_id: str
    external_event_type: str
    external_schema_version: int
    accepted_at: datetime
    correlation_id: str | None
    schema_version: int = 1

    @classmethod
    def from_receipt(
        cls,
        receipt: InboundEventReceipt,
    ) -> InboundReceiptView:
        return cls(
            receipt_id=receipt.id,
            accepted_event_id=receipt.accepted_event_id,
            source_id=receipt.source_id,
            source_event_id=receipt.source_event_id,
            external_event_type=receipt.external_event_type,
            external_schema_version=receipt.external_schema_version,
            accepted_at=receipt.accepted_at,
            correlation_id=receipt.correlation_id,
        )


@dataclass(frozen=True, slots=True)
class InboundSourceViewPage:
    """Safe source page."""

    items: tuple[InboundSourceView, ...]
    page: InboundPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("inbound source view page count is inconsistent")


@dataclass(frozen=True, slots=True)
class InboundEventViewPage:
    """Safe payload-free event page."""

    items: tuple[InboundEventView, ...]
    page: InboundPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("inbound event view page count is inconsistent")


@dataclass(frozen=True, slots=True)
class InboundManagerSnapshot:
    """Safe administration counters and durable component health."""

    closed: bool
    reads: int
    mutations: int
    denied: int
    conflicts: int
    audit_failures: int
    observation_failures: int
    machine_administration_enabled: bool
    sources: InboundSourceRepositorySnapshot
    events: InboundEventRepositorySnapshot
    replay: InboundReplayRepositorySnapshot
    recovery: InboundRecoverySnapshot
    schemas: InboundSchemaRegistrySnapshot
    schema_version: int = 1

    def __post_init__(self) -> None:
        counters = (
            self.reads,
            self.mutations,
            self.denied,
            self.conflicts,
            self.audit_failures,
            self.observation_failures,
        )
        if any(value < 0 for value in counters):
            raise ValueError("inbound manager counters cannot be negative")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound manager snapshot version")


class InboundManager:
    """Authorize and persist safe inbound source and event administration."""

    def __init__(
        self,
        *,
        sources: InboundSourceRepository,
        events: InboundEventRepository,
        replay: InboundReplayRepository,
        recovery: InboundPublicationRecovery,
        schemas: InboundSchemaRegistry,
        config: InboundManagerConfig | None = None,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        clock: InboundManagerClock | None = None,
        source_id_factory: InboundSourceIdFactory = uuid4,
    ) -> None:
        if not all(
            callable(getattr(sources, name, None))
            for name in ("add", "get", "list", "replace", "snapshot")
        ):
            raise TypeError("inbound manager source repository is invalid")
        if not all(
            callable(getattr(events, name, None))
            for name in ("get", "get_receipt", "list", "snapshot")
        ):
            raise TypeError("inbound manager event repository is invalid")
        if not callable(getattr(replay, "snapshot", None)):
            raise TypeError("inbound manager replay repository is invalid")
        if not isinstance(recovery, InboundPublicationRecovery):
            raise TypeError("inbound manager recovery is invalid")
        if not isinstance(schemas, InboundSchemaRegistry):
            raise TypeError("inbound manager schema registry is invalid")
        resolved_config = InboundManagerConfig() if config is None else config
        if not isinstance(resolved_config, InboundManagerConfig):
            raise TypeError("inbound manager config is invalid")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("inbound manager audit must be AuditLedger")
        if observability is not None and not isinstance(
            observability,
            ObservabilityHub,
        ):
            raise TypeError("inbound manager observability must be ObservabilityHub")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("inbound manager clock must be callable")
        if not callable(source_id_factory):
            raise TypeError("inbound source id factory must be callable")

        self._sources = sources
        self._events = events
        self._replay = replay
        self._recovery = recovery
        self._schemas = schemas
        self._config = resolved_config
        self._audit = audit
        self._observability = observability
        self._clock = resolved_clock
        self._source_id_factory = source_id_factory
        self._closed = False
        self._reads = 0
        self._mutations = 0
        self._denied = 0
        self._conflicts = 0
        self._audit_failures = 0
        self._observation_failures = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def list_sources(
        self,
        context: SecurityContext,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundSourceViewPage:
        await self._require(
            context,
            INBOUND_SOURCES_READ_PERMISSION,
            resource="inbound-sources",
            aggregate=True,
        )
        page = await self._sources.list(request)
        await self._increment(reads=1)
        return _source_page(page)

    async def get_source(
        self,
        source_id: UUID,
        context: SecurityContext,
    ) -> InboundSourceView:
        resource = _source_resource(source_id)
        await self._require(
            context,
            INBOUND_SOURCES_READ_PERMISSION,
            resource=resource,
        )
        source = await self._required_source(source_id)
        await self._increment(reads=1)
        return InboundSourceView.from_source(source)

    async def create_source(
        self,
        context: SecurityContext,
        *,
        name: str,
        display_name: str,
        authentication: InboundAuthenticationPolicy,
        event_types: frozenset[str],
        max_body_bytes: int = 262_144,
        max_header_bytes: int = 16_384,
        timestamp_skew: timedelta = timedelta(minutes=5),
        replay_retention: timedelta = timedelta(days=1),
        max_concurrency: int = 8,
        requests_per_minute: int = 120,
        retry: InboundPublicationRetryPolicy | None = None,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_CREATE_PERMISSION,
            resource="inbound-sources",
            aggregate=True,
        )
        now = self._now()
        source_id = self._source_id_factory()
        if not isinstance(source_id, UUID):
            raise TypeError("inbound source id factory must return UUID")
        source = InboundEventSource(
            id=source_id,
            name=name,
            display_name=display_name,
            authentication=authentication,
            event_types=event_types,
            created_at=now,
            updated_at=now,
            created_by=context.principal,
            max_body_bytes=max_body_bytes,
            max_header_bytes=max_header_bytes,
            timestamp_skew=timestamp_skew,
            replay_retention=replay_retention,
            max_concurrency=max_concurrency,
            requests_per_minute=requests_per_minute,
            retry=(InboundPublicationRetryPolicy() if retry is None else retry),
            status=InboundEventSourceStatus.DISABLED,
            disabled_at=now,
        )
        self._schemas.validate_source(source)
        await self._sources.add(source)
        await self._increment(mutations=1)
        await self._signal_source("create", source, context)
        return InboundSourceView.from_source(source)

    async def update_source(
        self,
        source_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
        name: str | None = None,
        display_name: str | None = None,
        event_types: frozenset[str] | None = None,
        max_body_bytes: int | None = None,
        max_header_bytes: int | None = None,
        timestamp_skew: timedelta | None = None,
        replay_retention: timedelta | None = None,
        max_concurrency: int | None = None,
        requests_per_minute: int | None = None,
        retry: InboundPublicationRetryPolicy | None = None,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_UPDATE_PERMISSION,
            resource=_source_resource(source_id),
        )
        current = await self._required_source(source_id)
        _require_expected_revision(expected_revision)
        changes = {
            field_name: value
            for field_name, value in (
                ("name", name),
                ("display_name", display_name),
                ("event_types", event_types),
                ("max_body_bytes", max_body_bytes),
                ("max_header_bytes", max_header_bytes),
                ("timestamp_skew", timestamp_skew),
                ("replay_retention", replay_retention),
                ("max_concurrency", max_concurrency),
                ("requests_per_minute", requests_per_minute),
                ("retry", retry),
            )
            if value is not None
        }
        if not changes:
            raise ValueError("inbound source update requires at least one field")
        if all(getattr(current, field_name) == value for field_name, value in changes.items()):
            raise ValueError("inbound source update does not change any field")
        updated = replace(
            current,
            name=current.name if name is None else name,
            display_name=(current.display_name if display_name is None else display_name),
            event_types=(current.event_types if event_types is None else event_types),
            max_body_bytes=(current.max_body_bytes if max_body_bytes is None else max_body_bytes),
            max_header_bytes=(
                current.max_header_bytes if max_header_bytes is None else max_header_bytes
            ),
            timestamp_skew=(current.timestamp_skew if timestamp_skew is None else timestamp_skew),
            replay_retention=(
                current.replay_retention if replay_retention is None else replay_retention
            ),
            max_concurrency=(
                current.max_concurrency if max_concurrency is None else max_concurrency
            ),
            requests_per_minute=(
                current.requests_per_minute if requests_per_minute is None else requests_per_minute
            ),
            retry=current.retry if retry is None else retry,
            updated_at=max(self._now(), current.updated_at),
            revision=current.revision + 1,
        )
        self._schemas.validate_source(updated)
        updated = await self._replace_source(
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_source("update", updated, context)
        return InboundSourceView.from_source(updated)

    async def update_authentication(
        self,
        source_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
        authentication: InboundAuthenticationPolicy,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
            resource=_source_resource(source_id),
        )
        current = await self._required_source(source_id)
        _require_expected_revision(expected_revision)
        if current.status is not InboundEventSourceStatus.DISABLED:
            raise InboundSourceConflictError(
                "inbound authentication changes require a disabled source"
            )
        if authentication == current.authentication:
            raise ValueError("inbound authentication update requires a change")
        updated = replace(
            current,
            authentication=authentication,
            updated_at=max(self._now(), current.updated_at),
            revision=current.revision + 1,
        )
        updated = await self._replace_source(
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_source(
            "update_authentication",
            updated,
            context,
        )
        return InboundSourceView.from_source(updated)

    async def rotate_hmac_key(
        self,
        source_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
        secret_ref: SecretRef,
        predecessor_valid_until: datetime | None = None,
        lease_ttl: timedelta | None = None,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_ROTATE_PERMISSION,
            resource=_source_resource(source_id),
        )
        current = await self._required_source(source_id)
        _require_expected_revision(expected_revision)
        authentication = current.authentication
        if not isinstance(authentication, InboundHmacPolicy):
            raise InboundSourceConflictError("only HMAC inbound sources support key rotation")
        if not isinstance(secret_ref, SecretRef):
            raise TypeError("inbound HMAC rotation requires SecretRef")
        if secret_ref.version is None:
            raise ValueError("inbound HMAC rotation requires an exact key version")
        if secret_ref.canonical != authentication.secret_ref.canonical:
            raise ValueError("inbound HMAC rotation must keep the secret identity")
        if secret_ref.version == authentication.secret_ref.version:
            raise ValueError("inbound HMAC rotation requires a new key version")

        now = self._now()
        valid_until = predecessor_valid_until
        if current.status is InboundEventSourceStatus.ACTIVE and valid_until is None:
            raise ValueError("active inbound HMAC rotation requires predecessor validity")
        if valid_until is not None:
            valid_until = _as_utc(
                valid_until,
                "inbound HMAC predecessor validity",
            )
            if valid_until <= now:
                raise ValueError("inbound HMAC predecessor validity must be in the future")
            if valid_until > now + current.replay_retention:
                raise ValueError("inbound HMAC predecessor validity exceeds replay retention")

        rotated = InboundHmacPolicy(
            secret_ref=secret_ref,
            scheme=authentication.scheme,
            lease_ttl=(authentication.lease_ttl if lease_ttl is None else lease_ttl),
            predecessor_secret_ref=(authentication.secret_ref if valid_until is not None else None),
            predecessor_valid_until=valid_until,
        )
        updated = replace(
            current,
            authentication=rotated,
            updated_at=max(now, current.updated_at),
            revision=current.revision + 1,
        )
        updated = await self._replace_source(
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_source("rotate_hmac_key", updated, context)
        return InboundSourceView.from_source(updated)

    async def disable_source(
        self,
        source_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_DISABLE_PERMISSION,
            resource=_source_resource(source_id),
        )
        current = await self._required_source(source_id)
        _require_expected_revision(expected_revision)
        if current.status is not InboundEventSourceStatus.ACTIVE:
            raise InboundSourceConflictError("only active inbound sources may be disabled")
        now = max(self._now(), current.updated_at)
        updated = replace(
            current,
            status=InboundEventSourceStatus.DISABLED,
            updated_at=now,
            disabled_at=now,
            revoked_at=None,
            revision=current.revision + 1,
        )
        updated = await self._replace_source(
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_source("disable", updated, context)
        return InboundSourceView.from_source(updated)

    async def enable_source(
        self,
        source_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_ENABLE_PERMISSION,
            resource=_source_resource(source_id),
        )
        current = await self._required_source(source_id)
        _require_expected_revision(expected_revision)
        if current.status is not InboundEventSourceStatus.DISABLED:
            raise InboundSourceConflictError("only disabled inbound sources may be enabled")
        self._schemas.validate_source(current)
        updated = replace(
            current,
            status=InboundEventSourceStatus.ACTIVE,
            updated_at=max(self._now(), current.updated_at),
            disabled_at=None,
            revoked_at=None,
            revision=current.revision + 1,
        )
        updated = await self._replace_source(
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_source("enable", updated, context)
        return InboundSourceView.from_source(updated)

    async def revoke_source(
        self,
        source_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
    ) -> InboundSourceView:
        await self._require(
            context,
            INBOUND_SOURCES_REVOKE_PERMISSION,
            resource=_source_resource(source_id),
        )
        current = await self._required_source(source_id)
        _require_expected_revision(expected_revision)
        if current.status is InboundEventSourceStatus.REVOKED:
            raise InboundSourceConflictError("revoked inbound source is terminal")
        now = max(self._now(), current.updated_at)
        updated = replace(
            current,
            status=InboundEventSourceStatus.REVOKED,
            updated_at=now,
            revoked_at=now,
            revision=current.revision + 1,
        )
        updated = await self._replace_source(
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_source("revoke", updated, context)
        return InboundSourceView.from_source(updated)

    async def list_events(
        self,
        context: SecurityContext,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundEventViewPage:
        await self._require(
            context,
            INBOUND_EVENTS_READ_PERMISSION,
            resource="inbound-events",
            aggregate=True,
        )
        page = await self._events.list(request)
        await self._increment(reads=1)
        return _event_page(page)

    async def get_event(
        self,
        accepted_event_id: UUID,
        context: SecurityContext,
    ) -> InboundEventView:
        await self._require(
            context,
            INBOUND_EVENTS_READ_PERMISSION,
            resource=_event_resource(accepted_event_id),
        )
        event = await self._required_event(accepted_event_id)
        await self._increment(reads=1)
        return InboundEventView.from_event(event)

    async def get_receipt(
        self,
        receipt_id: UUID,
        context: SecurityContext,
    ) -> InboundReceiptView:
        await self._require(
            context,
            INBOUND_RECEIPTS_READ_PERMISSION,
            resource=_receipt_resource(receipt_id),
        )
        if not isinstance(receipt_id, UUID):
            raise TypeError("inbound receipt id must be UUID")
        receipt = await self._events.get_receipt(receipt_id)
        if receipt is None:
            raise InboundEventNotFoundError("inbound receipt was not found")
        await self._increment(reads=1)
        return InboundReceiptView.from_receipt(receipt)

    async def redrive_event(
        self,
        accepted_event_id: UUID,
        context: SecurityContext,
        *,
        scheduled_at: datetime | None = None,
    ) -> InboundRedriveResult:
        await self._require(
            context,
            INBOUND_REDRIVE_PERMISSION,
            resource=_event_resource(accepted_event_id),
        )
        result = await self._recovery.redrive(
            accepted_event_id,
            context,
            scheduled_at=scheduled_at,
        )
        await self._increment(mutations=1)
        return result

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> InboundManagerSnapshot:
        await self._require(
            context,
            INBOUND_HEALTH_READ_PERMISSION,
            resource="inbound-health",
            aggregate=True,
        )
        sources = await self._sources.snapshot()
        events = await self._events.snapshot()
        replay = await self._replay.snapshot()
        recovery = await self._recovery.snapshot()
        schemas = self._schemas.snapshot()
        async with self._lock:
            self._reads += 1
            return InboundManagerSnapshot(
                closed=self._closed,
                reads=self._reads,
                mutations=self._mutations,
                denied=self._denied,
                conflicts=self._conflicts,
                audit_failures=self._audit_failures,
                observation_failures=self._observation_failures,
                machine_administration_enabled=(self._config.machine_administration_enabled),
                sources=sources,
                events=events,
                replay=replay,
                recovery=recovery,
                schemas=schemas,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _required_source(
        self,
        source_id: UUID,
    ) -> InboundEventSource:
        if not isinstance(source_id, UUID):
            raise TypeError("inbound source id must be UUID")
        source = await self._sources.get(source_id)
        if source is None:
            raise InboundSourceNotFoundError("inbound source was not found")
        return source

    async def _required_event(
        self,
        accepted_event_id: UUID,
    ) -> InboundAcceptedEvent:
        if not isinstance(accepted_event_id, UUID):
            raise TypeError("inbound accepted event id must be UUID")
        event = await self._events.get(accepted_event_id)
        if event is None:
            raise InboundEventNotFoundError("inbound accepted event was not found")
        return event

    async def _replace_source(
        self,
        replacement: InboundEventSource,
        *,
        expected_revision: int,
    ) -> InboundEventSource:
        try:
            return await self._sources.replace(
                replacement,
                expected_revision=expected_revision,
            )
        except InboundSourceConflictError:
            await self._increment(conflicts=1)
            raise

    async def _require(
        self,
        context: SecurityContext,
        permission: str,
        *,
        resource: str,
        aggregate: bool = False,
    ) -> None:
        self._ensure_open()
        if not isinstance(context, SecurityContext):
            raise TypeError("inbound manager context must be SecurityContext")
        allowed = False
        if context.authenticated and context.principal_type is PrincipalType.USER:
            allowed = permission in context.permissions
        elif (
            context.authenticated
            and context.principal_type is PrincipalType.SERVICE
            and self._config.machine_administration_enabled
            and not aggregate
        ):
            allowed = (
                permission in context.permissions
                and permission in context.scopes
                and context.attributes.get("resource") == resource
            )
        if allowed:
            return
        await self._increment(denied=1)
        raise InboundManagerAccessDeniedError(permission)

    async def _signal_source(
        self,
        action: str,
        source: InboundEventSource,
        context: SecurityContext,
    ) -> None:
        authentication = InboundAuthenticationView.from_policy(source.authentication)
        details: dict[str, object] = {
            "source_id": str(source.id),
            "name": source.name,
            "status": source.status.value,
            "revision": source.revision,
            "event_type_count": len(source.event_types),
            "authentication_mode": authentication.mode.value,
            "max_concurrency": source.max_concurrency,
            "requests_per_minute": source.requests_per_minute,
        }
        if authentication.key_version is not None:
            details["key_version"] = authentication.key_version
        if authentication.predecessor_key_version is not None:
            details["predecessor_key_version"] = authentication.predecessor_key_version

        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name=f"inbound.source.{action}",
                        source="phoenix.inbound",
                        category=AuditCategory.CONFIGURATION,
                        action=f"inbound_event.source.{action}",
                        resource=_source_resource(source.id),
                        actor=context.principal,
                        outcome=AuditOutcome.SUCCEEDED,
                        severity=(
                            AuditSeverity.WARNING
                            if action
                            in {
                                "disable",
                                "revoke",
                                "rotate_hmac_key",
                                "update_authentication",
                            }
                            else AuditSeverity.INFO
                        ),
                        details=details,
                        correlation_id=context.correlation_id,
                        causation_id=source.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)

        if self._observability is not None:
            try:
                await self._observability.metric(
                    "inbound.source.mutations",
                    1,
                    source="phoenix.inbound",
                    kind=MetricKind.COUNTER,
                    attributes={
                        "action": action,
                        "status": source.status.value,
                        "authentication_mode": authentication.mode.value,
                    },
                    correlation_id=context.correlation_id,
                    causation_id=source.id,
                )
                await self._observability.log(
                    f"inbound.source.{action}",
                    source="phoenix.inbound",
                    message="inbound source administration completed",
                    severity=(
                        Severity.WARNING if action in {"disable", "revoke"} else Severity.INFO
                    ),
                    attributes=details,
                    correlation_id=context.correlation_id,
                    causation_id=source.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _increment(self, **changes: int) -> None:
        async with self._lock:
            for name, amount in changes.items():
                attribute = f"_{name}"
                current = getattr(self, attribute)
                updated = current + amount
                if updated < 0:
                    raise RuntimeError("inbound manager counter cannot become negative")
                setattr(self, attribute, updated)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("inbound manager clock must return datetime")
        return _as_utc(value, "inbound manager clock")

    def _ensure_open(self) -> None:
        if self._closed:
            raise InboundManagerClosedError("inbound manager is closed")


def _source_page(page: InboundSourcePage) -> InboundSourceViewPage:
    return InboundSourceViewPage(
        items=tuple(InboundSourceView.from_source(item) for item in page.items),
        page=page.page,
    )


def _event_page(page: InboundEventPage) -> InboundEventViewPage:
    return InboundEventViewPage(
        items=tuple(InboundEventView.from_event(item) for item in page.items),
        page=page.page,
    )


def _source_resource(source_id: UUID) -> str:
    if not isinstance(source_id, UUID):
        raise TypeError("inbound source id must be UUID")
    return f"inbound-source:{source_id}"


def _event_resource(event_id: UUID) -> str:
    if not isinstance(event_id, UUID):
        raise TypeError("inbound accepted event id must be UUID")
    return f"inbound-event:{event_id}"


def _receipt_resource(receipt_id: UUID) -> str:
    if not isinstance(receipt_id, UUID):
        raise TypeError("inbound receipt id must be UUID")
    return f"inbound-receipt:{receipt_id}"


def _require_expected_revision(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("expected_revision must be a positive integer")


def _as_utc(value: datetime, label: str) -> datetime:
    _require_aware(value, label)
    return value.astimezone(UTC)


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _utc_now() -> datetime:
    return datetime.now(UTC)
