"""Protected webhook subscription and delivery administration."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from phoenix_os.audit import (
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks.contracts import (
    DEFAULT_WEBHOOK_PAGE_REQUEST,
    MAX_WEBHOOK_RETRY_ATTEMPTS,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryPage,
    WebhookDeliveryRepository,
    WebhookDeliveryRepositorySnapshot,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookHttpStatusClass,
    WebhookPageInfo,
    WebhookPageRequest,
    WebhookResourceFilters,
    WebhookRetryPolicy,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionPage,
    WebhookSubscriptionRepository,
    WebhookSubscriptionRepositorySnapshot,
    WebhookSubscriptionStatus,
)
from phoenix_os.webhooks.errors import (
    WebhookDeliveryNotFoundError,
    WebhookManagerAccessDeniedError,
    WebhookManagerClosedError,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
)
from phoenix_os.webhooks.recovery import (
    WEBHOOK_REDRIVE_PERMISSION as WEBHOOK_REDRIVE_PERMISSION,
)
from phoenix_os.webhooks.recovery import (
    WebhookDeliveryRecovery,
    WebhookRedriveResult,
)

WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION = "webhook.subscription.read"
WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION = "webhook.subscription.create"
WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION = "webhook.subscription.update"
WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION = "webhook.subscription.disable"
WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION = "webhook.subscription.enable"
WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION = "webhook.subscription.revoke"
WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION = "webhook.subscription.rotate"
WEBHOOK_DELIVERIES_READ_PERMISSION = "webhook.delivery.read"
WEBHOOK_HEALTH_READ_PERMISSION = "webhook.health.read"

type WebhookManagerClock = Callable[[], datetime]
type WebhookSubscriptionIdFactory = Callable[[], UUID]


@dataclass(frozen=True, slots=True)
class WebhookEndpointView:
    """Safe endpoint identity without retaining a possibly secret URL path."""

    scheme: str
    host: str
    port: int
    path_sha256: str
    loopback_development: bool

    @classmethod
    def from_endpoint(cls, endpoint: WebhookEndpoint) -> WebhookEndpointView:
        parsed = urlsplit(endpoint.url)
        path = parsed.path or "/"
        return cls(
            scheme=endpoint.scheme,
            host=endpoint.host,
            port=endpoint.port,
            path_sha256=hashlib.sha256(path.encode("ascii")).hexdigest(),
            loopback_development=endpoint.loopback_development,
        )


@dataclass(frozen=True, slots=True)
class WebhookSigningView:
    """Credential-free signing metadata."""

    scheme: str
    key_version: int
    lease_ttl_seconds: float

    @classmethod
    def from_policy(cls, policy: WebhookSigningPolicy) -> WebhookSigningView:
        return cls(
            scheme=policy.scheme.value,
            key_version=policy.key_version,
            lease_ttl_seconds=policy.lease_ttl.total_seconds(),
        )


@dataclass(frozen=True, slots=True)
class WebhookRetryView:
    """Safe bounded retry metadata."""

    max_attempts: int
    initial_delay_seconds: float
    multiplier: float
    max_delay_seconds: float
    jitter_ratio: float

    @classmethod
    def from_policy(cls, policy: WebhookRetryPolicy) -> WebhookRetryView:
        return cls(
            max_attempts=policy.max_attempts,
            initial_delay_seconds=policy.initial_delay.total_seconds(),
            multiplier=policy.multiplier,
            max_delay_seconds=policy.max_delay.total_seconds(),
            jitter_ratio=policy.jitter_ratio,
        )


@dataclass(frozen=True, slots=True)
class WebhookSubscriptionView:
    """Allowlisted subscription metadata without signing references or endpoint paths."""

    id: UUID
    name: str
    display_name: str
    event_types: tuple[str, ...]
    endpoint: WebhookEndpointView
    signing: WebhookSigningView
    egress_policy: str
    retry: WebhookRetryView
    resource_filters: Mapping[str, Mapping[str, tuple[str, ...]]]
    status: WebhookSubscriptionStatus
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None
    revoked_at: datetime | None
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if tuple(sorted(self.event_types)) != self.event_types:
            raise ValueError("webhook subscription view event types must be sorted")
        if self.revision <= 0:
            raise ValueError("webhook subscription view revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported webhook subscription view schema version")
        object.__setattr__(self, "status", WebhookSubscriptionStatus(self.status))
        object.__setattr__(
            self,
            "resource_filters",
            _freeze_filter_view(self.resource_filters),
        )

    @classmethod
    def from_subscription(
        cls,
        subscription: WebhookSubscription,
    ) -> WebhookSubscriptionView:
        return cls(
            id=subscription.id,
            name=subscription.name,
            display_name=subscription.display_name,
            event_types=tuple(sorted(subscription.event_types)),
            endpoint=WebhookEndpointView.from_endpoint(subscription.endpoint),
            signing=WebhookSigningView.from_policy(subscription.signing),
            egress_policy=subscription.egress_policy,
            retry=WebhookRetryView.from_policy(subscription.retry),
            resource_filters={
                event_name: {
                    field_name: tuple(sorted(values))
                    for field_name, values in sorted(fields.items())
                }
                for event_name, fields in sorted(subscription.resource_filters.items())
            },
            status=subscription.status,
            created_at=subscription.created_at,
            updated_at=subscription.updated_at,
            disabled_at=subscription.disabled_at,
            revoked_at=subscription.revoked_at,
            revision=subscription.revision,
        )


@dataclass(frozen=True, slots=True)
class WebhookAttemptView:
    """Safe immutable facts from one completed delivery attempt."""

    number: int
    scheduled_at: datetime
    started_at: datetime
    finished_at: datetime
    outcome: WebhookAttemptOutcome
    status_class: WebhookHttpStatusClass | None
    retry_scheduled: bool
    next_attempt_at: datetime | None
    error_category: str | None

    @classmethod
    def from_attempt(cls, attempt: WebhookAttempt) -> WebhookAttemptView:
        return cls(
            number=attempt.number,
            scheduled_at=attempt.scheduled_at,
            started_at=attempt.started_at,
            finished_at=attempt.finished_at,
            outcome=attempt.outcome,
            status_class=attempt.status_class,
            retry_scheduled=attempt.retry_scheduled,
            next_attempt_at=attempt.next_attempt_at,
            error_category=attempt.error_category,
        )


@dataclass(frozen=True, slots=True)
class WebhookDeliveryView:
    """Body-free delivery metadata and bounded attempt history."""

    id: UUID
    subscription_id: UUID
    event_type: str
    status: WebhookDeliveryStatus
    occurred_at: datetime
    created_at: datetime
    updated_at: datetime
    source_event_id: UUID | None
    correlation_id: str | None
    attempts: tuple[WebhookAttemptView, ...]
    current_attempt: int | None
    in_flight_at: datetime | None
    next_attempt_at: datetime | None
    terminal_at: datetime | None
    redrive_eligible: bool
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        status = WebhookDeliveryStatus(self.status)
        if len(self.attempts) > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook delivery view contains too many attempts")
        if self.revision <= 0:
            raise ValueError("webhook delivery view revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported webhook delivery view schema version")
        object.__setattr__(self, "status", status)

    @classmethod
    def from_delivery(cls, delivery: WebhookDelivery) -> WebhookDeliveryView:
        return cls(
            id=delivery.id,
            subscription_id=delivery.subscription_id,
            event_type=delivery.event_type,
            status=delivery.status,
            occurred_at=delivery.occurred_at,
            created_at=delivery.created_at,
            updated_at=delivery.updated_at,
            source_event_id=delivery.source_event_id,
            correlation_id=delivery.correlation_id,
            attempts=tuple(WebhookAttemptView.from_attempt(item) for item in delivery.attempts),
            current_attempt=delivery.current_attempt,
            in_flight_at=delivery.in_flight_at,
            next_attempt_at=delivery.next_attempt_at,
            terminal_at=delivery.terminal_at,
            redrive_eligible=delivery.redrive_eligible,
            revision=delivery.revision,
        )


@dataclass(frozen=True, slots=True)
class WebhookSubscriptionViewPage:
    """Safe subscription page."""

    items: tuple[WebhookSubscriptionView, ...]
    page: WebhookPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("webhook subscription view page count is inconsistent")


@dataclass(frozen=True, slots=True)
class WebhookDeliveryViewPage:
    """Safe delivery page."""

    items: tuple[WebhookDeliveryView, ...]
    page: WebhookPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("webhook delivery view page count is inconsistent")


@dataclass(frozen=True, slots=True)
class WebhookManagerSnapshot:
    """Safe administration counters and durable repository health."""

    closed: bool
    reads: int
    mutations: int
    denied: int
    conflicts: int
    audit_failures: int
    observation_failures: int
    subscriptions: WebhookSubscriptionRepositorySnapshot
    deliveries: WebhookDeliveryRepositorySnapshot

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
            raise ValueError("webhook manager counters cannot be negative")


class WebhookManager:
    """Authorize and persist safe webhook administration operations."""

    def __init__(
        self,
        *,
        subscriptions: WebhookSubscriptionRepository,
        deliveries: WebhookDeliveryRepository,
        recovery: WebhookDeliveryRecovery,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        clock: WebhookManagerClock | None = None,
        subscription_id_factory: WebhookSubscriptionIdFactory = uuid4,
    ) -> None:
        if not isinstance(recovery, WebhookDeliveryRecovery):
            raise TypeError("webhook manager recovery must be WebhookDeliveryRecovery")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("webhook manager audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("webhook manager observability must be ObservabilityHub")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("webhook manager clock must be callable")
        if not callable(subscription_id_factory):
            raise TypeError("webhook subscription id factory must be callable")

        self._subscriptions = subscriptions
        self._deliveries = deliveries
        self._recovery = recovery
        self._audit = audit
        self._observability = observability
        self._clock = resolved_clock
        self._subscription_id_factory = subscription_id_factory
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

    async def list_subscriptions(
        self,
        context: SecurityContext,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> WebhookSubscriptionViewPage:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION)
        page = await self._subscriptions.list(request)
        await self._increment(reads=1)
        return _subscription_page(page)

    async def get_subscription(
        self,
        subscription_id: UUID,
        context: SecurityContext,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION)
        subscription = await self._required_subscription(subscription_id)
        await self._increment(reads=1)
        return WebhookSubscriptionView.from_subscription(subscription)

    async def create_subscription(
        self,
        context: SecurityContext,
        *,
        name: str,
        display_name: str,
        event_types: frozenset[str],
        endpoint: WebhookEndpoint,
        signing: WebhookSigningPolicy,
        egress_policy: str,
        retry: WebhookRetryPolicy | None = None,
        resource_filters: WebhookResourceFilters | None = None,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION)
        now = self._now()
        subscription_id = self._subscription_id_factory()
        if not isinstance(subscription_id, UUID):
            raise TypeError("webhook subscription id factory must return UUID")
        subscription = WebhookSubscription(
            id=subscription_id,
            name=name,
            display_name=display_name,
            event_types=event_types,
            endpoint=endpoint,
            signing=signing,
            egress_policy=egress_policy,
            created_at=now,
            updated_at=now,
            created_by=context.principal,
            retry=WebhookRetryPolicy() if retry is None else retry,
            resource_filters={} if resource_filters is None else resource_filters,
        )
        await self._subscriptions.add(subscription)
        await self._increment(mutations=1)
        await self._signal_subscription("create", subscription, context)
        return WebhookSubscriptionView.from_subscription(subscription)

    async def update_subscription(
        self,
        subscription_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
        name: str | None = None,
        display_name: str | None = None,
        event_types: frozenset[str] | None = None,
        endpoint: WebhookEndpoint | None = None,
        egress_policy: str | None = None,
        retry: WebhookRetryPolicy | None = None,
        resource_filters: WebhookResourceFilters | None = None,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION)
        current = await self._required_subscription(subscription_id)
        _require_expected_revision(expected_revision)
        changes: dict[str, object] = {}
        for field_name, value in (
            ("name", name),
            ("display_name", display_name),
            ("event_types", event_types),
            ("endpoint", endpoint),
            ("egress_policy", egress_policy),
            ("retry", retry),
            ("resource_filters", resource_filters),
        ):
            if value is not None:
                changes[field_name] = value
        if not changes:
            raise ValueError("webhook subscription update requires at least one field")
        if all(getattr(current, field_name) == value for field_name, value in changes.items()):
            raise ValueError("webhook subscription update does not change any field")
        updated = replace(
            current,
            name=current.name if name is None else name,
            display_name=current.display_name if display_name is None else display_name,
            event_types=current.event_types if event_types is None else event_types,
            endpoint=current.endpoint if endpoint is None else endpoint,
            egress_policy=(current.egress_policy if egress_policy is None else egress_policy),
            retry=current.retry if retry is None else retry,
            resource_filters=(
                current.resource_filters if resource_filters is None else resource_filters
            ),
            updated_at=max(self._now(), current.updated_at),
            revision=current.revision + 1,
        )
        updated = await self._replace_subscription(
            current,
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_subscription("update", updated, context)
        return WebhookSubscriptionView.from_subscription(updated)

    async def disable_subscription(
        self,
        subscription_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION)
        current = await self._required_subscription(subscription_id)
        _require_expected_revision(expected_revision)
        if current.status is not WebhookSubscriptionStatus.ACTIVE:
            raise WebhookSubscriptionConflictError(
                "only active webhook subscriptions may be disabled"
            )
        now = max(self._now(), current.updated_at)
        updated = replace(
            current,
            status=WebhookSubscriptionStatus.DISABLED,
            updated_at=now,
            disabled_at=now,
            revoked_at=None,
            revision=current.revision + 1,
        )
        updated = await self._replace_subscription(
            current,
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_subscription("disable", updated, context)
        return WebhookSubscriptionView.from_subscription(updated)

    async def enable_subscription(
        self,
        subscription_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION)
        current = await self._required_subscription(subscription_id)
        _require_expected_revision(expected_revision)
        if current.status is not WebhookSubscriptionStatus.DISABLED:
            raise WebhookSubscriptionConflictError(
                "only disabled webhook subscriptions may be enabled"
            )
        updated = replace(
            current,
            status=WebhookSubscriptionStatus.ACTIVE,
            updated_at=max(self._now(), current.updated_at),
            disabled_at=None,
            revoked_at=None,
            revision=current.revision + 1,
        )
        updated = await self._replace_subscription(
            current,
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_subscription("enable", updated, context)
        return WebhookSubscriptionView.from_subscription(updated)

    async def revoke_subscription(
        self,
        subscription_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION)
        current = await self._required_subscription(subscription_id)
        _require_expected_revision(expected_revision)
        if current.status is WebhookSubscriptionStatus.REVOKED:
            raise WebhookSubscriptionConflictError("revoked webhook subscription is terminal")
        now = max(self._now(), current.updated_at)
        updated = replace(
            current,
            status=WebhookSubscriptionStatus.REVOKED,
            updated_at=now,
            revoked_at=now,
            revision=current.revision + 1,
        )
        updated = await self._replace_subscription(
            current,
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_subscription("revoke", updated, context)
        return WebhookSubscriptionView.from_subscription(updated)

    async def rotate_signing_key(
        self,
        subscription_id: UUID,
        context: SecurityContext,
        *,
        expected_revision: int,
        secret_ref: SecretRef,
        lease_ttl: timedelta | None = None,
    ) -> WebhookSubscriptionView:
        await self._require(context, WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION)
        current = await self._required_subscription(subscription_id)
        _require_expected_revision(expected_revision)
        signing = WebhookSigningPolicy(
            secret_ref=secret_ref,
            scheme=current.signing.scheme,
            lease_ttl=current.signing.lease_ttl if lease_ttl is None else lease_ttl,
        )
        if signing == current.signing:
            raise ValueError("webhook signing-key rotation requires a new reference or lease")
        updated = replace(
            current,
            signing=signing,
            updated_at=max(self._now(), current.updated_at),
            revision=current.revision + 1,
        )
        updated = await self._replace_subscription(
            current,
            updated,
            expected_revision=expected_revision,
        )
        await self._increment(mutations=1)
        await self._signal_subscription("rotate_signing_key", updated, context)
        return WebhookSubscriptionView.from_subscription(updated)

    async def list_deliveries(
        self,
        context: SecurityContext,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> WebhookDeliveryViewPage:
        await self._require(context, WEBHOOK_DELIVERIES_READ_PERMISSION)
        page = await self._deliveries.list(request)
        await self._increment(reads=1)
        return _delivery_page(page)

    async def get_delivery(
        self,
        delivery_id: UUID,
        context: SecurityContext,
    ) -> WebhookDeliveryView:
        await self._require(context, WEBHOOK_DELIVERIES_READ_PERMISSION)
        delivery = await self._required_delivery(delivery_id)
        await self._increment(reads=1)
        return WebhookDeliveryView.from_delivery(delivery)

    async def redrive_delivery(
        self,
        delivery_id: UUID,
        context: SecurityContext,
        *,
        scheduled_at: datetime | None = None,
    ) -> WebhookRedriveResult:
        await self._require(context, WEBHOOK_REDRIVE_PERMISSION)
        result = await self._recovery.redrive(
            delivery_id,
            context,
            scheduled_at=scheduled_at,
        )
        await self._increment(mutations=1)
        return result

    async def snapshot(self, context: SecurityContext) -> WebhookManagerSnapshot:
        await self._require(context, WEBHOOK_HEALTH_READ_PERMISSION)
        subscriptions = await self._subscriptions.snapshot()
        deliveries = await self._deliveries.snapshot()
        async with self._lock:
            self._reads += 1
            return WebhookManagerSnapshot(
                closed=self._closed,
                reads=self._reads,
                mutations=self._mutations,
                denied=self._denied,
                conflicts=self._conflicts,
                audit_failures=self._audit_failures,
                observation_failures=self._observation_failures,
                subscriptions=subscriptions,
                deliveries=deliveries,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _required_subscription(self, subscription_id: UUID) -> WebhookSubscription:
        if not isinstance(subscription_id, UUID):
            raise TypeError("webhook subscription id must be UUID")
        subscription = await self._subscriptions.get(subscription_id)
        if subscription is None:
            raise WebhookSubscriptionNotFoundError("webhook subscription was not found")
        return subscription

    async def _required_delivery(self, delivery_id: UUID) -> WebhookDelivery:
        if not isinstance(delivery_id, UUID):
            raise TypeError("webhook delivery id must be UUID")
        delivery = await self._deliveries.get(delivery_id)
        if delivery is None:
            raise WebhookDeliveryNotFoundError("webhook delivery was not found")
        return delivery

    async def _replace_subscription(
        self,
        current: WebhookSubscription,
        replacement: WebhookSubscription,
        *,
        expected_revision: int,
    ) -> WebhookSubscription:
        try:
            return await self._subscriptions.replace(
                replacement,
                expected_revision=expected_revision,
            )
        except WebhookSubscriptionConflictError:
            await self._increment(conflicts=1)
            raise

    async def _require(self, context: SecurityContext, permission: str) -> None:
        self._ensure_open()
        if not isinstance(context, SecurityContext):
            raise TypeError("webhook manager context must be SecurityContext")
        if not context.authenticated or permission not in context.permissions:
            await self._increment(denied=1)
            raise WebhookManagerAccessDeniedError(permission)

    async def _signal_subscription(
        self,
        action: str,
        subscription: WebhookSubscription,
        context: SecurityContext,
    ) -> None:
        details: dict[str, object] = {
            "subscription_id": str(subscription.id),
            "name": subscription.name,
            "status": subscription.status.value,
            "revision": subscription.revision,
            "event_type_count": len(subscription.event_types),
            "egress_policy": subscription.egress_policy,
            "key_version": subscription.signing.key_version,
        }
        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name=f"webhook.subscription.{action}",
                        source="phoenix.webhooks",
                        category=AuditCategory.OTHER,
                        action=f"webhook.subscription.{action}",
                        resource=f"webhook-subscription:{subscription.id}",
                        actor=context.principal,
                        outcome=AuditOutcome.SUCCEEDED,
                        severity=(
                            AuditSeverity.WARNING
                            if action in {"disable", "revoke", "rotate_signing_key"}
                            else AuditSeverity.INFO
                        ),
                        details=details,
                        correlation_id=context.correlation_id,
                        causation_id=subscription.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)
        if self._observability is not None:
            try:
                await self._observability.metric(
                    "webhook.subscription.mutations",
                    1,
                    source="phoenix.webhooks",
                    kind=MetricKind.COUNTER,
                    attributes={
                        "action": action,
                        "status": subscription.status.value,
                    },
                    correlation_id=context.correlation_id,
                    causation_id=subscription.id,
                )
                await self._observability.log(
                    "webhook.subscription.changed",
                    source="phoenix.webhooks",
                    message="webhook subscription administration completed",
                    severity=(
                        Severity.WARNING if action in {"disable", "revoke"} else Severity.INFO
                    ),
                    attributes=details,
                    correlation_id=context.correlation_id,
                    causation_id=subscription.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _increment(self, **changes: int) -> None:
        async with self._lock:
            for name, amount in changes.items():
                attribute = f"_{name}"
                value = getattr(self, attribute) + amount
                if value < 0:
                    raise RuntimeError("webhook manager counter cannot become negative")
                setattr(self, attribute, value)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("webhook manager clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("webhook manager clock must be timezone-aware")
        return value.astimezone(UTC)

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookManagerClosedError("webhook manager is closed")


def webhook_subscription_view_to_dict(view: WebhookSubscriptionView) -> dict[str, object]:
    return {
        "schema_version": view.schema_version,
        "id": str(view.id),
        "name": view.name,
        "display_name": view.display_name,
        "event_types": list(view.event_types),
        "endpoint": {
            "scheme": view.endpoint.scheme,
            "host": view.endpoint.host,
            "port": view.endpoint.port,
            "path_sha256": view.endpoint.path_sha256,
            "loopback_development": view.endpoint.loopback_development,
        },
        "signing": {
            "scheme": view.signing.scheme,
            "key_version": view.signing.key_version,
            "lease_ttl_seconds": view.signing.lease_ttl_seconds,
        },
        "egress_policy": view.egress_policy,
        "retry": {
            "max_attempts": view.retry.max_attempts,
            "initial_delay_seconds": view.retry.initial_delay_seconds,
            "multiplier": view.retry.multiplier,
            "max_delay_seconds": view.retry.max_delay_seconds,
            "jitter_ratio": view.retry.jitter_ratio,
        },
        "resource_filters": {
            event_name: {field_name: list(values) for field_name, values in fields.items()}
            for event_name, fields in view.resource_filters.items()
        },
        "status": view.status.value,
        "created_at": view.created_at.isoformat(),
        "updated_at": view.updated_at.isoformat(),
        "disabled_at": _optional_datetime(view.disabled_at),
        "revoked_at": _optional_datetime(view.revoked_at),
        "revision": view.revision,
    }


def webhook_subscription_view_page_to_dict(
    page: WebhookSubscriptionViewPage,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "items": [webhook_subscription_view_to_dict(item) for item in page.items],
        "page": _page_info_to_dict(page.page),
    }


def webhook_delivery_view_to_dict(view: WebhookDeliveryView) -> dict[str, object]:
    return {
        "schema_version": view.schema_version,
        "id": str(view.id),
        "subscription_id": str(view.subscription_id),
        "event_type": view.event_type,
        "status": view.status.value,
        "occurred_at": view.occurred_at.isoformat(),
        "created_at": view.created_at.isoformat(),
        "updated_at": view.updated_at.isoformat(),
        "source_event_id": None if view.source_event_id is None else str(view.source_event_id),
        "correlation_id": view.correlation_id,
        "attempts": [_attempt_view_to_dict(item) for item in view.attempts],
        "current_attempt": view.current_attempt,
        "in_flight_at": _optional_datetime(view.in_flight_at),
        "next_attempt_at": _optional_datetime(view.next_attempt_at),
        "terminal_at": _optional_datetime(view.terminal_at),
        "redrive_eligible": view.redrive_eligible,
        "revision": view.revision,
    }


def webhook_delivery_view_page_to_dict(page: WebhookDeliveryViewPage) -> dict[str, object]:
    return {
        "schema_version": 1,
        "items": [webhook_delivery_view_to_dict(item) for item in page.items],
        "page": _page_info_to_dict(page.page),
    }


def webhook_manager_snapshot_to_dict(snapshot: WebhookManagerSnapshot) -> dict[str, object]:
    subscriptions = snapshot.subscriptions
    deliveries = snapshot.deliveries
    return {
        "schema_version": 1,
        "closed": snapshot.closed,
        "reads": snapshot.reads,
        "mutations": snapshot.mutations,
        "denied": snapshot.denied,
        "conflicts": snapshot.conflicts,
        "audit_failures": snapshot.audit_failures,
        "observation_failures": snapshot.observation_failures,
        "subscriptions": {
            "closed": subscriptions.closed,
            "subscriptions": subscriptions.subscriptions,
            "active": subscriptions.active,
            "disabled": subscriptions.disabled,
            "revoked": subscriptions.revoked,
            "capacity": subscriptions.capacity,
        },
        "deliveries": {
            "closed": deliveries.closed,
            "deliveries": deliveries.deliveries,
            "pending": deliveries.pending,
            "in_flight": deliveries.in_flight,
            "retrying": deliveries.retrying,
            "succeeded": deliveries.succeeded,
            "failed": deliveries.failed,
            "dead_letter": deliveries.dead_letter,
            "cancelled": deliveries.cancelled,
            "attempts": deliveries.attempts,
            "capacity": deliveries.capacity,
        },
    }


def webhook_redrive_result_to_dict(result: WebhookRedriveResult) -> dict[str, object]:
    return {
        "schema_version": 1,
        "delivery_id": str(result.delivery_id),
        "status": result.status.value,
        "completed_attempts": result.completed_attempts,
        "next_attempt_at": result.next_attempt_at.isoformat(),
        "revision": result.revision,
    }


def _subscription_page(page: WebhookSubscriptionPage) -> WebhookSubscriptionViewPage:
    return WebhookSubscriptionViewPage(
        items=tuple(WebhookSubscriptionView.from_subscription(item) for item in page.items),
        page=page.page,
    )


def _delivery_page(page: WebhookDeliveryPage) -> WebhookDeliveryViewPage:
    return WebhookDeliveryViewPage(
        items=tuple(WebhookDeliveryView.from_delivery(item) for item in page.items),
        page=page.page,
    )


def _attempt_view_to_dict(view: WebhookAttemptView) -> dict[str, object]:
    return {
        "number": view.number,
        "scheduled_at": view.scheduled_at.isoformat(),
        "started_at": view.started_at.isoformat(),
        "finished_at": view.finished_at.isoformat(),
        "outcome": view.outcome.value,
        "status_class": None if view.status_class is None else view.status_class.value,
        "retry_scheduled": view.retry_scheduled,
        "next_attempt_at": _optional_datetime(view.next_attempt_at),
        "error_category": view.error_category,
    }


def _page_info_to_dict(page: WebhookPageInfo) -> dict[str, object]:
    return {
        "offset": page.offset,
        "limit": page.limit,
        "returned": page.returned,
        "total": page.total,
        "next_offset": page.next_offset,
    }


def _freeze_filter_view(
    value: Mapping[str, Mapping[str, tuple[str, ...]]],
) -> Mapping[str, Mapping[str, tuple[str, ...]]]:
    result: dict[str, Mapping[str, tuple[str, ...]]] = {}
    for event_name, fields in value.items():
        result[event_name] = MappingProxyType(
            {field_name: tuple(values) for field_name, values in fields.items()}
        )
    return MappingProxyType(result)


def _require_expected_revision(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("expected_revision must be a positive integer")


def _optional_datetime(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _utc_now() -> datetime:
    return datetime.now(UTC)
