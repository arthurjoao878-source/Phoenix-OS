"""Durable webhook attempt orchestration, retry, audit, and health snapshots."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from phoenix_os.audit import (
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.webhooks.contracts import (
    MAX_WEBHOOK_PAGE_SIZE,
    MAX_WEBHOOK_RETRY_ATTEMPTS,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryRepository,
    WebhookDeliveryStatus,
    WebhookEgressPolicy,
    WebhookHttpStatusClass,
    WebhookPageRequest,
    WebhookSubscription,
    WebhookSubscriptionRepository,
)
from phoenix_os.webhooks.errors import (
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDispatcherClosedError,
    WebhookEndpointRejectedError,
    WebhookSigningError,
    WebhookTransportError,
)
from phoenix_os.webhooks.signing import WebhookSignedRequest
from phoenix_os.webhooks.transport import WebhookTransportResult

DEFAULT_WEBHOOK_DISPATCH_BATCH_SIZE = 50
DEFAULT_WEBHOOK_GLOBAL_CONCURRENCY = 16
DEFAULT_WEBHOOK_PER_ENDPOINT_CONCURRENCY = 4
MAX_WEBHOOK_DISPATCH_BATCH_SIZE = 200
MAX_WEBHOOK_GLOBAL_CONCURRENCY = 1_024
MAX_WEBHOOK_PER_ENDPOINT_CONCURRENCY = 64

type WebhookDispatcherClock = Callable[[], datetime]


class WebhookRequestSigner(Protocol):
    """Sign one immutable delivery using the current subscription revision."""

    async def sign(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription,
        *,
        attempt: int,
        timestamp: datetime | None = None,
    ) -> WebhookSignedRequest: ...


class WebhookRequestTransport(Protocol):
    """Send one already-signed request through a reviewed egress policy."""

    async def send(
        self,
        request: WebhookSignedRequest,
        subscription: WebhookSubscription,
        *,
        policy: WebhookEgressPolicy,
    ) -> WebhookTransportResult: ...


@dataclass(frozen=True, slots=True)
class WebhookDispatcherConfig:
    """Bounded dispatcher scan and concurrency limits."""

    batch_size: int = DEFAULT_WEBHOOK_DISPATCH_BATCH_SIZE
    global_concurrency: int = DEFAULT_WEBHOOK_GLOBAL_CONCURRENCY
    per_endpoint_concurrency: int = DEFAULT_WEBHOOK_PER_ENDPOINT_CONCURRENCY

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (
                self.batch_size,
                self.global_concurrency,
                self.per_endpoint_concurrency,
            )
        ):
            raise TypeError("webhook dispatcher limits must be integers")
        if not 1 <= self.batch_size <= MAX_WEBHOOK_DISPATCH_BATCH_SIZE:
            raise ValueError("webhook dispatcher batch size is outside supported bounds")
        if not 1 <= self.global_concurrency <= MAX_WEBHOOK_GLOBAL_CONCURRENCY:
            raise ValueError("webhook dispatcher global concurrency is outside supported bounds")
        if not 1 <= self.per_endpoint_concurrency <= MAX_WEBHOOK_PER_ENDPOINT_CONCURRENCY:
            raise ValueError(
                "webhook dispatcher per-endpoint concurrency is outside supported bounds"
            )
        if self.per_endpoint_concurrency > self.global_concurrency:
            raise ValueError(
                "webhook dispatcher per-endpoint concurrency cannot exceed global concurrency"
            )


class WebhookDispatchDisposition(StrEnum):
    """Safe outcome from one dispatcher decision."""

    SKIPPED = "skipped"
    CONFLICT = "conflict"
    SUCCEEDED = "succeeded"
    RETRYING = "retrying"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class WebhookDispatchResult:
    """Bounded non-sensitive outcome from one delivery dispatch decision."""

    delivery_id: UUID
    disposition: WebhookDispatchDisposition
    status: WebhookDeliveryStatus
    attempt: int | None = None
    status_class: WebhookHttpStatusClass | None = None
    error_category: str | None = None
    next_attempt_at: datetime | None = None

    def __post_init__(self) -> None:
        disposition = WebhookDispatchDisposition(self.disposition)
        status = WebhookDeliveryStatus(self.status)
        status_class = self.status_class
        if status_class is not None:
            status_class = WebhookHttpStatusClass(status_class)
        if self.attempt is not None and not 1 <= self.attempt <= MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook dispatch result attempt is outside supported bounds")
        if self.next_attempt_at is not None:
            _require_aware(self.next_attempt_at, "webhook dispatch next_attempt_at")
        error_category = self.error_category
        if error_category is not None:
            error_category = _normalize_error_category(error_category)
        expected_statuses = {
            WebhookDispatchDisposition.SUCCEEDED: WebhookDeliveryStatus.SUCCEEDED,
            WebhookDispatchDisposition.RETRYING: WebhookDeliveryStatus.RETRYING,
            WebhookDispatchDisposition.FAILED: WebhookDeliveryStatus.FAILED,
            WebhookDispatchDisposition.DEAD_LETTER: WebhookDeliveryStatus.DEAD_LETTER,
            WebhookDispatchDisposition.CANCELLED: WebhookDeliveryStatus.CANCELLED,
        }
        expected_status = expected_statuses.get(disposition)
        if expected_status is not None and status is not expected_status:
            raise ValueError("webhook dispatch result disposition and status are inconsistent")
        if disposition is WebhookDispatchDisposition.RETRYING:
            if self.next_attempt_at is None:
                raise ValueError("retrying webhook dispatch result is inconsistent")
        elif self.next_attempt_at is not None:
            raise ValueError("non-retrying webhook dispatch result cannot schedule another attempt")
        if disposition is WebhookDispatchDisposition.SUCCEEDED:
            if status_class is not WebhookHttpStatusClass.SUCCESSFUL:
                raise ValueError("successful webhook dispatch result requires a 2xx status class")
            if self.error_category is not None:
                raise ValueError("successful webhook dispatch result cannot contain an error")
        elif (
            disposition
            not in {
                WebhookDispatchDisposition.SKIPPED,
                WebhookDispatchDisposition.CONFLICT,
            }
            and self.error_category is None
        ):
            raise ValueError("failed webhook dispatch result requires an error category")
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "status_class", status_class)
        object.__setattr__(self, "error_category", error_category)


@dataclass(frozen=True, slots=True)
class WebhookDispatchBatch:
    """Deterministically ordered outcomes from one due-delivery scan."""

    results: tuple[WebhookDispatchResult, ...]

    @property
    def considered(self) -> int:
        return len(self.results)

    def count(self, disposition: WebhookDispatchDisposition) -> int:
        return sum(item.disposition is disposition for item in self.results)


@dataclass(frozen=True, slots=True)
class WebhookDispatcherSnapshot:
    """Safe bounded dispatcher and durable-delivery health facts."""

    closed: bool
    batches: int
    considered: int
    claimed: int
    succeeded: int
    retrying: int
    failed: int
    dead_letter: int
    cancelled: int
    conflicts: int
    skipped: int
    endpoint_rejections: int
    signing_failures: int
    transport_failures: int
    saturation_events: int
    audit_failures: int
    observation_failures: int
    active: int
    endpoint_lanes: int
    global_limit: int
    per_endpoint_limit: int
    pending_deliveries: int
    retrying_deliveries: int
    in_flight_deliveries: int

    def __post_init__(self) -> None:
        counters = (
            self.batches,
            self.considered,
            self.claimed,
            self.succeeded,
            self.retrying,
            self.failed,
            self.dead_letter,
            self.cancelled,
            self.conflicts,
            self.skipped,
            self.endpoint_rejections,
            self.signing_failures,
            self.transport_failures,
            self.saturation_events,
            self.audit_failures,
            self.observation_failures,
            self.active,
            self.endpoint_lanes,
            self.pending_deliveries,
            self.retrying_deliveries,
            self.in_flight_deliveries,
        )
        if any(value < 0 for value in counters):
            raise ValueError("webhook dispatcher snapshot counters cannot be negative")
        if not 1 <= self.global_limit <= MAX_WEBHOOK_GLOBAL_CONCURRENCY:
            raise ValueError("webhook dispatcher snapshot global limit is invalid")
        if not 1 <= self.per_endpoint_limit <= MAX_WEBHOOK_PER_ENDPOINT_CONCURRENCY:
            raise ValueError("webhook dispatcher snapshot endpoint limit is invalid")
        if self.active > self.global_limit:
            raise ValueError("webhook dispatcher snapshot active count exceeds its limit")


class WebhookDispatcher:
    """Claim, sign, send, classify, and durably complete webhook attempts."""

    def __init__(
        self,
        *,
        subscriptions: WebhookSubscriptionRepository,
        deliveries: WebhookDeliveryRepository,
        signer: WebhookRequestSigner,
        transport: WebhookRequestTransport,
        egress_policies: Mapping[str, WebhookEgressPolicy],
        config: WebhookDispatcherConfig | None = None,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        clock: WebhookDispatcherClock | None = None,
    ) -> None:
        if not callable(getattr(signer, "sign", None)):
            raise TypeError("webhook dispatcher signer must expose sign")
        if not callable(getattr(transport, "send", None)):
            raise TypeError("webhook dispatcher transport must expose send")
        resolved_config = WebhookDispatcherConfig() if config is None else config
        if not isinstance(resolved_config, WebhookDispatcherConfig):
            raise TypeError("webhook dispatcher config must be WebhookDispatcherConfig")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("webhook dispatcher audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("webhook dispatcher observability must be ObservabilityHub")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("webhook dispatcher clock must be callable")

        policies: dict[str, WebhookEgressPolicy] = {}
        for name, policy in egress_policies.items():
            if not isinstance(name, str) or not isinstance(policy, WebhookEgressPolicy):
                raise TypeError("webhook dispatcher egress policies are invalid")
            if name != policy.name:
                raise ValueError("webhook dispatcher egress policy key must match policy name")
            if name in policies:
                raise ValueError("webhook dispatcher egress policies must be unique")
            policies[name] = policy

        self._subscriptions = subscriptions
        self._deliveries = deliveries
        self._signer = signer
        self._transport = transport
        self._policies = MappingProxyType(policies)
        self._config = resolved_config
        self._audit = audit
        self._observability = observability
        self._clock = resolved_clock
        self._global_lane = asyncio.Semaphore(resolved_config.global_concurrency)
        self._endpoint_lanes: dict[str, asyncio.Semaphore] = {}
        self._lane_lock = asyncio.Lock()
        self._counter_lock = asyncio.Lock()
        self._closed = False
        self._batches = 0
        self._considered = 0
        self._claimed = 0
        self._succeeded = 0
        self._retrying = 0
        self._failed = 0
        self._dead_letter = 0
        self._cancelled = 0
        self._conflicts = 0
        self._skipped = 0
        self._endpoint_rejections = 0
        self._signing_failures = 0
        self._transport_failures = 0
        self._saturation_events = 0
        self._audit_failures = 0
        self._observation_failures = 0
        self._active = 0

    @property
    def closed(self) -> bool:
        return self._closed

    async def dispatch_due(self, *, limit: int | None = None) -> WebhookDispatchBatch:
        """Dispatch one bounded, deterministically ordered batch of due deliveries."""

        self._ensure_open()
        resolved_limit = self._config.batch_size if limit is None else limit
        if type(resolved_limit) is not int:
            raise TypeError("webhook dispatch limit must be an integer")
        if not 1 <= resolved_limit <= MAX_WEBHOOK_DISPATCH_BATCH_SIZE:
            raise ValueError("webhook dispatch limit is outside supported bounds")
        due = await self._due_deliveries(self._now(), resolved_limit)
        if not due:
            await self._increment(batches=1)
            return WebhookDispatchBatch(())
        results = await asyncio.gather(*(self.dispatch(item.id) for item in due))
        await self._increment(batches=1)
        return WebhookDispatchBatch(tuple(results))

    async def dispatch(self, delivery_id: UUID) -> WebhookDispatchResult:
        """Attempt one due delivery while enforcing all concurrency and lifecycle guards."""

        self._ensure_open()
        if not isinstance(delivery_id, UUID):
            raise TypeError("webhook delivery id must be UUID")
        await self._increment(considered=1)
        current = await self._deliveries.get(delivery_id)
        if current is None:
            raise WebhookDeliveryNotFoundError("webhook delivery was not found")
        now = self._now()
        if not _is_due(current, now):
            return await self._skipped_result(current)

        subscription = await self._subscriptions.get(current.subscription_id)
        if subscription is None:
            return await self._cancel(current, now, "subscription_missing")
        if not subscription.deliverable:
            return await self._cancel(current, now, "subscription_inactive")

        endpoint_lane = await self._endpoint_lane(subscription.endpoint.url)
        if self._global_lane.locked() or endpoint_lane.locked():
            await self._increment(saturation_events=1)
            await self._observe_saturation(subscription, current)

        async with endpoint_lane, self._global_lane:
            await self._increment(active=1)
            try:
                return await self._dispatch_claimed(
                    delivery_id,
                    endpoint=subscription.endpoint.url,
                )
            finally:
                await self._increment(active=-1)

    async def snapshot(self) -> WebhookDispatcherSnapshot:
        repository = await self._deliveries.snapshot()
        async with self._counter_lock:
            return WebhookDispatcherSnapshot(
                closed=self._closed,
                batches=self._batches,
                considered=self._considered,
                claimed=self._claimed,
                succeeded=self._succeeded,
                retrying=self._retrying,
                failed=self._failed,
                dead_letter=self._dead_letter,
                cancelled=self._cancelled,
                conflicts=self._conflicts,
                skipped=self._skipped,
                endpoint_rejections=self._endpoint_rejections,
                signing_failures=self._signing_failures,
                transport_failures=self._transport_failures,
                saturation_events=self._saturation_events,
                audit_failures=self._audit_failures,
                observation_failures=self._observation_failures,
                active=self._active,
                endpoint_lanes=len(self._endpoint_lanes),
                global_limit=self._config.global_concurrency,
                per_endpoint_limit=self._config.per_endpoint_concurrency,
                pending_deliveries=repository.pending,
                retrying_deliveries=repository.retrying,
                in_flight_deliveries=repository.in_flight,
            )

    async def close(self) -> None:
        async with self._counter_lock:
            self._closed = True

    async def _dispatch_claimed(
        self,
        delivery_id: UUID,
        *,
        endpoint: str,
    ) -> WebhookDispatchResult:
        now = self._now()
        current = await self._deliveries.get(delivery_id)
        if current is None:
            raise WebhookDeliveryNotFoundError("webhook delivery was not found")
        if not _is_due(current, now):
            return await self._skipped_result(current)

        subscription = await self._subscriptions.get(current.subscription_id)
        if subscription is None:
            return await self._cancel(current, now, "subscription_missing")
        if not subscription.deliverable:
            return await self._cancel(current, now, "subscription_inactive")
        if subscription.endpoint.url != endpoint:
            return await self._conflict_result(current)

        scheduled_at = current.next_attempt_at
        if scheduled_at is None:  # pragma: no cover - protected by _is_due
            raise RuntimeError("due webhook delivery lost its schedule")
        attempt_number = current.completed_attempts + 1
        started_at = max(now, current.updated_at, scheduled_at)
        claimed = replace(
            current,
            status=WebhookDeliveryStatus.IN_FLIGHT,
            updated_at=started_at,
            current_attempt=attempt_number,
            in_flight_at=started_at,
            next_attempt_at=None,
            terminal_at=None,
            revision=current.revision + 1,
        )
        try:
            claimed = await self._deliveries.replace(
                claimed,
                expected_revision=current.revision,
            )
        except WebhookDeliveryConflictError:
            return await self._conflict_result(current)
        await self._increment(claimed=1)

        subscription = await self._subscriptions.get(claimed.subscription_id)
        if subscription is None:
            return await self._cancel(
                claimed, self._now_not_before(started_at), "subscription_missing"
            )
        if not subscription.deliverable:
            return await self._cancel(
                claimed,
                self._now_not_before(started_at),
                "subscription_inactive",
            )
        if subscription.endpoint.url != endpoint:
            return await self._complete_failure(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                status_class=None,
                category="subscription_changed",
                retryable=True,
            )

        policy = self._policies.get(subscription.egress_policy)
        if policy is None:
            return await self._complete_failure(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                status_class=None,
                category="egress_policy_missing",
                retryable=False,
            )

        try:
            signed = await self._signer.sign(
                claimed,
                subscription,
                attempt=attempt_number,
            )
            transport_result = await self._transport.send(
                signed,
                subscription,
                policy=policy,
            )
        except asyncio.CancelledError:
            try:
                await asyncio.shield(
                    self._complete_failure(
                        claimed,
                        subscription,
                        scheduled_at=scheduled_at,
                        started_at=started_at,
                        status_class=None,
                        category="attempt_cancelled",
                        retryable=True,
                    )
                )
            finally:
                raise
        except WebhookEndpointRejectedError as exception:
            await self._increment(endpoint_rejections=1)
            return await self._complete_failure(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                status_class=None,
                category=exception.category,
                retryable=False,
            )
        except WebhookSigningError:
            await self._increment(signing_failures=1)
            return await self._complete_failure(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                status_class=None,
                category="signing_failed",
                retryable=True,
            )
        except WebhookTransportError as exception:
            await self._increment(transport_failures=1)
            return await self._complete_failure(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                status_class=None,
                category=exception.category,
                retryable=exception.retryable,
            )
        except Exception:
            await self._increment(transport_failures=1)
            return await self._complete_failure(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                status_class=None,
                category="dispatcher_failed",
                retryable=True,
            )

        if transport_result.successful:
            return await self._complete_success(
                claimed,
                subscription,
                scheduled_at=scheduled_at,
                started_at=started_at,
                result=transport_result,
            )
        category = transport_result.error_category
        if category is None:  # pragma: no cover - transport result invariant
            category = "transport_failed"
        return await self._complete_failure(
            claimed,
            subscription,
            scheduled_at=scheduled_at,
            started_at=started_at,
            status_class=transport_result.status_class,
            category=category,
            retryable=transport_result.retryable,
        )

    async def _complete_success(
        self,
        claimed: WebhookDelivery,
        subscription: WebhookSubscription,
        *,
        scheduled_at: datetime,
        started_at: datetime,
        result: WebhookTransportResult,
    ) -> WebhookDispatchResult:
        finished_at = self._now_not_before(started_at)
        attempt = WebhookAttempt(
            delivery_id=claimed.id,
            number=claimed.current_attempt or claimed.completed_attempts + 1,
            scheduled_at=scheduled_at,
            started_at=started_at,
            finished_at=finished_at,
            outcome=WebhookAttemptOutcome.SUCCEEDED,
            status_class=result.status_class,
        )
        completed = replace(
            claimed,
            status=WebhookDeliveryStatus.SUCCEEDED,
            updated_at=finished_at,
            attempts=(*claimed.attempts, attempt),
            current_attempt=None,
            in_flight_at=None,
            next_attempt_at=None,
            terminal_at=finished_at,
            revision=claimed.revision + 1,
        )
        completed = await self._deliveries.replace(completed, expected_revision=claimed.revision)
        dispatch_result = WebhookDispatchResult(
            delivery_id=completed.id,
            disposition=WebhookDispatchDisposition.SUCCEEDED,
            status=completed.status,
            attempt=attempt.number,
            status_class=result.status_class,
        )
        await self._increment(succeeded=1)
        await self._signal_attempt(completed, subscription, attempt, dispatch_result)
        return dispatch_result

    async def _complete_failure(
        self,
        claimed: WebhookDelivery,
        subscription: WebhookSubscription,
        *,
        scheduled_at: datetime,
        started_at: datetime,
        status_class: WebhookHttpStatusClass | None,
        category: str,
        retryable: bool,
    ) -> WebhookDispatchResult:
        finished_at = self._now_not_before(started_at)
        attempt_number = claimed.current_attempt or claimed.completed_attempts + 1
        retry_scheduled = (
            retryable
            and attempt_number < subscription.retry.max_attempts
            and attempt_number < MAX_WEBHOOK_RETRY_ATTEMPTS
        )
        next_attempt_at: datetime | None = None
        if retry_scheduled:
            delay = webhook_retry_delay(claimed, subscription, attempt_number)
            next_attempt_at = finished_at + delay
            status = WebhookDeliveryStatus.RETRYING
            disposition = WebhookDispatchDisposition.RETRYING
            outcome = WebhookAttemptOutcome.RETRYABLE_FAILURE
        elif retryable:
            status = WebhookDeliveryStatus.DEAD_LETTER
            disposition = WebhookDispatchDisposition.DEAD_LETTER
            outcome = WebhookAttemptOutcome.RETRYABLE_FAILURE
        else:
            status = WebhookDeliveryStatus.FAILED
            disposition = WebhookDispatchDisposition.FAILED
            outcome = WebhookAttemptOutcome.TERMINAL_FAILURE

        attempt = WebhookAttempt(
            delivery_id=claimed.id,
            number=attempt_number,
            scheduled_at=scheduled_at,
            started_at=started_at,
            finished_at=finished_at,
            outcome=outcome,
            status_class=status_class,
            retry_scheduled=retry_scheduled,
            next_attempt_at=next_attempt_at,
            error_category=category,
        )
        completed = replace(
            claimed,
            status=status,
            updated_at=finished_at,
            attempts=(*claimed.attempts, attempt),
            current_attempt=None,
            in_flight_at=None,
            next_attempt_at=next_attempt_at,
            terminal_at=None if retry_scheduled else finished_at,
            revision=claimed.revision + 1,
        )
        completed = await self._deliveries.replace(completed, expected_revision=claimed.revision)
        dispatch_result = WebhookDispatchResult(
            delivery_id=completed.id,
            disposition=disposition,
            status=completed.status,
            attempt=attempt.number,
            status_class=status_class,
            error_category=category,
            next_attempt_at=next_attempt_at,
        )
        if disposition is WebhookDispatchDisposition.RETRYING:
            await self._increment(retrying=1)
        elif disposition is WebhookDispatchDisposition.DEAD_LETTER:
            await self._increment(dead_letter=1)
        else:
            await self._increment(failed=1)
        await self._signal_attempt(completed, subscription, attempt, dispatch_result)
        return dispatch_result

    async def _cancel(
        self,
        current: WebhookDelivery,
        now: datetime,
        category: str,
    ) -> WebhookDispatchResult:
        if current.status.terminal:
            return await self._skipped_result(current)
        cancelled = replace(
            current,
            status=WebhookDeliveryStatus.CANCELLED,
            updated_at=max(now, current.updated_at),
            current_attempt=None,
            in_flight_at=None,
            next_attempt_at=None,
            terminal_at=max(now, current.updated_at),
            revision=current.revision + 1,
        )
        try:
            cancelled = await self._deliveries.replace(
                cancelled,
                expected_revision=current.revision,
            )
        except WebhookDeliveryConflictError:
            return await self._conflict_result(current)
        result = WebhookDispatchResult(
            delivery_id=cancelled.id,
            disposition=WebhookDispatchDisposition.CANCELLED,
            status=cancelled.status,
            error_category=category,
        )
        await self._increment(cancelled=1)
        await self._signal_cancelled(cancelled, category)
        return result

    async def _due_deliveries(
        self,
        now: datetime,
        limit: int,
    ) -> tuple[WebhookDelivery, ...]:
        due: list[WebhookDelivery] = []
        request = WebhookPageRequest(limit=MAX_WEBHOOK_PAGE_SIZE)
        while True:
            page = await self._deliveries.list(request)
            due.extend(item for item in page.items if _is_due(item, now))
            next_offset = page.page.next_offset
            if next_offset is None:
                break
            request = WebhookPageRequest(
                offset=next_offset,
                limit=MAX_WEBHOOK_PAGE_SIZE,
            )
        ordered = sorted(
            due,
            key=lambda item: (
                item.next_attempt_at or item.created_at,
                item.created_at,
                item.id.hex,
            ),
        )
        return tuple(ordered[:limit])

    async def _endpoint_lane(self, endpoint: str) -> asyncio.Semaphore:
        async with self._lane_lock:
            lane = self._endpoint_lanes.get(endpoint)
            if lane is None:
                lane = asyncio.Semaphore(self._config.per_endpoint_concurrency)
                self._endpoint_lanes[endpoint] = lane
            return lane

    async def _skipped_result(self, delivery: WebhookDelivery) -> WebhookDispatchResult:
        await self._increment(skipped=1)
        return WebhookDispatchResult(
            delivery_id=delivery.id,
            disposition=WebhookDispatchDisposition.SKIPPED,
            status=delivery.status,
        )

    async def _conflict_result(self, delivery: WebhookDelivery) -> WebhookDispatchResult:
        await self._increment(conflicts=1)
        return WebhookDispatchResult(
            delivery_id=delivery.id,
            disposition=WebhookDispatchDisposition.CONFLICT,
            status=delivery.status,
        )

    async def _signal_attempt(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription,
        attempt: WebhookAttempt,
        result: WebhookDispatchResult,
    ) -> None:
        details: dict[str, object] = {
            "delivery_id": str(delivery.id),
            "subscription_id": str(subscription.id),
            "event_type": delivery.event_type,
            "attempt": attempt.number,
            "status": delivery.status.value,
            "outcome": attempt.outcome.value,
            "retry_scheduled": attempt.retry_scheduled,
            "egress_policy": subscription.egress_policy,
            "key_version": subscription.signing.key_version,
        }
        if attempt.status_class is not None:
            details["status_class"] = attempt.status_class.value
        if attempt.error_category is not None:
            details["error_category"] = attempt.error_category

        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name="webhook.delivery.attempted",
                        source="phoenix.webhooks",
                        category=AuditCategory.OTHER,
                        action="webhook.delivery.attempt",
                        resource=f"webhook-delivery:{delivery.id}",
                        actor="phoenix.webhooks",
                        outcome=(
                            AuditOutcome.SUCCEEDED
                            if attempt.outcome is WebhookAttemptOutcome.SUCCEEDED
                            else AuditOutcome.FAILED
                        ),
                        severity=_audit_severity(result.disposition),
                        details=details,
                        correlation_id=delivery.correlation_id,
                        causation_id=delivery.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)

        if self._observability is not None:
            try:
                duration_ms = max(
                    0.0,
                    (attempt.finished_at - attempt.started_at).total_seconds() * 1_000,
                )
                await self._observability.metric(
                    "webhook.delivery.attempts",
                    1,
                    source="phoenix.webhooks",
                    kind=MetricKind.COUNTER,
                    attributes=details,
                    correlation_id=delivery.correlation_id,
                    causation_id=delivery.id,
                )
                await self._observability.metric(
                    "webhook.delivery.duration",
                    duration_ms,
                    source="phoenix.webhooks",
                    kind=MetricKind.GAUGE,
                    unit="ms",
                    attributes={
                        "status": delivery.status.value,
                        "outcome": attempt.outcome.value,
                    },
                    correlation_id=delivery.correlation_id,
                    causation_id=delivery.id,
                )
                await self._observability.log(
                    "webhook.delivery.completed",
                    source="phoenix.webhooks",
                    message="webhook delivery attempt completed",
                    severity=_observation_severity(result.disposition),
                    attributes=details,
                    correlation_id=delivery.correlation_id,
                    causation_id=delivery.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _signal_cancelled(self, delivery: WebhookDelivery, category: str) -> None:
        details: dict[str, object] = {
            "delivery_id": str(delivery.id),
            "subscription_id": str(delivery.subscription_id),
            "event_type": delivery.event_type,
            "status": delivery.status.value,
            "error_category": category,
        }
        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name="webhook.delivery.cancelled",
                        source="phoenix.webhooks",
                        category=AuditCategory.OTHER,
                        action="webhook.delivery.cancel",
                        resource=f"webhook-delivery:{delivery.id}",
                        actor="phoenix.webhooks",
                        outcome=AuditOutcome.RESTRICTED,
                        severity=AuditSeverity.WARNING,
                        details=details,
                        correlation_id=delivery.correlation_id,
                        causation_id=delivery.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)
        if self._observability is not None:
            try:
                await self._observability.metric(
                    "webhook.delivery.cancelled",
                    1,
                    source="phoenix.webhooks",
                    kind=MetricKind.COUNTER,
                    attributes=details,
                    correlation_id=delivery.correlation_id,
                    causation_id=delivery.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _observe_saturation(
        self,
        subscription: WebhookSubscription,
        delivery: WebhookDelivery,
    ) -> None:
        if self._observability is None:
            return
        try:
            await self._observability.metric(
                "webhook.dispatcher.saturation",
                1,
                source="phoenix.webhooks",
                kind=MetricKind.COUNTER,
                attributes={
                    "egress_policy": subscription.egress_policy,
                    "global_limit": self._config.global_concurrency,
                    "per_endpoint_limit": self._config.per_endpoint_concurrency,
                },
                correlation_id=delivery.correlation_id,
                causation_id=delivery.id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._increment(observation_failures=1)

    async def _increment(self, **changes: int) -> None:
        async with self._counter_lock:
            for name, amount in changes.items():
                attribute = f"_{name}"
                current = getattr(self, attribute)
                updated = current + amount
                if updated < 0:
                    raise RuntimeError("webhook dispatcher counter cannot become negative")
                setattr(self, attribute, updated)

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime):
            raise TypeError("webhook dispatcher clock must return datetime")
        _require_aware(now, "webhook dispatcher clock")
        return now.astimezone(UTC)

    def _now_not_before(self, minimum: datetime) -> datetime:
        return max(self._now(), minimum)

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookDispatcherClosedError("webhook dispatcher is closed")


def webhook_retry_delay(
    delivery: WebhookDelivery,
    subscription: WebhookSubscription,
    completed_attempts: int,
) -> timedelta:
    """Return deterministic bounded retry delay with non-secret stable jitter."""

    if delivery.subscription_id != subscription.id:
        raise ValueError("webhook delivery belongs to another subscription")
    base = subscription.retry.base_delay_after(completed_attempts)
    base_microseconds = max(1, round(base.total_seconds() * 1_000_000))
    maximum_microseconds = max(
        1,
        round(subscription.retry.max_delay.total_seconds() * 1_000_000),
    )
    span = round(base_microseconds * subscription.retry.jitter_ratio)
    if span <= 0:
        return timedelta(microseconds=min(base_microseconds, maximum_microseconds))
    seed = hashlib.sha256(
        b"\n".join(
            (
                b"phoenix-webhook-retry-v1",
                str(delivery.id).encode("ascii"),
                str(completed_attempts).encode("ascii"),
                delivery.body_sha256.encode("ascii"),
            )
        )
    ).digest()
    offset = int.from_bytes(seed[:8], "big") % (2 * span + 1) - span
    jittered = max(1, min(maximum_microseconds, base_microseconds + offset))
    return timedelta(microseconds=jittered)


def _is_due(delivery: WebhookDelivery, now: datetime) -> bool:
    return (
        delivery.status.schedulable
        and delivery.next_attempt_at is not None
        and delivery.next_attempt_at <= now
    )


def _normalize_error_category(value: str) -> str:
    normalized = value.strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if (
        not normalized
        or len(normalized) > 64
        or not normalized[0].isalpha()
        or any(character not in allowed for character in normalized)
    ):
        raise ValueError("webhook dispatch error category contains unsupported characters")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")


def _audit_severity(disposition: WebhookDispatchDisposition) -> AuditSeverity:
    if disposition is WebhookDispatchDisposition.SUCCEEDED:
        return AuditSeverity.INFO
    if disposition is WebhookDispatchDisposition.RETRYING:
        return AuditSeverity.WARNING
    return AuditSeverity.ERROR


def _observation_severity(disposition: WebhookDispatchDisposition) -> Severity:
    if disposition is WebhookDispatchDisposition.SUCCEEDED:
        return Severity.INFO
    if disposition is WebhookDispatchDisposition.RETRYING:
        return Severity.WARNING
    return Severity.ERROR


def _utc_now() -> datetime:
    return datetime.now(UTC)
