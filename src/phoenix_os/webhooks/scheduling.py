"""Durable Event Bus selection and scheduling for webhook deliveries."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from phoenix_os.events import BusClosedError, Event, EventBus, Subscription
from phoenix_os.webhooks.contracts import (
    MAX_WEBHOOK_PAGE_SIZE,
    WebhookDelivery,
    WebhookDeliveryRepository,
    WebhookEventType,
    WebhookPageRequest,
    WebhookPayload,
    WebhookSubscription,
    WebhookSubscriptionRepository,
)
from phoenix_os.webhooks.envelope import (
    new_webhook_delivery,
    webhook_delivery_deduplication_key,
)
from phoenix_os.webhooks.errors import (
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliverySchedulerClosedError,
    WebhookEventAdapterStateError,
    WebhookEventNotFoundError,
)
from phoenix_os.webhooks.registry import WebhookEventRegistry

type WebhookClock = Callable[[], datetime]

_MISSING = object()


@dataclass(frozen=True, slots=True)
class WebhookScheduleResult:
    """Deterministic outcome from scheduling one registered Event Bus event."""

    event_id: UUID
    event_type: str
    considered: int
    matched: int
    filtered: int
    duplicates: int
    deliveries: tuple[WebhookDelivery, ...]

    def __post_init__(self) -> None:
        event_type = WebhookEventType(self.event_type).name
        counts = (self.considered, self.matched, self.filtered, self.duplicates)
        if any(value < 0 for value in counts):
            raise ValueError("webhook schedule counters cannot be negative")
        if self.considered != self.matched + self.filtered:
            raise ValueError("webhook schedule considered count is inconsistent")
        if self.matched != len(self.deliveries) + self.duplicates:
            raise ValueError("webhook schedule matched count is inconsistent")
        for delivery in self.deliveries:
            if delivery.source_event_id != self.event_id:
                raise ValueError("scheduled webhook delivery belongs to another event")
            if delivery.event_type != event_type:
                raise ValueError("scheduled webhook delivery has another event type")
        object.__setattr__(self, "event_type", event_type)

    @property
    def scheduled(self) -> int:
        return len(self.deliveries)


@dataclass(frozen=True, slots=True)
class WebhookEventAdapterSnapshot:
    """Safe bounded counters for the Event Bus webhook adapter."""

    started: bool
    processed: int
    ignored: int
    failures: int
    considered: int
    filtered: int
    duplicates: int
    scheduled: int

    def __post_init__(self) -> None:
        counts = (
            self.processed,
            self.ignored,
            self.failures,
            self.considered,
            self.filtered,
            self.duplicates,
            self.scheduled,
        )
        if any(value < 0 for value in counts):
            raise ValueError("webhook event adapter counters cannot be negative")
        if self.filtered > self.considered:
            raise ValueError("webhook event adapter filter count is inconsistent")


class WebhookDeliveryScheduler:
    """Create at most one durable delivery per subscription and source event."""

    def __init__(
        self,
        *,
        registry: WebhookEventRegistry,
        subscriptions: WebhookSubscriptionRepository,
        deliveries: WebhookDeliveryRepository,
        clock: WebhookClock | None = None,
    ) -> None:
        if not isinstance(registry, WebhookEventRegistry):
            raise TypeError("registry must be WebhookEventRegistry")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("webhook scheduler clock must be callable")

        self._registry = registry
        self._subscriptions = subscriptions
        self._deliveries = deliveries
        self._clock = resolved_clock
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def schedule(self, event: Event) -> WebhookScheduleResult:
        if not isinstance(event, Event):
            raise TypeError("event must be Event")

        async with self._lock:
            self._ensure_open()
            event_type = await self._registry.describe(event.name)
            candidates = await self._matching_subscriptions(event_type.name)
            if not candidates:
                return WebhookScheduleResult(
                    event_id=event.id,
                    event_type=event_type.name,
                    considered=0,
                    matched=0,
                    filtered=0,
                    duplicates=0,
                    deliveries=(),
                )

            payload = await self._registry.serialize(event)
            created_at = self._now()
            scheduled: list[WebhookDelivery] = []
            filtered = 0
            duplicates = 0

            for subscription in candidates:
                if not _matches_resource_filters(subscription, payload):
                    filtered += 1
                    continue

                deduplication_key = webhook_delivery_deduplication_key(
                    subscription.id,
                    event.id,
                )
                existing = await self._deliveries.get_by_deduplication_key(deduplication_key)
                if existing is not None:
                    duplicates += 1
                    continue

                delivery = new_webhook_delivery(
                    subscription,
                    event,
                    payload,
                    created_at=created_at,
                )
                try:
                    await self._deliveries.add(delivery)
                except WebhookDeliveryAlreadyExistsError:
                    existing = await self._deliveries.get_by_deduplication_key(deduplication_key)
                    if existing is None:
                        raise
                    duplicates += 1
                else:
                    scheduled.append(delivery)

            matched = len(scheduled) + duplicates
            return WebhookScheduleResult(
                event_id=event.id,
                event_type=event_type.name,
                considered=len(candidates),
                matched=matched,
                filtered=filtered,
                duplicates=duplicates,
                deliveries=tuple(scheduled),
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _matching_subscriptions(
        self,
        event_type: str,
    ) -> tuple[WebhookSubscription, ...]:
        result: list[WebhookSubscription] = []
        request = WebhookPageRequest(limit=MAX_WEBHOOK_PAGE_SIZE)

        while True:
            page = await self._subscriptions.list(request)
            for subscription in page.items:
                if not subscription.deliverable or event_type not in subscription.event_types:
                    continue
                await self._registry.validate_subscription(subscription)
                result.append(subscription)
            next_offset = page.page.next_offset
            if next_offset is None:
                return tuple(result)
            request = WebhookPageRequest(
                offset=next_offset,
                limit=MAX_WEBHOOK_PAGE_SIZE,
            )

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime):
            raise TypeError("webhook scheduler clock must return datetime")
        if now.tzinfo is None:
            raise ValueError("webhook scheduler clock must return an aware datetime")
        return now.astimezone(UTC)

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookDeliverySchedulerClosedError("webhook delivery scheduler is closed")


class WebhookEventAdapter:
    """Runtime lifecycle adapter from the Event Bus to durable scheduling."""

    def __init__(
        self,
        *,
        events: EventBus,
        scheduler: WebhookDeliveryScheduler,
        priority: int = -50,
    ) -> None:
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if not isinstance(scheduler, WebhookDeliveryScheduler):
            raise TypeError("scheduler must be WebhookDeliveryScheduler")
        if type(priority) is not int:
            raise TypeError("webhook event adapter priority must be an integer")

        self._events = events
        self._scheduler = scheduler
        self._priority = priority
        self._subscription: Subscription | None = None
        self._processed = 0
        self._ignored = 0
        self._failures = 0
        self._considered = 0
        self._filtered = 0
        self._duplicates = 0
        self._scheduled = 0
        self._lock = asyncio.Lock()

    async def start(self, context: object) -> None:
        del context
        async with self._lock:
            if self._subscription is not None:
                raise WebhookEventAdapterStateError("webhook event adapter is already started")
            if self._scheduler.closed:
                raise WebhookEventAdapterStateError("webhook event adapter scheduler is closed")
            self._subscription = await self._events.subscribe(
                "*",
                self._handle,
                priority=self._priority,
            )

    async def stop(self, context: object) -> None:
        del context
        async with self._lock:
            subscription = self._subscription
            self._subscription = None
        if subscription is not None:
            try:
                await self._events.unsubscribe(subscription)
            except BusClosedError:
                pass

    async def snapshot(self) -> WebhookEventAdapterSnapshot:
        async with self._lock:
            return WebhookEventAdapterSnapshot(
                started=self._subscription is not None,
                processed=self._processed,
                ignored=self._ignored,
                failures=self._failures,
                considered=self._considered,
                filtered=self._filtered,
                duplicates=self._duplicates,
                scheduled=self._scheduled,
            )

    async def _handle(self, event: Event) -> None:
        try:
            result = await self._scheduler.schedule(event)
        except WebhookEventNotFoundError:
            async with self._lock:
                self._ignored += 1
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            async with self._lock:
                self._failures += 1
            raise

        async with self._lock:
            self._processed += 1
            self._considered += result.considered
            self._filtered += result.filtered
            self._duplicates += result.duplicates
            self._scheduled += result.scheduled


def _matches_resource_filters(
    subscription: WebhookSubscription,
    payload: WebhookPayload,
) -> bool:
    filters = subscription.resource_filters.get(payload.event_type.name)
    if not filters:
        return True

    for field_name, allowed_values in filters.items():
        actual_values = _filter_values(payload.data.get(field_name, _MISSING))
        if actual_values is None or allowed_values.isdisjoint(actual_values):
            return False
    return True


def _filter_values(value: object) -> frozenset[str] | None:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Sequence):
        if any(not isinstance(item, str) for item in value):
            return None
        return frozenset(value)
    return None


def _utc_now() -> datetime:
    return datetime.now(UTC)
