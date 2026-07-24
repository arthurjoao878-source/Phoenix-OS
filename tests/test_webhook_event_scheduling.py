from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.events import Event, EventBus
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    WebhookDeliveryScheduler,
    WebhookDeliverySchedulerClosedError,
    WebhookEndpoint,
    WebhookEventAdapter,
    WebhookEventAdapterStateError,
    WebhookEventNotFoundError,
    WebhookEventRegistry,
    WebhookEventType,
    WebhookPayload,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionStatus,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(seconds=1)
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000024")


class _JobCompletedSerializer:
    def __init__(self) -> None:
        self.event_type = WebhookEventType(
            "jobs.completed",
            resource_filter_fields=frozenset({"job_id", "tags"}),
        )
        self.calls = 0

    def serialize(self, event: Event) -> WebhookPayload:
        self.calls += 1
        return WebhookPayload(
            event_type=self.event_type,
            data={
                "job_id": event.payload["job_id"],
                "tags": event.payload["tags"],
                "source": event.source,
            },
        )


def _event(
    *,
    event_id: UUID = _EVENT_ID,
    name: str = "jobs.completed",
) -> Event:
    return Event(
        id=event_id,
        name=name,
        source="scheduler",
        occurred_at=_NOW,
        payload={
            "job_id": "job-1",
            "tags": ("release", "production"),
            "private_token": "must-not-leak",
        },
    )


def _subscription(
    number: int,
    *,
    event_types: frozenset[str] = frozenset({"jobs.completed"}),
    resource_filters: object = None,
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE,
) -> WebhookSubscription:
    updated_at = _LATER if status is not WebhookSubscriptionStatus.ACTIVE else _NOW
    values: dict[str, object] = {
        "id": UUID(int=number),
        "name": f"subscription-{number}",
        "display_name": f"Subscription {number}",
        "event_types": event_types,
        "endpoint": WebhookEndpoint(f"https://hooks{number}.example.com/phoenix"),
        "signing": WebhookSigningPolicy(SecretRef("webhook-key", "integrations", 1)),
        "egress_policy": "production.webhooks",
        "created_at": _NOW,
        "updated_at": updated_at,
        "created_by": "maintainer:test",
        "resource_filters": {} if resource_filters is None else resource_filters,
        "status": status,
        "disabled_at": _LATER if status is WebhookSubscriptionStatus.DISABLED else None,
        "revoked_at": _LATER if status is WebhookSubscriptionStatus.REVOKED else None,
    }
    return WebhookSubscription(**cast(Any, values))


async def _services() -> tuple[
    WebhookEventRegistry,
    _JobCompletedSerializer,
    InMemoryWebhookSubscriptionRepository,
    InMemoryWebhookDeliveryRepository,
    WebhookDeliveryScheduler,
]:
    registry = WebhookEventRegistry()
    serializer = _JobCompletedSerializer()
    await registry.register(serializer)
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    scheduler = WebhookDeliveryScheduler(
        registry=registry,
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=lambda: _LATER,
    )
    return registry, serializer, subscriptions, deliveries, scheduler


@pytest.mark.asyncio
async def test_scheduler_creates_filtered_durable_deliveries_once() -> None:
    _, serializer, subscriptions, deliveries, scheduler = await _services()
    await subscriptions.add(_subscription(1))
    await subscriptions.add(
        _subscription(
            2,
            resource_filters={
                "jobs.completed": {
                    "job_id": frozenset({"job-1"}),
                    "tags": frozenset({"production"}),
                }
            },
        )
    )
    await subscriptions.add(
        _subscription(
            3,
            resource_filters={"jobs.completed": {"job_id": frozenset({"job-2"})}},
        )
    )
    await subscriptions.add(_subscription(4, status=WebhookSubscriptionStatus.DISABLED))
    await subscriptions.add(_subscription(5, event_types=frozenset({"workflows.failed"})))

    result = await scheduler.schedule(_event())

    assert serializer.calls == 1
    assert result.considered == 3
    assert result.matched == 2
    assert result.filtered == 1
    assert result.duplicates == 0
    assert result.scheduled == 2

    page = await deliveries.list()
    assert len(page.items) == 2
    assert {item.subscription_id for item in page.items} == {
        UUID(int=1),
        UUID(int=2),
    }
    for delivery in page.items:
        body = json.loads(delivery.canonical_body)
        assert body["payload"]["job_id"] == "job-1"
        assert "private_token" not in body["payload"]


@pytest.mark.asyncio
async def test_scheduler_is_restart_safe_for_replayed_source_event() -> None:
    registry, _, subscriptions, deliveries, first = await _services()
    await subscriptions.add(_subscription(1))
    event = _event()

    first_result = await first.schedule(event)
    await first.close()

    restarted = WebhookDeliveryScheduler(
        registry=registry,
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=lambda: _LATER,
    )
    second_result = await restarted.schedule(event)

    assert first_result.scheduled == 1
    assert second_result.scheduled == 0
    assert second_result.duplicates == 1
    assert (await deliveries.snapshot()).deliveries == 1


@pytest.mark.asyncio
async def test_scheduler_serializes_concurrent_replay_without_duplicates() -> None:
    _, _, subscriptions, deliveries, scheduler = await _services()
    await subscriptions.add(_subscription(1))
    event = _event()

    first, second = await asyncio.gather(
        scheduler.schedule(event),
        scheduler.schedule(event),
    )

    assert sorted((first.scheduled, second.scheduled)) == [0, 1]
    assert sorted((first.duplicates, second.duplicates)) == [0, 1]
    assert (await deliveries.snapshot()).deliveries == 1


@pytest.mark.asyncio
async def test_scheduler_pages_all_matching_subscriptions() -> None:
    _, serializer, subscriptions, deliveries, scheduler = await _services()
    for number in range(1, 206):
        await subscriptions.add(_subscription(number))

    result = await scheduler.schedule(_event())

    assert serializer.calls == 1
    assert result.considered == 205
    assert result.scheduled == 205
    assert (await deliveries.snapshot()).deliveries == 205


@pytest.mark.asyncio
async def test_scheduler_rejects_unregistered_events_and_closed_work() -> None:
    _, _, _, _, scheduler = await _services()

    with pytest.raises(WebhookEventNotFoundError):
        await scheduler.schedule(_event(name="jobs.unknown"))

    await scheduler.close()
    await scheduler.close()

    with pytest.raises(WebhookDeliverySchedulerClosedError):
        await scheduler.schedule(_event())


@pytest.mark.asyncio
async def test_event_adapter_ignores_unknown_events_and_schedules_registered_events() -> None:
    _, _, subscriptions, deliveries, scheduler = await _services()
    await subscriptions.add(_subscription(1))
    events = EventBus()
    adapter = WebhookEventAdapter(events=events, scheduler=scheduler)

    await adapter.start(object())

    unknown = await events.publish(_event(name="jobs.unknown"))
    registered = await events.publish(_event())

    assert unknown.succeeded is True
    assert registered.succeeded is True
    snapshot = await adapter.snapshot()
    assert snapshot.started is True
    assert snapshot.processed == 1
    assert snapshot.ignored == 1
    assert snapshot.failures == 0
    assert snapshot.scheduled == 1
    assert (await deliveries.snapshot()).deliveries == 1

    await adapter.stop(object())
    await adapter.stop(object())
    assert (await adapter.snapshot()).started is False


@pytest.mark.asyncio
async def test_event_adapter_rejects_double_start_and_preserves_handler_failures() -> None:
    registry = WebhookEventRegistry()

    class FailingSerializer:
        event_type = WebhookEventType("jobs.completed")

        def serialize(self, event: Event) -> WebhookPayload:
            raise ValueError("sensitive serializer failure")

    await registry.register(FailingSerializer())
    subscriptions = InMemoryWebhookSubscriptionRepository()
    await subscriptions.add(_subscription(1))
    scheduler = WebhookDeliveryScheduler(
        registry=registry,
        subscriptions=subscriptions,
        deliveries=InMemoryWebhookDeliveryRepository(),
        clock=lambda: _LATER,
    )
    events = EventBus()
    adapter = WebhookEventAdapter(events=events, scheduler=scheduler)

    await adapter.start(object())
    with pytest.raises(WebhookEventAdapterStateError):
        await adapter.start(object())

    report = await events.publish(_event())

    assert report.succeeded is False
    assert len(report.failures) == 1
    assert isinstance(report.failures[0].exception.__cause__, ValueError)
    snapshot = await adapter.snapshot()
    assert snapshot.failures == 1
    assert snapshot.processed == 0

    await events.close()
    await adapter.stop(object())
