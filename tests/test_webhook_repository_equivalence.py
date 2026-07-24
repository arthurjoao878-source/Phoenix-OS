from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.secrets import SecretRef
from phoenix_os.state import MemoryStateStore
from phoenix_os.webhooks import (
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    StateWebhookDeliveryRepository,
    StateWebhookSubscriptionRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliveryRepositoryClosedError,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookHttpStatusClass,
    WebhookPageRequest,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionAlreadyExistsError,
    WebhookSubscriptionRepositoryClosedError,
    WebhookSubscriptionStatus,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_BODY = b'{"event_type":"jobs.completed"}'
_BODY_SHA256 = hashlib.sha256(_BODY).hexdigest()


def _subscription(index: int, name: str) -> WebhookSubscription:
    created_at = _NOW + timedelta(seconds=index)
    return WebhookSubscription(
        id=UUID(int=index),
        name=name,
        display_name=name.replace(".", " ").title(),
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/phoenix"),
        signing=WebhookSigningPolicy(SecretRef("webhook-key", "integrations", 1)),
        egress_policy="production.webhooks",
        created_at=created_at,
        updated_at=created_at,
        created_by="maintainer:arthur",
    )


def _delivery(index: int) -> WebhookDelivery:
    created_at = _NOW + timedelta(seconds=index)
    return WebhookDelivery(
        id=UUID(int=1_000 + index),
        subscription_id=UUID(int=2_000 + index),
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(f"delivery:{index}".encode()).hexdigest(),
        canonical_body=_BODY,
        body_sha256=_BODY_SHA256,
        occurred_at=created_at,
        created_at=created_at,
        updated_at=created_at,
        next_attempt_at=created_at,
        source_event_id=UUID(int=3_000 + index),
        correlation_id=f"request-{index}",
    )


def _to_in_flight(delivery: WebhookDelivery) -> WebhookDelivery:
    started_at = delivery.updated_at + timedelta(seconds=1)
    return replace(
        delivery,
        status=WebhookDeliveryStatus.IN_FLIGHT,
        current_attempt=len(delivery.attempts) + 1,
        in_flight_at=started_at,
        next_attempt_at=None,
        updated_at=started_at,
        revision=delivery.revision + 1,
    )


def _to_succeeded(delivery: WebhookDelivery) -> WebhookDelivery:
    if delivery.current_attempt is None or delivery.in_flight_at is None:
        raise AssertionError("test delivery must be in flight")

    finished_at = delivery.in_flight_at + timedelta(seconds=1)
    attempt = WebhookAttempt(
        delivery_id=delivery.id,
        number=delivery.current_attempt,
        scheduled_at=delivery.in_flight_at,
        started_at=delivery.in_flight_at,
        finished_at=finished_at,
        outcome=WebhookAttemptOutcome.SUCCEEDED,
        status_class=WebhookHttpStatusClass.SUCCESSFUL,
    )
    return replace(
        delivery,
        status=WebhookDeliveryStatus.SUCCEEDED,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        terminal_at=finished_at,
        updated_at=finished_at,
        revision=delivery.revision + 1,
    )


@pytest.mark.asyncio
async def test_subscription_repositories_are_contract_equivalent() -> None:
    memory = InMemoryWebhookSubscriptionRepository()
    state = StateWebhookSubscriptionRepository(MemoryStateStore())
    repositories = (memory, state)
    subscriptions = (
        _subscription(1, "release.notifications"),
        _subscription(2, "backup.notifications"),
    )

    for repository in repositories:
        for subscription in subscriptions:
            await repository.add(subscription)

    assert await memory.get(subscriptions[0].id) == await state.get(subscriptions[0].id)
    assert await memory.get_by_name(" RELEASE.NOTIFICATIONS ") == await state.get_by_name(
        " RELEASE.NOTIFICATIONS "
    )
    assert await memory.list() == await state.list()

    request = WebhookPageRequest(offset=1, limit=1)
    assert await memory.list(request) == await state.list(request)
    assert await memory.snapshot() == await state.snapshot()

    disabled_at = subscriptions[0].updated_at + timedelta(seconds=1)
    replacement = replace(
        subscriptions[0],
        name="release.disabled",
        display_name="Release Disabled",
        status=WebhookSubscriptionStatus.DISABLED,
        disabled_at=disabled_at,
        updated_at=disabled_at,
        revision=2,
    )

    memory_replaced = await memory.replace(
        replacement,
        expected_revision=1,
    )
    state_replaced = await state.replace(
        replacement,
        expected_revision=1,
    )

    assert memory_replaced == state_replaced
    assert await memory.get_by_name("release.notifications") == await state.get_by_name(
        "release.notifications"
    )
    assert await memory.get_by_name("release.disabled") == await state.get_by_name(
        "release.disabled"
    )
    assert await memory.snapshot() == await state.snapshot()

    duplicate = _subscription(3, "RELEASE.DISABLED")

    with pytest.raises(WebhookSubscriptionAlreadyExistsError) as memory_error:
        await memory.add(duplicate)

    with pytest.raises(WebhookSubscriptionAlreadyExistsError) as state_error:
        await state.add(duplicate)

    assert type(memory_error.value) is type(state_error.value)

    for repository in repositories:
        await repository.close()
        assert repository.closed is True

        with pytest.raises(WebhookSubscriptionRepositoryClosedError):
            await repository.get(subscriptions[0].id)


@pytest.mark.asyncio
async def test_delivery_repositories_are_contract_equivalent() -> None:
    memory = InMemoryWebhookDeliveryRepository()
    state = StateWebhookDeliveryRepository(MemoryStateStore())
    repositories = (memory, state)
    deliveries = (_delivery(1), _delivery(2))

    for repository in repositories:
        for delivery in deliveries:
            await repository.add(delivery)

    assert await memory.get(deliveries[0].id) == await state.get(deliveries[0].id)
    assert await memory.get_by_deduplication_key(
        deliveries[0].deduplication_key
    ) == await state.get_by_deduplication_key(deliveries[0].deduplication_key)
    assert await memory.list() == await state.list()

    request = WebhookPageRequest(offset=1, limit=1)
    assert await memory.list(request) == await state.list(request)
    assert await memory.snapshot() == await state.snapshot()

    in_flight = _to_in_flight(deliveries[0])

    memory_in_flight = await memory.replace(
        in_flight,
        expected_revision=1,
    )
    state_in_flight = await state.replace(
        in_flight,
        expected_revision=1,
    )

    assert memory_in_flight == state_in_flight

    succeeded = _to_succeeded(in_flight)

    memory_succeeded = await memory.replace(
        succeeded,
        expected_revision=2,
    )
    state_succeeded = await state.replace(
        succeeded,
        expected_revision=2,
    )

    assert memory_succeeded == state_succeeded
    assert await memory.list() == await state.list()
    assert await memory.snapshot() == await state.snapshot()

    duplicate = replace(
        _delivery(3),
        deduplication_key=deliveries[1].deduplication_key,
    )

    with pytest.raises(WebhookDeliveryAlreadyExistsError) as memory_error:
        await memory.add(duplicate)

    with pytest.raises(WebhookDeliveryAlreadyExistsError) as state_error:
        await state.add(duplicate)

    assert type(memory_error.value) is type(state_error.value)

    for repository in repositories:
        await repository.close()
        assert repository.closed is True

        with pytest.raises(WebhookDeliveryRepositoryClosedError):
            await repository.get(deliveries[0].id)
