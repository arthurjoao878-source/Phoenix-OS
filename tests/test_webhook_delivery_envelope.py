from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.events import Event
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    InMemoryWebhookDeliveryRepository,
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookEventType,
    WebhookPayload,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionStatus,
    canonical_webhook_delivery_body,
    new_webhook_delivery,
    webhook_delivery_deduplication_key,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_CREATED_AT = _NOW + timedelta(seconds=1)
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000024")
_OTHER_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000124")
_OTHER_EVENT_ID = UUID("00000000-0000-4000-8000-000000000125")
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000224")
_OTHER_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000225")


def _subscription(**changes: object) -> WebhookSubscription:
    values: dict[str, object] = {
        "id": _SUBSCRIPTION_ID,
        "name": "release.notifications",
        "display_name": "Release Notifications",
        "event_types": frozenset({"jobs.completed"}),
        "endpoint": WebhookEndpoint("https://hooks.example.com/phoenix"),
        "signing": WebhookSigningPolicy(SecretRef("release-webhook", "integrations", 2)),
        "egress_policy": "production.webhooks",
        "created_at": _NOW,
        "updated_at": _NOW,
        "created_by": "maintainer:arthur",
    }
    values.update(changes)
    return WebhookSubscription(**cast(Any, values))


def _event(**changes: object) -> Event:
    values: dict[str, object] = {
        "name": "jobs.completed",
        "source": "scheduler",
        "payload": {"job_id": "job-1", "private_token": "must-not-leak"},
        "id": _EVENT_ID,
        "occurred_at": _NOW,
        "correlation_id": "request-123",
    }
    values.update(changes)
    return Event(**cast(Any, values))


def _payload(**changes: object) -> WebhookPayload:
    values: dict[str, object] = {
        "event_type": WebhookEventType("jobs.completed", schema_version=3),
        "data": {
            "job_id": "job-1",
            "message": "Concluído",
            "steps": ("build", "publish"),
        },
    }
    values.update(changes)
    return WebhookPayload(**cast(Any, values))


def test_canonical_body_is_deterministic_and_contains_only_safe_payload() -> None:
    subscription = _subscription()
    event = _event()
    payload = _payload()

    body = canonical_webhook_delivery_body(
        delivery_id=_DELIVERY_ID,
        subscription=subscription,
        event=event,
        payload=payload,
    )

    expected = {
        "schema_version": 1,
        "event_schema_version": 3,
        "delivery_id": str(_DELIVERY_ID),
        "subscription_id": str(_SUBSCRIPTION_ID),
        "event_type": "jobs.completed",
        "event_id": str(_EVENT_ID),
        "occurred_at": _NOW.isoformat(),
        "payload": {
            "job_id": "job-1",
            "message": "Concluído",
            "steps": ["build", "publish"],
        },
    }
    expected_bytes = json.dumps(
        expected,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert body == expected_bytes
    assert b"private_token" not in body
    assert body == canonical_webhook_delivery_body(
        delivery_id=_DELIVERY_ID,
        subscription=subscription,
        event=event,
        payload=payload,
    )


def test_new_delivery_is_pending_with_immutable_body_and_digest() -> None:
    delivery = new_webhook_delivery(
        _subscription(),
        _event(),
        _payload(),
        delivery_id=_DELIVERY_ID,
        created_at=_CREATED_AT,
    )

    assert delivery.id == _DELIVERY_ID
    assert delivery.subscription_id == _SUBSCRIPTION_ID
    assert delivery.event_type == "jobs.completed"
    assert delivery.source_event_id == _EVENT_ID
    assert delivery.correlation_id == "request-123"
    assert delivery.status is WebhookDeliveryStatus.PENDING
    assert delivery.next_attempt_at == _CREATED_AT
    assert delivery.attempts == ()
    assert delivery.body_sha256 == hashlib.sha256(delivery.canonical_body).hexdigest()


def test_deduplication_key_is_stable_and_scoped_by_subscription_and_event() -> None:
    key = webhook_delivery_deduplication_key(_SUBSCRIPTION_ID, _EVENT_ID)

    assert key == webhook_delivery_deduplication_key(
        _SUBSCRIPTION_ID,
        _EVENT_ID,
    )
    assert key != webhook_delivery_deduplication_key(
        _OTHER_SUBSCRIPTION_ID,
        _EVENT_ID,
    )
    assert key != webhook_delivery_deduplication_key(
        _SUBSCRIPTION_ID,
        _OTHER_EVENT_ID,
    )


@pytest.mark.asyncio
async def test_repository_rejects_replayed_source_event() -> None:
    first = new_webhook_delivery(
        _subscription(),
        _event(),
        _payload(),
        delivery_id=_DELIVERY_ID,
        created_at=_CREATED_AT,
    )
    replay = new_webhook_delivery(
        _subscription(),
        _event(),
        _payload(),
        delivery_id=_OTHER_DELIVERY_ID,
        created_at=_CREATED_AT,
    )
    repository = InMemoryWebhookDeliveryRepository()

    await repository.add(first)

    with pytest.raises(WebhookDeliveryAlreadyExistsError, match="deduplication"):
        await repository.add(replay)

    assert await repository.get_by_deduplication_key(first.deduplication_key) == first


def test_delivery_rejects_inactive_subscription() -> None:
    subscription = _subscription(
        status=WebhookSubscriptionStatus.DISABLED,
        disabled_at=_NOW,
    )

    with pytest.raises(ValueError, match="not active"):
        new_webhook_delivery(
            subscription,
            _event(),
            _payload(),
            delivery_id=_DELIVERY_ID,
            created_at=_CREATED_AT,
        )


def test_delivery_rejects_unsubscribed_or_mismatched_event_type() -> None:
    with pytest.raises(ValueError, match="does not include"):
        new_webhook_delivery(
            _subscription(event_types=frozenset({"workflows.failed"})),
            _event(),
            _payload(),
            delivery_id=_DELIVERY_ID,
            created_at=_CREATED_AT,
        )

    with pytest.raises(ValueError, match="does not match"):
        new_webhook_delivery(
            _subscription(),
            _event(),
            _payload(event_type=WebhookEventType("workflows.failed")),
            delivery_id=_DELIVERY_ID,
            created_at=_CREATED_AT,
        )
