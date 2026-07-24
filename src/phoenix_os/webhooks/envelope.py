"""Canonical delivery envelopes and stable webhook deduplication."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID, uuid4

from phoenix_os.events import Event
from phoenix_os.webhooks._json import canonical_json_bytes, thaw_json_value
from phoenix_os.webhooks.contracts import (
    WebhookDelivery,
    WebhookEventType,
    WebhookPayload,
    WebhookSubscription,
)

_ENVELOPE_SCHEMA_VERSION = 1
_DEDUPLICATION_SCHEMA_VERSION = 1


def webhook_delivery_deduplication_key(
    subscription_id: UUID,
    source_event_id: UUID,
) -> str:
    """Return the stable key for one subscription and source-event identity."""

    if not isinstance(subscription_id, UUID):
        raise TypeError("subscription_id must be UUID")
    if not isinstance(source_event_id, UUID):
        raise TypeError("source_event_id must be UUID")

    identity = {
        "schema_version": _DEDUPLICATION_SCHEMA_VERSION,
        "subscription_id": str(subscription_id),
        "event_id": str(source_event_id),
    }
    return hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


def canonical_webhook_delivery_body(
    *,
    delivery_id: UUID,
    subscription: WebhookSubscription,
    event: Event,
    payload: WebhookPayload,
) -> bytes:
    """Return the immutable canonical request body for one delivery."""

    _validate_delivery_inputs(
        delivery_id=delivery_id,
        subscription=subscription,
        event=event,
        payload=payload,
    )

    envelope = {
        "schema_version": _ENVELOPE_SCHEMA_VERSION,
        "event_schema_version": payload.event_type.schema_version,
        "delivery_id": str(delivery_id),
        "subscription_id": str(subscription.id),
        "event_type": payload.event_type.name,
        "event_id": str(event.id),
        "occurred_at": event.occurred_at.isoformat(),
        "payload": thaw_json_value(payload.data),
    }
    return canonical_json_bytes(envelope)


def new_webhook_delivery(
    subscription: WebhookSubscription,
    event: Event,
    payload: WebhookPayload,
    *,
    delivery_id: UUID | None = None,
    created_at: datetime | None = None,
) -> WebhookDelivery:
    """Create one pending durable delivery from a reviewed safe payload."""

    resolved_id = uuid4() if delivery_id is None else delivery_id
    resolved_created_at = datetime.now(UTC) if created_at is None else created_at

    if not isinstance(resolved_created_at, datetime):
        raise TypeError("created_at must be datetime")

    body = canonical_webhook_delivery_body(
        delivery_id=resolved_id,
        subscription=subscription,
        event=event,
        payload=payload,
    )

    return WebhookDelivery(
        id=resolved_id,
        subscription_id=subscription.id,
        event_type=payload.event_type.name,
        deduplication_key=webhook_delivery_deduplication_key(
            subscription.id,
            event.id,
        ),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=event.occurred_at,
        created_at=resolved_created_at,
        updated_at=resolved_created_at,
        source_event_id=event.id,
        correlation_id=event.correlation_id,
        next_attempt_at=resolved_created_at,
    )


def _validate_delivery_inputs(
    *,
    delivery_id: UUID,
    subscription: WebhookSubscription,
    event: Event,
    payload: WebhookPayload,
) -> None:
    if not isinstance(delivery_id, UUID):
        raise TypeError("delivery_id must be UUID")
    if not isinstance(subscription, WebhookSubscription):
        raise TypeError("subscription must be WebhookSubscription")
    if not isinstance(event, Event):
        raise TypeError("event must be Event")
    if not isinstance(payload, WebhookPayload):
        raise TypeError("payload must be WebhookPayload")
    if not subscription.status.deliverable:
        raise ValueError("webhook subscription is not active")

    event_name = WebhookEventType(event.name).name
    if event_name not in subscription.event_types:
        raise ValueError("webhook subscription does not include the event type")
    if payload.event_type.name != event_name:
        raise ValueError("webhook payload event type does not match the source event")
