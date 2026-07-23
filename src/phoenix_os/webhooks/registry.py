"""Explicit registry for safe webhook event serializers."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from uuid import UUID, uuid4

from phoenix_os.events import Event
from phoenix_os.webhooks._json import canonical_json_bytes, thaw_json_value
from phoenix_os.webhooks.contracts import (
    WebhookEventRegistration,
    WebhookEventType,
    WebhookPayload,
    WebhookPayloadSerializer,
    WebhookSubscription,
)
from phoenix_os.webhooks.errors import (
    WebhookEventAlreadyRegisteredError,
    WebhookEventNotFoundError,
    WebhookEventRegistryClosedError,
    WebhookPayloadSerializationError,
    WebhookResourceFilterError,
)


@dataclass(slots=True)
class _RegisteredWebhookEvent:
    registration: WebhookEventRegistration
    event_type: WebhookEventType
    serializer: WebhookPayloadSerializer
    sequence: int


class WebhookEventRegistry:
    """Register reviewed serializers for explicitly supported webhook events."""

    def __init__(self) -> None:
        self._by_name: dict[str, _RegisteredWebhookEvent] = {}
        self._by_id: dict[UUID, str] = {}
        self._sequence = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def register(
        self,
        serializer: WebhookPayloadSerializer,
    ) -> WebhookEventRegistration:
        self._ensure_open()

        event_type = getattr(serializer, "event_type", None)
        if not isinstance(event_type, WebhookEventType):
            raise TypeError("webhook serializer event_type must be WebhookEventType")
        if not callable(getattr(serializer, "serialize", None)):
            raise TypeError("webhook serializer must provide a callable serialize method")

        async with self._lock:
            self._ensure_open()
            if event_type.name in self._by_name:
                raise WebhookEventAlreadyRegisteredError(
                    f"webhook event already registered: {event_type.name}"
                )

            registration = WebhookEventRegistration(
                id=uuid4(),
                name=event_type.name,
            )
            registered = _RegisteredWebhookEvent(
                registration=registration,
                event_type=event_type,
                serializer=serializer,
                sequence=self._sequence,
            )
            self._sequence += 1
            self._by_name[event_type.name] = registered
            self._by_id[registration.id] = event_type.name
            return registration

    async def unregister(
        self,
        registration: WebhookEventRegistration,
    ) -> bool:
        self._ensure_open()
        if not isinstance(registration, WebhookEventRegistration):
            raise TypeError("registration must be WebhookEventRegistration")

        async with self._lock:
            self._ensure_open()
            name = self._by_id.get(registration.id)
            if name is None or name != registration.name:
                return False

            current = self._by_name.get(name)
            if current is None or current.registration != registration:
                return False

            del self._by_id[registration.id]
            del self._by_name[name]
            return True

    async def describe(self, name: str) -> WebhookEventType:
        return (await self._resolve(name)).event_type

    async def list_event_types(self) -> tuple[WebhookEventType, ...]:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            registered = sorted(
                self._by_name.values(),
                key=lambda item: item.sequence,
            )
            return tuple(item.event_type for item in registered)

    async def serialize(self, event: Event) -> WebhookPayload:
        self._ensure_open()
        if not isinstance(event, Event):
            raise TypeError("event must be Event")

        registered = await self._resolve(event.name)

        try:
            payload = registered.serializer.serialize(event)
            if inspect.isawaitable(payload):
                payload = await payload
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            raise WebhookPayloadSerializationError(
                f"webhook payload serializer failed: {registered.event_type.name}"
            ) from exception

        if not isinstance(payload, WebhookPayload):
            raise WebhookPayloadSerializationError(
                "webhook payload serializer must return WebhookPayload"
            )
        if payload.event_type != registered.event_type:
            raise WebhookPayloadSerializationError(
                "webhook payload event type does not match its registration"
            )

        try:
            serialized = _canonical_payload_bytes(payload)
        except (TypeError, ValueError) as exception:
            raise WebhookPayloadSerializationError(
                "webhook payload could not be serialized canonically"
            ) from exception

        if len(serialized) > registered.event_type.max_payload_bytes:
            raise WebhookPayloadSerializationError(
                "webhook payload exceeds the registered maximum size"
            )

        return payload

    async def validate_subscription(
        self,
        subscription: WebhookSubscription,
    ) -> None:
        self._ensure_open()
        if not isinstance(subscription, WebhookSubscription):
            raise TypeError("subscription must be WebhookSubscription")

        async with self._lock:
            self._ensure_open()

            for event_name in sorted(subscription.event_types):
                registered = self._by_name.get(event_name)
                if registered is None:
                    raise WebhookEventNotFoundError(f"webhook event not found: {event_name}")

                supplied = subscription.resource_filters.get(event_name, {})
                unsupported = frozenset(supplied) - registered.event_type.resource_filter_fields
                if unsupported:
                    fields = ", ".join(sorted(unsupported))
                    raise WebhookResourceFilterError(
                        f"unsupported resource filters for {event_name}: {fields}"
                    )

    async def close(self) -> None:
        async with self._lock:
            self._by_name.clear()
            self._by_id.clear()
            self._closed = True

    async def _resolve(self, name: str) -> _RegisteredWebhookEvent:
        self._ensure_open()
        normalized = _normalize_event_name(name)

        async with self._lock:
            self._ensure_open()
            try:
                return self._by_name[normalized]
            except KeyError as exception:
                raise WebhookEventNotFoundError(
                    f"webhook event not found: {normalized}"
                ) from exception

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookEventRegistryClosedError("webhook event registry is closed")


def _normalize_event_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("webhook event name must be a string")
    return WebhookEventType(value).name


def _canonical_payload_bytes(payload: WebhookPayload) -> bytes:
    return canonical_json_bytes(thaw_json_value(payload.data))
