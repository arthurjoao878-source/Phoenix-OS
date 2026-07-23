from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.events import Event
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    WebhookEndpoint,
    WebhookEventAlreadyRegisteredError,
    WebhookEventNotFoundError,
    WebhookEventRegistration,
    WebhookEventRegistry,
    WebhookEventRegistryClosedError,
    WebhookEventType,
    WebhookPayload,
    WebhookPayloadSerializationError,
    WebhookResourceFilterError,
    WebhookSigningPolicy,
    WebhookSubscription,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000024")


class _JobCompletedSerializer:
    def __init__(self, event_type: WebhookEventType) -> None:
        self.event_type = event_type
        self.events: list[Event] = []

    def serialize(self, event: Event) -> WebhookPayload:
        self.events.append(event)
        return WebhookPayload(
            event_type=self.event_type,
            data={
                "event_id": str(event.id),
                "job_id": str(event.payload["job_id"]),
                "source": event.source,
            },
        )


def _event(name: str = "jobs.completed") -> Event:
    return Event(
        name=name,
        source="scheduler",
        payload={
            "job_id": "job-1",
            "private_token": "must-not-leak",
        },
    )


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


@pytest.mark.asyncio
async def test_registry_registers_describes_lists_and_unregisters() -> None:
    event_type = WebhookEventType(
        "jobs.completed",
        resource_filter_fields=frozenset({"job_id"}),
    )
    serializer = _JobCompletedSerializer(event_type)
    registry = WebhookEventRegistry()

    registration = await registry.register(serializer)

    assert registration.name == "jobs.completed"
    assert await registry.describe(" Jobs.Completed ") == event_type
    assert await registry.list_event_types() == (event_type,)

    await registry.unregister(registration)

    with pytest.raises(WebhookEventNotFoundError, match=r"jobs\.completed"):
        await registry.describe("jobs.completed")


@pytest.mark.asyncio
async def test_registry_rejects_duplicate_event_registration() -> None:
    event_type = WebhookEventType("jobs.completed")
    registry = WebhookEventRegistry()

    await registry.register(_JobCompletedSerializer(event_type))

    with pytest.raises(
        WebhookEventAlreadyRegisteredError,
        match=r"jobs\.completed",
    ):
        await registry.register(_JobCompletedSerializer(event_type))


@pytest.mark.asyncio
async def test_registry_rejects_forged_registration_handle() -> None:
    registry = WebhookEventRegistry()
    registration = await registry.register(
        _JobCompletedSerializer(WebhookEventType("jobs.completed"))
    )
    forged = WebhookEventRegistration(
        id=UUID("00000000-0000-4000-8000-000000000099"),
        name=registration.name,
    )

    assert await registry.unregister(forged) is False

    assert await registry.describe("jobs.completed") == WebhookEventType("jobs.completed")


@pytest.mark.asyncio
async def test_registry_serializes_only_allowlisted_payload_fields() -> None:
    event_type = WebhookEventType("jobs.completed")
    serializer = _JobCompletedSerializer(event_type)
    registry = WebhookEventRegistry()
    event = _event()

    await registry.register(serializer)
    payload = await registry.serialize(event)

    assert serializer.events == [event]
    assert payload.event_type == event_type
    assert payload.data["job_id"] == "job-1"
    assert payload.data["source"] == "scheduler"
    assert "private_token" not in payload.data


@pytest.mark.asyncio
async def test_registry_supports_async_serializers() -> None:
    event_type = WebhookEventType("jobs.completed")

    class AsyncSerializer:
        event_type = WebhookEventType("jobs.completed")

        async def serialize(self, event: Event) -> WebhookPayload:
            await asyncio.sleep(0)
            return WebhookPayload(
                event_type=self.event_type,
                data={"job_id": event.payload["job_id"]},
            )

    registry = WebhookEventRegistry()
    await registry.register(AsyncSerializer())

    payload = await registry.serialize(_event())

    assert payload.event_type == event_type
    assert payload.data == {"job_id": "job-1"}


@pytest.mark.asyncio
async def test_registry_wraps_serializer_failures() -> None:
    class FailingSerializer:
        event_type = WebhookEventType("jobs.completed")

        def serialize(self, event: Event) -> WebhookPayload:
            raise ValueError("sensitive internal failure")

    registry = WebhookEventRegistry()
    await registry.register(FailingSerializer())

    with pytest.raises(
        WebhookPayloadSerializationError,
        match=r"jobs\.completed",
    ) as raised:
        await registry.serialize(_event())

    assert isinstance(raised.value.__cause__, ValueError)


@pytest.mark.asyncio
async def test_registry_preserves_serializer_cancellation() -> None:
    class CancelledSerializer:
        event_type = WebhookEventType("jobs.completed")

        async def serialize(self, event: Event) -> WebhookPayload:
            raise asyncio.CancelledError

    registry = WebhookEventRegistry()
    await registry.register(CancelledSerializer())

    with pytest.raises(asyncio.CancelledError):
        await registry.serialize(_event())


@pytest.mark.asyncio
async def test_registry_rejects_non_payload_serializer_result() -> None:
    class InvalidSerializer:
        event_type = WebhookEventType("jobs.completed")

        def serialize(self, event: Event) -> WebhookPayload:
            return cast(WebhookPayload, {"job_id": event.payload["job_id"]})

    registry = WebhookEventRegistry()
    await registry.register(InvalidSerializer())

    with pytest.raises(
        WebhookPayloadSerializationError,
        match="WebhookPayload",
    ):
        await registry.serialize(_event())


@pytest.mark.asyncio
async def test_registry_rejects_mismatched_payload_event_type() -> None:
    class MismatchedSerializer:
        event_type = WebhookEventType("jobs.completed")

        def serialize(self, event: Event) -> WebhookPayload:
            return WebhookPayload(
                event_type=WebhookEventType("workflows.failed"),
                data={"job_id": event.payload["job_id"]},
            )

    registry = WebhookEventRegistry()
    await registry.register(MismatchedSerializer())

    with pytest.raises(WebhookPayloadSerializationError):
        await registry.serialize(_event())


@pytest.mark.asyncio
async def test_registry_enforces_canonical_utf8_payload_size() -> None:
    data = {"message": "é"}
    canonical_size = len(
        json.dumps(
            data,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    event_type = WebhookEventType(
        "jobs.completed",
        max_payload_bytes=canonical_size - 1,
    )

    class OversizedSerializer:
        def __init__(self) -> None:
            self.event_type = event_type

        def serialize(self, event: Event) -> WebhookPayload:
            return WebhookPayload(
                event_type=self.event_type,
                data=data,
            )

    registry = WebhookEventRegistry()
    await registry.register(OversizedSerializer())

    with pytest.raises(WebhookPayloadSerializationError):
        await registry.serialize(_event())


@pytest.mark.asyncio
async def test_registry_validates_supported_resource_filters() -> None:
    registry = WebhookEventRegistry()
    await registry.register(
        _JobCompletedSerializer(
            WebhookEventType(
                "jobs.completed",
                resource_filter_fields=frozenset({"job_id"}),
            )
        )
    )
    subscription = _subscription(
        resource_filters={"jobs.completed": {"job_id": frozenset({"job-1"})}}
    )

    await registry.validate_subscription(subscription)


@pytest.mark.asyncio
async def test_registry_rejects_invalid_subscription_selection() -> None:
    registry = WebhookEventRegistry()
    await registry.register(
        _JobCompletedSerializer(
            WebhookEventType(
                "jobs.completed",
                resource_filter_fields=frozenset({"job_id"}),
            )
        )
    )

    with pytest.raises(
        WebhookResourceFilterError,
        match="tenant_id",
    ):
        await registry.validate_subscription(
            _subscription(
                resource_filters={"jobs.completed": {"tenant_id": frozenset({"tenant-1"})}}
            )
        )

    with pytest.raises(
        WebhookEventNotFoundError,
        match=r"workflows\.failed",
    ):
        await registry.validate_subscription(
            _subscription(event_types=frozenset({"jobs.completed", "workflows.failed"}))
        )


@pytest.mark.asyncio
async def test_registry_close_is_idempotent_and_rejects_operations() -> None:
    registry = WebhookEventRegistry()
    await registry.register(_JobCompletedSerializer(WebhookEventType("jobs.completed")))

    await registry.close()
    await registry.close()

    assert registry.closed is True

    with pytest.raises(WebhookEventRegistryClosedError):
        await registry.list_event_types()

    with pytest.raises(WebhookEventRegistryClosedError):
        await registry.serialize(_event())


@pytest.mark.asyncio
async def test_registry_requires_registered_event_for_serialization() -> None:
    registry = WebhookEventRegistry()

    with pytest.raises(
        WebhookEventNotFoundError,
        match=r"jobs\.completed",
    ):
        await registry.serialize(_event())


@pytest.mark.asyncio
async def test_registry_rejects_invalid_serializer_shapes() -> None:
    registry = WebhookEventRegistry()

    with pytest.raises(TypeError, match="event_type"):
        await registry.register(cast(Any, object()))

    class MissingSerialize:
        event_type = WebhookEventType("jobs.completed")

    with pytest.raises(TypeError, match="callable serialize"):
        await registry.register(cast(Any, MissingSerialize()))
