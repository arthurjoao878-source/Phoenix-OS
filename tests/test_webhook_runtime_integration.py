from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.configuration import Configuration, RuntimeAssembler
from phoenix_os.events import Event, EventBus
from phoenix_os.kernel import AllowAllAuthorizer, Kernel, Router
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef, SecretsManager
from phoenix_os.webhooks import (
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    WebhookDeliveryRepository,
    WebhookEgressPolicy,
    WebhookEndpoint,
    WebhookEventAlreadyRegisteredError,
    WebhookEventNotFoundError,
    WebhookEventType,
    WebhookPayload,
    WebhookRuntimeBundle,
    WebhookRuntimeState,
    WebhookSigningPolicy,
    WebhookSubscriptionRepository,
    create_webhook_runtime,
)

_RFC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "rfcs"
    / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"
)


class _Serializer:
    def __init__(self, event_name: str = "jobs.completed") -> None:
        self._event_type = WebhookEventType(
            event_name,
            resource_filter_fields=frozenset({"job_id"}),
        )

    @property
    def event_type(self) -> WebhookEventType:
        return self._event_type

    def serialize(self, event: Event) -> WebhookPayload:
        data: dict[str, object] = {
            "event_id": str(event.id),
            "source": event.source,
        }
        job_id = event.payload.get("job_id")
        if isinstance(job_id, str):
            data["job_id"] = job_id
        return WebhookPayload(
            event_type=self._event_type,
            data=data,
        )


def _assembler(
    *,
    webhooks_enabled: bool,
    secrets: SecretsManager | None = None,
    serializers: tuple[_Serializer, ...] = (),
    policies: Mapping[str, WebhookEgressPolicy] | None = None,
    subscriptions: WebhookSubscriptionRepository | None = None,
    deliveries: WebhookDeliveryRepository | None = None,
) -> RuntimeAssembler:
    events = EventBus()
    return RuntimeAssembler(
        kernel=Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        configuration=Configuration({}, {}),
        secrets=secrets,
        webhooks_enabled=webhooks_enabled,
        webhook_event_serializers=serializers,
        webhook_egress_policies=policies,
        webhook_subscription_repository=subscriptions,
        webhook_delivery_repository=deliveries,
        webhook_dispatch_poll_interval=60.0,
    )


def _manager_context(permission: str) -> SecurityContext:
    return SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({permission}),
    )


@pytest.mark.asyncio
async def test_disabled_assembler_registers_no_webhook_services() -> None:
    runtime = await _assembler(webhooks_enabled=False).assemble()
    snapshot = await runtime.snapshot()

    assert "webhooks" not in runtime.services
    assert all(not name.startswith("webhooks") for name in snapshot.components)

    await runtime.stop()


def test_webhook_options_require_explicit_enablement() -> None:
    with pytest.raises(
        ValueError,
        match="require webhooks_enabled",
    ):
        _assembler(
            webhooks_enabled=False,
            secrets=SecretsManager(),
            serializers=(_Serializer(),),
            policies={
                "default": WebhookEgressPolicy("default"),
            },
        )


def test_enabled_webhooks_require_secrets() -> None:
    with pytest.raises(
        ValueError,
        match="require a SecretsManager",
    ):
        _assembler(
            webhooks_enabled=True,
            serializers=(_Serializer(),),
            policies={
                "default": WebhookEgressPolicy("default"),
            },
        )


@pytest.mark.parametrize(
    ("serializers", "policies", "message"),
    [
        (
            (),
            {"default": WebhookEgressPolicy("default")},
            "at least one event serializer",
        ),
        (
            (_Serializer(),),
            {},
            "at least one egress policy",
        ),
    ],
)
def test_enabled_webhooks_require_reviewed_inputs(
    serializers: tuple[_Serializer, ...],
    policies: Mapping[str, WebhookEgressPolicy],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _assembler(
            webhooks_enabled=True,
            secrets=SecretsManager(),
            serializers=serializers,
            policies=policies,
        )


@pytest.mark.asyncio
async def test_runtime_exposes_owned_webhook_services_and_order() -> None:
    runtime = await _assembler(
        webhooks_enabled=True,
        secrets=SecretsManager(),
        serializers=(_Serializer(),),
        policies={
            "default": WebhookEgressPolicy("default"),
        },
    ).assemble()

    bundle = runtime.service("webhooks")
    assert isinstance(bundle, WebhookRuntimeBundle)
    assert runtime.service("webhooks.manager") is bundle.manager
    assert runtime.service("webhooks.dispatcher") is bundle.dispatcher
    assert runtime.service("webhooks.events") is bundle.event_adapter

    snapshot = await runtime.snapshot()
    owner_index = snapshot.components.index("webhooks")
    worker_index = snapshot.components.index("webhooks.dispatcher")
    adapter_index = snapshot.components.index("webhooks.events")
    assert owner_index < worker_index < adapter_index

    await runtime.stop()


@pytest.mark.asyncio
async def test_start_registers_and_recovers_before_event_subscription() -> None:
    runtime = await _assembler(
        webhooks_enabled=True,
        secrets=SecretsManager(),
        serializers=(_Serializer(),),
        policies={
            "default": WebhookEgressPolicy("default"),
        },
    ).assemble()
    bundle = runtime.service("webhooks")
    assert isinstance(bundle, WebhookRuntimeBundle)

    await runtime.start()

    event_types = await bundle.registry.list_event_types()
    owner = await bundle.owner.snapshot()
    adapter = await bundle.event_adapter.snapshot()

    assert tuple(item.name for item in event_types) == ("jobs.completed",)
    assert owner.state is WebhookRuntimeState.RUNNING
    assert owner.registered_events == 1
    assert owner.recovery_batches == 1
    assert adapter.started

    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_manager_rejects_unregistered_event_type() -> None:
    runtime = await _assembler(
        webhooks_enabled=True,
        secrets=SecretsManager(),
        serializers=(_Serializer(),),
        policies={
            "default": WebhookEgressPolicy("default"),
        },
    ).assemble()
    bundle = runtime.service("webhooks")
    assert isinstance(bundle, WebhookRuntimeBundle)
    await runtime.start()

    with pytest.raises(WebhookEventNotFoundError):
        await bundle.manager.create_subscription(
            _manager_context("webhook.subscription.create"),
            name="unsupported",
            display_name="Unsupported",
            event_types=frozenset({"workflows.completed"}),
            endpoint=WebhookEndpoint("https://hooks.example.test/phoenix"),
            signing=WebhookSigningPolicy(SecretRef("signing", "webhooks", 1)),
            egress_policy="default",
        )

    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_manager_accepts_registered_event_type() -> None:
    runtime = await _assembler(
        webhooks_enabled=True,
        secrets=SecretsManager(),
        serializers=(_Serializer(),),
        policies={
            "default": WebhookEgressPolicy("default"),
        },
    ).assemble()
    bundle = runtime.service("webhooks")
    assert isinstance(bundle, WebhookRuntimeBundle)
    await runtime.start()

    created = await bundle.manager.create_subscription(
        _manager_context("webhook.subscription.create"),
        name="jobs-completed",
        display_name="Jobs Completed",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.test/phoenix"),
        signing=WebhookSigningPolicy(SecretRef("signing", "webhooks", 1)),
        egress_policy="default",
    )

    assert created.event_types == ("jobs.completed",)
    assert created.endpoint.host == "hooks.example.test"

    await runtime.stop()


@pytest.mark.asyncio
async def test_event_adapter_creates_durable_delivery() -> None:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    runtime = await _assembler(
        webhooks_enabled=True,
        secrets=SecretsManager(),
        serializers=(_Serializer(),),
        policies={
            "default": WebhookEgressPolicy("default"),
        },
        subscriptions=subscriptions,
        deliveries=deliveries,
    ).assemble()
    bundle = runtime.service("webhooks")
    assert isinstance(bundle, WebhookRuntimeBundle)
    await runtime.start()

    await bundle.manager.create_subscription(
        _manager_context("webhook.subscription.create"),
        name="jobs-completed",
        display_name="Jobs Completed",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.test/phoenix"),
        signing=WebhookSigningPolicy(SecretRef("signing", "webhooks", 1)),
        egress_policy="default",
    )

    events = cast(EventBus, runtime.service("events"))
    await events.emit(
        "jobs.completed",
        source="test.jobs",
        payload={"job_id": "job-1"},
    )
    page = await deliveries.list()

    assert len(page.items) == 1
    assert page.items[0].event_type == "jobs.completed"
    assert page.items[0].canonical_body

    await runtime.stop()


@pytest.mark.asyncio
async def test_shutdown_closes_runtime_owned_webhook_resources() -> None:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    runtime = await _assembler(
        webhooks_enabled=True,
        secrets=SecretsManager(),
        serializers=(_Serializer(),),
        policies={
            "default": WebhookEgressPolicy("default"),
        },
        subscriptions=subscriptions,
        deliveries=deliveries,
    ).assemble()
    bundle = runtime.service("webhooks")
    assert isinstance(bundle, WebhookRuntimeBundle)

    await runtime.start()
    await runtime.stop()

    owner = await bundle.owner.snapshot()
    worker = await bundle.dispatcher_worker.snapshot()
    adapter = await bundle.event_adapter.snapshot()

    assert owner.state is WebhookRuntimeState.STOPPED
    assert worker.state is WebhookRuntimeState.STOPPED
    assert not adapter.started
    assert subscriptions.closed
    assert deliveries.closed
    assert bundle.registry.closed
    assert bundle.scheduler.closed
    assert bundle.dispatcher.closed
    assert bundle.recovery.closed
    assert bundle.manager.closed
    assert bundle.transport.closed


@pytest.mark.asyncio
async def test_duplicate_serializer_failure_closes_partial_runtime() -> None:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    bundle = create_webhook_runtime(
        events=EventBus(),
        subscriptions=subscriptions,
        deliveries=deliveries,
        secrets=SecretsManager(),
        serializers=(
            _Serializer(),
            _Serializer(),
        ),
        egress_policies={
            "default": WebhookEgressPolicy("default"),
        },
    )

    with pytest.raises(WebhookEventAlreadyRegisteredError):
        await bundle.owner.start()

    owner = await bundle.owner.snapshot()
    assert owner.state is WebhookRuntimeState.FAILED
    assert subscriptions.closed
    assert deliveries.closed
    assert bundle.registry.closed
    assert bundle.dispatcher.closed


def test_rfc_marks_runtime_ownership_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] RuntimeAssembler integration and lifecycle ownership" in rfc
    assert "stops event selection before the dispatcher" in rfc
