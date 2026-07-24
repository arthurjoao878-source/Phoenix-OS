from __future__ import annotations

import asyncio
from collections import Counter, deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    WEBHOOK_ATTEMPT_HEADER,
    WEBHOOK_CONTENT_TYPE,
    WEBHOOK_CONTENT_TYPE_HEADER,
    WEBHOOK_ID_HEADER,
    WEBHOOK_KEY_VERSION_HEADER,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_TIMESTAMP_HEADER,
    WEBHOOK_USER_AGENT,
    WEBHOOK_USER_AGENT_HEADER,
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookDispatchDisposition,
    WebhookDispatcher,
    WebhookDispatcherClosedError,
    WebhookDispatcherConfig,
    WebhookEgressPolicy,
    WebhookEndpoint,
    WebhookEndpointRejectedError,
    WebhookEventType,
    WebhookHttpStatusClass,
    WebhookPayload,
    WebhookRequestTransport,
    WebhookRetryPolicy,
    WebhookSignedRequest,
    WebhookSigningError,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionStatus,
    WebhookTransportError,
    WebhookTransportResult,
    new_webhook_delivery,
    webhook_retry_delay,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_FAKE_SIGNATURE_DIGEST = "a5" * 32


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


class _RecordingSigner:
    def __init__(self, failures: tuple[Exception, ...] = ()) -> None:
        self.versions: list[int] = []
        self._failures = deque(failures)

    async def sign(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription,
        *,
        attempt: int,
        timestamp: datetime | None = None,
    ) -> WebhookSignedRequest:
        del timestamp
        await asyncio.sleep(0)
        self.versions.append(subscription.signing.key_version)
        if self._failures:
            raise self._failures.popleft()
        timestamp_value = _NOW
        headers = {
            WEBHOOK_CONTENT_TYPE_HEADER: WEBHOOK_CONTENT_TYPE,
            WEBHOOK_USER_AGENT_HEADER: WEBHOOK_USER_AGENT,
            WEBHOOK_ID_HEADER: str(delivery.id),
            WEBHOOK_TIMESTAMP_HEADER: "2026-07-24T12:00:00Z",
            WEBHOOK_SIGNATURE_HEADER: (
                f"{subscription.signing.scheme.value}={_FAKE_SIGNATURE_DIGEST}"
            ),
            WEBHOOK_KEY_VERSION_HEADER: str(subscription.signing.key_version),
            WEBHOOK_ATTEMPT_HEADER: str(attempt),
        }
        return WebhookSignedRequest(
            delivery_id=delivery.id,
            subscription_id=subscription.id,
            attempt=attempt,
            timestamp=timestamp_value,
            key_version=subscription.signing.key_version,
            scheme=subscription.signing.scheme,
            body=delivery.canonical_body,
            headers=headers,
        )


class _QueueTransport:
    def __init__(self, outcomes: tuple[WebhookTransportResult | Exception, ...]) -> None:
        self._outcomes = deque(outcomes)
        self.key_versions: list[int] = []

    async def send(
        self,
        request: WebhookSignedRequest,
        subscription: WebhookSubscription,
        *,
        policy: WebhookEgressPolicy,
    ) -> WebhookTransportResult:
        await asyncio.sleep(0)
        assert policy.name == subscription.egress_policy
        self.key_versions.append(request.key_version)
        outcome = self._outcomes.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _GateTransport:
    def __init__(self, expected_active: int) -> None:
        self._expected_active = expected_active
        self._release = asyncio.Event()
        self.ready = asyncio.Event()
        self.active = 0
        self.maximum = 0
        self.per_endpoint: Counter[str] = Counter()
        self.per_endpoint_maximum: Counter[str] = Counter()
        self._lock = asyncio.Lock()

    async def send(
        self,
        request: WebhookSignedRequest,
        subscription: WebhookSubscription,
        *,
        policy: WebhookEgressPolicy,
    ) -> WebhookTransportResult:
        del request, policy
        endpoint = subscription.endpoint.url
        async with self._lock:
            self.active += 1
            self.maximum = max(self.maximum, self.active)
            self.per_endpoint[endpoint] += 1
            self.per_endpoint_maximum[endpoint] = max(
                self.per_endpoint_maximum[endpoint],
                self.per_endpoint[endpoint],
            )
            if self.active == self._expected_active:
                self.ready.set()
        await self._release.wait()
        async with self._lock:
            self.active -= 1
            self.per_endpoint[endpoint] -= 1
        return _success()

    def release(self) -> None:
        self._release.set()


def _success() -> WebhookTransportResult:
    return WebhookTransportResult(
        status_code=204,
        status_class=WebhookHttpStatusClass.SUCCESSFUL,
        successful=True,
        retryable=False,
        error_category=None,
        response_body_bytes=0,
    )


def _retryable() -> WebhookTransportResult:
    return WebhookTransportResult(
        status_code=503,
        status_class=WebhookHttpStatusClass.SERVER_ERROR,
        successful=False,
        retryable=True,
        error_category="http_server_error",
        response_body_bytes=0,
    )


def _terminal() -> WebhookTransportResult:
    return WebhookTransportResult(
        status_code=400,
        status_class=WebhookHttpStatusClass.CLIENT_ERROR,
        successful=False,
        retryable=False,
        error_category="http_client_error",
        response_body_bytes=0,
    )


def _subscription(
    index: int = 1,
    *,
    endpoint: str = "https://hooks.example.com/phoenix",
    key_version: int = 1,
    retry: WebhookRetryPolicy | None = None,
    egress_policy: str = "production.webhooks",
) -> WebhookSubscription:
    return WebhookSubscription(
        id=UUID(int=1_000 + index),
        name=f"release.notifications.{index}",
        display_name=f"Release Notifications {index}",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint(endpoint),
        signing=WebhookSigningPolicy(
            SecretRef(f"release-webhook-{index}", "integrations", key_version)
        ),
        egress_policy=egress_policy,
        retry=WebhookRetryPolicy() if retry is None else retry,
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
    )


def _delivery(
    subscription: WebhookSubscription,
    index: int = 1,
    *,
    created_at: datetime = _NOW,
) -> WebhookDelivery:
    event_type = WebhookEventType("jobs.completed")
    event = Event(
        id=UUID(int=2_000 + index),
        name=event_type.name,
        source="scheduler",
        occurred_at=_NOW,
        correlation_id=f"delivery-correlation-{index}",
        payload={"job_id": f"job-{index}", "private_token": "must-not-leak"},
    )
    payload = WebhookPayload(
        event_type=event_type,
        data={"job_id": f"job-{index}"},
    )
    return new_webhook_delivery(
        subscription,
        event,
        payload,
        delivery_id=UUID(int=3_000 + index),
        created_at=created_at,
    )


async def _dispatcher(
    *,
    subscriptions: tuple[WebhookSubscription, ...],
    deliveries: tuple[WebhookDelivery, ...],
    signer: _RecordingSigner,
    transport: WebhookRequestTransport,
    clock: _Clock,
    policies: tuple[WebhookEgressPolicy, ...] | None = None,
    config: WebhookDispatcherConfig | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> tuple[
    InMemoryWebhookSubscriptionRepository,
    InMemoryWebhookDeliveryRepository,
    WebhookDispatcher,
]:
    subscription_repository = InMemoryWebhookSubscriptionRepository()
    delivery_repository = InMemoryWebhookDeliveryRepository()
    for subscription in subscriptions:
        await subscription_repository.add(subscription)
    for delivery in deliveries:
        await delivery_repository.add(delivery)
    resolved_policies = (
        (WebhookEgressPolicy("production.webhooks"),) if policies is None else policies
    )
    dispatcher = WebhookDispatcher(
        subscriptions=subscription_repository,
        deliveries=delivery_repository,
        signer=signer,
        transport=transport,
        egress_policies={policy.name: policy for policy in resolved_policies},
        config=config,
        audit=audit,
        observability=observability,
        clock=clock,
    )
    return subscription_repository, delivery_repository, dispatcher


def test_dispatcher_config_rejects_unbounded_concurrency() -> None:
    with pytest.raises(ValueError, match="batch size"):
        WebhookDispatcherConfig(batch_size=0)
    with pytest.raises(ValueError, match="global concurrency"):
        WebhookDispatcherConfig(global_concurrency=0)
    with pytest.raises(ValueError, match="cannot exceed"):
        WebhookDispatcherConfig(global_concurrency=2, per_endpoint_concurrency=3)


def test_retry_delay_is_deterministic_bounded_and_non_secret() -> None:
    subscription = _subscription(
        retry=WebhookRetryPolicy(
            max_attempts=4,
            initial_delay=timedelta(seconds=10),
            multiplier=2,
            max_delay=timedelta(seconds=60),
            jitter_ratio=0.25,
        )
    )
    delivery = _delivery(subscription)

    first = webhook_retry_delay(delivery, subscription, 1)
    second = webhook_retry_delay(delivery, subscription, 1)

    assert first == second
    assert timedelta(seconds=7.5) <= first <= timedelta(seconds=12.5)
    assert "release-webhook" not in repr(first)


@pytest.mark.asyncio
async def test_successful_attempt_is_durable_audited_and_observable() -> None:
    subscription = _subscription()
    delivery = _delivery(subscription)
    clock = _Clock()
    signer = _RecordingSigner()
    transport = _QueueTransport((_success(),))
    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    _, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=signer,
        transport=transport,
        clock=clock,
        audit=audit,
        observability=observability,
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.SUCCEEDED
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.SUCCEEDED
    assert persisted.completed_attempts == 1
    assert persisted.attempts[0].status_class is WebhookHttpStatusClass.SUCCESSFUL

    records = await audit.read(
        AuditQuery(),
        SecurityContext(
            principal="maintainer:test",
            principal_type=PrincipalType.USER,
            authenticated=True,
            permissions=frozenset({"audit.read"}),
        ),
    )
    assert len(records) == 1
    assert records[0].event.action == "webhook.delivery.attempt"
    assert records[0].event.details["key_version"] == 1
    observations = await sink.snapshot()
    rendered = repr((records, observations.records))
    assert "must-not-leak" not in rendered
    assert _FAKE_SIGNATURE_DIGEST not in rendered


@pytest.mark.asyncio
async def test_retryable_result_schedules_deterministic_retry() -> None:
    subscription = _subscription(
        retry=WebhookRetryPolicy(
            max_attempts=3,
            initial_delay=timedelta(seconds=10),
            multiplier=2,
            max_delay=timedelta(seconds=30),
            jitter_ratio=0,
        )
    )
    delivery = _delivery(subscription)
    clock = _Clock()
    _, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=_RecordingSigner(),
        transport=_QueueTransport((_retryable(),)),
        clock=clock,
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.RETRYING
    assert result.next_attempt_at == _NOW + timedelta(seconds=10)
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.RETRYING
    assert persisted.attempts[0].retry_scheduled is True
    assert persisted.next_attempt_at == result.next_attempt_at


@pytest.mark.asyncio
async def test_retry_budget_exhaustion_enters_dead_letter() -> None:
    subscription = _subscription(retry=WebhookRetryPolicy(max_attempts=1))
    delivery = _delivery(subscription)
    _, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=_RecordingSigner(),
        transport=_QueueTransport((_retryable(),)),
        clock=_Clock(),
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.DEAD_LETTER
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.DEAD_LETTER
    assert persisted.attempts[-1].retry_scheduled is False


@pytest.mark.asyncio
async def test_terminal_response_marks_delivery_failed() -> None:
    subscription = _subscription()
    delivery = _delivery(subscription)
    _, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=_RecordingSigner(),
        transport=_QueueTransport((_terminal(),)),
        clock=_Clock(),
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.FAILED
    assert result.status_class is WebhookHttpStatusClass.CLIENT_ERROR
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.FAILED


@pytest.mark.asyncio
async def test_disabled_subscription_is_cancelled_before_signing() -> None:
    active = _subscription()
    delivery = _delivery(active)
    subscription = replace(
        active,
        status=WebhookSubscriptionStatus.DISABLED,
        disabled_at=_NOW,
        revision=2,
    )
    signer = _RecordingSigner()
    _, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=signer,
        transport=_QueueTransport((_success(),)),
        clock=_Clock(),
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.CANCELLED
    assert result.error_category == "subscription_inactive"
    assert signer.versions == []
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.CANCELLED


@pytest.mark.asyncio
async def test_each_retry_uses_latest_explicit_signing_key_version() -> None:
    subscription = _subscription(
        retry=WebhookRetryPolicy(
            max_attempts=3,
            initial_delay=timedelta(seconds=1),
            max_delay=timedelta(seconds=1),
            jitter_ratio=0,
        )
    )
    delivery = _delivery(subscription)
    clock = _Clock()
    signer = _RecordingSigner()
    subscriptions, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=signer,
        transport=_QueueTransport((_retryable(), _success())),
        clock=clock,
    )

    first = await dispatcher.dispatch(delivery.id)
    assert first.next_attempt_at is not None
    clock.value = first.next_attempt_at
    rotated = replace(
        subscription,
        signing=WebhookSigningPolicy(SecretRef("release-webhook-1", "integrations", 2)),
        updated_at=clock.value,
        revision=subscription.revision + 1,
    )
    await subscriptions.replace(rotated, expected_revision=subscription.revision)

    second = await dispatcher.dispatch(delivery.id)

    assert second.disposition is WebhookDispatchDisposition.SUCCEEDED
    assert signer.versions == [1, 2]
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.completed_attempts == 2


@pytest.mark.asyncio
async def test_global_and_per_endpoint_limits_are_enforced() -> None:
    first = _subscription(1, endpoint="https://a.example.com/hooks")
    second = _subscription(2, endpoint="https://a.example.com/hooks")
    third = _subscription(3, endpoint="https://b.example.com/hooks")
    fourth = _subscription(4, endpoint="https://b.example.com/hooks")
    deliveries = tuple(
        _delivery(subscription, index)
        for index, subscription in enumerate((first, second, third, fourth), start=1)
    )
    gate = _GateTransport(expected_active=2)
    _, _, dispatcher = await _dispatcher(
        subscriptions=(first, second, third, fourth),
        deliveries=deliveries,
        signer=_RecordingSigner(),
        transport=gate,
        clock=_Clock(),
        config=WebhookDispatcherConfig(
            batch_size=4,
            global_concurrency=2,
            per_endpoint_concurrency=1,
        ),
    )

    task = asyncio.create_task(dispatcher.dispatch_due(limit=4))
    await asyncio.wait_for(gate.ready.wait(), timeout=1)
    await asyncio.sleep(0)
    assert gate.maximum == 2
    assert max(gate.per_endpoint_maximum.values()) == 1
    gate.release()
    batch = await task

    assert batch.considered == 4
    assert batch.count(WebhookDispatchDisposition.SUCCEEDED) == 4
    snapshot = await dispatcher.snapshot()
    assert snapshot.saturation_events >= 1
    assert snapshot.active == 0


@pytest.mark.asyncio
async def test_missing_egress_policy_fails_closed_without_transport() -> None:
    subscription = _subscription(egress_policy="missing.webhooks")
    delivery = _delivery(subscription)
    signer = _RecordingSigner()
    transport = _QueueTransport((_success(),))
    _, deliveries, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=signer,
        transport=transport,
        clock=_Clock(),
        policies=(),
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.FAILED
    assert result.error_category == "egress_policy_missing"
    assert signer.versions == []
    assert transport.key_versions == []
    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.FAILED


@pytest.mark.asyncio
async def test_safe_endpoint_and_transport_errors_drive_policy() -> None:
    first = _subscription(1)
    second = _subscription(2)
    first_delivery = _delivery(first, 1)
    second_delivery = _delivery(second, 2)
    _, _, dispatcher = await _dispatcher(
        subscriptions=(first, second),
        deliveries=(first_delivery, second_delivery),
        signer=_RecordingSigner(),
        transport=_QueueTransport(
            (
                WebhookEndpointRejectedError("destination_not_allowed"),
                WebhookTransportError("timeout", retryable=True),
            )
        ),
        clock=_Clock(),
    )

    first_result = await dispatcher.dispatch(first_delivery.id)
    second_result = await dispatcher.dispatch(second_delivery.id)

    assert first_result.disposition is WebhookDispatchDisposition.FAILED
    assert first_result.error_category == "destination_not_allowed"
    assert second_result.disposition is WebhookDispatchDisposition.RETRYING
    assert second_result.error_category == "timeout"
    snapshot = await dispatcher.snapshot()
    assert snapshot.endpoint_rejections == 1
    assert snapshot.transport_failures == 1


@pytest.mark.asyncio
async def test_signing_failure_is_retryable_and_redacted() -> None:
    subscription = _subscription()
    delivery = _delivery(subscription)
    _, _, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=_RecordingSigner((WebhookSigningError("secret material unavailable"),)),
        transport=_QueueTransport((_success(),)),
        clock=_Clock(),
    )

    result = await dispatcher.dispatch(delivery.id)

    assert result.disposition is WebhookDispatchDisposition.RETRYING
    assert result.error_category == "signing_failed"
    assert "secret material unavailable" not in repr(result)
    snapshot = await dispatcher.snapshot()
    assert snapshot.signing_failures == 1


@pytest.mark.asyncio
async def test_dispatch_due_orders_due_items_and_skips_future_work() -> None:
    subscription = _subscription()
    first = _delivery(subscription, 1)
    second = _delivery(subscription, 2)
    future = replace(
        _delivery(subscription, 3),
        next_attempt_at=_NOW + timedelta(hours=1),
    )
    _, _, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(future, second, first),
        signer=_RecordingSigner(),
        transport=_QueueTransport((_success(), _success())),
        clock=_Clock(),
    )

    batch = await dispatcher.dispatch_due(limit=2)

    assert [item.delivery_id for item in batch.results] == [first.id, second.id]
    snapshot = await dispatcher.snapshot()
    assert snapshot.succeeded == 2
    assert snapshot.pending_deliveries == 1


@pytest.mark.asyncio
async def test_closed_dispatcher_rejects_new_work() -> None:
    subscription = _subscription()
    delivery = _delivery(subscription)
    _, _, dispatcher = await _dispatcher(
        subscriptions=(subscription,),
        deliveries=(delivery,),
        signer=_RecordingSigner(),
        transport=_QueueTransport((_success(),)),
        clock=_Clock(),
    )
    await dispatcher.close()

    with pytest.raises(WebhookDispatcherClosedError):
        await dispatcher.dispatch(delivery.id)
