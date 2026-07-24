from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.state import MemoryStateStore
from phoenix_os.webhooks import (
    WEBHOOK_REDRIVE_PERMISSION,
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    StateWebhookDeliveryRepository,
    StateWebhookSubscriptionRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryRecovery,
    WebhookDeliveryStatus,
    WebhookDispatchDisposition,
    WebhookDispatcher,
    WebhookEgressPolicy,
    WebhookEndpoint,
    WebhookHttpStatusClass,
    WebhookRecoveryClosedError,
    WebhookRecoveryDisposition,
    WebhookRedriveAccessDeniedError,
    WebhookRedriveNotEligibleError,
    WebhookRetryPolicy,
    WebhookSignedRequest,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionStatus,
    WebhookTransportResult,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000401")
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000402")


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class _Signer:
    async def sign(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription,
        *,
        attempt: int,
        timestamp: datetime | None = None,
    ) -> WebhookSignedRequest:
        del delivery, subscription, attempt, timestamp
        return cast(WebhookSignedRequest, object())


class _SuccessfulTransport:
    async def send(
        self,
        request: WebhookSignedRequest,
        subscription: WebhookSubscription,
        *,
        policy: WebhookEgressPolicy,
    ) -> WebhookTransportResult:
        del request, subscription, policy
        return WebhookTransportResult(
            status_code=204,
            status_class=WebhookHttpStatusClass.SUCCESSFUL,
            successful=True,
            retryable=False,
            error_category=None,
            response_body_bytes=0,
        )


def _context(*, permitted: bool = True, authenticated: bool = True) -> SecurityContext:
    permissions = frozenset({WEBHOOK_REDRIVE_PERMISSION}) if permitted else frozenset()
    principal_type = PrincipalType.USER if authenticated else PrincipalType.ANONYMOUS
    return SecurityContext(
        principal="maintainer:test" if authenticated else "anonymous",
        principal_type=principal_type,
        authenticated=authenticated,
        permissions=permissions,
        correlation_id="redrive-correlation",
    )


def _subscription(
    *,
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE,
    max_attempts: int = 3,
) -> WebhookSubscription:
    inactive_at = _NOW + timedelta(seconds=30)
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="recovery.notifications",
        display_name="Recovery Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/phoenix"),
        signing=WebhookSigningPolicy(SecretRef("webhook-key", "integrations", 1)),
        egress_policy="production.webhooks",
        retry=WebhookRetryPolicy(
            max_attempts=max_attempts,
            initial_delay=timedelta(seconds=1),
            multiplier=2,
            max_delay=timedelta(seconds=30),
            jitter_ratio=0,
        ),
        created_at=_NOW,
        updated_at=_NOW if status is WebhookSubscriptionStatus.ACTIVE else inactive_at,
        created_by="maintainer:test",
        status=status,
        disabled_at=inactive_at if status is WebhookSubscriptionStatus.DISABLED else None,
        revoked_at=inactive_at if status is WebhookSubscriptionStatus.REVOKED else None,
    )


def _attempts(
    delivery_id: UUID,
    count: int,
    *,
    final_retry_scheduled: bool = False,
) -> tuple[WebhookAttempt, ...]:
    attempts: list[WebhookAttempt] = []
    scheduled_at = _NOW
    for number in range(1, count + 1):
        started_at = scheduled_at
        finished_at = started_at + timedelta(seconds=1)
        retry_scheduled = number < count or final_retry_scheduled
        next_attempt_at = finished_at + timedelta(seconds=1) if retry_scheduled else None
        attempts.append(
            WebhookAttempt(
                delivery_id=delivery_id,
                number=number,
                scheduled_at=scheduled_at,
                started_at=started_at,
                finished_at=finished_at,
                outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
                retry_scheduled=retry_scheduled,
                next_attempt_at=next_attempt_at,
                error_category="io_failed",
            )
        )
        scheduled_at = next_attempt_at or finished_at
    return tuple(attempts)


def _delivery_body(delivery_id: UUID) -> bytes:
    return b'{"delivery_id":"' + str(delivery_id).encode("ascii") + b'","safe":"must-not-leak"}'


def _dead_letter(
    *,
    delivery_id: UUID = _DELIVERY_ID,
    attempts: int = 2,
) -> WebhookDelivery:
    history = _attempts(delivery_id, attempts)
    terminal_at = history[-1].finished_at
    body = _delivery_body(delivery_id)
    return WebhookDelivery(
        id=delivery_id,
        subscription_id=_SUBSCRIPTION_ID,
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(f"dedupe:{delivery_id}".encode()).hexdigest(),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=terminal_at,
        status=WebhookDeliveryStatus.DEAD_LETTER,
        source_event_id=delivery_id,
        correlation_id="delivery-correlation",
        attempts=history,
        terminal_at=terminal_at,
    )


def _pending(*, delivery_id: UUID = _DELIVERY_ID) -> WebhookDelivery:
    body = _delivery_body(delivery_id)
    return WebhookDelivery(
        id=delivery_id,
        subscription_id=_SUBSCRIPTION_ID,
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(f"dedupe:{delivery_id}".encode()).hexdigest(),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=_NOW,
        source_event_id=delivery_id,
        next_attempt_at=_NOW,
    )


def _in_flight(
    *,
    delivery_id: UUID = _DELIVERY_ID,
    completed_attempts: int = 0,
    offset_seconds: int = 10,
) -> WebhookDelivery:
    history = _attempts(
        delivery_id,
        completed_attempts,
        final_retry_scheduled=completed_attempts > 0,
    )
    if history:
        in_flight_at = history[-1].next_attempt_at
        assert in_flight_at is not None
    else:
        in_flight_at = _NOW + timedelta(seconds=offset_seconds)
    body = _delivery_body(delivery_id)
    return WebhookDelivery(
        id=delivery_id,
        subscription_id=_SUBSCRIPTION_ID,
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(f"dedupe:{delivery_id}".encode()).hexdigest(),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=in_flight_at,
        status=WebhookDeliveryStatus.IN_FLIGHT,
        source_event_id=delivery_id,
        correlation_id="delivery-correlation",
        attempts=history,
        current_attempt=completed_attempts + 1,
        in_flight_at=in_flight_at,
    )


async def _memory_recovery(
    subscription: WebhookSubscription,
    delivery: WebhookDelivery,
    *,
    clock: _Clock,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> tuple[
    InMemoryWebhookSubscriptionRepository,
    InMemoryWebhookDeliveryRepository,
    WebhookDeliveryRecovery,
]:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    await subscriptions.add(subscription)
    await deliveries.add(delivery)
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        audit=audit,
        observability=observability,
        clock=clock,
    )
    return subscriptions, deliveries, recovery


@pytest.mark.asyncio
async def test_authorized_redrive_preserves_identity_body_and_attempt_history() -> None:
    subscription = _subscription()
    delivery = _dead_letter()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, deliveries, recovery = await _memory_recovery(
        subscription,
        delivery,
        clock=clock,
    )

    result = await recovery.redrive(delivery.id, _context())

    persisted = await deliveries.get(delivery.id)
    assert persisted is not None
    assert result.status is WebhookDeliveryStatus.RETRYING
    assert persisted.status is WebhookDeliveryStatus.RETRYING
    assert persisted.id == delivery.id
    assert persisted.canonical_body == delivery.canonical_body
    assert persisted.body_sha256 == delivery.body_sha256
    assert persisted.deduplication_key == delivery.deduplication_key
    assert persisted.attempts == delivery.attempts
    assert persisted.next_attempt_at == result.next_attempt_at
    assert persisted.terminal_at is None
    assert not persisted.attempts[-1].retry_scheduled
    assert not persisted.redrive_eligible


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("authenticated", "permitted"),
    ((False, False), (True, False)),
)
async def test_redrive_requires_authenticated_permission(
    authenticated: bool,
    permitted: bool,
) -> None:
    delivery = _dead_letter()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, deliveries, recovery = await _memory_recovery(
        _subscription(),
        delivery,
        clock=clock,
    )

    with pytest.raises(WebhookRedriveAccessDeniedError):
        await recovery.redrive(
            delivery.id,
            _context(authenticated=authenticated, permitted=permitted),
        )

    persisted = await deliveries.get(delivery.id)
    assert persisted == delivery
    snapshot = await recovery.snapshot()
    assert snapshot.redrive_denied == 1


@pytest.mark.asyncio
async def test_redrive_rejects_non_dead_letter_delivery() -> None:
    delivery = _pending()
    clock = _Clock(_NOW + timedelta(minutes=1))
    _, _, recovery = await _memory_recovery(
        _subscription(),
        delivery,
        clock=clock,
    )

    with pytest.raises(WebhookRedriveNotEligibleError) as captured:
        await recovery.redrive(delivery.id, _context())

    assert captured.value.category == "delivery_not_eligible"


@pytest.mark.asyncio
async def test_redrive_rejects_global_attempt_exhaustion() -> None:
    delivery = _dead_letter(attempts=20)
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, _, recovery = await _memory_recovery(
        _subscription(max_attempts=20),
        delivery,
        clock=clock,
    )

    assert not delivery.redrive_eligible
    with pytest.raises(WebhookRedriveNotEligibleError):
        await recovery.redrive(delivery.id, _context())


@pytest.mark.asyncio
async def test_redrive_rejects_inactive_subscription() -> None:
    delivery = _dead_letter()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, _, recovery = await _memory_recovery(
        _subscription(status=WebhookSubscriptionStatus.DISABLED),
        delivery,
        clock=clock,
    )

    with pytest.raises(WebhookRedriveNotEligibleError) as captured:
        await recovery.redrive(delivery.id, _context())

    assert captured.value.category == "subscription_inactive"


@pytest.mark.asyncio
async def test_redriven_delivery_dispatches_with_next_contiguous_attempt() -> None:
    subscription = _subscription()
    delivery = _dead_letter()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    subscriptions, deliveries, recovery = await _memory_recovery(
        subscription,
        delivery,
        clock=clock,
    )
    redrive = await recovery.redrive(delivery.id, _context())
    clock.now = redrive.next_attempt_at

    dispatcher = WebhookDispatcher(
        subscriptions=subscriptions,
        deliveries=deliveries,
        signer=_Signer(),
        transport=_SuccessfulTransport(),
        egress_policies={"production.webhooks": WebhookEgressPolicy("production.webhooks")},
        clock=clock,
    )
    result = await dispatcher.dispatch(delivery.id)

    persisted = await deliveries.get(delivery.id)
    assert result.disposition is WebhookDispatchDisposition.SUCCEEDED
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.SUCCEEDED
    assert persisted.completed_attempts == delivery.completed_attempts + 1
    assert persisted.attempts[-1].number == delivery.completed_attempts + 1


@pytest.mark.asyncio
async def test_recovery_schedules_retry_and_retains_interrupted_attempt() -> None:
    subscription = _subscription(max_attempts=3)
    delivery = _in_flight()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, deliveries, recovery = await _memory_recovery(
        subscription,
        delivery,
        clock=clock,
    )

    batch = await recovery.recover_in_flight()

    persisted = await deliveries.get(delivery.id)
    assert batch.count(WebhookRecoveryDisposition.RETRYING) == 1
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.RETRYING
    assert persisted.completed_attempts == 1
    assert persisted.attempts[-1].error_category == "runtime_recovery"
    assert persisted.attempts[-1].retry_scheduled
    assert persisted.next_attempt_at == persisted.attempts[-1].next_attempt_at


@pytest.mark.asyncio
async def test_recovery_dead_letters_exhausted_interrupted_attempt() -> None:
    subscription = _subscription(max_attempts=1)
    delivery = _in_flight()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, deliveries, recovery = await _memory_recovery(
        subscription,
        delivery,
        clock=clock,
    )

    batch = await recovery.recover_in_flight()

    persisted = await deliveries.get(delivery.id)
    assert batch.count(WebhookRecoveryDisposition.DEAD_LETTER) == 1
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.DEAD_LETTER
    assert persisted.redrive_eligible
    assert not persisted.attempts[-1].retry_scheduled
    assert persisted.terminal_at is not None


@pytest.mark.asyncio
async def test_recovery_cancels_interrupted_delivery_for_inactive_subscription() -> None:
    delivery = _in_flight()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, deliveries, recovery = await _memory_recovery(
        _subscription(status=WebhookSubscriptionStatus.REVOKED),
        delivery,
        clock=clock,
    )

    batch = await recovery.recover_in_flight()

    persisted = await deliveries.get(delivery.id)
    assert batch.count(WebhookRecoveryDisposition.CANCELLED) == 1
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.CANCELLED
    assert persisted.completed_attempts == 0


@pytest.mark.asyncio
async def test_recovery_batch_is_deterministic_and_bounded() -> None:
    subscription = _subscription(max_attempts=3)
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    await subscriptions.add(subscription)

    first_id = UUID("00000000-0000-4000-8000-000000000411")
    second_id = UUID("00000000-0000-4000-8000-000000000412")
    third_id = UUID("00000000-0000-4000-8000-000000000413")
    first = _in_flight(delivery_id=first_id, offset_seconds=30)
    second = _in_flight(delivery_id=second_id, offset_seconds=10)
    third = _in_flight(delivery_id=third_id, offset_seconds=20)
    for delivery in (first, second, third):
        await deliveries.add(delivery)

    clock = _Clock(_NOW + timedelta(minutes=2))
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=clock,
    )
    batch = await recovery.recover_in_flight(limit=2)

    assert tuple(item.delivery_id for item in batch.results) == (second_id, third_id)
    remaining = await deliveries.get(first_id)
    assert remaining is not None
    assert remaining.status is WebhookDeliveryStatus.IN_FLIGHT


@pytest.mark.asyncio
async def test_state_repository_retains_redrive_across_recreation() -> None:
    delivery = _dead_letter()
    subscription = _subscription()
    store = MemoryStateStore()
    subscriptions = StateWebhookSubscriptionRepository(store)
    deliveries = StateWebhookDeliveryRepository(store)
    await subscriptions.add(subscription)
    await deliveries.add(delivery)
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=clock,
    )

    await recovery.redrive(delivery.id, _context())

    recovered_subscriptions = StateWebhookSubscriptionRepository(store)
    recovered_deliveries = StateWebhookDeliveryRepository(store)
    persisted = await recovered_deliveries.get(delivery.id)
    assert await recovered_subscriptions.get(subscription.id) == subscription
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.RETRYING
    assert persisted.attempts == delivery.attempts
    assert persisted.canonical_body == delivery.canonical_body
    assert persisted.terminal_at is None


@pytest.mark.asyncio
async def test_state_repository_retains_interrupted_recovery_across_recreation() -> None:
    delivery = _in_flight()
    subscription = _subscription(max_attempts=3)
    store = MemoryStateStore()
    subscriptions = StateWebhookSubscriptionRepository(store)
    deliveries = StateWebhookDeliveryRepository(store)
    await subscriptions.add(subscription)
    await deliveries.add(delivery)
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=clock,
    )

    await recovery.recover_in_flight()

    recovered_deliveries = StateWebhookDeliveryRepository(store)
    persisted = await recovered_deliveries.get(delivery.id)
    assert persisted is not None
    assert persisted.status is WebhookDeliveryStatus.RETRYING
    assert persisted.completed_attempts == 1
    assert persisted.attempts[-1].error_category == "runtime_recovery"


@pytest.mark.asyncio
async def test_redrive_and_recovery_audit_and_observability_are_redacted() -> None:
    subscription = _subscription()
    delivery = _dead_letter()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    audit = AuditLedger(InMemoryAuditStore())
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    _, _, recovery = await _memory_recovery(
        subscription,
        delivery,
        clock=clock,
        audit=audit,
        observability=observability,
    )

    await recovery.redrive(delivery.id, _context())

    records = await audit.read(
        AuditQuery(),
        SecurityContext(
            principal="maintainer:test",
            principal_type=PrincipalType.USER,
            authenticated=True,
            permissions=frozenset({"audit.read"}),
        ),
    )
    observations = await sink.snapshot()
    rendered = repr((records, observations.records))
    assert len(records) == 1
    assert records[0].event.action == "webhook.delivery.redrive"
    assert "must-not-leak" not in rendered
    assert delivery.body_sha256 not in rendered
    assert subscription.endpoint.url not in rendered
    assert subscription.signing.secret_ref.canonical not in rendered


def test_manual_redrive_schedule_must_follow_final_attempt() -> None:
    delivery = _dead_letter()
    with pytest.raises(ValueError, match="manual redrive"):
        replace(
            delivery,
            status=WebhookDeliveryStatus.RETRYING,
            updated_at=delivery.updated_at,
            next_attempt_at=delivery.attempts[-1].finished_at,
            terminal_at=None,
            revision=delivery.revision + 1,
        )


@pytest.mark.asyncio
async def test_closed_recovery_rejects_new_work() -> None:
    delivery = _dead_letter()
    clock = _Clock(delivery.updated_at + timedelta(minutes=1))
    _, _, recovery = await _memory_recovery(
        _subscription(),
        delivery,
        clock=clock,
    )
    await recovery.close()

    with pytest.raises(WebhookRecoveryClosedError):
        await recovery.redrive(delivery.id, _context())
    with pytest.raises(WebhookRecoveryClosedError):
        await recovery.recover_in_flight()
