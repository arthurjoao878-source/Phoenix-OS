from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    WEBHOOK_DELIVERIES_READ_PERMISSION,
    WEBHOOK_HEALTH_READ_PERMISSION,
    WEBHOOK_REDRIVE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryRecovery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookManager,
    WebhookManagerAccessDeniedError,
    WebhookManagerClosedError,
    WebhookPageRequest,
    WebhookRetryPolicy,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionStatus,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(minutes=3)
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000001001")
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000002001")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000003001")

_ALL_PERMISSIONS = frozenset(
    {
        WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION,
        WEBHOOK_DELIVERIES_READ_PERMISSION,
        WEBHOOK_REDRIVE_PERMISSION,
        WEBHOOK_HEALTH_READ_PERMISSION,
    }
)


def _context(*, permissions: frozenset[str] = _ALL_PERMISSIONS) -> SecurityContext:
    return SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=permissions,
        correlation_id="management-correlation",
    )


def _subscription(
    *,
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE,
    revision: int = 1,
    signing_version: int = 1,
) -> WebhookSubscription:
    disabled_at = _NOW if status is WebhookSubscriptionStatus.DISABLED else None
    revoked_at = _NOW if status is WebhookSubscriptionStatus.REVOKED else None
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint(
            "https://hooks.example.com/private-path-token",
        ),
        signing=WebhookSigningPolicy(
            SecretRef("must-not-leak", "integrations", signing_version),
        ),
        egress_policy="production.webhooks",
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        retry=WebhookRetryPolicy(
            max_attempts=3,
            initial_delay=timedelta(seconds=5),
            max_delay=timedelta(minutes=1),
        ),
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
    )


def _dead_letter(subscription: WebhookSubscription) -> WebhookDelivery:
    body = b'{"payload":{"job_id":"job-1","token":"must-not-leak"}}'
    started = _NOW + timedelta(minutes=1)
    finished = _NOW + timedelta(minutes=2)
    attempt = WebhookAttempt(
        delivery_id=_DELIVERY_ID,
        number=1,
        scheduled_at=started,
        started_at=started,
        finished_at=finished,
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        retry_scheduled=False,
        error_category="timeout",
    )
    return WebhookDelivery(
        id=_DELIVERY_ID,
        subscription_id=subscription.id,
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(b"deduplication").hexdigest(),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=finished,
        status=WebhookDeliveryStatus.DEAD_LETTER,
        source_event_id=_EVENT_ID,
        correlation_id="delivery-correlation",
        attempts=(attempt,),
        terminal_at=finished,
    )


async def _manager(
    *,
    subscription: WebhookSubscription | None = None,
    delivery: WebhookDelivery | None = None,
    audit: AuditLedger | None = None,
) -> tuple[
    InMemoryWebhookSubscriptionRepository,
    InMemoryWebhookDeliveryRepository,
    WebhookManager,
]:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    if subscription is not None:
        await subscriptions.add(subscription)
    if delivery is not None:
        await deliveries.add(delivery)
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        audit=audit,
        clock=lambda: _LATER,
    )
    manager = WebhookManager(
        subscriptions=subscriptions,
        deliveries=deliveries,
        recovery=recovery,
        audit=audit,
        clock=lambda: _LATER,
        subscription_id_factory=lambda: _SUBSCRIPTION_ID,
    )
    return subscriptions, deliveries, manager


@pytest.mark.asyncio
async def test_create_list_and_get_subscription_use_safe_views() -> None:
    _, _, manager = await _manager()

    created = await manager.create_subscription(
        _context(),
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/private-path-token"),
        signing=WebhookSigningPolicy(
            SecretRef("must-not-leak", "integrations", 1),
        ),
        egress_policy="production.webhooks",
    )

    page = await manager.list_subscriptions(_context())
    fetched = await manager.get_subscription(created.id, _context())
    rendered = repr((created, page, fetched))

    assert created.id == _SUBSCRIPTION_ID
    assert page.items == (created,)
    assert fetched == created
    assert created.endpoint.host == "hooks.example.com"
    assert created.signing.key_version == 1
    assert "private-path-token" not in rendered
    assert "must-not-leak" not in rendered


@pytest.mark.asyncio
async def test_update_preserves_signing_and_changes_reviewed_fields() -> None:
    subscription = _subscription()
    _, _, manager = await _manager(subscription=subscription)

    updated = await manager.update_subscription(
        subscription.id,
        _context(),
        expected_revision=1,
        display_name="Updated Notifications",
        event_types=frozenset({"jobs.completed", "workflows.completed"}),
        egress_policy="secondary.webhooks",
    )

    assert updated.display_name == "Updated Notifications"
    assert updated.event_types == ("jobs.completed", "workflows.completed")
    assert updated.egress_policy == "secondary.webhooks"
    assert updated.signing.key_version == 1
    assert updated.revision == 2


@pytest.mark.asyncio
async def test_update_rejects_noop_and_stale_revision() -> None:
    subscription = _subscription()
    _, _, manager = await _manager(subscription=subscription)

    with pytest.raises(ValueError):
        await manager.update_subscription(
            subscription.id,
            _context(),
            expected_revision=1,
        )

    with pytest.raises(WebhookSubscriptionConflictError):
        await manager.update_subscription(
            subscription.id,
            _context(),
            expected_revision=2,
            display_name="Changed",
        )


@pytest.mark.asyncio
async def test_disable_and_enable_subscription() -> None:
    subscription = _subscription()
    _, _, manager = await _manager(subscription=subscription)

    disabled = await manager.disable_subscription(
        subscription.id,
        _context(),
        expected_revision=1,
    )
    enabled = await manager.enable_subscription(
        subscription.id,
        _context(),
        expected_revision=2,
    )

    assert disabled.status is WebhookSubscriptionStatus.DISABLED
    assert disabled.disabled_at == _LATER
    assert enabled.status is WebhookSubscriptionStatus.ACTIVE
    assert enabled.disabled_at is None
    assert enabled.revision == 3


@pytest.mark.asyncio
async def test_revoke_subscription_is_terminal() -> None:
    subscription = _subscription()
    _, _, manager = await _manager(subscription=subscription)

    revoked = await manager.revoke_subscription(
        subscription.id,
        _context(),
        expected_revision=1,
    )

    assert revoked.status is WebhookSubscriptionStatus.REVOKED
    with pytest.raises(WebhookSubscriptionConflictError):
        await manager.enable_subscription(
            subscription.id,
            _context(),
            expected_revision=2,
        )


@pytest.mark.asyncio
async def test_rotate_signing_key_exposes_only_version() -> None:
    subscription = _subscription()
    _, _, manager = await _manager(subscription=subscription)

    rotated = await manager.rotate_signing_key(
        subscription.id,
        _context(),
        expected_revision=1,
        secret_ref=SecretRef("rotated-secret", "integrations", 2),
        lease_ttl=timedelta(seconds=20),
    )

    rendered = repr(rotated)
    assert rotated.signing.key_version == 2
    assert rotated.signing.lease_ttl_seconds == 20
    assert "rotated-secret" not in rendered
    assert "integrations" not in rendered


@pytest.mark.asyncio
async def test_delivery_views_never_retain_body_or_digest() -> None:
    subscription = _subscription()
    delivery = _dead_letter(subscription)
    _, _, manager = await _manager(
        subscription=subscription,
        delivery=delivery,
    )

    page = await manager.list_deliveries(_context(), WebhookPageRequest(limit=10))
    view = await manager.get_delivery(delivery.id, _context())
    rendered = repr((page, view))

    assert view.status is WebhookDeliveryStatus.DEAD_LETTER
    assert view.redrive_eligible
    assert len(view.attempts) == 1
    assert "must-not-leak" not in rendered
    assert delivery.body_sha256 not in rendered
    assert delivery.deduplication_key not in rendered


@pytest.mark.asyncio
async def test_redrive_preserves_identity_body_and_attempt_history() -> None:
    subscription = _subscription()
    delivery = _dead_letter(subscription)
    _, deliveries, manager = await _manager(
        subscription=subscription,
        delivery=delivery,
    )

    result = await manager.redrive_delivery(delivery.id, _context())
    persisted = await deliveries.get(delivery.id)

    assert persisted is not None
    assert result.delivery_id == delivery.id
    assert persisted.status is WebhookDeliveryStatus.RETRYING
    assert persisted.canonical_body == delivery.canonical_body
    assert persisted.attempts == delivery.attempts
    assert persisted.revision == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("permission", "operation"),
    (
        (
            WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
            "read",
        ),
        (
            WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
            "update",
        ),
        (
            WEBHOOK_DELIVERIES_READ_PERMISSION,
            "delivery",
        ),
        (
            WEBHOOK_HEALTH_READ_PERMISSION,
            "health",
        ),
    ),
)
async def test_exact_permissions_are_required(permission: str, operation: str) -> None:
    subscription = _subscription()
    delivery = _dead_letter(subscription)
    _, _, manager = await _manager(
        subscription=subscription,
        delivery=delivery,
    )
    context = _context(permissions=_ALL_PERMISSIONS - {permission})

    with pytest.raises(WebhookManagerAccessDeniedError):
        if operation == "read":
            await manager.get_subscription(subscription.id, context)
        elif operation == "update":
            await manager.update_subscription(
                subscription.id,
                context,
                expected_revision=1,
                display_name="Denied",
            )
        elif operation == "delivery":
            await manager.get_delivery(delivery.id, context)
        else:
            await manager.snapshot(context)


@pytest.mark.asyncio
async def test_snapshot_contains_only_bounded_repository_counts() -> None:
    subscription = _subscription()
    delivery = _dead_letter(subscription)
    _, _, manager = await _manager(
        subscription=subscription,
        delivery=delivery,
    )

    snapshot = await manager.snapshot(_context())

    assert snapshot.subscriptions.subscriptions == 1
    assert snapshot.deliveries.deliveries == 1
    assert snapshot.deliveries.dead_letter == 1
    assert snapshot.reads == 1


@pytest.mark.asyncio
async def test_audit_facts_exclude_endpoint_and_secret_reference() -> None:
    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)
    _, _, manager = await _manager(audit=audit)

    await manager.create_subscription(
        _context(),
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/private-path-token"),
        signing=WebhookSigningPolicy(
            SecretRef("must-not-leak", "integrations", 1),
        ),
        egress_policy="production.webhooks",
    )

    records = await audit.read(
        AuditQuery(),
        SecurityContext(
            principal="audit-reader",
            principal_type=PrincipalType.USER,
            authenticated=True,
            permissions=frozenset({"audit.read"}),
        ),
    )
    rendered = repr(records)

    assert len(records) == 1
    assert records[0].event.action == "webhook.subscription.create"
    assert "private-path-token" not in rendered
    assert "must-not-leak" not in rendered
    assert "integrations" not in rendered


@pytest.mark.asyncio
async def test_close_is_idempotent_and_rejects_new_work() -> None:
    _, _, manager = await _manager()

    await manager.close()
    await manager.close()

    with pytest.raises(WebhookManagerClosedError):
        await manager.list_subscriptions(_context())


@pytest.mark.asyncio
async def test_disabled_subscription_can_rotate_key_but_revoked_cannot() -> None:
    disabled = _subscription(status=WebhookSubscriptionStatus.DISABLED)
    _, _, manager = await _manager(subscription=disabled)

    rotated = await manager.rotate_signing_key(
        disabled.id,
        _context(),
        expected_revision=1,
        secret_ref=SecretRef("rotated", "integrations", 2),
    )
    assert rotated.status is WebhookSubscriptionStatus.DISABLED

    subscriptions, _, manager = await _manager(
        subscription=_subscription(status=WebhookSubscriptionStatus.REVOKED),
    )
    current = await subscriptions.get(_SUBSCRIPTION_ID)
    assert current is not None
    with pytest.raises(WebhookSubscriptionConflictError):
        await manager.rotate_signing_key(
            current.id,
            _context(),
            expected_revision=1,
            secret_ref=SecretRef("rotated", "integrations", 2),
        )


@pytest.mark.asyncio
async def test_manager_view_tracks_current_repository_state() -> None:
    subscription = _subscription()
    subscriptions, _, manager = await _manager(subscription=subscription)

    replacement = replace(
        subscription,
        display_name="Repository Update",
        updated_at=_LATER,
        revision=2,
    )
    await subscriptions.replace(replacement, expected_revision=1)

    view = await manager.get_subscription(subscription.id, _context())

    assert view.display_name == "Repository Update"
    assert view.revision == 2
