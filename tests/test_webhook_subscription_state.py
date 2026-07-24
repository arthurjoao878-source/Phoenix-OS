from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest

from phoenix_os.secrets import SecretRef
from phoenix_os.state import MemoryStateStore, StateKey
from phoenix_os.webhooks import (
    MAX_WEBHOOK_SUBSCRIPTION_CAPACITY,
    StateWebhookSubscriptionRepository,
    WebhookCorruptionError,
    WebhookEndpoint,
    WebhookPageRequest,
    WebhookPersistenceError,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionAlreadyExistsError,
    WebhookSubscriptionCapacityError,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
    WebhookSubscriptionRepositoryClosedError,
    WebhookSubscriptionStatus,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_NAMESPACE = "webhook-subscriptions"


def _subscription(
    name: str = "release.notifications",
    *,
    subscription_id: UUID | None = None,
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    updated_at: datetime = _NOW,
    revision: int = 1,
) -> WebhookSubscription:
    return WebhookSubscription(
        id=subscription_id or uuid4(),
        name=name,
        display_name=name.replace(".", " ").title(),
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/phoenix"),
        signing=WebhookSigningPolicy(SecretRef("webhook-key", "integrations", 1)),
        egress_policy="production.webhooks",
        created_at=_NOW,
        updated_at=updated_at,
        created_by="maintainer:arthur",
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
    )


@pytest.mark.parametrize(
    "capacity",
    [0, -1, MAX_WEBHOOK_SUBSCRIPTION_CAPACITY + 1],
)
def test_repository_rejects_invalid_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        StateWebhookSubscriptionRepository(
            MemoryStateStore(),
            capacity=capacity,
        )


@pytest.mark.asyncio
async def test_repository_adds_and_reads_subscription() -> None:
    store = MemoryStateStore()
    repository = StateWebhookSubscriptionRepository(store)
    subscription = _subscription()

    await repository.add(subscription)

    assert await repository.get(subscription.id) == subscription
    assert await repository.get_by_name(" RELEASE.NOTIFICATIONS ") == subscription


@pytest.mark.asyncio
async def test_state_survives_repository_recreation() -> None:
    store = MemoryStateStore()
    first = StateWebhookSubscriptionRepository(store)
    subscription = _subscription()

    await first.add(subscription)
    await first.close()

    second = StateWebhookSubscriptionRepository(store)

    assert await second.get(subscription.id) == subscription
    assert await second.get_by_name(subscription.name) == subscription


@pytest.mark.asyncio
async def test_repository_returns_none_for_unknown_subscription() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())

    assert await repository.get(uuid4()) is None
    assert await repository.get_by_name("missing.subscription") is None


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_id() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())
    subscription_id = uuid4()

    await repository.add(
        _subscription(
            "release.notifications",
            subscription_id=subscription_id,
        )
    )

    with pytest.raises(WebhookSubscriptionAlreadyExistsError, match="id"):
        await repository.add(
            _subscription(
                "backup.notifications",
                subscription_id=subscription_id,
            )
        )


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_name() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())

    await repository.add(_subscription("release.notifications"))

    with pytest.raises(WebhookSubscriptionAlreadyExistsError, match="name"):
        await repository.add(_subscription("RELEASE.NOTIFICATIONS"))


@pytest.mark.asyncio
async def test_repository_serializes_concurrent_duplicate_adds() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())
    first = _subscription("release.notifications")
    second = _subscription("release.notifications")

    results = await asyncio.gather(
        repository.add(first),
        repository.add(second),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    failures = [result for result in results if isinstance(result, Exception)]
    assert len(failures) == 1
    assert isinstance(failures[0], WebhookSubscriptionAlreadyExistsError)


@pytest.mark.asyncio
async def test_repository_enforces_capacity() -> None:
    repository = StateWebhookSubscriptionRepository(
        MemoryStateStore(),
        capacity=1,
    )

    await repository.add(_subscription("release.notifications"))

    with pytest.raises(WebhookSubscriptionCapacityError):
        await repository.add(_subscription("backup.notifications"))


@pytest.mark.asyncio
async def test_repository_lists_in_deterministic_order() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())

    for name in (
        "charlie.notifications",
        "alpha.notifications",
        "bravo.notifications",
    ):
        await repository.add(_subscription(name))

    page = await repository.list()

    assert tuple(item.name for item in page.items) == (
        "alpha.notifications",
        "bravo.notifications",
        "charlie.notifications",
    )
    assert page.page.total == 3


@pytest.mark.asyncio
async def test_repository_paginates_subscriptions() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())

    for name in (
        "delta.notifications",
        "alpha.notifications",
        "charlie.notifications",
        "bravo.notifications",
    ):
        await repository.add(_subscription(name))

    first = await repository.list(WebhookPageRequest(offset=0, limit=2))
    second = await repository.list(WebhookPageRequest(offset=2, limit=2))

    assert tuple(item.name for item in first.items) == (
        "alpha.notifications",
        "bravo.notifications",
    )
    assert first.page.next_offset == 2
    assert tuple(item.name for item in second.items) == (
        "charlie.notifications",
        "delta.notifications",
    )
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_repository_replaces_and_renames_subscription() -> None:
    store = MemoryStateStore()
    repository = StateWebhookSubscriptionRepository(store)
    subscription = _subscription()
    await repository.add(subscription)

    updated = replace(
        subscription,
        name="deploy.notifications",
        display_name="Deploy Notifications",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    result = await repository.replace(updated, expected_revision=1)

    assert result == updated
    assert await repository.get_by_name("release.notifications") is None
    assert await repository.get_by_name("deploy.notifications") == updated

    restarted = StateWebhookSubscriptionRepository(store)
    assert await restarted.get(updated.id) == updated


@pytest.mark.asyncio
async def test_replace_rejects_unknown_subscription() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())

    with pytest.raises(WebhookSubscriptionNotFoundError):
        await repository.replace(
            _subscription(revision=2),
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_or_skipped_revision() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())
    subscription = _subscription()
    await repository.add(subscription)

    updated = replace(
        subscription,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(WebhookSubscriptionConflictError, match="revision conflict"):
        await repository.replace(updated, expected_revision=2)

    skipped = replace(updated, revision=3)
    with pytest.raises(WebhookSubscriptionConflictError, match="increment exactly once"):
        await repository.replace(skipped, expected_revision=1)


@pytest.mark.asyncio
async def test_revoked_subscription_is_terminal() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())
    revoked_at = _NOW + timedelta(seconds=1)
    subscription = _subscription(
        status=WebhookSubscriptionStatus.REVOKED,
        updated_at=revoked_at,
        revoked_at=revoked_at,
    )
    await repository.add(subscription)

    replacement = replace(
        subscription,
        updated_at=revoked_at + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(WebhookSubscriptionConflictError, match="terminal"):
        await repository.replace(replacement, expected_revision=1)


@pytest.mark.asyncio
async def test_snapshot_reports_persisted_status_counts() -> None:
    repository = StateWebhookSubscriptionRepository(
        MemoryStateStore(),
        capacity=10,
    )
    disabled_at = _NOW + timedelta(seconds=1)
    revoked_at = _NOW + timedelta(seconds=2)

    await repository.add(_subscription("active.notifications"))
    await repository.add(
        _subscription(
            "disabled.notifications",
            status=WebhookSubscriptionStatus.DISABLED,
            updated_at=disabled_at,
            disabled_at=disabled_at,
        )
    )
    await repository.add(
        _subscription(
            "revoked.notifications",
            status=WebhookSubscriptionStatus.REVOKED,
            updated_at=revoked_at,
            revoked_at=revoked_at,
        )
    )

    snapshot = await repository.snapshot()

    assert snapshot.closed is False
    assert snapshot.subscriptions == 3
    assert snapshot.active == 1
    assert snapshot.disabled == 1
    assert snapshot.revoked == 1
    assert snapshot.capacity == 10


@pytest.mark.asyncio
async def test_close_does_not_clear_state_or_close_borrowed_store() -> None:
    store = MemoryStateStore()
    repository = StateWebhookSubscriptionRepository(store)
    subscription = _subscription()
    await repository.add(subscription)

    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()

    assert snapshot.closed is True
    assert snapshot.subscriptions == 1
    assert store.closed is False

    restarted = StateWebhookSubscriptionRepository(store)
    assert await restarted.get(subscription.id) == subscription


@pytest.mark.asyncio
async def test_closed_repository_rejects_operational_work() -> None:
    repository = StateWebhookSubscriptionRepository(MemoryStateStore())
    subscription = _subscription()
    await repository.close()

    with pytest.raises(WebhookSubscriptionRepositoryClosedError):
        await repository.add(subscription)

    with pytest.raises(WebhookSubscriptionRepositoryClosedError):
        await repository.get(subscription.id)

    with pytest.raises(WebhookSubscriptionRepositoryClosedError):
        await repository.get_by_name(subscription.name)

    with pytest.raises(WebhookSubscriptionRepositoryClosedError):
        await repository.list()


@pytest.mark.asyncio
async def test_namespaces_isolate_subscription_state() -> None:
    store = MemoryStateStore()
    first = StateWebhookSubscriptionRepository(
        store,
        namespace="webhook-subscriptions-primary",
    )
    second = StateWebhookSubscriptionRepository(
        store,
        namespace="webhook-subscriptions-secondary",
    )
    subscription = _subscription()

    await first.add(subscription)

    assert await first.get(subscription.id) == subscription
    assert await second.get(subscription.id) is None

    await second.add(subscription)
    assert await second.get(subscription.id) == subscription


@pytest.mark.asyncio
async def test_missing_name_index_is_detected_as_corruption() -> None:
    store = MemoryStateStore()
    repository = StateWebhookSubscriptionRepository(store)
    subscription = _subscription()
    await repository.add(subscription)

    index_key = StateKey(
        _NAMESPACE,
        f"subscription_name_{subscription.name}",
        dict,
    )
    stored_index = await store.get(index_key)
    assert stored_index is not None

    await store.delete(
        cast(StateKey[object], index_key),
        expected_version=stored_index.version,
    )

    with pytest.raises(WebhookCorruptionError, match="incomplete"):
        await repository.get(subscription.id)

    with pytest.raises(WebhookCorruptionError, match="incomplete"):
        await repository.list()


@pytest.mark.asyncio
async def test_tampered_record_digest_is_detected() -> None:
    store = MemoryStateStore()
    repository = StateWebhookSubscriptionRepository(store)
    subscription = _subscription()
    await repository.add(subscription)

    record_key = StateKey(
        _NAMESPACE,
        f"subscription_record_{subscription.id.hex}",
        dict,
    )
    stored = await store.get(record_key)
    assert stored is not None

    tampered = dict(cast(dict[str, object], stored.value))
    tampered["record_digest"] = "0" * 64

    await store.put(
        record_key,
        tampered,
        expected_version=stored.version,
    )

    with pytest.raises(WebhookCorruptionError, match="digest"):
        await repository.get(subscription.id)


@pytest.mark.asyncio
async def test_closed_state_store_failure_is_wrapped() -> None:
    store = MemoryStateStore()
    repository = StateWebhookSubscriptionRepository(store)
    await store.close()

    with pytest.raises(WebhookPersistenceError):
        await repository.get(uuid4())
