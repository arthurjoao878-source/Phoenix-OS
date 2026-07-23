from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    MAX_WEBHOOK_SUBSCRIPTION_CAPACITY,
    InMemoryWebhookSubscriptionRepository,
    WebhookEndpoint,
    WebhookPageRequest,
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


def _subscription(
    name: str,
    *,
    subscription_id: UUID | None = None,
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime = _NOW,
    updated_at: datetime = _NOW,
    created_by: str = "maintainer:arthur",
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
        created_at=created_at,
        updated_at=updated_at,
        created_by=created_by,
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
        InMemoryWebhookSubscriptionRepository(capacity=capacity)


@pytest.mark.asyncio
async def test_repository_adds_and_reads_subscription() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    subscription = _subscription("release.notifications")

    await repository.add(subscription)

    assert await repository.get(subscription.id) is subscription
    assert await repository.get_by_name(" RELEASE.NOTIFICATIONS ") is subscription


@pytest.mark.asyncio
async def test_repository_returns_none_for_unknown_subscription() -> None:
    repository = InMemoryWebhookSubscriptionRepository()

    assert await repository.get(uuid4()) is None
    assert await repository.get_by_name("missing.subscription") is None


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_id() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    subscription_id = uuid4()

    await repository.add(_subscription("release.notifications", subscription_id=subscription_id))

    with pytest.raises(WebhookSubscriptionAlreadyExistsError, match="id"):
        await repository.add(_subscription("backup.notifications", subscription_id=subscription_id))


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_name() -> None:
    repository = InMemoryWebhookSubscriptionRepository()

    await repository.add(_subscription("release.notifications"))

    with pytest.raises(WebhookSubscriptionAlreadyExistsError, match="name"):
        await repository.add(_subscription("RELEASE.NOTIFICATIONS"))


@pytest.mark.asyncio
async def test_repository_enforces_capacity() -> None:
    repository = InMemoryWebhookSubscriptionRepository(capacity=1)

    await repository.add(_subscription("release.notifications"))

    with pytest.raises(WebhookSubscriptionCapacityError):
        await repository.add(_subscription("backup.notifications"))


@pytest.mark.asyncio
async def test_repository_serializes_concurrent_duplicate_adds() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
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
async def test_repository_lists_subscriptions_in_deterministic_order() -> None:
    repository = InMemoryWebhookSubscriptionRepository()

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
    assert page.page.next_offset is None


@pytest.mark.asyncio
async def test_repository_paginates_subscriptions() -> None:
    repository = InMemoryWebhookSubscriptionRepository()

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
    repository = InMemoryWebhookSubscriptionRepository()
    subscription = _subscription("release.notifications")
    await repository.add(subscription)

    updated = replace(
        subscription,
        name="deploy.notifications",
        display_name="Deploy Notifications",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    result = await repository.replace(updated, expected_revision=1)

    assert result is updated
    assert await repository.get_by_name("release.notifications") is None
    assert await repository.get_by_name("deploy.notifications") is updated


@pytest.mark.asyncio
async def test_replace_rejects_unknown_subscription() -> None:
    repository = InMemoryWebhookSubscriptionRepository()

    with pytest.raises(WebhookSubscriptionNotFoundError):
        await repository.replace(
            _subscription("release.notifications", revision=2),
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_or_skipped_revision() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    subscription = _subscription("release.notifications")
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
@pytest.mark.parametrize(
    "changes",
    [
        {"created_at": _NOW - timedelta(seconds=1)},
        {"created_by": "maintainer:other"},
        {"schema_version": 2},
    ],
)
async def test_replace_rejects_immutable_or_backward_metadata(
    changes: dict[str, object],
) -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    subscription = _subscription("release.notifications")
    await repository.add(subscription)

    values = {
        "updated_at": _NOW + timedelta(seconds=1),
        "revision": 2,
        **changes,
    }

    if changes.get("schema_version") == 2:
        with pytest.raises(ValueError, match="schema version"):
            replace(subscription, **cast(Any, values))
        return

    replacement = replace(subscription, **cast(Any, values))
    with pytest.raises(WebhookSubscriptionConflictError):
        await repository.replace(replacement, expected_revision=1)


@pytest.mark.asyncio
async def test_replace_rejects_updated_at_moving_backwards() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    current_time = _NOW + timedelta(seconds=2)
    subscription = _subscription(
        "release.notifications",
        updated_at=current_time,
    )
    await repository.add(subscription)

    replacement = replace(
        subscription,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(WebhookSubscriptionConflictError, match="backwards"):
        await repository.replace(replacement, expected_revision=1)


@pytest.mark.asyncio
async def test_replace_rejects_name_owned_by_another_subscription() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    first = _subscription("release.notifications")
    second = _subscription("backup.notifications")
    await repository.add(first)
    await repository.add(second)

    renamed = replace(
        second,
        name=first.name,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(WebhookSubscriptionAlreadyExistsError, match="name"):
        await repository.replace(renamed, expected_revision=1)


@pytest.mark.asyncio
async def test_revoked_subscription_is_terminal() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    revoked_at = _NOW + timedelta(seconds=1)
    subscription = _subscription(
        "release.notifications",
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
async def test_snapshot_reports_bounded_status_counts() -> None:
    repository = InMemoryWebhookSubscriptionRepository(capacity=10)
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
async def test_close_is_idempotent_clears_state_and_rejects_work() -> None:
    repository = InMemoryWebhookSubscriptionRepository()
    subscription = _subscription("release.notifications")
    await repository.add(subscription)

    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()
    assert snapshot.closed is True
    assert snapshot.subscriptions == 0

    operations = (
        repository.add(_subscription("backup.notifications")),
        repository.get(subscription.id),
        repository.get_by_name(subscription.name),
        repository.list(),
    )
    for operation in operations:
        with pytest.raises(WebhookSubscriptionRepositoryClosedError):
            await operation
