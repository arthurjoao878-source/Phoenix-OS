from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest

from phoenix_os.state import MemoryStateStore, StateKey
from phoenix_os.webhooks import (
    MAX_WEBHOOK_DELIVERY_CAPACITY,
    StateWebhookDeliveryRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookCorruptionError,
    WebhookDelivery,
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliveryCapacityError,
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryRepositoryClosedError,
    WebhookDeliveryStatus,
    WebhookHttpStatusClass,
    WebhookPageRequest,
    WebhookPersistenceError,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_NAMESPACE = "webhook-deliveries"


def _delivery(
    seed: int = 1,
    *,
    delivery_id: UUID | None = None,
    deduplication_key: str | None = None,
) -> WebhookDelivery:
    identifier = delivery_id or uuid4()
    occurred_at = _NOW + timedelta(minutes=seed)
    body = (
        b'{"delivery_id":"'
        + str(identifier).encode("ascii")
        + b'","payload":{"safe":true},"schema_version":1}'
    )

    return WebhookDelivery(
        id=identifier,
        subscription_id=UUID("00000000-0000-4000-8000-000000000024"),
        event_type="jobs.completed",
        deduplication_key=(
            deduplication_key or hashlib.sha256(f"subscription:event:{seed}".encode()).hexdigest()
        ),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=occurred_at,
        created_at=occurred_at,
        updated_at=occurred_at,
        source_event_id=uuid4(),
        correlation_id=f"request-{seed}",
        next_attempt_at=occurred_at,
    )


def _to_in_flight(
    delivery: WebhookDelivery,
    *,
    at: datetime | None = None,
) -> WebhookDelivery:
    claimed_at = at or delivery.updated_at + timedelta(seconds=1)

    return replace(
        delivery,
        status=WebhookDeliveryStatus.IN_FLIGHT,
        current_attempt=len(delivery.attempts) + 1,
        in_flight_at=claimed_at,
        next_attempt_at=None,
        terminal_at=None,
        updated_at=claimed_at,
        revision=delivery.revision + 1,
    )


def _completed_attempt(
    delivery: WebhookDelivery,
    *,
    outcome: WebhookAttemptOutcome,
    status_class: WebhookHttpStatusClass | None,
    error_category: str | None,
    retry_scheduled: bool = False,
    next_attempt_at: datetime | None = None,
) -> WebhookAttempt:
    assert delivery.current_attempt is not None
    assert delivery.in_flight_at is not None

    started_at = delivery.in_flight_at + timedelta(milliseconds=10)
    finished_at = started_at + timedelta(milliseconds=20)

    return WebhookAttempt(
        delivery_id=delivery.id,
        number=delivery.current_attempt,
        scheduled_at=delivery.in_flight_at,
        started_at=started_at,
        finished_at=finished_at,
        outcome=outcome,
        status_class=status_class,
        retry_scheduled=retry_scheduled,
        next_attempt_at=next_attempt_at,
        error_category=error_category,
    )


def _to_retrying(
    delivery: WebhookDelivery,
) -> WebhookDelivery:
    assert delivery.in_flight_at is not None

    started_at = delivery.in_flight_at + timedelta(milliseconds=10)
    finished_at = started_at + timedelta(milliseconds=20)
    next_attempt_at = finished_at + timedelta(minutes=1)

    attempt = WebhookAttempt(
        delivery_id=delivery.id,
        number=delivery.current_attempt or 1,
        scheduled_at=delivery.in_flight_at,
        started_at=started_at,
        finished_at=finished_at,
        outcome=(WebhookAttemptOutcome.RETRYABLE_FAILURE),
        status_class=(WebhookHttpStatusClass.SERVER_ERROR),
        retry_scheduled=True,
        next_attempt_at=next_attempt_at,
        error_category="http.server",
    )

    return replace(
        delivery,
        status=WebhookDeliveryStatus.RETRYING,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        next_attempt_at=next_attempt_at,
        terminal_at=None,
        updated_at=finished_at,
        revision=delivery.revision + 1,
    )


def _to_succeeded(
    delivery: WebhookDelivery,
) -> WebhookDelivery:
    attempt = _completed_attempt(
        delivery,
        outcome=WebhookAttemptOutcome.SUCCEEDED,
        status_class=(WebhookHttpStatusClass.SUCCESSFUL),
        error_category=None,
    )

    return replace(
        delivery,
        status=WebhookDeliveryStatus.SUCCEEDED,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        next_attempt_at=None,
        terminal_at=attempt.finished_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_failed(
    delivery: WebhookDelivery,
) -> WebhookDelivery:
    attempt = _completed_attempt(
        delivery,
        outcome=(WebhookAttemptOutcome.TERMINAL_FAILURE),
        status_class=(WebhookHttpStatusClass.CLIENT_ERROR),
        error_category="http.client",
    )

    return replace(
        delivery,
        status=WebhookDeliveryStatus.FAILED,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        next_attempt_at=None,
        terminal_at=attempt.finished_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_dead_letter(
    delivery: WebhookDelivery,
) -> WebhookDelivery:
    attempt = _completed_attempt(
        delivery,
        outcome=(WebhookAttemptOutcome.RETRYABLE_FAILURE),
        status_class=(WebhookHttpStatusClass.SERVER_ERROR),
        error_category="http.server",
    )

    return replace(
        delivery,
        status=WebhookDeliveryStatus.DEAD_LETTER,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        next_attempt_at=None,
        terminal_at=attempt.finished_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_cancelled(
    delivery: WebhookDelivery,
) -> WebhookDelivery:
    cancelled_at = delivery.updated_at + timedelta(seconds=1)

    return replace(
        delivery,
        status=WebhookDeliveryStatus.CANCELLED,
        current_attempt=None,
        in_flight_at=None,
        next_attempt_at=None,
        terminal_at=cancelled_at,
        updated_at=cancelled_at,
        revision=delivery.revision + 1,
    )


@pytest.mark.parametrize(
    "capacity",
    [
        0,
        -1,
        MAX_WEBHOOK_DELIVERY_CAPACITY + 1,
    ],
)
def test_repository_rejects_invalid_capacity(
    capacity: int,
) -> None:
    with pytest.raises(ValueError, match="capacity"):
        StateWebhookDeliveryRepository(
            MemoryStateStore(),
            capacity=capacity,
        )


@pytest.mark.asyncio
async def test_repository_adds_and_reads_delivery() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    delivery = _delivery()

    await repository.add(delivery)

    assert await repository.get(delivery.id) == delivery
    assert (
        await repository.get_by_deduplication_key(f" {delivery.deduplication_key.upper()} ")
        == delivery
    )


@pytest.mark.asyncio
async def test_state_survives_repository_recreation() -> None:
    store = MemoryStateStore()
    first = StateWebhookDeliveryRepository(store)
    delivery = _delivery()

    await first.add(delivery)
    await first.close()

    second = StateWebhookDeliveryRepository(store)

    assert await second.get(delivery.id) == delivery
    assert await second.get_by_deduplication_key(delivery.deduplication_key) == delivery


@pytest.mark.asyncio
async def test_repository_returns_none_for_unknown_delivery() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    missing_key = hashlib.sha256(b"missing").hexdigest()

    assert await repository.get(uuid4()) is None
    assert await repository.get_by_deduplication_key(missing_key) is None


@pytest.mark.asyncio
async def test_repository_rejects_invalid_deduplication_lookup() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())

    with pytest.raises(
        ValueError,
        match="deduplication key",
    ):
        await repository.get_by_deduplication_key("not-a-digest")


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_id() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    delivery_id = uuid4()

    await repository.add(
        _delivery(
            1,
            delivery_id=delivery_id,
        )
    )

    with pytest.raises(
        WebhookDeliveryAlreadyExistsError,
        match="id",
    ):
        await repository.add(
            _delivery(
                2,
                delivery_id=delivery_id,
            )
        )


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_deduplication_key() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    first = _delivery(1)
    await repository.add(first)

    with pytest.raises(
        WebhookDeliveryAlreadyExistsError,
        match="deduplication key",
    ):
        await repository.add(
            _delivery(
                2,
                deduplication_key=(first.deduplication_key),
            )
        )


@pytest.mark.asyncio
async def test_repository_serializes_concurrent_duplicates() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    first = _delivery(1)
    second = _delivery(
        2,
        deduplication_key=first.deduplication_key,
    )

    results = await asyncio.gather(
        repository.add(first),
        repository.add(second),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1

    failures = [result for result in results if isinstance(result, Exception)]
    assert len(failures) == 1
    assert isinstance(
        failures[0],
        WebhookDeliveryAlreadyExistsError,
    )


@pytest.mark.asyncio
async def test_repository_enforces_capacity() -> None:
    repository = StateWebhookDeliveryRepository(
        MemoryStateStore(),
        capacity=1,
    )

    await repository.add(_delivery(1))

    with pytest.raises(WebhookDeliveryCapacityError):
        await repository.add(_delivery(2))


@pytest.mark.asyncio
async def test_repository_lists_in_deterministic_order() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())

    third = _delivery(3)
    first = _delivery(1)
    second = _delivery(2)

    for delivery in (third, first, second):
        await repository.add(delivery)

    page = await repository.list()

    assert page.items == (
        first,
        second,
        third,
    )
    assert page.page.total == 3


@pytest.mark.asyncio
async def test_repository_paginates_deliveries() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())

    deliveries = tuple(_delivery(seed) for seed in range(1, 5))
    for delivery in reversed(deliveries):
        await repository.add(delivery)

    first = await repository.list(
        WebhookPageRequest(
            offset=0,
            limit=2,
        )
    )
    second = await repository.list(
        WebhookPageRequest(
            offset=2,
            limit=2,
        )
    )

    assert first.items == deliveries[:2]
    assert first.page.next_offset == 2
    assert second.items == deliveries[2:]
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_repository_persists_lifecycle_and_attempts() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    pending = _delivery()

    await repository.add(pending)

    in_flight = _to_in_flight(pending)
    await repository.replace(
        in_flight,
        expected_revision=pending.revision,
    )

    retrying = _to_retrying(in_flight)
    await repository.replace(
        retrying,
        expected_revision=in_flight.revision,
    )

    restarted = StateWebhookDeliveryRepository(store)
    assert await restarted.get(retrying.id) == retrying

    second_in_flight = _to_in_flight(
        retrying,
        at=retrying.next_attempt_at,
    )
    await restarted.replace(
        second_in_flight,
        expected_revision=retrying.revision,
    )

    succeeded = _to_succeeded(second_in_flight)
    await restarted.replace(
        succeeded,
        expected_revision=(second_in_flight.revision),
    )

    assert await restarted.get(succeeded.id) == succeeded
    assert len(succeeded.attempts) == 2


@pytest.mark.asyncio
async def test_replace_rejects_unknown_delivery() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    pending = _delivery()

    with pytest.raises(WebhookDeliveryNotFoundError):
        await repository.replace(
            _to_in_flight(pending),
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_and_skipped_revision() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    pending = _delivery()
    await repository.add(pending)

    in_flight = _to_in_flight(pending)

    with pytest.raises(
        WebhookDeliveryConflictError,
        match="revision conflict",
    ):
        await repository.replace(
            in_flight,
            expected_revision=2,
        )

    skipped = replace(
        in_flight,
        revision=3,
    )
    with pytest.raises(
        WebhookDeliveryConflictError,
        match="increment exactly once",
    ):
        await repository.replace(
            skipped,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_immutable_metadata_change() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    pending = _delivery()
    await repository.add(pending)

    in_flight = _to_in_flight(pending)
    changed = replace(
        in_flight,
        event_type="jobs.failed",
    )

    with pytest.raises(
        WebhookDeliveryConflictError,
        match="event_type",
    ):
        await repository.replace(
            changed,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_illegal_transition() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    pending = _delivery()
    await repository.add(pending)

    succeeded = _to_succeeded(_to_in_flight(pending))
    succeeded = replace(
        succeeded,
        revision=2,
    )

    with pytest.raises(
        WebhookDeliveryConflictError,
        match="transition",
    ):
        await repository.replace(
            succeeded,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_terminal_delivery_is_immutable() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    succeeded = _to_succeeded(_to_in_flight(_delivery()))
    await repository.add(succeeded)

    replacement = replace(
        succeeded,
        updated_at=(succeeded.updated_at + timedelta(seconds=1)),
        revision=succeeded.revision + 1,
    )

    with pytest.raises(
        WebhookDeliveryConflictError,
        match="terminal",
    ):
        await repository.replace(
            replacement,
            expected_revision=succeeded.revision,
        )


@pytest.mark.asyncio
async def test_snapshot_reports_status_and_attempt_counts() -> None:
    repository = StateWebhookDeliveryRepository(
        MemoryStateStore(),
        capacity=20,
    )

    deliveries = (
        _delivery(1),
        _to_in_flight(_delivery(2)),
        _to_retrying(_to_in_flight(_delivery(3))),
        _to_succeeded(_to_in_flight(_delivery(4))),
        _to_failed(_to_in_flight(_delivery(5))),
        _to_dead_letter(_to_in_flight(_delivery(6))),
        _to_cancelled(_delivery(7)),
    )

    for delivery in deliveries:
        await repository.add(delivery)

    snapshot = await repository.snapshot()

    assert snapshot.closed is False
    assert snapshot.deliveries == 7
    assert snapshot.pending == 1
    assert snapshot.in_flight == 1
    assert snapshot.retrying == 1
    assert snapshot.succeeded == 1
    assert snapshot.failed == 1
    assert snapshot.dead_letter == 1
    assert snapshot.cancelled == 1
    assert snapshot.attempts == 4
    assert snapshot.capacity == 20


@pytest.mark.asyncio
async def test_close_preserves_state_and_borrowed_store() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    delivery = _delivery()

    await repository.add(delivery)
    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()

    assert snapshot.closed is True
    assert snapshot.deliveries == 1
    assert store.closed is False

    restarted = StateWebhookDeliveryRepository(store)
    assert await restarted.get(delivery.id) == delivery


@pytest.mark.asyncio
async def test_closed_repository_rejects_operational_work() -> None:
    repository = StateWebhookDeliveryRepository(MemoryStateStore())
    delivery = _delivery()
    await repository.close()

    with pytest.raises(WebhookDeliveryRepositoryClosedError):
        await repository.add(delivery)

    with pytest.raises(WebhookDeliveryRepositoryClosedError):
        await repository.get(delivery.id)

    with pytest.raises(WebhookDeliveryRepositoryClosedError):
        await repository.get_by_deduplication_key(delivery.deduplication_key)

    with pytest.raises(WebhookDeliveryRepositoryClosedError):
        await repository.list()


@pytest.mark.asyncio
async def test_namespaces_isolate_delivery_state() -> None:
    store = MemoryStateStore()
    first = StateWebhookDeliveryRepository(
        store,
        namespace="webhook-deliveries-primary",
    )
    second = StateWebhookDeliveryRepository(
        store,
        namespace="webhook-deliveries-secondary",
    )
    delivery = _delivery()

    await first.add(delivery)

    assert await first.get(delivery.id) == delivery
    assert await second.get(delivery.id) is None

    await second.add(delivery)
    assert await second.get(delivery.id) == delivery


@pytest.mark.asyncio
async def test_missing_deduplication_index_is_corruption() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    delivery = _delivery()
    await repository.add(delivery)

    index_key = StateKey(
        _NAMESPACE,
        (f"delivery_deduplication_{delivery.deduplication_key}"),
        dict,
    )
    stored_index = await store.get(index_key)
    assert stored_index is not None

    await store.delete(
        cast(StateKey[object], index_key),
        expected_version=stored_index.version,
    )

    with pytest.raises(
        WebhookCorruptionError,
        match="incomplete",
    ):
        await repository.get(delivery.id)

    with pytest.raises(
        WebhookCorruptionError,
        match="incomplete",
    ):
        await repository.list()


@pytest.mark.asyncio
async def test_tampered_delivery_digest_is_detected() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    delivery = _delivery()
    await repository.add(delivery)

    record_key = StateKey(
        _NAMESPACE,
        f"delivery_record_{delivery.id.hex}",
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

    with pytest.raises(
        WebhookCorruptionError,
        match="digest",
    ):
        await repository.get(delivery.id)


@pytest.mark.asyncio
async def test_tampered_index_digest_is_detected() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    delivery = _delivery()
    await repository.add(delivery)

    index_key = StateKey(
        _NAMESPACE,
        (f"delivery_deduplication_{delivery.deduplication_key}"),
        dict,
    )
    stored = await store.get(index_key)
    assert stored is not None

    tampered = dict(cast(dict[str, object], stored.value))
    tampered["record_digest"] = "0" * 64

    await store.put(
        index_key,
        tampered,
        expected_version=stored.version,
    )

    with pytest.raises(
        WebhookCorruptionError,
        match="mismatched digest",
    ):
        await repository.get(delivery.id)


@pytest.mark.asyncio
async def test_orphaned_deduplication_index_is_detected() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    delivery = _delivery()
    await repository.add(delivery)

    record_key = StateKey(
        _NAMESPACE,
        f"delivery_record_{delivery.id.hex}",
        dict,
    )
    stored = await store.get(record_key)
    assert stored is not None

    await store.delete(
        cast(StateKey[object], record_key),
        expected_version=stored.version,
    )

    with pytest.raises(
        WebhookCorruptionError,
        match="missing record",
    ):
        await repository.get_by_deduplication_key(delivery.deduplication_key)


@pytest.mark.asyncio
async def test_closed_state_store_failure_is_wrapped() -> None:
    store = MemoryStateStore()
    repository = StateWebhookDeliveryRepository(store)
    await store.close()

    with pytest.raises(WebhookPersistenceError):
        await repository.get(uuid4())
