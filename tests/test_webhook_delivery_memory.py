from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from phoenix_os.webhooks import (
    MAX_WEBHOOK_DELIVERY_CAPACITY,
    InMemoryWebhookDeliveryRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliveryCapacityError,
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryRepositoryClosedError,
    WebhookDeliveryStatus,
    WebhookHttpStatusClass,
    WebhookPageRequest,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_BODY = b'{"schema_version":1,"payload":{"safe":true}}'
_BODY_DIGEST = hashlib.sha256(_BODY).hexdigest()


def _delivery(
    index: int = 1,
    *,
    delivery_id: UUID | None = None,
    created_at: datetime = _NOW,
    revision: int = 1,
) -> WebhookDelivery:
    key = hashlib.sha256(f"delivery:{index}".encode()).hexdigest()
    return WebhookDelivery(
        id=delivery_id or UUID(int=index),
        subscription_id=UUID(int=10_000 + index),
        event_type="jobs.completed",
        deduplication_key=key,
        canonical_body=_BODY,
        body_sha256=_BODY_DIGEST,
        occurred_at=created_at,
        created_at=created_at,
        updated_at=created_at,
        next_attempt_at=created_at,
        source_event_id=UUID(int=20_000 + index),
        correlation_id=f"request-{index}",
        revision=revision,
    )


def _to_in_flight(
    delivery: WebhookDelivery,
    *,
    at: datetime | None = None,
) -> WebhookDelivery:
    started_at = at or delivery.updated_at + timedelta(seconds=1)
    return replace(
        delivery,
        status=WebhookDeliveryStatus.IN_FLIGHT,
        current_attempt=len(delivery.attempts) + 1,
        in_flight_at=started_at,
        next_attempt_at=None,
        updated_at=started_at,
        revision=delivery.revision + 1,
    )


def _completed_attempt(
    delivery: WebhookDelivery,
    *,
    outcome: WebhookAttemptOutcome,
    status_class: WebhookHttpStatusClass | None,
    error_category: str | None,
    retry_at: datetime | None = None,
) -> WebhookAttempt:
    if delivery.current_attempt is None or delivery.in_flight_at is None:
        raise AssertionError("test delivery must be in flight")
    finished_at = delivery.in_flight_at + timedelta(seconds=1)
    return WebhookAttempt(
        delivery_id=delivery.id,
        number=delivery.current_attempt,
        scheduled_at=delivery.in_flight_at,
        started_at=delivery.in_flight_at,
        finished_at=finished_at,
        outcome=outcome,
        status_class=status_class,
        retry_scheduled=retry_at is not None,
        next_attempt_at=retry_at,
        error_category=error_category,
    )


def _to_succeeded(delivery: WebhookDelivery) -> WebhookDelivery:
    attempt = _completed_attempt(
        delivery,
        outcome=WebhookAttemptOutcome.SUCCEEDED,
        status_class=WebhookHttpStatusClass.SUCCESSFUL,
        error_category=None,
    )
    return replace(
        delivery,
        status=WebhookDeliveryStatus.SUCCEEDED,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        terminal_at=attempt.finished_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_retrying(delivery: WebhookDelivery) -> WebhookDelivery:
    retry_at = delivery.updated_at + timedelta(minutes=1)
    attempt = _completed_attempt(
        delivery,
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=WebhookHttpStatusClass.SERVER_ERROR,
        error_category="http.server",
        retry_at=retry_at,
    )
    return replace(
        delivery,
        status=WebhookDeliveryStatus.RETRYING,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        next_attempt_at=retry_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_failed(delivery: WebhookDelivery) -> WebhookDelivery:
    attempt = _completed_attempt(
        delivery,
        outcome=WebhookAttemptOutcome.TERMINAL_FAILURE,
        status_class=WebhookHttpStatusClass.REDIRECTION,
        error_category="http.redirect",
    )
    return replace(
        delivery,
        status=WebhookDeliveryStatus.FAILED,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        terminal_at=attempt.finished_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_dead_letter(delivery: WebhookDelivery) -> WebhookDelivery:
    attempt = _completed_attempt(
        delivery,
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=None,
        error_category="transport.timeout",
    )
    return replace(
        delivery,
        status=WebhookDeliveryStatus.DEAD_LETTER,
        attempts=(*delivery.attempts, attempt),
        current_attempt=None,
        in_flight_at=None,
        terminal_at=attempt.finished_at,
        updated_at=attempt.finished_at,
        revision=delivery.revision + 1,
    )


def _to_cancelled(delivery: WebhookDelivery) -> WebhookDelivery:
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
    [0, -1, MAX_WEBHOOK_DELIVERY_CAPACITY + 1],
)
def test_repository_rejects_invalid_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        InMemoryWebhookDeliveryRepository(capacity=capacity)


@pytest.mark.asyncio
async def test_repository_adds_and_reads_delivery() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    delivery = _delivery()

    await repository.add(delivery)

    assert await repository.get(delivery.id) is delivery
    assert (
        await repository.get_by_deduplication_key(f" {delivery.deduplication_key.upper()} ")
        is delivery
    )


@pytest.mark.asyncio
async def test_repository_returns_none_for_unknown_delivery() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    missing_key = hashlib.sha256(b"missing").hexdigest()

    assert await repository.get(uuid4()) is None
    assert await repository.get_by_deduplication_key(missing_key) is None


@pytest.mark.asyncio
async def test_repository_rejects_invalid_deduplication_lookup() -> None:
    repository = InMemoryWebhookDeliveryRepository()

    with pytest.raises(ValueError, match="deduplication key"):
        await repository.get_by_deduplication_key("not-a-digest")


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_id() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    delivery_id = uuid4()
    await repository.add(_delivery(1, delivery_id=delivery_id))

    with pytest.raises(WebhookDeliveryAlreadyExistsError, match="id"):
        await repository.add(_delivery(2, delivery_id=delivery_id))


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_deduplication_key() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    first = _delivery(1)
    await repository.add(first)

    duplicate = replace(_delivery(2), deduplication_key=first.deduplication_key)
    with pytest.raises(WebhookDeliveryAlreadyExistsError, match="deduplication key"):
        await repository.add(duplicate)


@pytest.mark.asyncio
async def test_repository_enforces_capacity() -> None:
    repository = InMemoryWebhookDeliveryRepository(capacity=1)
    await repository.add(_delivery(1))

    with pytest.raises(WebhookDeliveryCapacityError):
        await repository.add(_delivery(2))


@pytest.mark.asyncio
async def test_repository_serializes_concurrent_duplicate_adds() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    first = _delivery(1)
    second = replace(_delivery(2), deduplication_key=first.deduplication_key)

    results = await asyncio.gather(
        repository.add(first),
        repository.add(second),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    failures = [result for result in results if isinstance(result, Exception)]
    assert len(failures) == 1
    assert isinstance(failures[0], WebhookDeliveryAlreadyExistsError)


@pytest.mark.asyncio
async def test_repository_lists_deliveries_in_deterministic_order() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    common_time = _NOW
    deliveries = (
        _delivery(3, created_at=common_time),
        _delivery(1, created_at=common_time),
        _delivery(2, created_at=common_time - timedelta(seconds=1)),
    )
    for delivery in deliveries:
        await repository.add(delivery)

    page = await repository.list()

    assert tuple(item.id for item in page.items) == (
        deliveries[2].id,
        deliveries[1].id,
        deliveries[0].id,
    )
    assert page.page.total == 3
    assert page.page.next_offset is None


@pytest.mark.asyncio
async def test_repository_paginates_deliveries() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    for index in range(1, 5):
        await repository.add(_delivery(index, created_at=_NOW + timedelta(seconds=index)))

    first = await repository.list(WebhookPageRequest(offset=0, limit=2))
    second = await repository.list(WebhookPageRequest(offset=2, limit=2))

    assert tuple(item.id.int for item in first.items) == (1, 2)
    assert first.page.next_offset == 2
    assert tuple(item.id.int for item in second.items) == (3, 4)
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_repository_transitions_pending_delivery_to_in_flight() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    pending = _delivery()
    await repository.add(pending)
    in_flight = _to_in_flight(pending)

    result = await repository.replace(in_flight, expected_revision=1)

    assert result is in_flight
    assert await repository.get(pending.id) is in_flight


@pytest.mark.asyncio
async def test_repository_transitions_retrying_delivery_to_next_attempt() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    first_attempt = _to_in_flight(_delivery())
    retrying = _to_retrying(first_attempt)
    await repository.add(retrying)
    second_attempt = _to_in_flight(retrying, at=retrying.next_attempt_at)

    result = await repository.replace(
        second_attempt,
        expected_revision=retrying.revision,
    )

    assert result.current_attempt == 2
    assert result.attempts == retrying.attempts


@pytest.mark.asyncio
async def test_replace_rejects_unknown_delivery() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    replacement = _to_in_flight(_delivery())

    with pytest.raises(WebhookDeliveryNotFoundError):
        await repository.replace(replacement, expected_revision=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("expected_revision", [0, -1])
async def test_replace_rejects_nonpositive_expected_revision(
    expected_revision: int,
) -> None:
    repository = InMemoryWebhookDeliveryRepository()

    with pytest.raises(ValueError, match="expected_revision"):
        await repository.replace(
            _to_in_flight(_delivery()),
            expected_revision=expected_revision,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_or_skipped_revision() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    pending = _delivery()
    await repository.add(pending)
    in_flight = _to_in_flight(pending)

    with pytest.raises(WebhookDeliveryConflictError, match="revision conflict"):
        await repository.replace(in_flight, expected_revision=2)

    skipped = replace(in_flight, revision=3)
    with pytest.raises(WebhookDeliveryConflictError, match="increment exactly once"):
        await repository.replace(skipped, expected_revision=1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field_name",
    [
        "subscription_id",
        "event_type",
        "deduplication_key",
        "canonical_body",
        "occurred_at",
        "created_at",
        "source_event_id",
        "correlation_id",
    ],
)
async def test_replace_rejects_immutable_metadata(field_name: str) -> None:
    repository = InMemoryWebhookDeliveryRepository()
    pending = _delivery()
    await repository.add(pending)
    in_flight = _to_in_flight(pending)

    changes: dict[str, object] = {
        "subscription_id": uuid4(),
        "event_type": "jobs.failed",
        "deduplication_key": hashlib.sha256(b"changed").hexdigest(),
        "canonical_body": b'{"changed":true}',
        "occurred_at": pending.occurred_at - timedelta(seconds=1),
        "created_at": pending.created_at + timedelta(microseconds=1),
        "source_event_id": uuid4(),
        "correlation_id": "changed-request",
    }
    if field_name == "canonical_body":
        changed_body = cast(bytes, changes[field_name])
        changes["body_sha256"] = hashlib.sha256(changed_body).hexdigest()

    replacement = replace(
        in_flight,
        **cast(Any, {field_name: changes[field_name]}),
        **cast(Any, {"body_sha256": changes["body_sha256"]}) if "body_sha256" in changes else {},
    )
    with pytest.raises(WebhookDeliveryConflictError, match=field_name):
        await repository.replace(replacement, expected_revision=1)


@pytest.mark.asyncio
async def test_replace_rejects_updated_at_moving_backwards() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    current = _to_retrying(_to_in_flight(_delivery()))
    await repository.add(current)
    earlier = current.updated_at - timedelta(microseconds=1)
    replacement = _to_in_flight(current, at=earlier)

    with pytest.raises(WebhookDeliveryConflictError, match="backwards"):
        await repository.replace(
            replacement,
            expected_revision=current.revision,
        )


@pytest.mark.asyncio
async def test_replace_rejects_illegal_lifecycle_transition() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    pending = _delivery()
    await repository.add(pending)
    succeeded = _to_succeeded(_to_in_flight(pending))
    succeeded = replace(succeeded, revision=2)

    with pytest.raises(WebhookDeliveryConflictError, match="transition"):
        await repository.replace(succeeded, expected_revision=1)


@pytest.mark.asyncio
async def test_replace_rejects_rewritten_attempt_history() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    first_in_flight = _to_in_flight(_delivery())
    retrying = _to_retrying(first_in_flight)
    second_in_flight = _to_in_flight(retrying, at=retrying.next_attempt_at)
    await repository.add(second_in_flight)
    succeeded = _to_succeeded(second_in_flight)
    rewritten = replace(
        succeeded.attempts[0],
        error_category="transport.timeout",
        status_class=None,
    )
    replacement = replace(succeeded, attempts=(rewritten, succeeded.attempts[1]))

    with pytest.raises(WebhookDeliveryConflictError, match="rewrite attempt history"):
        await repository.replace(
            replacement,
            expected_revision=second_in_flight.revision,
        )


@pytest.mark.asyncio
async def test_in_flight_completion_must_append_exactly_one_attempt() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    in_flight = _to_in_flight(_delivery())
    await repository.add(in_flight)
    cancelled = _to_cancelled(in_flight)
    attempt_one = _completed_attempt(
        in_flight,
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=None,
        error_category="transport.timeout",
    )
    attempt_two = replace(
        attempt_one,
        number=2,
        scheduled_at=attempt_one.finished_at,
        started_at=attempt_one.finished_at,
        finished_at=attempt_one.finished_at + timedelta(seconds=1),
        outcome=WebhookAttemptOutcome.SUCCEEDED,
        status_class=WebhookHttpStatusClass.SUCCESSFUL,
        error_category=None,
    )
    invalid = replace(
        cancelled,
        status=WebhookDeliveryStatus.SUCCEEDED,
        attempts=(attempt_one, attempt_two),
        terminal_at=attempt_two.finished_at,
        updated_at=attempt_two.finished_at,
    )

    with pytest.raises(WebhookDeliveryConflictError, match="at most one attempt"):
        await repository.replace(invalid, expected_revision=in_flight.revision)


@pytest.mark.asyncio
async def test_cancelled_in_flight_delivery_cannot_append_attempt() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    in_flight = _to_in_flight(_delivery())
    await repository.add(in_flight)
    attempt = _completed_attempt(
        in_flight,
        outcome=WebhookAttemptOutcome.TERMINAL_FAILURE,
        status_class=WebhookHttpStatusClass.REDIRECTION,
        error_category="http.redirect",
    )
    cancelled = _to_cancelled(in_flight)
    cancelled = replace(cancelled, attempts=(attempt,))

    with pytest.raises(WebhookDeliveryConflictError, match="cannot append"):
        await repository.replace(cancelled, expected_revision=in_flight.revision)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_factory",
    [_to_succeeded, _to_failed, _to_dead_letter, _to_cancelled],
)
async def test_terminal_delivery_is_immutable(terminal_factory: Any) -> None:
    repository = InMemoryWebhookDeliveryRepository()
    in_flight = _to_in_flight(_delivery())
    terminal = (
        terminal_factory(in_flight)
        if terminal_factory is not _to_cancelled
        else terminal_factory(_delivery())
    )
    await repository.add(terminal)
    replacement = replace(
        terminal,
        updated_at=terminal.updated_at + timedelta(seconds=1),
        revision=terminal.revision + 1,
    )

    with pytest.raises(WebhookDeliveryConflictError, match="terminal"):
        await repository.replace(
            replacement,
            expected_revision=terminal.revision,
        )


@pytest.mark.asyncio
async def test_snapshot_reports_bounded_status_and_attempt_counts() -> None:
    repository = InMemoryWebhookDeliveryRepository(capacity=20)
    pending = _delivery(1)
    in_flight = _to_in_flight(_delivery(2))
    retrying = _to_retrying(_to_in_flight(_delivery(3)))
    succeeded = _to_succeeded(_to_in_flight(_delivery(4)))
    failed = _to_failed(_to_in_flight(_delivery(5)))
    dead_letter = _to_dead_letter(_to_in_flight(_delivery(6)))
    cancelled = _to_cancelled(_delivery(7))
    for delivery in (
        pending,
        in_flight,
        retrying,
        succeeded,
        failed,
        dead_letter,
        cancelled,
    ):
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
async def test_close_is_idempotent_clears_state_and_rejects_work() -> None:
    repository = InMemoryWebhookDeliveryRepository()
    delivery = _delivery()
    await repository.add(delivery)

    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()
    assert snapshot.closed is True
    assert snapshot.deliveries == 0

    operations = (
        repository.add(_delivery(2)),
        repository.get(delivery.id),
        repository.get_by_deduplication_key(delivery.deduplication_key),
        repository.list(),
    )
    for operation in operations:
        with pytest.raises(WebhookDeliveryRepositoryClosedError):
            await operation
