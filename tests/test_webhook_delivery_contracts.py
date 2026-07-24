from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.webhooks import (
    MAX_WEBHOOK_DELIVERY_BODY_BYTES,
    MAX_WEBHOOK_RETRY_ATTEMPTS,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryPage,
    WebhookDeliveryRepositorySnapshot,
    WebhookDeliveryStatus,
    WebhookHttpStatusClass,
    WebhookPageInfo,
)

DELIVERY_ID = UUID("00000000-0000-0000-0000-000000000101")
SUBSCRIPTION_ID = UUID("00000000-0000-0000-0000-000000000201")
EVENT_ID = UUID("00000000-0000-0000-0000-000000000301")
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
BODY = b'{"schema_version":1,"payload":{"safe":true}}'
BODY_DIGEST = hashlib.sha256(BODY).hexdigest()
DEDUPLICATION_KEY = hashlib.sha256(b"subscription:event").hexdigest()


def _attempt(
    *,
    number: int = 1,
    outcome: WebhookAttemptOutcome = WebhookAttemptOutcome.SUCCEEDED,
    status_class: WebhookHttpStatusClass | None = WebhookHttpStatusClass.SUCCESSFUL,
    retry_scheduled: bool = False,
    next_attempt_at: datetime | None = None,
    error_category: str | None = None,
) -> WebhookAttempt:
    scheduled_at = NOW + timedelta(seconds=number)
    started_at = scheduled_at + timedelta(milliseconds=10)
    finished_at = started_at + timedelta(milliseconds=20)
    return WebhookAttempt(
        delivery_id=DELIVERY_ID,
        number=number,
        scheduled_at=scheduled_at,
        started_at=started_at,
        finished_at=finished_at,
        outcome=outcome,
        status_class=status_class,
        retry_scheduled=retry_scheduled,
        next_attempt_at=next_attempt_at,
        error_category=error_category,
    )


def _delivery(**changes: object) -> WebhookDelivery:
    values: dict[str, object] = {
        "id": DELIVERY_ID,
        "subscription_id": SUBSCRIPTION_ID,
        "event_type": "job.completed",
        "deduplication_key": DEDUPLICATION_KEY,
        "canonical_body": BODY,
        "body_sha256": BODY_DIGEST,
        "occurred_at": NOW,
        "created_at": NOW,
        "updated_at": NOW,
        "next_attempt_at": NOW,
        "source_event_id": EVENT_ID,
        "correlation_id": "request-123",
    }
    values.update(changes)
    return WebhookDelivery(**values)  # type: ignore[arg-type]


def test_attempt_success_requires_only_safe_2xx_metadata() -> None:
    attempt = _attempt()

    assert attempt.outcome is WebhookAttemptOutcome.SUCCEEDED
    assert attempt.status_class is WebhookHttpStatusClass.SUCCESSFUL
    assert attempt.retry_scheduled is False
    assert attempt.error_category is None


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"number": 0}, "number"),
        ({"number": MAX_WEBHOOK_RETRY_ATTEMPTS + 1}, "number"),
        ({"status_class": WebhookHttpStatusClass.SERVER_ERROR}, "2xx"),
        ({"error_category": "transport.timeout"}, "error category"),
        ({"retry_scheduled": True}, "schedule a retry"),
        ({"next_attempt_at": NOW + timedelta(minutes=1)}, "schedule a retry"),
    ],
)
def test_successful_attempt_rejects_inconsistent_metadata(
    changes: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        _attempt(**changes)  # type: ignore[arg-type]


def test_retryable_attempt_normalizes_error_and_schedules_retry() -> None:
    next_attempt_at = NOW + timedelta(minutes=2)
    attempt = _attempt(
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=WebhookHttpStatusClass.SERVER_ERROR,
        retry_scheduled=True,
        next_attempt_at=next_attempt_at,
        error_category=" HTTP.Server ",
    )

    assert attempt.error_category == "http.server"
    assert attempt.next_attempt_at == next_attempt_at


@pytest.mark.parametrize(
    "changes",
    [
        {
            "outcome": WebhookAttemptOutcome.RETRYABLE_FAILURE,
            "status_class": None,
            "error_category": None,
        },
        {
            "outcome": WebhookAttemptOutcome.RETRYABLE_FAILURE,
            "status_class": WebhookHttpStatusClass.SUCCESSFUL,
            "error_category": "http.success",
        },
        {
            "outcome": WebhookAttemptOutcome.RETRYABLE_FAILURE,
            "status_class": None,
            "error_category": "transport.timeout",
            "retry_scheduled": True,
        },
        {
            "outcome": WebhookAttemptOutcome.TERMINAL_FAILURE,
            "status_class": WebhookHttpStatusClass.REDIRECTION,
            "error_category": "http.redirect",
            "retry_scheduled": True,
            "next_attempt_at": NOW + timedelta(minutes=2),
        },
    ],
)
def test_failed_attempt_rejects_inconsistent_metadata(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _attempt(**changes)  # type: ignore[arg-type]


def test_attempt_rejects_invalid_timestamps_and_schema() -> None:
    attempt = _attempt()

    with pytest.raises(ValueError, match="started_at"):
        replace(attempt, started_at=attempt.scheduled_at - timedelta(microseconds=1))

    with pytest.raises(ValueError, match="finished_at"):
        replace(attempt, finished_at=attempt.started_at - timedelta(microseconds=1))

    with pytest.raises(ValueError, match="schema"):
        replace(attempt, schema_version=2)


@pytest.mark.parametrize("category", ["", " has space ", "UPPER/SLASH", "x" * 65])
def test_attempt_rejects_unsafe_error_categories(category: str) -> None:
    with pytest.raises(ValueError, match="error category"):
        _attempt(
            outcome=WebhookAttemptOutcome.TERMINAL_FAILURE,
            status_class=None,
            error_category=category,
        )


def test_pending_delivery_is_immutable_and_redacts_body_from_repr() -> None:
    delivery = _delivery()

    assert delivery.status is WebhookDeliveryStatus.PENDING
    assert delivery.completed_attempts == 0
    assert delivery.event_type == "job.completed"
    assert delivery.correlation_id == "request-123"
    assert "canonical_body=<redacted>" in repr(delivery)
    assert BODY.decode() not in repr(delivery)


@pytest.mark.parametrize(
    "changes",
    [
        {"canonical_body": bytearray(BODY)},
        {"canonical_body": b""},
        {"canonical_body": b"x" * (MAX_WEBHOOK_DELIVERY_BODY_BYTES + 1)},
        {"body_sha256": "0" * 64},
        {"body_sha256": "not-a-digest"},
        {"deduplication_key": "not-a-digest"},
    ],
)
def test_delivery_rejects_invalid_body_or_digest(changes: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        _delivery(**changes)


def test_delivery_rejects_invalid_timestamps_revision_and_schema() -> None:
    with pytest.raises(ValueError, match="created_at"):
        _delivery(created_at=NOW - timedelta(seconds=1), updated_at=NOW)

    with pytest.raises(ValueError, match="updated_at"):
        _delivery(updated_at=NOW - timedelta(seconds=1))

    with pytest.raises(ValueError, match="revision"):
        _delivery(revision=0)

    with pytest.raises(ValueError, match="schema"):
        _delivery(schema_version=2)


@pytest.mark.parametrize("correlation_id", ["", "  ", "x" * 129, "bad\nvalue"])
def test_delivery_rejects_unsafe_correlation_ids(correlation_id: str) -> None:
    with pytest.raises(ValueError, match="correlation id"):
        _delivery(correlation_id=correlation_id)


def test_in_flight_delivery_requires_exact_current_attempt_metadata() -> None:
    delivery = _delivery(
        status=WebhookDeliveryStatus.IN_FLIGHT,
        current_attempt=1,
        in_flight_at=NOW,
        next_attempt_at=None,
    )

    assert delivery.current_attempt == 1

    with pytest.raises(ValueError, match="attempt number"):
        replace(delivery, current_attempt=2)

    with pytest.raises(ValueError, match="inconsistent"):
        replace(delivery, in_flight_at=None)


def test_retrying_delivery_requires_matching_retryable_attempt() -> None:
    next_attempt_at = NOW + timedelta(minutes=2)
    attempt = _attempt(
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=WebhookHttpStatusClass.SERVER_ERROR,
        retry_scheduled=True,
        next_attempt_at=next_attempt_at,
        error_category="http.server",
    )
    delivery = _delivery(
        status=WebhookDeliveryStatus.RETRYING,
        attempts=(attempt,),
        updated_at=attempt.finished_at,
        next_attempt_at=next_attempt_at,
    )

    assert delivery.completed_attempts == 1

    with pytest.raises(ValueError, match="retry metadata"):
        replace(delivery, next_attempt_at=next_attempt_at + timedelta(seconds=1))


def test_successful_delivery_requires_successful_final_attempt() -> None:
    attempt = _attempt()
    delivery = _delivery(
        status=WebhookDeliveryStatus.SUCCEEDED,
        attempts=(attempt,),
        updated_at=attempt.finished_at,
        next_attempt_at=None,
        terminal_at=attempt.finished_at,
    )

    assert delivery.status.terminal is True

    retry = _attempt(
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=None,
        error_category="transport.timeout",
    )
    with pytest.raises(ValueError, match="successful final attempt"):
        replace(delivery, attempts=(retry,))


def test_failed_and_dead_letter_deliveries_require_matching_final_outcome() -> None:
    terminal = _attempt(
        outcome=WebhookAttemptOutcome.TERMINAL_FAILURE,
        status_class=WebhookHttpStatusClass.REDIRECTION,
        error_category="http.redirect",
    )
    failed = _delivery(
        status=WebhookDeliveryStatus.FAILED,
        attempts=(terminal,),
        updated_at=terminal.finished_at,
        next_attempt_at=None,
        terminal_at=terminal.finished_at,
    )
    assert failed.status is WebhookDeliveryStatus.FAILED

    exhausted = _attempt(
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        status_class=None,
        error_category="transport.timeout",
    )
    dead_letter = _delivery(
        status=WebhookDeliveryStatus.DEAD_LETTER,
        attempts=(exhausted,),
        updated_at=exhausted.finished_at,
        next_attempt_at=None,
        terminal_at=exhausted.finished_at,
    )
    assert dead_letter.status is WebhookDeliveryStatus.DEAD_LETTER

    with pytest.raises(ValueError, match="exhausted"):
        replace(dead_letter, attempts=(terminal,))


def test_cancelled_delivery_requires_terminal_metadata_without_attempts() -> None:
    delivery = _delivery(
        status=WebhookDeliveryStatus.CANCELLED,
        next_attempt_at=None,
        terminal_at=NOW,
    )

    assert delivery.status is WebhookDeliveryStatus.CANCELLED

    with pytest.raises(ValueError, match="terminal metadata"):
        replace(delivery, terminal_at=None)


def test_delivery_rejects_foreign_or_noncontiguous_attempts() -> None:
    attempt = _attempt()

    with pytest.raises(ValueError, match="another delivery"):
        _delivery(
            status=WebhookDeliveryStatus.SUCCEEDED,
            attempts=(replace(attempt, delivery_id=EVENT_ID),),
            updated_at=attempt.finished_at,
            next_attempt_at=None,
            terminal_at=attempt.finished_at,
        )

    with pytest.raises(ValueError, match="contiguous"):
        _delivery(
            status=WebhookDeliveryStatus.SUCCEEDED,
            attempts=(replace(attempt, number=2),),
            updated_at=attempt.finished_at,
            next_attempt_at=None,
            terminal_at=attempt.finished_at,
        )


def test_delivery_page_rejects_mismatched_or_duplicate_items() -> None:
    first = _delivery()
    page = WebhookPageInfo(offset=0, limit=10, returned=1, total=1, next_offset=None)

    assert WebhookDeliveryPage((first,), page).items == (first,)

    with pytest.raises(ValueError, match="count"):
        WebhookDeliveryPage((), page)

    duplicate_page = WebhookPageInfo(
        offset=0,
        limit=10,
        returned=2,
        total=2,
        next_offset=None,
    )
    with pytest.raises(ValueError, match="unique"):
        WebhookDeliveryPage((first, first), duplicate_page)


def test_delivery_repository_snapshot_validates_safe_counters() -> None:
    snapshot = WebhookDeliveryRepositorySnapshot(
        closed=False,
        deliveries=3,
        pending=1,
        in_flight=0,
        retrying=1,
        succeeded=1,
        failed=0,
        dead_letter=0,
        cancelled=0,
        attempts=2,
        capacity=100,
    )

    assert snapshot.deliveries == 3

    with pytest.raises(ValueError, match="status counts"):
        replace(snapshot, pending=2)

    with pytest.raises(ValueError, match="attempt count"):
        replace(snapshot, attempts=3 * MAX_WEBHOOK_RETRY_ATTEMPTS + 1)
