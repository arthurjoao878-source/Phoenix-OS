"""Protected dead-letter redrive and interrupted-attempt recovery."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import NoReturn
from uuid import UUID

from phoenix_os.audit import (
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext
from phoenix_os.webhooks.contracts import (
    MAX_WEBHOOK_PAGE_SIZE,
    MAX_WEBHOOK_RETRY_ATTEMPTS,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryRepository,
    WebhookDeliveryStatus,
    WebhookPageRequest,
    WebhookSubscription,
    WebhookSubscriptionRepository,
)
from phoenix_os.webhooks.dispatcher import webhook_retry_delay
from phoenix_os.webhooks.errors import (
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookRecoveryClosedError,
    WebhookRedriveAccessDeniedError,
    WebhookRedriveNotEligibleError,
)

WEBHOOK_REDRIVE_PERMISSION = "webhook.delivery.redrive"
DEFAULT_WEBHOOK_RECOVERY_BATCH_SIZE = 50
MAX_WEBHOOK_RECOVERY_BATCH_SIZE = MAX_WEBHOOK_PAGE_SIZE

type WebhookRecoveryClock = Callable[[], datetime]


class WebhookRecoveryDisposition(StrEnum):
    """Safe result classification for one interrupted delivery."""

    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"
    CANCELLED = "cancelled"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class WebhookRedriveResult:
    """Safe metadata from scheduling one explicit dead-letter retry."""

    delivery_id: UUID
    status: WebhookDeliveryStatus
    completed_attempts: int
    next_attempt_at: datetime
    revision: int

    def __post_init__(self) -> None:
        status = WebhookDeliveryStatus(self.status)
        if status is not WebhookDeliveryStatus.RETRYING:
            raise ValueError("webhook redrive result must be retrying")
        if not 0 < self.completed_attempts < MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook redrive attempt count is outside supported bounds")
        _require_aware(self.next_attempt_at, "webhook redrive next_attempt_at")
        if self.revision <= 0:
            raise ValueError("webhook redrive revision must be positive")
        object.__setattr__(self, "status", status)


@dataclass(frozen=True, slots=True)
class WebhookRecoveryResult:
    """Safe bounded result from recovering one interrupted attempt."""

    delivery_id: UUID
    disposition: WebhookRecoveryDisposition
    status: WebhookDeliveryStatus
    attempt: int | None = None
    next_attempt_at: datetime | None = None
    error_category: str = "runtime_recovery"

    def __post_init__(self) -> None:
        disposition = WebhookRecoveryDisposition(self.disposition)
        status = WebhookDeliveryStatus(self.status)
        expected = {
            WebhookRecoveryDisposition.RETRYING: WebhookDeliveryStatus.RETRYING,
            WebhookRecoveryDisposition.DEAD_LETTER: WebhookDeliveryStatus.DEAD_LETTER,
            WebhookRecoveryDisposition.CANCELLED: WebhookDeliveryStatus.CANCELLED,
        }.get(disposition)
        if expected is not None and status is not expected:
            raise ValueError("webhook recovery disposition and status are inconsistent")
        if self.attempt is not None and not 1 <= self.attempt <= MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook recovery attempt is outside supported bounds")
        if disposition is WebhookRecoveryDisposition.RETRYING:
            if self.next_attempt_at is None:
                raise ValueError("retrying webhook recovery requires next_attempt_at")
        elif self.next_attempt_at is not None:
            raise ValueError("terminal webhook recovery cannot schedule another attempt")
        if not self.error_category.strip():
            raise ValueError("webhook recovery error category must not be blank")
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "error_category", self.error_category.strip().lower())


@dataclass(frozen=True, slots=True)
class WebhookRecoveryBatch:
    """Deterministically ordered outcomes from one interrupted-attempt scan."""

    results: tuple[WebhookRecoveryResult, ...]

    @property
    def considered(self) -> int:
        return len(self.results)

    def count(self, disposition: WebhookRecoveryDisposition) -> int:
        return sum(item.disposition is disposition for item in self.results)


@dataclass(frozen=True, slots=True)
class WebhookRecoverySnapshot:
    """Safe counters for dead-letter redrive and interrupted-attempt recovery."""

    closed: bool
    redrives: int
    redrive_denied: int
    redrive_rejected: int
    recovery_batches: int
    recovered: int
    retrying: int
    dead_letter: int
    cancelled: int
    conflicts: int
    audit_failures: int
    observation_failures: int

    def __post_init__(self) -> None:
        counters = (
            self.redrives,
            self.redrive_denied,
            self.redrive_rejected,
            self.recovery_batches,
            self.recovered,
            self.retrying,
            self.dead_letter,
            self.cancelled,
            self.conflicts,
            self.audit_failures,
            self.observation_failures,
        )
        if any(value < 0 for value in counters):
            raise ValueError("webhook recovery counters cannot be negative")


class WebhookDeliveryRecovery:
    """Authorize dead-letter redrive and recover interrupted in-flight attempts."""

    def __init__(
        self,
        *,
        subscriptions: WebhookSubscriptionRepository,
        deliveries: WebhookDeliveryRepository,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        clock: WebhookRecoveryClock | None = None,
    ) -> None:
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("webhook recovery audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("webhook recovery observability must be ObservabilityHub")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("webhook recovery clock must be callable")

        self._subscriptions = subscriptions
        self._deliveries = deliveries
        self._audit = audit
        self._observability = observability
        self._clock = resolved_clock
        self._closed = False
        self._redrives = 0
        self._redrive_denied = 0
        self._redrive_rejected = 0
        self._recovery_batches = 0
        self._recovered = 0
        self._retrying = 0
        self._dead_letter = 0
        self._cancelled = 0
        self._conflicts = 0
        self._audit_failures = 0
        self._observation_failures = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def redrive(
        self,
        delivery_id: UUID,
        context: SecurityContext,
        *,
        scheduled_at: datetime | None = None,
    ) -> WebhookRedriveResult:
        """Schedule one protected explicit retry without rewriting attempt history."""

        self._ensure_open()
        if not isinstance(delivery_id, UUID):
            raise TypeError("webhook delivery id must be UUID")
        if not isinstance(context, SecurityContext):
            raise TypeError("webhook redrive context must be SecurityContext")
        await self._authorize_redrive(context)

        current = await self._deliveries.get(delivery_id)
        if current is None:
            raise WebhookDeliveryNotFoundError("webhook delivery was not found")
        if not current.redrive_eligible:
            await self._reject_redrive("delivery_not_eligible")

        subscription = await self._subscriptions.get(current.subscription_id)
        if subscription is None:
            await self._reject_redrive("subscription_missing")
        if not subscription.deliverable:
            await self._reject_redrive("subscription_inactive")

        now = self._now()
        requested = (
            now
            if scheduled_at is None
            else _as_utc(
                scheduled_at,
                "webhook redrive scheduled_at",
            )
        )
        last_attempt = current.attempts[-1]
        minimum = max(current.updated_at, last_attempt.finished_at) + timedelta(microseconds=1)
        next_attempt_at = max(now, requested, minimum)
        updated_at = max(now, current.updated_at)

        replacement = replace(
            current,
            status=WebhookDeliveryStatus.RETRYING,
            updated_at=updated_at,
            current_attempt=None,
            in_flight_at=None,
            next_attempt_at=next_attempt_at,
            terminal_at=None,
            revision=current.revision + 1,
        )
        try:
            replacement = await self._deliveries.replace(
                replacement,
                expected_revision=current.revision,
            )
        except WebhookDeliveryConflictError:
            await self._increment(conflicts=1)
            raise

        await self._increment(redrives=1)
        await self._signal_redrive(replacement, subscription, context)
        return WebhookRedriveResult(
            delivery_id=replacement.id,
            status=replacement.status,
            completed_attempts=replacement.completed_attempts,
            next_attempt_at=next_attempt_at,
            revision=replacement.revision,
        )

    async def recover_in_flight(
        self,
        *,
        limit: int | None = None,
    ) -> WebhookRecoveryBatch:
        """Recover one bounded deterministic batch of interrupted in-flight attempts."""

        self._ensure_open()
        resolved_limit = DEFAULT_WEBHOOK_RECOVERY_BATCH_SIZE if limit is None else limit
        if type(resolved_limit) is not int:
            raise TypeError("webhook recovery limit must be an integer")
        if not 1 <= resolved_limit <= MAX_WEBHOOK_RECOVERY_BATCH_SIZE:
            raise ValueError("webhook recovery limit is outside supported bounds")

        interrupted = await self._interrupted_deliveries(resolved_limit)
        results: list[WebhookRecoveryResult] = []
        for delivery in interrupted:
            results.append(await self._recover_one(delivery.id))
        await self._increment(recovery_batches=1)
        return WebhookRecoveryBatch(tuple(results))

    async def snapshot(self) -> WebhookRecoverySnapshot:
        async with self._lock:
            return WebhookRecoverySnapshot(
                closed=self._closed,
                redrives=self._redrives,
                redrive_denied=self._redrive_denied,
                redrive_rejected=self._redrive_rejected,
                recovery_batches=self._recovery_batches,
                recovered=self._recovered,
                retrying=self._retrying,
                dead_letter=self._dead_letter,
                cancelled=self._cancelled,
                conflicts=self._conflicts,
                audit_failures=self._audit_failures,
                observation_failures=self._observation_failures,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _recover_one(self, delivery_id: UUID) -> WebhookRecoveryResult:
        current = await self._deliveries.get(delivery_id)
        if current is None:
            raise WebhookDeliveryNotFoundError("webhook delivery was not found")
        if current.status is not WebhookDeliveryStatus.IN_FLIGHT:
            await self._increment(conflicts=1)
            return WebhookRecoveryResult(
                delivery_id=current.id,
                disposition=WebhookRecoveryDisposition.CONFLICT,
                status=current.status,
                error_category="recovery_conflict",
            )

        subscription = await self._subscriptions.get(current.subscription_id)
        if subscription is None:
            return await self._recover_cancel(current, "subscription_missing")
        if not subscription.deliverable:
            return await self._recover_cancel(current, "subscription_inactive")

        started_at = current.in_flight_at
        attempt_number = current.current_attempt
        if started_at is None or attempt_number is None:  # pragma: no cover - contract invariant
            raise RuntimeError("in-flight webhook delivery has no attempt metadata")
        finished_at = max(self._now(), current.updated_at, started_at)
        retry_scheduled = (
            attempt_number < subscription.retry.max_attempts
            and attempt_number < MAX_WEBHOOK_RETRY_ATTEMPTS
        )
        next_attempt_at: datetime | None = None
        if retry_scheduled:
            next_attempt_at = finished_at + webhook_retry_delay(
                current,
                subscription,
                attempt_number,
            )
            status = WebhookDeliveryStatus.RETRYING
            disposition = WebhookRecoveryDisposition.RETRYING
        else:
            status = WebhookDeliveryStatus.DEAD_LETTER
            disposition = WebhookRecoveryDisposition.DEAD_LETTER

        attempt = WebhookAttempt(
            delivery_id=current.id,
            number=attempt_number,
            scheduled_at=started_at,
            started_at=started_at,
            finished_at=finished_at,
            outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
            retry_scheduled=retry_scheduled,
            next_attempt_at=next_attempt_at,
            error_category="runtime_recovery",
        )
        replacement = replace(
            current,
            status=status,
            updated_at=finished_at,
            attempts=(*current.attempts, attempt),
            current_attempt=None,
            in_flight_at=None,
            next_attempt_at=next_attempt_at,
            terminal_at=None if retry_scheduled else finished_at,
            revision=current.revision + 1,
        )
        try:
            replacement = await self._deliveries.replace(
                replacement,
                expected_revision=current.revision,
            )
        except WebhookDeliveryConflictError:
            await self._increment(conflicts=1)
            return WebhookRecoveryResult(
                delivery_id=current.id,
                disposition=WebhookRecoveryDisposition.CONFLICT,
                status=current.status,
                attempt=attempt_number,
                error_category="recovery_conflict",
            )

        changes = {"recovered": 1}
        if disposition is WebhookRecoveryDisposition.RETRYING:
            changes["retrying"] = 1
        else:
            changes["dead_letter"] = 1
        await self._increment(**changes)
        result = WebhookRecoveryResult(
            delivery_id=replacement.id,
            disposition=disposition,
            status=replacement.status,
            attempt=attempt_number,
            next_attempt_at=next_attempt_at,
        )
        await self._signal_recovery(replacement, subscription, result)
        return result

    async def _recover_cancel(
        self,
        current: WebhookDelivery,
        category: str,
    ) -> WebhookRecoveryResult:
        finished_at = max(self._now(), current.updated_at)
        replacement = replace(
            current,
            status=WebhookDeliveryStatus.CANCELLED,
            updated_at=finished_at,
            current_attempt=None,
            in_flight_at=None,
            next_attempt_at=None,
            terminal_at=finished_at,
            revision=current.revision + 1,
        )
        try:
            replacement = await self._deliveries.replace(
                replacement,
                expected_revision=current.revision,
            )
        except WebhookDeliveryConflictError:
            await self._increment(conflicts=1)
            return WebhookRecoveryResult(
                delivery_id=current.id,
                disposition=WebhookRecoveryDisposition.CONFLICT,
                status=current.status,
                attempt=current.current_attempt,
                error_category="recovery_conflict",
            )

        await self._increment(recovered=1, cancelled=1)
        result = WebhookRecoveryResult(
            delivery_id=replacement.id,
            disposition=WebhookRecoveryDisposition.CANCELLED,
            status=replacement.status,
            attempt=current.current_attempt,
            error_category=category,
        )
        await self._signal_recovery(replacement, None, result)
        return result

    async def _interrupted_deliveries(
        self,
        limit: int,
    ) -> tuple[WebhookDelivery, ...]:
        interrupted: list[WebhookDelivery] = []
        request = WebhookPageRequest(limit=MAX_WEBHOOK_PAGE_SIZE)
        while True:
            page = await self._deliveries.list(request)
            interrupted.extend(
                item for item in page.items if item.status is WebhookDeliveryStatus.IN_FLIGHT
            )
            next_offset = page.page.next_offset
            if next_offset is None:
                break
            request = WebhookPageRequest(
                offset=next_offset,
                limit=MAX_WEBHOOK_PAGE_SIZE,
            )
        ordered = sorted(
            interrupted,
            key=lambda item: (
                item.in_flight_at or item.updated_at,
                item.created_at,
                item.id.hex,
            ),
        )
        return tuple(ordered[:limit])

    async def _authorize_redrive(self, context: SecurityContext) -> None:
        permitted = {
            WEBHOOK_REDRIVE_PERMISSION,
            "webhook.delivery.*",
            "webhook.*",
            "*",
        }
        if not context.authenticated or context.permissions.isdisjoint(permitted):
            await self._increment(redrive_denied=1)
            raise WebhookRedriveAccessDeniedError(
                "authenticated webhook redrive permission is required"
            )

    async def _reject_redrive(self, category: str) -> NoReturn:
        await self._increment(redrive_rejected=1)
        raise WebhookRedriveNotEligibleError(category)

    async def _signal_redrive(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription,
        context: SecurityContext,
    ) -> None:
        details: dict[str, object] = {
            "delivery_id": str(delivery.id),
            "subscription_id": str(delivery.subscription_id),
            "event_type": delivery.event_type,
            "completed_attempts": delivery.completed_attempts,
            "next_attempt_at": delivery.next_attempt_at.isoformat()
            if delivery.next_attempt_at is not None
            else None,
            "egress_policy": subscription.egress_policy,
            "key_version": subscription.signing.key_version,
        }
        causation_id = context.causation_id or delivery.id
        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name="webhook.delivery.redriven",
                        source="phoenix.webhooks",
                        category=AuditCategory.OTHER,
                        action="webhook.delivery.redrive",
                        resource=f"webhook-delivery:{delivery.id}",
                        actor=context.principal,
                        outcome=AuditOutcome.SUCCEEDED,
                        severity=AuditSeverity.WARNING,
                        details=details,
                        correlation_id=context.correlation_id,
                        causation_id=causation_id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)
        if self._observability is not None:
            try:
                await self._observability.metric(
                    "webhook.delivery.redrives",
                    1,
                    source="phoenix.webhooks",
                    kind=MetricKind.COUNTER,
                    attributes=details,
                    correlation_id=context.correlation_id,
                    causation_id=causation_id,
                )
                await self._observability.log(
                    "webhook.delivery.redriven",
                    source="phoenix.webhooks",
                    message="dead-letter webhook delivery scheduled for explicit retry",
                    severity=Severity.WARNING,
                    attributes=details,
                    correlation_id=context.correlation_id,
                    causation_id=causation_id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _signal_recovery(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription | None,
        result: WebhookRecoveryResult,
    ) -> None:
        details: dict[str, object] = {
            "delivery_id": str(delivery.id),
            "subscription_id": str(delivery.subscription_id),
            "event_type": delivery.event_type,
            "status": delivery.status.value,
            "disposition": result.disposition.value,
            "error_category": result.error_category,
        }
        if result.attempt is not None:
            details["attempt"] = result.attempt
        if subscription is not None:
            details["egress_policy"] = subscription.egress_policy
            details["key_version"] = subscription.signing.key_version

        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name="webhook.delivery.recovered",
                        source="phoenix.webhooks",
                        category=AuditCategory.RUNTIME,
                        action="webhook.delivery.recover",
                        resource=f"webhook-delivery:{delivery.id}",
                        actor="phoenix.webhooks",
                        outcome=AuditOutcome.SUCCEEDED,
                        severity=AuditSeverity.WARNING,
                        details=details,
                        correlation_id=delivery.correlation_id,
                        causation_id=delivery.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)
        if self._observability is not None:
            try:
                await self._observability.metric(
                    "webhook.delivery.recoveries",
                    1,
                    source="phoenix.webhooks",
                    kind=MetricKind.COUNTER,
                    attributes=details,
                    correlation_id=delivery.correlation_id,
                    causation_id=delivery.id,
                )
                await self._observability.log(
                    "webhook.delivery.recovered",
                    source="phoenix.webhooks",
                    message="interrupted webhook attempt recovered",
                    severity=Severity.WARNING,
                    attributes=details,
                    correlation_id=delivery.correlation_id,
                    causation_id=delivery.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _increment(self, **changes: int) -> None:
        async with self._lock:
            for name, amount in changes.items():
                attribute = f"_{name}"
                current = getattr(self, attribute)
                updated = current + amount
                if updated < 0:
                    raise RuntimeError("webhook recovery counter cannot become negative")
                setattr(self, attribute, updated)

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime):
            raise TypeError("webhook recovery clock must return datetime")
        return _as_utc(now, "webhook recovery clock")

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookRecoveryClosedError("webhook delivery recovery is closed")


def _as_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")


def _utc_now() -> datetime:
    return datetime.now(UTC)
