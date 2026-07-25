"""Asynchronous durable Event Bus publication for accepted inbound events."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from phoenix_os.audit import (
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.events import BusClosedError, ErrorPolicy, Event, EventBus
from phoenix_os.inbound_events.contracts import (
    MAX_INBOUND_PAGE_SIZE,
    MAX_INBOUND_PUBLICATION_ATTEMPTS,
    InboundAcceptedEvent,
    InboundEventPage,
    InboundEventRepository,
    InboundEventSource,
    InboundPageRequest,
    InboundPublicationAttempt,
    InboundPublicationOutcome,
    InboundPublicationStatus,
    InboundSourceRepository,
)
from phoenix_os.inbound_events.errors import (
    InboundEventConflictError,
    InboundEventNotFoundError,
    InboundPublisherClosedError,
    InboundPublisherStateError,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity

DEFAULT_INBOUND_PUBLICATION_BATCH_SIZE = 50
DEFAULT_INBOUND_PUBLISHER_CONCURRENCY = 16
DEFAULT_INBOUND_PUBLISHER_POLL_INTERVAL = 1.0
MAX_INBOUND_PUBLISHER_CONCURRENCY = 1_024

type InboundPublisherClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class InboundPublisherConfig:
    """Finite scan and worker concurrency bounds."""

    batch_size: int = DEFAULT_INBOUND_PUBLICATION_BATCH_SIZE
    global_concurrency: int = DEFAULT_INBOUND_PUBLISHER_CONCURRENCY
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.batch_size) is not int:
            raise TypeError("inbound publisher batch size must be an integer")
        if type(self.global_concurrency) is not int:
            raise TypeError("inbound publisher concurrency must be an integer")
        if not 1 <= self.batch_size <= MAX_INBOUND_PAGE_SIZE:
            raise ValueError("inbound publisher batch size is outside supported bounds")
        if not 1 <= self.global_concurrency <= MAX_INBOUND_PUBLISHER_CONCURRENCY:
            raise ValueError("inbound publisher concurrency is outside supported bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound publisher config version")


class InboundPublicationDisposition(StrEnum):
    """Safe result from one publication decision."""

    SKIPPED = "skipped"
    CONFLICT = "conflict"
    PUBLISHED = "published"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"
    DISCARDED = "discarded"


@dataclass(frozen=True, slots=True)
class InboundPublicationResult:
    """Bounded publication result without payloads or protected digests."""

    accepted_event_id: UUID
    disposition: InboundPublicationDisposition
    status: InboundPublicationStatus
    attempt: int | None = None
    error_category: str | None = None
    next_attempt_at: datetime | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        disposition = InboundPublicationDisposition(self.disposition)
        status = InboundPublicationStatus(self.status)
        if self.attempt is not None and not (1 <= self.attempt <= MAX_INBOUND_PUBLICATION_ATTEMPTS):
            raise ValueError("inbound publication result attempt is outside bounds")
        category = self.error_category
        if category is not None:
            category = _normalize_error_category(category)
        if self.next_attempt_at is not None:
            _require_aware(self.next_attempt_at, "inbound publication result schedule")
        expected = {
            InboundPublicationDisposition.PUBLISHED: InboundPublicationStatus.PUBLISHED,
            InboundPublicationDisposition.RETRYING: InboundPublicationStatus.RETRYING,
            InboundPublicationDisposition.DEAD_LETTER: InboundPublicationStatus.DEAD_LETTER,
            InboundPublicationDisposition.DISCARDED: InboundPublicationStatus.DISCARDED,
        }.get(disposition)
        if expected is not None and status is not expected:
            raise ValueError("inbound publication disposition and status are inconsistent")
        if disposition is InboundPublicationDisposition.RETRYING:
            if self.next_attempt_at is None or category is None:
                raise ValueError("retrying inbound publication result is inconsistent")
        elif self.next_attempt_at is not None:
            raise ValueError("non-retrying publication cannot schedule another attempt")
        if disposition is InboundPublicationDisposition.PUBLISHED:
            if category is not None:
                raise ValueError("published inbound result cannot contain an error")
        elif (
            disposition
            not in {
                InboundPublicationDisposition.SKIPPED,
                InboundPublicationDisposition.CONFLICT,
            }
            and category is None
        ):
            raise ValueError("failed inbound publication result requires an error")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound publication result version")
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "error_category", category)


@dataclass(frozen=True, slots=True)
class InboundPublicationBatch:
    """Deterministically ordered outcomes from one bounded scan."""

    results: tuple[InboundPublicationResult, ...]

    @property
    def considered(self) -> int:
        return len(self.results)

    def count(self, disposition: InboundPublicationDisposition) -> int:
        return sum(item.disposition is disposition for item in self.results)


@dataclass(frozen=True, slots=True)
class InboundPublisherSnapshot:
    """Safe publisher and durable queue health counters."""

    closed: bool
    batches: int
    considered: int
    claimed: int
    published: int
    retrying: int
    dead_letter: int
    discarded: int
    conflicts: int
    skipped: int
    source_missing: int
    bus_failures: int
    handler_failures: int
    publisher_failures: int
    saturation_events: int
    audit_failures: int
    observation_failures: int
    active: int
    global_limit: int
    pending_events: int
    retrying_events: int
    publishing_events: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        counters = (
            self.batches,
            self.considered,
            self.claimed,
            self.published,
            self.retrying,
            self.dead_letter,
            self.discarded,
            self.conflicts,
            self.skipped,
            self.source_missing,
            self.bus_failures,
            self.handler_failures,
            self.publisher_failures,
            self.saturation_events,
            self.audit_failures,
            self.observation_failures,
            self.active,
            self.pending_events,
            self.retrying_events,
            self.publishing_events,
        )
        if any(value < 0 for value in counters):
            raise ValueError("inbound publisher snapshot counters cannot be negative")
        if not 1 <= self.global_limit <= MAX_INBOUND_PUBLISHER_CONCURRENCY:
            raise ValueError("inbound publisher snapshot concurrency is invalid")
        if self.active > self.global_limit:
            raise ValueError("inbound publisher active count exceeds its limit")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound publisher snapshot version")


class InboundPublisherRuntimeState(StrEnum):
    """One-shot lifecycle state for the Runtime-owned publisher worker."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class InboundPublisherWorkerSnapshot:
    """Safe bounded publisher-worker counters."""

    state: InboundPublisherRuntimeState
    ticks: int
    considered: int
    failures: int
    last_error: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if min(self.ticks, self.considered, self.failures) < 0:
            raise ValueError("inbound publisher worker counters cannot be negative")
        error = None if self.last_error is None else self.last_error.strip() or None
        if error is not None and len(error) > 128:
            raise ValueError("inbound publisher worker error category is too long")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound publisher worker snapshot version")
        object.__setattr__(self, "state", InboundPublisherRuntimeState(self.state))
        object.__setattr__(self, "last_error", error)


class InboundEventPublisher:
    """Claim due events, publish stable Event Bus facts, and durably complete attempts."""

    def __init__(
        self,
        *,
        sources: InboundSourceRepository,
        events: InboundEventRepository,
        event_bus: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        config: InboundPublisherConfig | None = None,
        clock: InboundPublisherClock | None = None,
    ) -> None:
        if not callable(getattr(sources, "get", None)):
            raise TypeError("inbound publisher source repository is invalid")
        if not all(
            callable(getattr(events, name, None)) for name in ("get", "list", "replace", "snapshot")
        ):
            raise TypeError("inbound publisher event repository is invalid")
        if not isinstance(event_bus, EventBus):
            raise TypeError("inbound publisher requires EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("inbound publisher audit must be AuditLedger")
        if observability is not None and not isinstance(
            observability,
            ObservabilityHub,
        ):
            raise TypeError("inbound publisher observability must be ObservabilityHub")
        resolved_config = InboundPublisherConfig() if config is None else config
        if not isinstance(resolved_config, InboundPublisherConfig):
            raise TypeError("inbound publisher config is invalid")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("inbound publisher clock must be callable")
        self._sources = sources
        self._events = events
        self._event_bus = event_bus
        self._audit = audit
        self._observability = observability
        self._config = resolved_config
        self._clock = resolved_clock
        self._lane = asyncio.Semaphore(resolved_config.global_concurrency)
        self._counter_lock = asyncio.Lock()
        self._closed = False
        self._batches = 0
        self._considered = 0
        self._claimed = 0
        self._published = 0
        self._retrying = 0
        self._dead_letter = 0
        self._discarded = 0
        self._conflicts = 0
        self._skipped = 0
        self._source_missing = 0
        self._bus_failures = 0
        self._handler_failures = 0
        self._publisher_failures = 0
        self._saturation_events = 0
        self._audit_failures = 0
        self._observation_failures = 0
        self._active = 0

    @property
    def closed(self) -> bool:
        return self._closed

    async def publish_due(self, *, limit: int | None = None) -> InboundPublicationBatch:
        """Publish one bounded deterministic batch of due accepted events."""

        self._ensure_open()
        resolved_limit = self._config.batch_size if limit is None else limit
        if type(resolved_limit) is not int:
            raise TypeError("inbound publication limit must be an integer")
        if not 1 <= resolved_limit <= MAX_INBOUND_PAGE_SIZE:
            raise ValueError("inbound publication limit is outside supported bounds")
        due = await self._due_events(self._now(), resolved_limit)
        if not due:
            await self._increment(batches=1)
            return InboundPublicationBatch(())
        results = await asyncio.gather(*(self.publish(item.id) for item in due))
        await self._increment(batches=1)
        return InboundPublicationBatch(tuple(results))

    async def publish(self, accepted_event_id: UUID) -> InboundPublicationResult:
        """Attempt one due accepted event under bounded concurrency."""

        self._ensure_open()
        if not isinstance(accepted_event_id, UUID):
            raise TypeError("inbound accepted event id must be UUID")
        await self._increment(considered=1)
        current = await self._events.get(accepted_event_id)
        if current is None:
            raise InboundEventNotFoundError("inbound accepted event was not found")
        if not _is_due(current, self._now()):
            return await self._skipped_result(current)
        if self._lane.locked():
            await self._increment(saturation_events=1)
        async with self._lane:
            await self._increment(active=1)
            try:
                return await self._publish_claimed(accepted_event_id)
            finally:
                await self._increment(active=-1)

    async def snapshot(self) -> InboundPublisherSnapshot:
        repository = await self._events.snapshot()
        async with self._counter_lock:
            return InboundPublisherSnapshot(
                closed=self._closed,
                batches=self._batches,
                considered=self._considered,
                claimed=self._claimed,
                published=self._published,
                retrying=self._retrying,
                dead_letter=self._dead_letter,
                discarded=self._discarded,
                conflicts=self._conflicts,
                skipped=self._skipped,
                source_missing=self._source_missing,
                bus_failures=self._bus_failures,
                handler_failures=self._handler_failures,
                publisher_failures=self._publisher_failures,
                saturation_events=self._saturation_events,
                audit_failures=self._audit_failures,
                observation_failures=self._observation_failures,
                active=self._active,
                global_limit=self._config.global_concurrency,
                pending_events=repository.pending,
                retrying_events=repository.retrying,
                publishing_events=repository.publishing,
            )

    async def close(self) -> None:
        async with self._counter_lock:
            self._closed = True

    async def _publish_claimed(self, accepted_event_id: UUID) -> InboundPublicationResult:
        current = await self._events.get(accepted_event_id)
        if current is None:
            raise InboundEventNotFoundError("inbound accepted event was not found")
        if not _is_due(current, self._now()):
            return await self._skipped_result(current)
        source = await self._sources.get(current.source_id)
        if source is None:
            await self._increment(source_missing=1)
            return await self._discard(current, category="source_missing")
        if not source.accepting:
            return await self._discard(current, category="source_inactive")
        scheduled_at = current.next_attempt_at
        if scheduled_at is None:  # pragma: no cover
            raise RuntimeError("due inbound event lost its publication schedule")
        attempt_number = current.completed_attempts + 1
        started_at = max(self._now(), current.updated_at, scheduled_at)
        claimed = replace(
            current,
            status=InboundPublicationStatus.PUBLISHING,
            updated_at=started_at,
            current_attempt=attempt_number,
            publishing_at=started_at,
            next_attempt_at=None,
            terminal_at=None,
            revision=current.revision + 1,
        )
        try:
            claimed = await self._events.replace(
                claimed,
                expected_revision=current.revision,
            )
        except InboundEventConflictError:
            return await self._conflict_result(current)
        await self._increment(claimed=1)
        bus_event = _stable_bus_event(claimed, attempt_number)
        try:
            report = await self._event_bus.publish(
                bus_event,
                error_policy=ErrorPolicy.COLLECT,
            )
        except asyncio.CancelledError:
            try:
                await asyncio.shield(
                    self._complete_failure(
                        claimed,
                        source,
                        scheduled_at=scheduled_at,
                        started_at=started_at,
                        category="attempt_cancelled",
                    )
                )
            finally:
                raise
        except BusClosedError:
            await self._increment(bus_failures=1)
            return await self._complete_failure(
                claimed,
                source,
                scheduled_at=scheduled_at,
                started_at=started_at,
                category="event_bus_closed",
            )
        except Exception:
            await self._increment(publisher_failures=1)
            return await self._complete_failure(
                claimed,
                source,
                scheduled_at=scheduled_at,
                started_at=started_at,
                category="publisher_failed",
            )
        if report.succeeded:
            return await self._complete_success(
                claimed,
                source,
                scheduled_at=scheduled_at,
                started_at=started_at,
            )
        await self._increment(handler_failures=1)
        return await self._complete_failure(
            claimed,
            source,
            scheduled_at=scheduled_at,
            started_at=started_at,
            category="handler_failed",
        )

    async def _complete_success(
        self,
        claimed: InboundAcceptedEvent,
        source: InboundEventSource,
        *,
        scheduled_at: datetime,
        started_at: datetime,
    ) -> InboundPublicationResult:
        finished_at = self._now_not_before(started_at)
        attempt_number = claimed.current_attempt or claimed.completed_attempts + 1
        attempt = InboundPublicationAttempt(
            accepted_event_id=claimed.id,
            number=attempt_number,
            scheduled_at=scheduled_at,
            started_at=started_at,
            finished_at=finished_at,
            outcome=InboundPublicationOutcome.SUCCEEDED,
        )
        completed = replace(
            claimed,
            status=InboundPublicationStatus.PUBLISHED,
            updated_at=finished_at,
            attempts=(*claimed.attempts, attempt),
            current_attempt=None,
            publishing_at=None,
            next_attempt_at=None,
            terminal_at=finished_at,
            revision=claimed.revision + 1,
        )
        try:
            completed = await self._events.replace(
                completed,
                expected_revision=claimed.revision,
            )
        except InboundEventConflictError:
            return await self._conflict_result(claimed)
        result = InboundPublicationResult(
            accepted_event_id=completed.id,
            disposition=InboundPublicationDisposition.PUBLISHED,
            status=completed.status,
            attempt=attempt.number,
        )
        await self._increment(published=1)
        await self._signal_attempt(completed, source, attempt, result)
        return result

    async def _complete_failure(
        self,
        claimed: InboundAcceptedEvent,
        source: InboundEventSource,
        *,
        scheduled_at: datetime,
        started_at: datetime,
        category: str,
    ) -> InboundPublicationResult:
        finished_at = self._now_not_before(started_at)
        attempt_number = claimed.current_attempt or claimed.completed_attempts + 1
        retry_scheduled = (
            attempt_number < source.retry.max_attempts
            and attempt_number < MAX_INBOUND_PUBLICATION_ATTEMPTS
        )
        next_attempt_at: datetime | None = None
        if retry_scheduled:
            next_attempt_at = finished_at + source.retry.delay_after(attempt_number)
            status = InboundPublicationStatus.RETRYING
            disposition = InboundPublicationDisposition.RETRYING
        else:
            status = InboundPublicationStatus.DEAD_LETTER
            disposition = InboundPublicationDisposition.DEAD_LETTER
        attempt = InboundPublicationAttempt(
            accepted_event_id=claimed.id,
            number=attempt_number,
            scheduled_at=scheduled_at,
            started_at=started_at,
            finished_at=finished_at,
            outcome=InboundPublicationOutcome.RETRYABLE_FAILURE,
            retry_scheduled=retry_scheduled,
            next_attempt_at=next_attempt_at,
            error_category=category,
        )
        completed = replace(
            claimed,
            status=status,
            updated_at=finished_at,
            attempts=(*claimed.attempts, attempt),
            current_attempt=None,
            publishing_at=None,
            next_attempt_at=next_attempt_at,
            terminal_at=None if retry_scheduled else finished_at,
            revision=claimed.revision + 1,
        )
        try:
            completed = await self._events.replace(
                completed,
                expected_revision=claimed.revision,
            )
        except InboundEventConflictError:
            return await self._conflict_result(claimed)
        result = InboundPublicationResult(
            accepted_event_id=completed.id,
            disposition=disposition,
            status=completed.status,
            attempt=attempt.number,
            error_category=attempt.error_category,
            next_attempt_at=next_attempt_at,
        )
        if retry_scheduled:
            await self._increment(retrying=1)
        else:
            await self._increment(dead_letter=1)
        await self._signal_attempt(completed, source, attempt, result)
        return result

    async def _due_events(
        self,
        now: datetime,
        limit: int,
    ) -> tuple[InboundAcceptedEvent, ...]:
        due: list[InboundAcceptedEvent] = []
        request = InboundPageRequest(limit=MAX_INBOUND_PAGE_SIZE)
        while True:
            page: InboundEventPage = await self._events.list(request)
            due.extend(item for item in page.items if _is_due(item, now))
            next_offset = page.page.next_offset
            if next_offset is None:
                break
            request = InboundPageRequest(
                offset=next_offset,
                limit=MAX_INBOUND_PAGE_SIZE,
            )
        ordered = sorted(
            due,
            key=lambda item: (
                item.next_attempt_at or item.accepted_at,
                item.accepted_at,
                item.id.hex,
            ),
        )
        return tuple(ordered[:limit])

    async def _discard(
        self,
        current: InboundAcceptedEvent,
        *,
        category: str,
    ) -> InboundPublicationResult:
        finished_at = max(self._now(), current.updated_at)
        replacement = replace(
            current,
            status=InboundPublicationStatus.DISCARDED,
            updated_at=finished_at,
            current_attempt=None,
            publishing_at=None,
            next_attempt_at=None,
            terminal_at=finished_at,
            revision=current.revision + 1,
        )
        try:
            replacement = await self._events.replace(
                replacement,
                expected_revision=current.revision,
            )
        except InboundEventConflictError:
            return await self._conflict_result(current)

        result = InboundPublicationResult(
            accepted_event_id=replacement.id,
            disposition=InboundPublicationDisposition.DISCARDED,
            status=replacement.status,
            error_category=category,
        )
        await self._increment(discarded=1)
        await self._signal_discarded(replacement, result)
        return result

    async def _signal_attempt(
        self,
        event: InboundAcceptedEvent,
        source: InboundEventSource,
        attempt: InboundPublicationAttempt,
        result: InboundPublicationResult,
    ) -> None:
        details: dict[str, object] = {
            "accepted_event_id": str(event.id),
            "source_id": str(source.id),
            "event_type": event.external_event_type,
            "attempt": attempt.number,
            "status": event.status.value,
            "outcome": attempt.outcome.value,
            "retry_scheduled": attempt.retry_scheduled,
        }
        if attempt.error_category is not None:
            details["error_category"] = attempt.error_category

        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name="inbound.event.publication_attempted",
                        source="phoenix.inbound",
                        category=AuditCategory.OTHER,
                        action="inbound_event.publication.attempt",
                        resource=f"inbound-event:{event.id}",
                        actor="phoenix.inbound",
                        outcome=(
                            AuditOutcome.SUCCEEDED
                            if attempt.outcome is InboundPublicationOutcome.SUCCEEDED
                            else AuditOutcome.FAILED
                        ),
                        severity=_audit_severity(result.disposition),
                        details=details,
                        correlation_id=event.correlation_id,
                        causation_id=event.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)

        if self._observability is not None:
            try:
                duration_ms = max(
                    0.0,
                    (attempt.finished_at - attempt.started_at).total_seconds() * 1_000,
                )
                await self._observability.metric(
                    "inbound.event.publication_attempts",
                    1,
                    source="phoenix.inbound",
                    kind=MetricKind.COUNTER,
                    attributes=details,
                    correlation_id=event.correlation_id,
                    causation_id=event.id,
                )
                await self._observability.metric(
                    "inbound.event.publication_duration",
                    duration_ms,
                    source="phoenix.inbound",
                    kind=MetricKind.GAUGE,
                    unit="ms",
                    attributes={
                        "status": event.status.value,
                        "outcome": attempt.outcome.value,
                    },
                    correlation_id=event.correlation_id,
                    causation_id=event.id,
                )
                await self._observability.log(
                    "inbound.event.publication_completed",
                    source="phoenix.inbound",
                    message="inbound event publication attempt completed",
                    severity=_observation_severity(result.disposition),
                    attributes=details,
                    correlation_id=event.correlation_id,
                    causation_id=event.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _signal_discarded(
        self,
        event: InboundAcceptedEvent,
        result: InboundPublicationResult,
    ) -> None:
        details: dict[str, object] = {
            "accepted_event_id": str(event.id),
            "source_id": str(event.source_id),
            "event_type": event.external_event_type,
            "status": event.status.value,
            "error_category": result.error_category or "source_inactive",
        }
        if self._audit is not None:
            try:
                await self._audit.record(
                    AuditEvent(
                        name="inbound.event.discarded",
                        source="phoenix.inbound",
                        category=AuditCategory.OTHER,
                        action="inbound_event.publication.discard",
                        resource=f"inbound-event:{event.id}",
                        actor="phoenix.inbound",
                        outcome=AuditOutcome.RESTRICTED,
                        severity=AuditSeverity.WARNING,
                        details=details,
                        correlation_id=event.correlation_id,
                        causation_id=event.id,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(audit_failures=1)
        if self._observability is not None:
            try:
                await self._observability.metric(
                    "inbound.event.discarded",
                    1,
                    source="phoenix.inbound",
                    kind=MetricKind.COUNTER,
                    attributes=details,
                    correlation_id=event.correlation_id,
                    causation_id=event.id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._increment(observation_failures=1)

    async def _skipped_result(
        self,
        event: InboundAcceptedEvent,
        *,
        category: str | None = None,
    ) -> InboundPublicationResult:
        await self._increment(skipped=1)
        return InboundPublicationResult(
            accepted_event_id=event.id,
            disposition=InboundPublicationDisposition.SKIPPED,
            status=event.status,
            error_category=category,
        )

    async def _conflict_result(
        self,
        event: InboundAcceptedEvent,
    ) -> InboundPublicationResult:
        await self._increment(conflicts=1)
        return InboundPublicationResult(
            accepted_event_id=event.id,
            disposition=InboundPublicationDisposition.CONFLICT,
            status=event.status,
        )

    async def _increment(self, **changes: int) -> None:
        async with self._counter_lock:
            for name, amount in changes.items():
                attribute = f"_{name}"
                current = getattr(self, attribute)
                updated = current + amount
                if updated < 0:
                    raise RuntimeError("inbound publisher counter cannot become negative")
                setattr(self, attribute, updated)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("inbound publisher clock must return datetime")
        _require_aware(value, "inbound publisher clock")
        return value.astimezone(UTC)

    def _now_not_before(self, minimum: datetime) -> datetime:
        return max(self._now(), minimum)

    def _ensure_open(self) -> None:
        if self._closed:
            raise InboundPublisherClosedError("inbound event publisher is closed")


class InboundPublisherWorker:
    """Run bounded due-event scans under Runtime lifecycle hooks."""

    def __init__(
        self,
        publisher: InboundEventPublisher,
        *,
        poll_interval: float = DEFAULT_INBOUND_PUBLISHER_POLL_INTERVAL,
    ) -> None:
        if not isinstance(publisher, InboundEventPublisher):
            raise TypeError("inbound publisher worker requires InboundEventPublisher")
        if poll_interval <= 0:
            raise ValueError("inbound publisher poll interval must be positive")
        self._publisher = publisher
        self._poll_interval = poll_interval
        self._state = InboundPublisherRuntimeState.CREATED
        self._ticks = 0
        self._considered = 0
        self._failures = 0
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> InboundPublisherRuntimeState:
        return self._state

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not InboundPublisherRuntimeState.CREATED:
                raise InboundPublisherStateError(
                    f"cannot start inbound publisher worker from {self._state.value}"
                )
            if self._publisher.closed:
                raise InboundPublisherStateError("inbound publisher is already closed")
            self._state = InboundPublisherRuntimeState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name="phoenix-inbound-event-publisher",
            )

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is InboundPublisherRuntimeState.STOPPED:
                return
            if self._state not in {
                InboundPublisherRuntimeState.CREATED,
                InboundPublisherRuntimeState.RUNNING,
            }:
                raise InboundPublisherStateError(
                    f"cannot stop inbound publisher worker from {self._state.value}"
                )
            self._state = InboundPublisherRuntimeState.STOPPING
            self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = InboundPublisherRuntimeState.STOPPED

    async def run_once(self) -> InboundPublicationBatch:
        if self._state is not InboundPublisherRuntimeState.RUNNING:
            raise InboundPublisherStateError(
                f"cannot run inbound publisher from {self._state.value}"
            )
        async with self._tick_lock:
            self._ticks += 1
            try:
                batch = await self._publisher.publish_due()
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return InboundPublicationBatch(())
            self._considered += batch.considered
            self._last_error = None
            return batch

    async def snapshot(self) -> InboundPublisherWorkerSnapshot:
        async with self._state_lock:
            return InboundPublisherWorkerSnapshot(
                state=self._state,
                ticks=self._ticks,
                considered=self._considered,
                failures=self._failures,
                last_error=self._last_error,
            )

    async def _run_loop(self) -> None:
        while not self._stop_requested.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    self._stop_requested.wait(),
                    timeout=self._poll_interval,
                )
            except TimeoutError:
                pass


def _stable_bus_event(event: InboundAcceptedEvent, attempt: int) -> Event:
    return Event(
        name=event.internal_event_type,
        source="phoenix.inbound",
        payload=event.normalized_payload,
        metadata={
            "accepted_event_id": str(event.id),
            "source_id": str(event.source_id),
            "source_event_id": event.source_event_id,
            "external_event_type": event.external_event_type,
            "external_schema_version": str(event.external_schema_version),
            "publication_attempt": str(attempt),
        },
        id=event.id,
        occurred_at=event.occurred_at,
        correlation_id=event.correlation_id,
        causation_id=event.id,
    )


def _is_due(event: InboundAcceptedEvent, now: datetime) -> bool:
    return (
        event.status.schedulable
        and event.next_attempt_at is not None
        and event.next_attempt_at <= now
    )


def _normalize_error_category(value: str) -> str:
    normalized = value.strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if (
        not normalized
        or len(normalized) > 64
        or not normalized[0].isalpha()
        or any(character not in allowed for character in normalized)
    ):
        raise ValueError("inbound publisher error category is invalid")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _audit_severity(
    disposition: InboundPublicationDisposition,
) -> AuditSeverity:
    if disposition is InboundPublicationDisposition.PUBLISHED:
        return AuditSeverity.INFO
    if disposition is InboundPublicationDisposition.RETRYING:
        return AuditSeverity.WARNING
    return AuditSeverity.ERROR


def _observation_severity(
    disposition: InboundPublicationDisposition,
) -> Severity:
    if disposition is InboundPublicationDisposition.PUBLISHED:
        return Severity.INFO
    if disposition is InboundPublicationDisposition.RETRYING:
        return Severity.WARNING
    return Severity.ERROR


def _utc_now() -> datetime:
    return datetime.now(UTC)
