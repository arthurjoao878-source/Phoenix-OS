"""Interrupted publication recovery, redrive, retention, audit, and health."""

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
    InboundReplayRepository,
    InboundSourceRepository,
)
from phoenix_os.inbound_events.errors import (
    InboundEventConflictError,
    InboundEventNotFoundError,
    InboundRecoveryClosedError,
    InboundRecoveryStateError,
    InboundRedriveAccessDeniedError,
    InboundRedriveNotEligibleError,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

INBOUND_REDRIVE_PERMISSION = "inbound_event.dead_letter.redrive"
DEFAULT_INBOUND_RECOVERY_BATCH_SIZE = 50
DEFAULT_INBOUND_RECOVERY_POLL_INTERVAL = 60.0
MAX_INBOUND_RECOVERY_BATCH_SIZE = MAX_INBOUND_PAGE_SIZE

type InboundRecoveryClock = Callable[[], datetime]


class InboundRecoveryDisposition(StrEnum):
    """Safe outcome from one interrupted publication recovery."""

    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"
    DISCARDED = "discarded"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class InboundRedriveResult:
    """Safe metadata from one explicit eligible dead-letter redrive."""

    accepted_event_id: UUID
    status: InboundPublicationStatus
    completed_attempts: int
    next_attempt_at: datetime
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        status = InboundPublicationStatus(self.status)
        if status is not InboundPublicationStatus.RETRYING:
            raise ValueError("inbound redrive result must be retrying")
        if not 0 < self.completed_attempts < MAX_INBOUND_PUBLICATION_ATTEMPTS:
            raise ValueError("inbound redrive attempt count is outside bounds")
        _require_aware(self.next_attempt_at, "inbound redrive schedule")
        if self.revision <= 0:
            raise ValueError("inbound redrive revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound redrive result version")
        object.__setattr__(self, "status", status)


@dataclass(frozen=True, slots=True)
class InboundRecoveryResult:
    """Safe result from recovering one interrupted publication."""

    accepted_event_id: UUID
    disposition: InboundRecoveryDisposition
    status: InboundPublicationStatus
    attempt: int | None = None
    next_attempt_at: datetime | None = None
    error_category: str = "runtime_recovery"
    schema_version: int = 1

    def __post_init__(self) -> None:
        disposition = InboundRecoveryDisposition(self.disposition)
        status = InboundPublicationStatus(self.status)
        expected = {
            InboundRecoveryDisposition.RETRYING: InboundPublicationStatus.RETRYING,
            InboundRecoveryDisposition.DEAD_LETTER: InboundPublicationStatus.DEAD_LETTER,
            InboundRecoveryDisposition.DISCARDED: InboundPublicationStatus.DISCARDED,
        }.get(disposition)
        if expected is not None and status is not expected:
            raise ValueError("inbound recovery disposition and status are inconsistent")
        if self.attempt is not None and not (1 <= self.attempt <= MAX_INBOUND_PUBLICATION_ATTEMPTS):
            raise ValueError("inbound recovery attempt is outside bounds")
        if disposition is InboundRecoveryDisposition.RETRYING:
            if self.next_attempt_at is None:
                raise ValueError("retrying inbound recovery requires a schedule")
        elif self.next_attempt_at is not None:
            raise ValueError("terminal inbound recovery cannot schedule an attempt")
        category = _normalize_error_category(self.error_category)
        if self.schema_version != 1:
            raise ValueError("unsupported inbound recovery result version")
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "error_category", category)


@dataclass(frozen=True, slots=True)
class InboundRecoveryBatch:
    """Deterministically ordered interrupted-publication outcomes."""

    results: tuple[InboundRecoveryResult, ...]

    @property
    def considered(self) -> int:
        return len(self.results)

    def count(self, disposition: InboundRecoveryDisposition) -> int:
        return sum(item.disposition is disposition for item in self.results)


@dataclass(frozen=True, slots=True)
class InboundMaintenanceBatch:
    """One bounded recovery and replay-retention pass."""

    recovery: InboundRecoveryBatch
    replay_pruned: int

    def __post_init__(self) -> None:
        if self.replay_pruned < 0:
            raise ValueError("inbound maintenance prune count cannot be negative")


@dataclass(frozen=True, slots=True)
class InboundRecoverySnapshot:
    """Safe recovery, redrive, retention, and signal counters."""

    closed: bool
    redrives: int
    redrive_denied: int
    redrive_rejected: int
    recovery_batches: int
    recovered: int
    retrying: int
    dead_letter: int
    discarded: int
    conflicts: int
    replay_pruned: int
    audit_failures: int
    observation_failures: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        counters = (
            self.redrives,
            self.redrive_denied,
            self.redrive_rejected,
            self.recovery_batches,
            self.recovered,
            self.retrying,
            self.dead_letter,
            self.discarded,
            self.conflicts,
            self.replay_pruned,
            self.audit_failures,
            self.observation_failures,
        )
        if any(value < 0 for value in counters):
            raise ValueError("inbound recovery counters cannot be negative")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound recovery snapshot version")


class InboundRecoveryRuntimeState(StrEnum):
    """One-shot lifecycle state for the Runtime-owned maintenance worker."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class InboundRecoveryWorkerSnapshot:
    """Safe bounded maintenance-worker counters."""

    state: InboundRecoveryRuntimeState
    ticks: int
    recovered: int
    replay_pruned: int
    failures: int
    last_error: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if min(self.ticks, self.recovered, self.replay_pruned, self.failures) < 0:
            raise ValueError("inbound recovery worker counters cannot be negative")
        error = None if self.last_error is None else self.last_error.strip() or None
        if error is not None and len(error) > 128:
            raise ValueError("inbound recovery worker error category is too long")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound recovery worker snapshot version")
        object.__setattr__(self, "state", InboundRecoveryRuntimeState(self.state))
        object.__setattr__(self, "last_error", error)


class InboundPublicationRecovery:
    """Recover interrupted attempts, authorize redrive, and prune replay retention."""

    def __init__(
        self,
        *,
        sources: InboundSourceRepository,
        events: InboundEventRepository,
        replay: InboundReplayRepository,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        clock: InboundRecoveryClock | None = None,
    ) -> None:
        if not callable(getattr(sources, "get", None)):
            raise TypeError("inbound recovery source repository is invalid")
        if not all(callable(getattr(events, name, None)) for name in ("get", "list", "replace")):
            raise TypeError("inbound recovery event repository is invalid")
        if not callable(getattr(replay, "prune_expired", None)):
            raise TypeError("inbound recovery replay repository is invalid")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("inbound recovery audit must be AuditLedger")
        if observability is not None and not isinstance(
            observability,
            ObservabilityHub,
        ):
            raise TypeError("inbound recovery observability must be ObservabilityHub")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("inbound recovery clock must be callable")

        self._sources = sources
        self._events = events
        self._replay = replay
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
        self._discarded = 0
        self._conflicts = 0
        self._replay_pruned = 0
        self._audit_failures = 0
        self._observation_failures = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def redrive(
        self,
        accepted_event_id: UUID,
        context: SecurityContext,
        *,
        scheduled_at: datetime | None = None,
    ) -> InboundRedriveResult:
        """Schedule one protected retry without rewriting stable identity or history."""

        self._ensure_open()
        if not isinstance(accepted_event_id, UUID):
            raise TypeError("inbound accepted event id must be UUID")
        if not isinstance(context, SecurityContext):
            raise TypeError("inbound redrive context must be SecurityContext")
        await self._authorize_redrive(context)

        current = await self._events.get(accepted_event_id)
        if current is None:
            raise InboundEventNotFoundError("inbound accepted event was not found")
        if (
            current.status is not InboundPublicationStatus.DEAD_LETTER
            or current.completed_attempts >= MAX_INBOUND_PUBLICATION_ATTEMPTS
        ):
            await self._reject_redrive("event_not_eligible")

        source = await self._sources.get(current.source_id)
        if source is None:
            await self._reject_redrive("source_missing")
        if not source.accepting:
            await self._reject_redrive("source_inactive")

        now = self._now()
        requested = (
            now
            if scheduled_at is None
            else _as_utc(
                scheduled_at,
                "inbound redrive schedule",
            )
        )
        last_attempt = current.attempts[-1]
        minimum = max(current.updated_at, last_attempt.finished_at) + timedelta(microseconds=1)
        updated_at = max(now, current.updated_at)
        next_attempt_at = max(now, requested, minimum, updated_at)

        replacement = replace(
            current,
            status=InboundPublicationStatus.RETRYING,
            updated_at=updated_at,
            current_attempt=None,
            publishing_at=None,
            next_attempt_at=next_attempt_at,
            terminal_at=None,
            revision=current.revision + 1,
        )
        try:
            replacement = await self._events.replace(
                replacement,
                expected_revision=current.revision,
            )
        except InboundEventConflictError:
            await self._increment(conflicts=1)
            raise

        await self._increment(redrives=1)
        await self._signal_redrive(replacement, source, context)
        return InboundRedriveResult(
            accepted_event_id=replacement.id,
            status=replacement.status,
            completed_attempts=replacement.completed_attempts,
            next_attempt_at=next_attempt_at,
            revision=replacement.revision,
        )

    async def recover_publishing(
        self,
        *,
        limit: int | None = None,
    ) -> InboundRecoveryBatch:
        """Recover one bounded deterministic batch left in publishing state."""

        self._ensure_open()
        resolved_limit = DEFAULT_INBOUND_RECOVERY_BATCH_SIZE if limit is None else limit
        if type(resolved_limit) is not int:
            raise TypeError("inbound recovery limit must be an integer")
        if not 1 <= resolved_limit <= MAX_INBOUND_RECOVERY_BATCH_SIZE:
            raise ValueError("inbound recovery limit is outside supported bounds")

        interrupted = await self._interrupted_events(resolved_limit)
        results: list[InboundRecoveryResult] = []
        for event in interrupted:
            results.append(await self._recover_one(event.id))
        await self._increment(
            recovery_batches=1,
            recovered=len(results),
        )
        return InboundRecoveryBatch(tuple(results))

    async def maintain(
        self,
        *,
        limit: int | None = None,
    ) -> InboundMaintenanceBatch:
        """Recover interrupted work and prune expired replay evidence."""

        recovery = await self.recover_publishing(limit=limit)
        pruned = await self._replay.prune_expired(now=self._now())
        if pruned:
            await self._increment(replay_pruned=pruned)
            await self._signal_replay_pruned(pruned)
        return InboundMaintenanceBatch(recovery, pruned)

    async def snapshot(self) -> InboundRecoverySnapshot:
        async with self._lock:
            return InboundRecoverySnapshot(
                closed=self._closed,
                redrives=self._redrives,
                redrive_denied=self._redrive_denied,
                redrive_rejected=self._redrive_rejected,
                recovery_batches=self._recovery_batches,
                recovered=self._recovered,
                retrying=self._retrying,
                dead_letter=self._dead_letter,
                discarded=self._discarded,
                conflicts=self._conflicts,
                replay_pruned=self._replay_pruned,
                audit_failures=self._audit_failures,
                observation_failures=self._observation_failures,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _recover_one(
        self,
        accepted_event_id: UUID,
    ) -> InboundRecoveryResult:
        current = await self._events.get(accepted_event_id)
        if current is None:
            raise InboundEventNotFoundError("inbound accepted event was not found")
        if current.status is not InboundPublicationStatus.PUBLISHING:
            await self._increment(conflicts=1)
            return InboundRecoveryResult(
                accepted_event_id=current.id,
                disposition=InboundRecoveryDisposition.CONFLICT,
                status=current.status,
                error_category="recovery_conflict",
            )

        source = await self._sources.get(current.source_id)
        if source is None or not source.accepting:
            return await self._recover_discard(
                current,
                "source_missing" if source is None else "source_inactive",
            )

        started_at = current.publishing_at
        attempt_number = current.current_attempt
        if started_at is None or attempt_number is None:  # pragma: no cover
            raise RuntimeError("publishing inbound event has no attempt metadata")
        finished_at = max(self._now(), current.updated_at, started_at)
        retry_scheduled = (
            attempt_number < source.retry.max_attempts
            and attempt_number < MAX_INBOUND_PUBLICATION_ATTEMPTS
        )
        next_attempt_at: datetime | None = None
        if retry_scheduled:
            next_attempt_at = finished_at + source.retry.delay_after(attempt_number)
            status = InboundPublicationStatus.RETRYING
            disposition = InboundRecoveryDisposition.RETRYING
        else:
            status = InboundPublicationStatus.DEAD_LETTER
            disposition = InboundRecoveryDisposition.DEAD_LETTER

        attempt = InboundPublicationAttempt(
            accepted_event_id=current.id,
            number=attempt_number,
            scheduled_at=started_at,
            started_at=started_at,
            finished_at=finished_at,
            outcome=InboundPublicationOutcome.RETRYABLE_FAILURE,
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
            publishing_at=None,
            next_attempt_at=next_attempt_at,
            terminal_at=None if retry_scheduled else finished_at,
            revision=current.revision + 1,
        )
        try:
            replacement = await self._events.replace(
                replacement,
                expected_revision=current.revision,
            )
        except InboundEventConflictError:
            await self._increment(conflicts=1)
            latest = await self._events.get(current.id)
            return InboundRecoveryResult(
                accepted_event_id=current.id,
                disposition=InboundRecoveryDisposition.CONFLICT,
                status=current.status if latest is None else latest.status,
                error_category="recovery_conflict",
            )

        if retry_scheduled:
            await self._increment(retrying=1)
        else:
            await self._increment(dead_letter=1)
        result = InboundRecoveryResult(
            accepted_event_id=replacement.id,
            disposition=disposition,
            status=replacement.status,
            attempt=attempt.number,
            next_attempt_at=next_attempt_at,
        )
        await self._signal_recovery(replacement, attempt, result)
        return result

    async def _recover_discard(
        self,
        current: InboundAcceptedEvent,
        category: str,
    ) -> InboundRecoveryResult:
        finished_at = max(
            self._now(),
            current.updated_at,
            current.publishing_at or current.updated_at,
        )
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
            await self._increment(conflicts=1)
            return InboundRecoveryResult(
                accepted_event_id=current.id,
                disposition=InboundRecoveryDisposition.CONFLICT,
                status=current.status,
                error_category="recovery_conflict",
            )

        await self._increment(discarded=1)
        result = InboundRecoveryResult(
            accepted_event_id=replacement.id,
            disposition=InboundRecoveryDisposition.DISCARDED,
            status=replacement.status,
            error_category=category,
        )
        await self._signal_recovery(replacement, None, result)
        return result

    async def _interrupted_events(
        self,
        limit: int,
    ) -> tuple[InboundAcceptedEvent, ...]:
        interrupted: list[InboundAcceptedEvent] = []
        request = InboundPageRequest(limit=MAX_INBOUND_PAGE_SIZE)
        while True:
            page: InboundEventPage = await self._events.list(request)
            interrupted.extend(
                item for item in page.items if item.status is InboundPublicationStatus.PUBLISHING
            )
            next_offset = page.page.next_offset
            if next_offset is None:
                break
            request = InboundPageRequest(
                offset=next_offset,
                limit=MAX_INBOUND_PAGE_SIZE,
            )
        ordered = sorted(
            interrupted,
            key=lambda item: (
                item.publishing_at or item.updated_at,
                item.accepted_at,
                item.id.hex,
            ),
        )
        return tuple(ordered[:limit])

    async def _authorize_redrive(self, context: SecurityContext) -> None:
        allowed = context.authenticated and (
            INBOUND_REDRIVE_PERMISSION in context.permissions or "*" in context.permissions
        )
        if allowed:
            return
        await self._increment(redrive_denied=1)
        raise InboundRedriveAccessDeniedError("inbound dead-letter redrive permission required")

    async def _reject_redrive(self, category: str) -> NoReturn:
        await self._increment(redrive_rejected=1)
        raise InboundRedriveNotEligibleError(_normalize_error_category(category))

    async def _signal_recovery(
        self,
        event: InboundAcceptedEvent,
        attempt: InboundPublicationAttempt | None,
        result: InboundRecoveryResult,
    ) -> None:
        details: dict[str, object] = {
            "accepted_event_id": str(event.id),
            "source_id": str(event.source_id),
            "event_type": event.external_event_type,
            "status": event.status.value,
            "disposition": result.disposition.value,
            "error_category": result.error_category,
        }
        if attempt is not None:
            details["attempt"] = attempt.number
            details["outcome"] = attempt.outcome.value
            details["retry_scheduled"] = attempt.retry_scheduled

        await self._record_audit(
            AuditEvent(
                name="inbound.event.publication_recovered",
                source="phoenix.inbound",
                category=AuditCategory.OTHER,
                action="inbound_event.publication.recover",
                resource=f"inbound-event:{event.id}",
                actor="phoenix.inbound",
                outcome=(
                    AuditOutcome.RESTRICTED
                    if result.disposition is InboundRecoveryDisposition.DISCARDED
                    else AuditOutcome.FAILED
                ),
                severity=(
                    AuditSeverity.WARNING
                    if result.disposition is InboundRecoveryDisposition.RETRYING
                    else AuditSeverity.ERROR
                ),
                details=details,
                correlation_id=event.correlation_id,
                causation_id=event.id,
            )
        )
        await self._emit_metric(
            "inbound.event.recovery",
            details,
            correlation_id=event.correlation_id,
            causation_id=event.id,
        )

    async def _signal_redrive(
        self,
        event: InboundAcceptedEvent,
        source: InboundEventSource,
        context: SecurityContext,
    ) -> None:
        details: dict[str, object] = {
            "accepted_event_id": str(event.id),
            "source_id": str(source.id),
            "event_type": event.external_event_type,
            "status": event.status.value,
            "completed_attempts": event.completed_attempts,
        }
        await self._record_audit(
            AuditEvent(
                name="inbound.event.dead_letter_redriven",
                source="phoenix.inbound",
                category=AuditCategory.OTHER,
                action="inbound_event.dead_letter.redrive",
                resource=f"inbound-event:{event.id}",
                actor=context.principal,
                outcome=AuditOutcome.SUCCEEDED,
                severity=AuditSeverity.WARNING,
                details=details,
                correlation_id=context.correlation_id or event.correlation_id,
                causation_id=event.id,
            )
        )
        await self._emit_metric(
            "inbound.event.redrive",
            details,
            correlation_id=context.correlation_id or event.correlation_id,
            causation_id=event.id,
        )

    async def _signal_replay_pruned(self, pruned: int) -> None:
        details: dict[str, object] = {"pruned": pruned}
        await self._record_audit(
            AuditEvent(
                name="inbound.replay.retention_pruned",
                source="phoenix.inbound",
                category=AuditCategory.STATE,
                action="inbound_event.replay.prune",
                resource="inbound-replay:retention",
                actor="phoenix.inbound",
                outcome=AuditOutcome.SUCCEEDED,
                severity=AuditSeverity.INFO,
                details=details,
            )
        )
        await self._emit_metric("inbound.replay.pruned", details)

    async def _record_audit(self, event: AuditEvent) -> None:
        if self._audit is None:
            return
        try:
            await self._audit.record(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._increment(audit_failures=1)

    async def _emit_metric(
        self,
        name: str,
        attributes: dict[str, object],
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> None:
        if self._observability is None:
            return
        try:
            await self._observability.metric(
                name,
                1,
                source="phoenix.inbound",
                kind=MetricKind.COUNTER,
                attributes=attributes,
                correlation_id=correlation_id,
                causation_id=causation_id,
            )
            await self._observability.log(
                f"{name}.completed",
                source="phoenix.inbound",
                message="inbound maintenance operation completed",
                severity=Severity.INFO,
                attributes=attributes,
                correlation_id=correlation_id,
                causation_id=causation_id,
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
                    raise RuntimeError("inbound recovery counter cannot become negative")
                setattr(self, attribute, updated)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("inbound recovery clock must return datetime")
        _require_aware(value, "inbound recovery clock")
        return value.astimezone(UTC)

    def _ensure_open(self) -> None:
        if self._closed:
            raise InboundRecoveryClosedError("inbound publication recovery is closed")


class InboundRecoveryWorker:
    """Run bounded recovery and replay-retention passes under Runtime hooks."""

    def __init__(
        self,
        recovery: InboundPublicationRecovery,
        *,
        poll_interval: float = DEFAULT_INBOUND_RECOVERY_POLL_INTERVAL,
    ) -> None:
        if not isinstance(recovery, InboundPublicationRecovery):
            raise TypeError("inbound recovery worker requires InboundPublicationRecovery")
        if poll_interval <= 0:
            raise ValueError("inbound recovery poll interval must be positive")
        self._recovery = recovery
        self._poll_interval = poll_interval
        self._state = InboundRecoveryRuntimeState.CREATED
        self._ticks = 0
        self._recovered = 0
        self._replay_pruned = 0
        self._failures = 0
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> InboundRecoveryRuntimeState:
        return self._state

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not InboundRecoveryRuntimeState.CREATED:
                raise InboundRecoveryStateError(
                    f"cannot start inbound recovery worker from {self._state.value}"
                )
            if self._recovery.closed:
                raise InboundRecoveryStateError("inbound publication recovery is already closed")
            self._state = InboundRecoveryRuntimeState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name="phoenix-inbound-event-recovery",
            )

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is InboundRecoveryRuntimeState.STOPPED:
                return
            if self._state not in {
                InboundRecoveryRuntimeState.CREATED,
                InboundRecoveryRuntimeState.RUNNING,
            }:
                raise InboundRecoveryStateError(
                    f"cannot stop inbound recovery worker from {self._state.value}"
                )
            self._state = InboundRecoveryRuntimeState.STOPPING
            self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = InboundRecoveryRuntimeState.STOPPED

    async def run_once(self) -> InboundMaintenanceBatch:
        if self._state is not InboundRecoveryRuntimeState.RUNNING:
            raise InboundRecoveryStateError(f"cannot run inbound recovery from {self._state.value}")
        async with self._tick_lock:
            self._ticks += 1
            try:
                batch = await self._recovery.maintain()
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return InboundMaintenanceBatch(InboundRecoveryBatch(()), 0)
            self._recovered += batch.recovery.considered
            self._replay_pruned += batch.replay_pruned
            self._last_error = None
            return batch

    async def snapshot(self) -> InboundRecoveryWorkerSnapshot:
        async with self._state_lock:
            return InboundRecoveryWorkerSnapshot(
                state=self._state,
                ticks=self._ticks,
                recovered=self._recovered,
                replay_pruned=self._replay_pruned,
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


def _normalize_error_category(value: str) -> str:
    normalized = value.strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if (
        not normalized
        or len(normalized) > 64
        or not normalized[0].isalpha()
        or any(character not in allowed for character in normalized)
    ):
        raise ValueError("inbound recovery error category is invalid")
    return normalized


def _as_utc(value: datetime, label: str) -> datetime:
    _require_aware(value, label)
    return value.astimezone(UTC)


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _utc_now() -> datetime:
    return datetime.now(UTC)
