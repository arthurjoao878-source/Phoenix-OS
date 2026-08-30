"""Bounded one-shot worker lifecycle for deterministic durable recovery admission."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    MAX_RECOVERY_CANDIDATE_PAGE,
    DurableAgentRunId,
    DurableRunStore,
)
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryAssessment,
    DurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_reliability import (
    NOOP_RELIABILITY_FAULT_INJECTOR,
    DurableRecoveryAttemptStore,
    ReliabilityFaultInjector,
    ReliabilityFaultPoint,
)
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError

MAX_RECOVERY_WORKER_PAGE_SIZE = MAX_RECOVERY_CANDIDATE_PAGE
MAX_RECOVERY_WORKER_CANDIDATES = MAX_RECOVERY_CANDIDATE_PAGE * 16
MAX_RECOVERY_WORKER_CONCURRENCY = 64
MAX_RECOVERY_WORKER_PASS_DURATION = timedelta(minutes=10)
MAX_RECOVERY_WORKER_SHUTDOWN_GRACE = timedelta(minutes=1)
MAX_RECOVERY_WORKER_CANCELLATION_GRACE = timedelta(seconds=30)

_OWNER_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _normalize_owner_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("owner_id must be a string")
    normalized = value.strip()
    if _OWNER_ID_PATTERN.fullmatch(normalized) is None:
        raise ValueError("owner_id is invalid")
    return normalized


def _require_positive_integer(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_positive_duration(
    value: timedelta,
    *,
    label: str,
    maximum: timedelta,
) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be a timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


class DurableRecoveryWorkerState(StrEnum):
    """Finite lifecycle for one manually triggered recovery worker."""

    CREATED = "created"
    RUNNING = "running"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class DurableRecoveryWorkerConfiguration:
    """Finite admission, concurrency, pass, and shutdown bounds."""

    owner_id: str = "phoenix-recovery"
    page_size: int = 32
    max_candidates: int = 256
    concurrency: int = 4
    pass_timeout: timedelta = timedelta(seconds=30)
    shutdown_grace: timedelta = timedelta(seconds=5)
    cancellation_grace: timedelta = timedelta(seconds=1)

    def __post_init__(self) -> None:
        object.__setattr__(self, "owner_id", _normalize_owner_id(self.owner_id))
        _require_positive_integer(
            self.page_size,
            label="page_size",
            maximum=MAX_RECOVERY_WORKER_PAGE_SIZE,
        )
        _require_positive_integer(
            self.max_candidates,
            label="max_candidates",
            maximum=MAX_RECOVERY_WORKER_CANDIDATES,
        )
        _require_positive_integer(
            self.concurrency,
            label="concurrency",
            maximum=MAX_RECOVERY_WORKER_CONCURRENCY,
        )
        if self.concurrency > self.page_size:
            raise ValueError("concurrency cannot exceed page_size")
        if self.concurrency > self.max_candidates:
            raise ValueError("concurrency cannot exceed max_candidates")
        _require_positive_duration(
            self.pass_timeout,
            label="pass_timeout",
            maximum=MAX_RECOVERY_WORKER_PASS_DURATION,
        )
        _require_positive_duration(
            self.shutdown_grace,
            label="shutdown_grace",
            maximum=MAX_RECOVERY_WORKER_SHUTDOWN_GRACE,
        )
        _require_positive_duration(
            self.cancellation_grace,
            label="cancellation_grace",
            maximum=MAX_RECOVERY_WORKER_CANCELLATION_GRACE,
        )


@dataclass(frozen=True, slots=True)
class DurableRecoveryWorkerReport:
    """Content-free outcome for one bounded recovery admission pass."""

    assessments: tuple[DurableRecoveryAssessment, ...]
    admitted: int
    conflicts: int
    failed: int
    pages: int
    exhausted: bool
    timed_out: bool
    stopped: bool
    started_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        assessments = tuple(self.assessments)
        if any(not isinstance(item, DurableRecoveryAssessment) for item in assessments):
            raise TypeError("assessments must contain DurableRecoveryAssessment values")
        object.__setattr__(self, "assessments", assessments)

        counters = (
            ("admitted", self.admitted),
            ("conflicts", self.conflicts),
            ("failed", self.failed),
            ("pages", self.pages),
        )
        for label, value in counters:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0:
                raise ValueError(f"{label} must not be negative")

        flags = (self.exhausted, self.timed_out, self.stopped)
        if any(type(value) is not bool for value in flags):
            raise TypeError("report flags must be booleans")
        if self.timed_out and self.stopped:
            raise ValueError("a recovery pass cannot be both timed out and stopped")
        if self.exhausted and (self.timed_out or self.stopped):
            raise ValueError("an interrupted recovery pass cannot be exhausted")

        completed = len(assessments) + self.conflicts + self.failed
        if completed > self.admitted:
            raise ValueError("recovery outcomes exceed admitted candidates")
        run_ids = tuple(item.run_id for item in assessments)
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("assessments contain duplicate durable run ids")
        if run_ids != tuple(sorted(run_ids)):
            raise ValueError("assessments must be ordered by durable run id")

        _require_timezone_aware(self.started_at, label="started_at")
        _require_timezone_aware(self.completed_at, label="completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")

    @property
    def assessed(self) -> int:
        return len(self.assessments)

    @property
    def truncated(self) -> bool:
        return not self.exhausted and not self.timed_out and not self.stopped


@dataclass(frozen=True, slots=True)
class DurableRecoveryWorkerSnapshot:
    """Content-free lifecycle and cumulative worker counters."""

    state: DurableRecoveryWorkerState
    active: int
    passes_started: int
    passes_completed: int
    passes_failed: int
    passes_timed_out: int
    passes_stopped: int
    candidates_admitted: int
    assessed: int
    conflicts: int
    failed: int
    forced_cancellations: int
    last_started_at: datetime | None
    last_completed_at: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.state, DurableRecoveryWorkerState):
            raise TypeError("state must be DurableRecoveryWorkerState")
        counters = (
            self.active,
            self.passes_started,
            self.passes_completed,
            self.passes_failed,
            self.passes_timed_out,
            self.passes_stopped,
            self.candidates_admitted,
            self.assessed,
            self.conflicts,
            self.failed,
            self.forced_cancellations,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in counters):
            raise TypeError("worker counters must be integers")
        if min(counters) < 0:
            raise ValueError("worker counters must not be negative")
        terminal_passes = (
            self.passes_completed + self.passes_failed + self.passes_timed_out + self.passes_stopped
        )
        if terminal_passes > self.passes_started:
            raise ValueError("terminal pass counters exceed started passes")
        if self.assessed + self.conflicts + self.failed > self.candidates_admitted:
            raise ValueError("candidate outcomes exceed admitted candidates")
        for label, value in (
            ("last_started_at", self.last_started_at),
            ("last_completed_at", self.last_completed_at),
        ):
            if value is not None:
                _require_timezone_aware(value, label=label)
        if (
            self.last_started_at is not None
            and self.last_completed_at is not None
            and self.last_completed_at < self.last_started_at
        ):
            raise ValueError("last_completed_at cannot precede last_started_at")

    @property
    def accepting(self) -> bool:
        return self.state is DurableRecoveryWorkerState.RUNNING


@runtime_checkable
class DurableRecoveryWorker(Protocol):
    """Manually triggered bounded recovery admission and finite lifecycle."""

    @property
    def state(self) -> DurableRecoveryWorkerState: ...

    def start(self) -> Awaitable[None]: ...

    def run_once(self) -> Awaitable[DurableRecoveryWorkerReport]: ...

    def snapshot(self) -> Awaitable[DurableRecoveryWorkerSnapshot]: ...

    def close(self) -> Awaitable[None]: ...


@dataclass(slots=True)
class _PassAccumulator:
    assessments: list[DurableRecoveryAssessment] = field(default_factory=list)
    admitted: int = 0
    conflicts: int = 0
    failed: int = 0
    pages: int = 0
    exhausted: bool = False
    stopped: bool = False


@dataclass(frozen=True, slots=True)
class _CandidateOutcome:
    assessment: DurableRecoveryAssessment | None = None
    conflict: bool = False
    failed: bool = False


class BoundedDurableRecoveryWorker(DurableRecoveryWorker):
    """Enumerate existing runs once with bounded pages, concurrency, and shutdown."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        coordinator: DurableRecoveryCoordinator,
        configuration: DurableRecoveryWorkerConfiguration | None = None,
        clock: Callable[[], datetime] | None = None,
        fault_injector: ReliabilityFaultInjector | None = None,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must be DurableRunStore")
        if not isinstance(coordinator, DurableRecoveryCoordinator):
            raise TypeError("coordinator must be DurableRecoveryCoordinator")
        selected_configuration = (
            DurableRecoveryWorkerConfiguration() if configuration is None else configuration
        )
        if not isinstance(selected_configuration, DurableRecoveryWorkerConfiguration):
            raise TypeError("configuration must be DurableRecoveryWorkerConfiguration")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("clock must be callable")
        selected_fault_injector = (
            NOOP_RELIABILITY_FAULT_INJECTOR if fault_injector is None else fault_injector
        )
        if not isinstance(selected_fault_injector, ReliabilityFaultInjector):
            raise TypeError("fault_injector must implement ReliabilityFaultInjector")

        self._store = store
        self._coordinator = coordinator
        self._configuration = selected_configuration
        self._persistent_recovery_attempts_available = isinstance(
            store,
            DurableRecoveryAttemptStore,
        )
        self._clock: Callable[[], datetime] = selected_clock
        self._fault_injector = selected_fault_injector
        self._state = DurableRecoveryWorkerState.CREATED
        self._stop_requested = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._active_pass: asyncio.Task[object] | None = None
        self._active_assessments = 0
        self._passes_started = 0
        self._passes_completed = 0
        self._passes_failed = 0
        self._passes_timed_out = 0
        self._passes_stopped = 0
        self._candidates_admitted = 0
        self._assessed = 0
        self._conflicts = 0
        self._failed = 0
        self._forced_cancellations = 0
        self._last_started_at: datetime | None = None
        self._last_completed_at: datetime | None = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> DurableRecoveryWorkerState:
        return self._state

    @property
    def configuration(self) -> DurableRecoveryWorkerConfiguration:
        return self._configuration

    async def start(self) -> None:
        """Enter the running state without scheduling autonomous recovery work."""

        async with self._lock:
            if self._state is DurableRecoveryWorkerState.RUNNING:
                return
            if self._state is not DurableRecoveryWorkerState.CREATED:
                raise RuntimeError("durable recovery worker cannot be restarted")
            self._stop_requested.clear()
            self._state = DurableRecoveryWorkerState.RUNNING

    async def run_once(self) -> DurableRecoveryWorkerReport:
        """Perform one bounded deterministic scan of existing recovery candidates."""

        task = asyncio.current_task()
        if task is None:  # pragma: no cover - asyncio invariant
            raise RuntimeError("durable recovery pass requires an asyncio task")
        started_at = self._now()
        async with self._lock:
            if self._state is not DurableRecoveryWorkerState.RUNNING:
                raise RuntimeError("durable recovery worker is not running")
            if self._active_pass is not None:
                raise AgentStateConflictError()
            if not self._persistent_recovery_attempts_available:
                raise AgentStateConflictError()
            self._active_pass = cast(asyncio.Task[object], task)
            self._passes_started += 1
            self._last_started_at = started_at

        accumulator = _PassAccumulator()
        timed_out = False
        try:
            try:
                async with asyncio.timeout(self._configuration.pass_timeout.total_seconds()):
                    await self._run_pass(accumulator)
            except TimeoutError:
                timed_out = True

            completed_at = self._now()
            report = DurableRecoveryWorkerReport(
                assessments=tuple(accumulator.assessments),
                admitted=accumulator.admitted,
                conflicts=accumulator.conflicts,
                failed=accumulator.failed,
                pages=accumulator.pages,
                exhausted=accumulator.exhausted,
                timed_out=timed_out,
                stopped=accumulator.stopped and not timed_out,
                started_at=started_at,
                completed_at=completed_at,
            )
            async with self._lock:
                self._record_report(report)
            return report
        except asyncio.CancelledError:
            async with self._lock:
                self._passes_stopped += 1
            raise
        except Exception:
            async with self._lock:
                self._passes_failed += 1
            raise
        finally:
            async with self._lock:
                if self._active_pass is task:
                    self._active_pass = None
                if self._last_completed_at is None or self._last_completed_at < started_at:
                    self._last_completed_at = started_at

    async def snapshot(self) -> DurableRecoveryWorkerSnapshot:
        async with self._lock:
            return DurableRecoveryWorkerSnapshot(
                state=self._state,
                active=self._active_assessments,
                passes_started=self._passes_started,
                passes_completed=self._passes_completed,
                passes_failed=self._passes_failed,
                passes_timed_out=self._passes_timed_out,
                passes_stopped=self._passes_stopped,
                candidates_admitted=self._candidates_admitted,
                assessed=self._assessed,
                conflicts=self._conflicts,
                failed=self._failed,
                forced_cancellations=self._forced_cancellations,
                last_started_at=self._last_started_at,
                last_completed_at=self._last_completed_at,
            )

    async def close(self) -> None:
        """Stop admission, drain one active pass, cancel finitely, and close once."""

        current = asyncio.current_task()
        wait_for_existing_close = False
        async with self._lock:
            if self._state is DurableRecoveryWorkerState.CLOSED:
                return
            if self._state is DurableRecoveryWorkerState.CLOSING:
                wait_for_existing_close = True
                active = None
            else:
                self._state = DurableRecoveryWorkerState.CLOSING
                self._stop_requested.set()
                active = self._active_pass

        if wait_for_existing_close:
            await self._closed_event.wait()
            return

        failure: BaseException | None = None
        try:
            if active is not None and active is not current:
                done, pending = await asyncio.wait(
                    {active},
                    timeout=self._configuration.shutdown_grace.total_seconds(),
                )
                if pending:
                    async with self._lock:
                        self._forced_cancellations += len(pending)
                    for task in pending:
                        task.cancel()
                    _done, stubborn = await asyncio.wait(
                        pending,
                        timeout=self._configuration.cancellation_grace.total_seconds(),
                    )
                    for task in stubborn:
                        task.add_done_callback(_consume_task)
                for task in done:
                    try:
                        task.result()
                    except (Exception, asyncio.CancelledError) as exception:
                        failure = exception
        except (Exception, asyncio.CancelledError) as exception:
            failure = exception
            if active is not None and active is not current and not active.done():
                active.cancel()
                active.add_done_callback(_consume_task)

        try:
            await self._coordinator.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception
        finally:
            async with self._lock:
                self._state = DurableRecoveryWorkerState.CLOSED
                self._closed_event.set()

        if failure is not None:
            raise failure

    async def _run_pass(self, accumulator: _PassAccumulator) -> None:
        after: DurableAgentRunId | None = None
        while accumulator.admitted < self._configuration.max_candidates:
            if self._stop_requested.is_set():
                accumulator.stopped = True
                return

            remaining = self._configuration.max_candidates - accumulator.admitted
            page_limit = min(self._configuration.page_size, remaining)
            candidates = await self._store.list_recovery_candidates(
                limit=page_limit,
                after=after,
            )
            _validate_candidate_page(candidates, limit=page_limit, after=after)
            self._fault_injector.inject(ReliabilityFaultPoint.RECOVERY_AFTER_CANDIDATE_READ)
            accumulator.pages += 1
            if not candidates:
                accumulator.exhausted = True
                return

            accumulator.admitted += len(candidates)
            stopped = await self._assess_page(candidates, accumulator)
            if stopped:
                accumulator.stopped = True
                return

            after = candidates[-1]
            if len(candidates) < page_limit:
                accumulator.exhausted = True
                return

    async def _assess_page(
        self,
        candidates: tuple[DurableAgentRunId, ...],
        accumulator: _PassAccumulator,
    ) -> bool:
        concurrency = self._configuration.concurrency
        for offset in range(0, len(candidates), concurrency):
            if self._stop_requested.is_set():
                return True
            batch = candidates[offset : offset + concurrency]
            outcomes = await asyncio.gather(
                *(self._assess_candidate(run_id) for run_id in batch),
            )
            for outcome in outcomes:
                if outcome.assessment is not None:
                    accumulator.assessments.append(outcome.assessment)
                elif outcome.conflict:
                    accumulator.conflicts += 1
                else:
                    accumulator.failed += 1
        return False

    async def _assess_candidate(self, run_id: DurableAgentRunId) -> _CandidateOutcome:
        async with self._lock:
            self._active_assessments += 1
        try:
            assessment = await self._coordinator.assess_candidate(
                run_id,
                owner_id=self._configuration.owner_id,
                now=self._now(),
            )
            if not isinstance(assessment, DurableRecoveryAssessment):
                return _CandidateOutcome(failed=True)
            if assessment.run_id != run_id:
                return _CandidateOutcome(failed=True)
            return _CandidateOutcome(assessment=assessment)
        except AgentStateConflictError:
            return _CandidateOutcome(conflict=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            return _CandidateOutcome(failed=True)
        finally:
            async with self._lock:
                self._active_assessments -= 1

    def _record_report(self, report: DurableRecoveryWorkerReport) -> None:
        if report.timed_out:
            self._passes_timed_out += 1
        elif report.stopped:
            self._passes_stopped += 1
        else:
            self._passes_completed += 1
        self._candidates_admitted += report.admitted
        self._assessed += report.assessed
        self._conflicts += report.conflicts
        self._failed += report.failed
        self._last_completed_at = report.completed_at

    def _now(self) -> datetime:
        value = self._clock()
        _require_timezone_aware(value, label="clock result")
        return value


def _validate_candidate_page(
    candidates: tuple[DurableAgentRunId, ...],
    *,
    limit: int,
    after: DurableAgentRunId | None,
) -> None:
    if not isinstance(candidates, tuple):
        raise TypeError("recovery candidate page must be a tuple")
    if len(candidates) > limit:
        raise AgentCodecError("recovery candidate page exceeds its requested limit")

    previous = after
    seen: set[DurableAgentRunId] = set()
    for run_id in candidates:
        if not isinstance(run_id, DurableAgentRunId):
            raise AgentCodecError("recovery candidate page contains an invalid run id")
        if run_id in seen:
            raise AgentCodecError("recovery candidate page contains a duplicate run id")
        if previous is not None and run_id <= previous:
            raise AgentCodecError("recovery candidate page is not strictly ordered")
        seen.add(run_id)
        previous = run_id


def _consume_task[T](task: asyncio.Task[T]) -> None:
    if task.cancelled():
        return
    try:
        task.exception()
    except BaseException:
        pass
