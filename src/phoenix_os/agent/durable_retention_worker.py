"""Bounded manually triggered worker lifecycle for durable retention cleanup."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    MAX_RECOVERY_CANDIDATE_PAGE,
    DurableAgentRunId,
    RetentionPolicy,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_retention import DurableRetentionStore
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentStateConflictError,
)

MAX_RETENTION_WORKER_PAGE_SIZE = MAX_RECOVERY_CANDIDATE_PAGE
MAX_RETENTION_WORKER_CANDIDATES = MAX_RECOVERY_CANDIDATE_PAGE * 16
MAX_RETENTION_WORKER_PASS_DURATION = timedelta(minutes=10)
MAX_RETENTION_WORKER_SHUTDOWN_GRACE = timedelta(minutes=1)
MAX_RETENTION_WORKER_CANCELLATION_GRACE = timedelta(seconds=30)

_OWNER_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _require_timezone_aware(
    value: datetime,
    *,
    label: str,
) -> None:
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


def _require_positive_integer(
    value: int,
    *,
    label: str,
    maximum: int,
) -> None:
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


class DurableRetentionWorkerState(StrEnum):
    """Finite lifecycle for manually triggered durable retention."""

    CREATED = "created"
    RUNNING = "running"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class DurableRetentionWorkerConfiguration:
    """Finite bounds for one manually triggered retention pass."""

    owner_id: str = "phoenix-retention"
    page_size: int = 32
    max_candidates: int = 256
    pass_timeout: timedelta = timedelta(seconds=30)
    shutdown_grace: timedelta = timedelta(seconds=5)
    cancellation_grace: timedelta = timedelta(seconds=1)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "owner_id",
            _normalize_owner_id(self.owner_id),
        )

        _require_positive_integer(
            self.page_size,
            label="page_size",
            maximum=MAX_RETENTION_WORKER_PAGE_SIZE,
        )

        _require_positive_integer(
            self.max_candidates,
            label="max_candidates",
            maximum=MAX_RETENTION_WORKER_CANDIDATES,
        )

        _require_positive_duration(
            self.pass_timeout,
            label="pass_timeout",
            maximum=MAX_RETENTION_WORKER_PASS_DURATION,
        )

        _require_positive_duration(
            self.shutdown_grace,
            label="shutdown_grace",
            maximum=MAX_RETENTION_WORKER_SHUTDOWN_GRACE,
        )

        _require_positive_duration(
            self.cancellation_grace,
            label="cancellation_grace",
            maximum=MAX_RETENTION_WORKER_CANCELLATION_GRACE,
        )


@dataclass(frozen=True, slots=True)
class DurableRetentionWorkerReport:
    """Content-free outcome for one bounded retention pass."""

    admitted: int
    payloads_deleted: int
    tombstoned: int
    purged: int
    conflicts: int
    failed: int
    pages: int
    exhausted: bool
    timed_out: bool
    stopped: bool
    started_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        for label, value in (
            ("admitted", self.admitted),
            ("payloads_deleted", self.payloads_deleted),
            ("tombstoned", self.tombstoned),
            ("purged", self.purged),
            ("conflicts", self.conflicts),
            ("failed", self.failed),
            ("pages", self.pages),
        ):
            if isinstance(value, bool) or not isinstance(
                value,
                int,
            ):
                raise TypeError(f"{label} must be an integer")

            if value < 0:
                raise ValueError(f"{label} must not be negative")

        if type(self.exhausted) is not bool:
            raise TypeError("exhausted must be a boolean")

        if type(self.timed_out) is not bool:
            raise TypeError("timed_out must be a boolean")

        if type(self.stopped) is not bool:
            raise TypeError("stopped must be a boolean")

        terminal_outcomes = sum(
            (
                self.exhausted,
                self.timed_out,
                self.stopped,
            )
        )

        if terminal_outcomes > 1:
            raise ValueError("retention pass terminal outcomes are mutually exclusive")

        if self.conflicts + self.failed > self.admitted:
            raise ValueError("candidate outcomes exceed admitted candidates")

        _require_timezone_aware(
            self.started_at,
            label="started_at",
        )
        _require_timezone_aware(
            self.completed_at,
            label="completed_at",
        )

        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")


@dataclass(slots=True)
class _RetentionPassAccumulator:
    admitted: int = 0
    payloads_deleted: int = 0
    tombstoned: int = 0
    purged: int = 0
    conflicts: int = 0
    failed: int = 0
    pages: int = 0
    exhausted: bool = False
    stopped: bool = False


@dataclass(frozen=True, slots=True)
class DurableRetentionWorkerSnapshot:
    """Content-free lifecycle counters for durable retention."""

    state: DurableRetentionWorkerState
    passes_started: int
    passes_completed: int
    passes_timed_out: int
    last_started_at: datetime | None
    last_completed_at: datetime | None
    passes_failed: int = 0
    passes_stopped: int = 0

    def __post_init__(self) -> None:
        if not isinstance(
            self.state,
            DurableRetentionWorkerState,
        ):
            raise TypeError("state must be DurableRetentionWorkerState")

        for label, value in (
            ("passes_started", self.passes_started),
            ("passes_completed", self.passes_completed),
            ("passes_timed_out", self.passes_timed_out),
            ("passes_failed", self.passes_failed),
            ("passes_stopped", self.passes_stopped),
        ):
            if isinstance(value, bool) or not isinstance(
                value,
                int,
            ):
                raise TypeError(f"{label} must be an integer")

            if value < 0:
                raise ValueError(f"{label} must not be negative")

        terminal_passes = (
            self.passes_completed + self.passes_timed_out + self.passes_failed + self.passes_stopped
        )

        if terminal_passes > self.passes_started:
            raise ValueError("terminal retention passes exceed started passes")

        if self.last_started_at is not None:
            _require_timezone_aware(
                self.last_started_at,
                label="last_started_at",
            )

        if self.last_completed_at is not None:
            _require_timezone_aware(
                self.last_completed_at,
                label="last_completed_at",
            )

        if (
            self.last_started_at is not None
            and self.last_completed_at is not None
            and self.last_completed_at < self.last_started_at
        ):
            raise ValueError("last_completed_at cannot precede last_started_at")

    @property
    def accepting(self) -> bool:
        return self.state is DurableRetentionWorkerState.RUNNING


@runtime_checkable
class DurableRetentionWorker(Protocol):
    """Manually triggered bounded durable retention worker."""

    @property
    def state(self) -> DurableRetentionWorkerState: ...

    def start(self) -> Awaitable[None]: ...

    def run_once(
        self,
    ) -> Awaitable[DurableRetentionWorkerReport]: ...

    def snapshot(
        self,
    ) -> Awaitable[DurableRetentionWorkerSnapshot]: ...

    def close(self) -> Awaitable[None]: ...


class BoundedDurableRetentionWorker(DurableRetentionWorker):
    """Finite retention lifecycle without autonomous scheduling."""

    def __init__(
        self,
        *,
        store: DurableRetentionStore,
        lease_manager: DurableLeaseManager,
        policy: RetentionPolicy,
        configuration: DurableRetentionWorkerConfiguration | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, DurableRetentionStore):
            raise TypeError("store must implement DurableRetentionStore")

        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")

        if not isinstance(policy, RetentionPolicy):
            raise TypeError("policy must be RetentionPolicy")

        bound_lease_manager = getattr(
            store,
            "lease_manager",
            None,
        )

        if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
            raise ValueError("lease_manager must match the retention store lease manager")

        selected_configuration = (
            DurableRetentionWorkerConfiguration() if configuration is None else configuration
        )

        if not isinstance(
            selected_configuration,
            DurableRetentionWorkerConfiguration,
        ):
            raise TypeError("configuration must be DurableRetentionWorkerConfiguration")

        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock

        if not callable(selected_clock):
            raise TypeError("clock must be callable")

        self._store = store
        self._lease_manager = lease_manager
        self._policy = policy
        self._configuration = selected_configuration
        self._clock: Callable[[], datetime] = selected_clock
        self._state = DurableRetentionWorkerState.CREATED
        self._passes_started = 0
        self._passes_completed = 0
        self._passes_timed_out = 0
        self._passes_failed = 0
        self._passes_stopped = 0
        self._last_started_at: datetime | None = None
        self._last_completed_at: datetime | None = None
        self._active_pass: asyncio.Task[object] | None = None
        self._lock = asyncio.Lock()
        self._closed_event = asyncio.Event()
        self._stop_requested = asyncio.Event()

    @property
    def state(self) -> DurableRetentionWorkerState:
        return self._state

    @property
    def store(self) -> DurableRetentionStore:
        return self._store

    @property
    def lease_manager(self) -> DurableLeaseManager:
        return self._lease_manager

    @property
    def policy(self) -> RetentionPolicy:
        return self._policy

    @property
    def configuration(
        self,
    ) -> DurableRetentionWorkerConfiguration:
        return self._configuration

    async def start(self) -> None:
        """Enable manually triggered retention passes."""

        async with self._lock:
            if self._state is DurableRetentionWorkerState.RUNNING:
                return

            if self._state is not DurableRetentionWorkerState.CREATED:
                raise RuntimeError("durable retention worker cannot be restarted")

            self._state = DurableRetentionWorkerState.RUNNING

    async def run_once(
        self,
    ) -> DurableRetentionWorkerReport:
        """Perform one bounded fenced retention cleanup pass."""

        task = asyncio.current_task()

        if task is None:  # pragma: no cover - asyncio invariant
            raise RuntimeError("durable retention pass requires an asyncio task")

        started_at = self._now()

        async with self._lock:
            if self._state is not DurableRetentionWorkerState.RUNNING:
                raise RuntimeError("durable retention worker is not running")

            if self._active_pass is not None:
                raise AgentStateConflictError()

            self._active_pass = task
            self._passes_started += 1
            self._last_started_at = started_at

        accumulator = _RetentionPassAccumulator()
        timed_out = False

        try:
            try:
                async with asyncio.timeout(self._configuration.pass_timeout.total_seconds()):
                    await self._run_pass(
                        accumulator,
                        started_at=started_at,
                    )
            except TimeoutError:
                timed_out = True
            except asyncio.CancelledError:
                completed_at = self._now()

                async with self._lock:
                    self._passes_stopped += 1
                    self._last_completed_at = completed_at

                raise
            except Exception:
                completed_at = self._now()

                async with self._lock:
                    self._passes_failed += 1
                    self._last_completed_at = completed_at

                raise

            completed_at = self._now()

            report = DurableRetentionWorkerReport(
                admitted=accumulator.admitted,
                payloads_deleted=accumulator.payloads_deleted,
                tombstoned=accumulator.tombstoned,
                purged=accumulator.purged,
                conflicts=accumulator.conflicts,
                failed=accumulator.failed,
                pages=accumulator.pages,
                exhausted=(accumulator.exhausted and not timed_out and not accumulator.stopped),
                timed_out=timed_out,
                stopped=(accumulator.stopped and not timed_out),
                started_at=started_at,
                completed_at=completed_at,
            )

            async with self._lock:
                if self._state not in {
                    DurableRetentionWorkerState.RUNNING,
                    DurableRetentionWorkerState.CLOSING,
                }:
                    raise RuntimeError("durable retention worker stopped during pass")

                if timed_out:
                    self._passes_timed_out += 1
                elif accumulator.stopped:
                    self._passes_stopped += 1
                else:
                    self._passes_completed += 1

                self._last_completed_at = completed_at

            return report

        finally:
            async with self._lock:
                if self._active_pass is task:
                    self._active_pass = None

    async def _run_pass(
        self,
        accumulator: _RetentionPassAccumulator,
        *,
        started_at: datetime,
    ) -> None:
        after: DurableAgentRunId | None = None

        while accumulator.admitted < self._configuration.max_candidates:
            if self._stop_requested.is_set():
                accumulator.stopped = True
                return

            remaining = self._configuration.max_candidates - accumulator.admitted

            limit = min(
                self._configuration.page_size,
                remaining,
            )

            candidates = await self._store.list_cleanup_candidates(
                policy=self._policy,
                now=started_at,
                limit=limit,
                after=after,
            )

            _validate_cleanup_candidate_page(
                candidates,
                limit=limit,
                after=after,
            )

            accumulator.pages += 1

            if not candidates:
                accumulator.exhausted = True
                return

            accumulator.admitted += len(candidates)

            for run_id in candidates:
                if self._stop_requested.is_set():
                    accumulator.stopped = True
                    return

                try:
                    lease = await self._lease_manager.acquire(
                        run_id,
                        owner_id=self._configuration.owner_id,
                        now=self._now(),
                    )
                except AgentStateConflictError:
                    accumulator.conflicts += 1
                    continue

                candidate_conflict = False
                candidate_failed = False
                release_conflict = False
                release_failed = False

                try:
                    try:
                        tombstone = await self._store.get_tombstone(run_id)

                        if tombstone is not None:
                            purged = await self._store.purge_expired_tombstone(
                                run_id,
                                lease=lease,
                                now=self._now(),
                            )

                            if purged:
                                accumulator.purged += 1
                        else:
                            payload_deleted = await self._store.delete_expired_protected_payloads(
                                run_id,
                                policy=self._policy,
                                lease=lease,
                                now=self._now(),
                            )

                            if payload_deleted:
                                accumulator.payloads_deleted += 1

                            current = await self._store.get_current(run_id)

                            if current is not None and current.status.terminal:
                                tombstone_now = self._now()

                                metadata_due_at = (
                                    current.created_at + self._policy.metadata_retention
                                )

                                if tombstone_now >= metadata_due_at:
                                    await self._store.tombstone_terminal_run(
                                        run_id,
                                        policy=self._policy,
                                        lease=lease,
                                        now=tombstone_now,
                                    )

                                    accumulator.tombstoned += 1

                    except asyncio.CancelledError:
                        raise
                    except AgentStateConflictError:
                        candidate_conflict = True
                    except Exception:
                        candidate_failed = True

                finally:
                    try:
                        await self._lease_manager.release(
                            lease,
                            now=self._now(),
                        )
                    except asyncio.CancelledError:
                        raise
                    except AgentStateConflictError:
                        release_conflict = True
                    except Exception:
                        release_failed = True

                if candidate_failed or release_failed:
                    accumulator.failed += 1
                elif candidate_conflict or release_conflict:
                    accumulator.conflicts += 1

            after = candidates[-1]

            if len(candidates) < limit:
                accumulator.exhausted = True
                return

    async def snapshot(
        self,
    ) -> DurableRetentionWorkerSnapshot:
        """Return content-free worker lifecycle state."""

        async with self._lock:
            return DurableRetentionWorkerSnapshot(
                state=self._state,
                passes_started=self._passes_started,
                passes_completed=self._passes_completed,
                passes_timed_out=self._passes_timed_out,
                last_started_at=self._last_started_at,
                passes_failed=self._passes_failed,
                passes_stopped=self._passes_stopped,
                last_completed_at=self._last_completed_at,
            )

    async def close(self) -> None:
        """Stop admission, drain finitely, cancel if needed, then close."""

        current = asyncio.current_task()
        wait_for_existing_close = False

        async with self._lock:
            if self._state is DurableRetentionWorkerState.CLOSED:
                return

            if self._state is DurableRetentionWorkerState.CLOSING:
                wait_for_existing_close = True
                active = None
            else:
                self._state = DurableRetentionWorkerState.CLOSING
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
                    for task in pending:
                        task.cancel()

                    completed_after_cancel, stubborn = await asyncio.wait(
                        pending,
                        timeout=self._configuration.cancellation_grace.total_seconds(),
                    )

                    for task in completed_after_cancel:
                        _consume_task(task)

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
                active.add_done_callback(_consume_task)
                active.cancel()

        finally:
            async with self._lock:
                self._state = DurableRetentionWorkerState.CLOSED
                self._closed_event.set()

        if failure is not None:
            raise failure

    def _now(self) -> datetime:
        now = self._clock()
        _require_timezone_aware(now, label="clock result")
        return now


def _validate_cleanup_candidate_page(
    candidates: tuple[DurableAgentRunId, ...],
    *,
    limit: int,
    after: DurableAgentRunId | None,
) -> None:
    if not isinstance(candidates, tuple):
        raise TypeError("retention candidate page must be a tuple")

    if len(candidates) > limit:
        raise AgentCodecError("retention candidate page exceeds its requested limit")

    previous = after
    seen: set[DurableAgentRunId] = set()

    for run_id in candidates:
        if not isinstance(
            run_id,
            DurableAgentRunId,
        ):
            raise AgentCodecError("retention candidate page contains an invalid run id")

        if run_id in seen:
            raise AgentCodecError("retention candidate page contains a duplicate run id")

        if previous is not None and run_id <= previous:
            raise AgentCodecError("retention candidate page is not strictly ordered")

        seen.add(run_id)
        previous = run_id


def _consume_task[T](task: asyncio.Task[T]) -> None:
    if task.cancelled():
        return

    try:
        task.exception()
    except BaseException:
        pass
