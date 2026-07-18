"""Runtime-owned bounded service loop for deterministic Phoenix job ticks."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from phoenix_os.jobs.contracts import JobRun
from phoenix_os.jobs.errors import JobWorkerStateError
from phoenix_os.jobs.scheduler import JobScheduler

type JobClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class JobWorkerState(StrEnum):
    """Observable lifecycle state of a one-shot Runtime job worker."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class JobWorkerSnapshot:
    """Non-sensitive point-in-time diagnostics for one worker loop."""

    state: JobWorkerState
    worker: str
    ticks: int
    runs: int
    failures: int
    last_tick_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        normalized = self.worker.strip()
        if not normalized:
            raise ValueError("worker must not be blank")
        if self.ticks < 0 or self.runs < 0 or self.failures < 0:
            raise ValueError("worker counters cannot be negative")
        if self.last_tick_at is not None and self.last_tick_at.tzinfo is None:
            raise ValueError("last_tick_at must be timezone-aware")
        error = None if self.last_error is None else self.last_error.strip()
        object.__setattr__(self, "state", JobWorkerState(self.state))
        object.__setattr__(self, "worker", normalized)
        object.__setattr__(self, "last_error", error or None)


class JobWorker:
    """Run bounded scheduler ticks while owned by the Phoenix Runtime lifecycle."""

    def __init__(
        self,
        scheduler: JobScheduler,
        *,
        poll_interval: float = 1.0,
        lease_ttl: timedelta = timedelta(seconds=30),
        batch_size: int = 100,
        worker: str = "phoenix.scheduler",
        clock: JobClock = _utc_now,
    ) -> None:
        normalized_worker = worker.strip()
        if not normalized_worker:
            raise ValueError("worker must not be blank")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if lease_ttl <= timedelta(0):
            raise ValueError("lease_ttl must be positive")
        if batch_size <= 0 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._scheduler = scheduler
        self._poll_interval = poll_interval
        self._lease_ttl = lease_ttl
        self._batch_size = batch_size
        self._worker = normalized_worker
        self._clock = clock
        self._state = JobWorkerState.CREATED
        self._ticks = 0
        self._runs = 0
        self._failures = 0
        self._last_tick_at: datetime | None = None
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> JobWorkerState:
        return self._state

    async def start(self, context: object) -> None:
        """Start the one-shot worker loop after Runtime dependencies are ready."""

        del context
        async with self._state_lock:
            if self._state is not JobWorkerState.CREATED:
                raise JobWorkerStateError(f"cannot start job worker from state {self._state.value}")
            self._state = JobWorkerState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name=f"phoenix-job-worker:{self._worker}",
            )

    async def stop(self, context: object) -> None:
        """Stop new ticks, wait for the active tick, and close the scheduler."""

        del context
        async with self._state_lock:
            if self._state is JobWorkerState.STOPPED:
                return
            if self._state is JobWorkerState.CREATED:
                self._state = JobWorkerState.STOPPING
            elif self._state is JobWorkerState.RUNNING:
                self._state = JobWorkerState.STOPPING
                self._stop_requested.set()
            task = self._task

        if task is not None:
            await task
        await self._scheduler.close()

        async with self._state_lock:
            self._task = None
            self._state = JobWorkerState.STOPPED

    async def run_once(self, *, now: datetime | None = None) -> tuple[JobRun, ...]:
        """Execute one bounded tick and isolate infrastructure failures from the loop."""

        if self._state is not JobWorkerState.RUNNING:
            raise JobWorkerStateError(f"cannot run job tick from state {self._state.value}")
        tick_at = self._clock() if now is None else now
        if tick_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        async with self._tick_lock:
            self._ticks += 1
            self._last_tick_at = tick_at
            try:
                runs = await self._scheduler.run_due(
                    now=tick_at,
                    worker=self._worker,
                    lease_ttl=self._lease_ttl,
                    limit=self._batch_size,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return ()
            self._runs += len(runs)
            self._last_error = None
            return runs

    async def snapshot(self) -> JobWorkerSnapshot:
        """Return stable worker counters without job arguments or outputs."""

        async with self._state_lock:
            return JobWorkerSnapshot(
                state=self._state,
                worker=self._worker,
                ticks=self._ticks,
                runs=self._runs,
                failures=self._failures,
                last_tick_at=self._last_tick_at,
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
