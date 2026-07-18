"""Runtime-owned reconciliation loop for durable Phoenix workflows."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from phoenix_os.workflows.contracts import WorkflowRecord
from phoenix_os.workflows.errors import WorkflowWorkerStateError
from phoenix_os.workflows.orchestrator import WorkflowOrchestrator

type WorkflowClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class WorkflowWorkerState(StrEnum):
    """Observable lifecycle state of a one-shot workflow worker."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class WorkflowWorkerSnapshot:
    """Non-sensitive point-in-time diagnostics for one reconciliation loop."""

    state: WorkflowWorkerState
    worker: str
    ticks: int
    workflows: int
    failures: int
    last_tick_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        normalized = self.worker.strip()
        if not normalized:
            raise ValueError("worker must not be blank")
        if self.ticks < 0 or self.workflows < 0 or self.failures < 0:
            raise ValueError("workflow worker counters cannot be negative")
        if self.last_tick_at is not None and self.last_tick_at.tzinfo is None:
            raise ValueError("last_tick_at must be timezone-aware")
        error = None if self.last_error is None else self.last_error.strip()
        object.__setattr__(self, "state", WorkflowWorkerState(self.state))
        object.__setattr__(self, "worker", normalized)
        object.__setattr__(self, "last_error", error or None)


class WorkflowWorker:
    """Reconcile persisted workflow instances while owned by Runtime."""

    def __init__(
        self,
        orchestrator: WorkflowOrchestrator,
        *,
        poll_interval: float = 1.0,
        worker: str = "phoenix.workflows",
        clock: WorkflowClock = _utc_now,
    ) -> None:
        normalized_worker = worker.strip()
        if not normalized_worker:
            raise ValueError("worker must not be blank")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._orchestrator = orchestrator
        self._poll_interval = poll_interval
        self._worker = normalized_worker
        self._clock = clock
        self._state = WorkflowWorkerState.CREATED
        self._ticks = 0
        self._workflows = 0
        self._failures = 0
        self._last_tick_at: datetime | None = None
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> WorkflowWorkerState:
        return self._state

    async def start(self, context: object) -> None:
        """Start the one-shot reconciliation loop after Runtime dependencies are ready."""

        del context
        async with self._state_lock:
            if self._state is not WorkflowWorkerState.CREATED:
                raise WorkflowWorkerStateError(
                    f"cannot start workflow worker from state {self._state.value}"
                )
            self._state = WorkflowWorkerState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name=f"phoenix-workflow-worker:{self._worker}",
            )

    async def stop(self, context: object) -> None:
        """Stop new reconciliation ticks and close the orchestrator."""

        del context
        async with self._state_lock:
            if self._state is WorkflowWorkerState.STOPPED:
                return
            if self._state is WorkflowWorkerState.CREATED:
                self._state = WorkflowWorkerState.STOPPING
            elif self._state is WorkflowWorkerState.RUNNING:
                self._state = WorkflowWorkerState.STOPPING
                self._stop_requested.set()
            task = self._task

        if task is not None:
            await task
        await self._orchestrator.close()

        async with self._state_lock:
            self._task = None
            self._state = WorkflowWorkerState.STOPPED

    async def run_once(self, *, now: datetime | None = None) -> tuple[WorkflowRecord, ...]:
        """Execute one bounded reconciliation tick and isolate infrastructure failures."""

        if self._state is not WorkflowWorkerState.RUNNING:
            raise WorkflowWorkerStateError(
                f"cannot run workflow tick from state {self._state.value}"
            )
        tick_at = self._clock() if now is None else now
        if tick_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        async with self._tick_lock:
            self._ticks += 1
            self._last_tick_at = tick_at
            try:
                workflows = await self._orchestrator.recover(now=tick_at)
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return ()
            self._workflows += len(workflows)
            self._last_error = None
            return workflows

    async def snapshot(self) -> WorkflowWorkerSnapshot:
        """Return stable counters without definitions, arguments, or outputs."""

        async with self._state_lock:
            return WorkflowWorkerSnapshot(
                state=self._state,
                worker=self._worker,
                ticks=self._ticks,
                workflows=self._workflows,
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
