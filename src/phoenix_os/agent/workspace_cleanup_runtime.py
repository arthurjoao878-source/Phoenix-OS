"""Runtime-owned bounded cleanup scheduling for secure Phoenix workspaces."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol, runtime_checkable

from phoenix_os.agent.errors import AgentServiceUnavailableError
from phoenix_os.runtime import RuntimeContext

MIN_WORKSPACE_CLEANUP_RUNTIME_INTERVAL = timedelta(milliseconds=10)
MAX_WORKSPACE_CLEANUP_RUNTIME_INTERVAL = timedelta(hours=24)
MAX_WORKSPACE_CLEANUP_RUNTIME_SHUTDOWN_TIMEOUT = timedelta(minutes=5)
WORKSPACE_CLEANUP_RUNTIME_QUEUE_CAPACITY = 1
WORKSPACE_CLEANUP_RUNTIME_WORKERS = 1


def _consume_cleanup_runtime_task_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@runtime_checkable
class _WorkspaceCleanupOwner(Protocol):
    """Runtime owner exposing one already-bounded cleanup cycle."""

    @property
    def closed(self) -> bool: ...

    @property
    def running(self) -> bool: ...

    async def cleanup_once(self) -> int: ...


@dataclass(frozen=True, slots=True)
class AgentWorkspaceCleanupRuntimeConfiguration:
    """Strict finite scheduling and shutdown bounds for cleanup maintenance."""

    interval: timedelta = timedelta(minutes=1)
    shutdown_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if not isinstance(self.interval, timedelta):
            raise TypeError("interval must be timedelta")
        if (
            self.interval < MIN_WORKSPACE_CLEANUP_RUNTIME_INTERVAL
            or self.interval > MAX_WORKSPACE_CLEANUP_RUNTIME_INTERVAL
        ):
            raise ValueError("interval is outside supported bounds")
        if not isinstance(self.shutdown_timeout, timedelta):
            raise TypeError("shutdown_timeout must be timedelta")
        if (
            self.shutdown_timeout <= timedelta(0)
            or self.shutdown_timeout > MAX_WORKSPACE_CLEANUP_RUNTIME_SHUTDOWN_TIMEOUT
        ):
            raise ValueError("shutdown_timeout is outside supported bounds")


class AgentWorkspaceCleanupRuntime:
    """Schedule one coalesced Runtime-owned cleanup cycle at a time.

    The queue has exactly one slot and the worker count is exactly one. Slow or
    cancellation-suppressing maintenance therefore consumes bounded concurrency
    instead of causing task replacement or an unbounded backlog. Each real cleanup
    deadline remains owned by AgentWorkspaceRuntimeOwner.cleanup_once().
    """

    def __init__(
        self,
        *,
        configuration: AgentWorkspaceCleanupRuntimeConfiguration,
        owner: _WorkspaceCleanupOwner,
    ) -> None:
        if not isinstance(configuration, AgentWorkspaceCleanupRuntimeConfiguration):
            raise TypeError("configuration must be AgentWorkspaceCleanupRuntimeConfiguration")
        if not isinstance(owner, _WorkspaceCleanupOwner):
            raise TypeError("owner must implement the workspace cleanup owner")

        self._configuration = configuration
        self._owner = owner
        self._queue: asyncio.Queue[None] = asyncio.Queue(
            maxsize=WORKSPACE_CLEANUP_RUNTIME_QUEUE_CAPACITY
        )
        self._scheduler: asyncio.Task[None] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._started = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._started and not self._closed

    @property
    def queued_cycles(self) -> int:
        return self._queue.qsize()

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._closed:
            raise AgentServiceUnavailableError()
        self._require_owner_running()
        if self._started:
            return

        scheduler = asyncio.create_task(
            self._schedule_loop(),
            name="phoenix-agent-workspace-cleanup-scheduler",
        )
        try:
            worker = asyncio.create_task(
                self._worker_loop(),
                name="phoenix-agent-workspace-cleanup-worker",
            )
        except BaseException:
            scheduler.cancel()
            scheduler.add_done_callback(_consume_cleanup_runtime_task_result)
            raise

        self._scheduler = scheduler
        self._worker = worker
        self._started = True

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._started = False

        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self._queue.task_done()

        tasks = tuple(task for task in (self._scheduler, self._worker) if task is not None)
        self._scheduler = None
        self._worker = None

        for task in tasks:
            task.cancel()

        if not tasks:
            return

        try:
            done, pending = await asyncio.wait(
                set(tasks),
                timeout=self._configuration.shutdown_timeout.total_seconds(),
            )
        except asyncio.CancelledError:
            for task in tasks:
                task.add_done_callback(_consume_cleanup_runtime_task_result)
            raise

        for task in done:
            _consume_cleanup_runtime_task_result(task)
        for task in pending:
            task.add_done_callback(_consume_cleanup_runtime_task_result)

    async def _schedule_loop(self) -> None:
        delay = self._configuration.interval.total_seconds()
        while not self._closed:
            await asyncio.sleep(delay)
            if self._closed:
                return
            try:
                self._queue.put_nowait(None)
            except asyncio.QueueFull:
                # One pending cycle is enough. Slow cleanup coalesces later ticks.
                pass

    async def _worker_loop(self) -> None:
        while not self._closed:
            await self._queue.get()
            try:
                if self._closed:
                    continue
                try:
                    await self._owner.cleanup_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # 4C adds content-free operational reporting. A failed
                    # maintenance cycle never kills the finite Runtime worker.
                    pass
            finally:
                self._queue.task_done()

    def _require_owner_running(self) -> None:
        try:
            closed = self._owner.closed
            running = self._owner.running
        except Exception:
            raise AgentServiceUnavailableError() from None
        if not isinstance(closed, bool) or not isinstance(running, bool):
            raise AgentServiceUnavailableError()
        if closed or not running:
            raise AgentServiceUnavailableError()
