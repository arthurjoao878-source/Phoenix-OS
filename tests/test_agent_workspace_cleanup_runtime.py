from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from phoenix_os.agent import (
    MAX_WORKSPACE_CLEANUP_RUNTIME_INTERVAL,
    MAX_WORKSPACE_CLEANUP_RUNTIME_SHUTDOWN_TIMEOUT,
    MIN_WORKSPACE_CLEANUP_RUNTIME_INTERVAL,
    WORKSPACE_CLEANUP_RUNTIME_QUEUE_CAPACITY,
    WORKSPACE_CLEANUP_RUNTIME_WORKERS,
    AgentServiceUnavailableError,
    AgentWorkspaceCleanupRuntime,
    AgentWorkspaceCleanupRuntimeConfiguration,
)
from phoenix_os.runtime import RuntimeContext


class _ImmediateOwner:
    def __init__(self) -> None:
        self._closed = False
        self._running = True
        self.calls = 0
        self.called = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._running

    async def cleanup_once(self) -> int:
        self.calls += 1
        self.called.set()
        return 0


class _BlockingOwner:
    def __init__(self) -> None:
        self._closed = False
        self._running = True
        self.active = 0
        self.max_active = 0
        self.started = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._running

    async def cleanup_once(self) -> int:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            await asyncio.Future()
        finally:
            self.active -= 1
        raise AssertionError("unreachable")


class _RetryOwner:
    def __init__(self) -> None:
        self._closed = False
        self._running = True
        self.calls = 0
        self.retried = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._running

    async def cleanup_once(self) -> int:
        self.calls += 1
        if self.calls == 1:
            raise AgentServiceUnavailableError()
        self.retried.set()
        return 0


class _CancellationSuppressingOwner:
    def __init__(self) -> None:
        self._closed = False
        self._running = True
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._running

    async def cleanup_once(self) -> int:
        self.started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.release.wait()
            self.finished.set()
            return 0
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_cleanup_runtime_schedules_bounded_owner_cycle() -> None:
    owner = _ImmediateOwner()
    runtime = AgentWorkspaceCleanupRuntime(
        configuration=AgentWorkspaceCleanupRuntimeConfiguration(
            interval=timedelta(milliseconds=10),
        ),
        owner=owner,
    )

    await runtime.start(RuntimeContext(services={}))
    await asyncio.wait_for(owner.called.wait(), timeout=0.5)

    assert runtime.running is True
    assert owner.calls >= 1
    assert WORKSPACE_CLEANUP_RUNTIME_QUEUE_CAPACITY == 1
    assert WORKSPACE_CLEANUP_RUNTIME_WORKERS == 1

    await runtime.close()
    assert runtime.closed is True
    assert runtime.running is False


@pytest.mark.asyncio
async def test_cleanup_runtime_coalesces_ticks_and_never_overlaps_cycles() -> None:
    owner = _BlockingOwner()
    runtime = AgentWorkspaceCleanupRuntime(
        configuration=AgentWorkspaceCleanupRuntimeConfiguration(
            interval=timedelta(milliseconds=10),
            shutdown_timeout=timedelta(milliseconds=20),
        ),
        owner=owner,
    )
    await runtime.start(RuntimeContext(services={}))

    await asyncio.wait_for(owner.started.wait(), timeout=0.5)
    await asyncio.sleep(0.05)

    assert owner.max_active == 1
    assert runtime.queued_cycles == 1

    await asyncio.wait_for(runtime.close(), timeout=0.5)
    assert owner.active == 0


@pytest.mark.asyncio
async def test_cleanup_runtime_retries_on_next_tick_after_failed_cycle() -> None:
    owner = _RetryOwner()
    runtime = AgentWorkspaceCleanupRuntime(
        configuration=AgentWorkspaceCleanupRuntimeConfiguration(
            interval=timedelta(milliseconds=10),
        ),
        owner=owner,
    )
    await runtime.start(RuntimeContext(services={}))

    await asyncio.wait_for(owner.retried.wait(), timeout=0.5)

    assert owner.calls >= 2
    await runtime.close()


@pytest.mark.asyncio
async def test_cleanup_runtime_shutdown_is_bounded_when_owner_suppresses_cancel() -> None:
    owner = _CancellationSuppressingOwner()
    runtime = AgentWorkspaceCleanupRuntime(
        configuration=AgentWorkspaceCleanupRuntimeConfiguration(
            interval=timedelta(milliseconds=10),
            shutdown_timeout=timedelta(milliseconds=10),
        ),
        owner=owner,
    )
    await runtime.start(RuntimeContext(services={}))
    await asyncio.wait_for(owner.started.wait(), timeout=0.5)

    await asyncio.wait_for(runtime.close(), timeout=0.5)

    assert runtime.closed is True
    assert runtime.running is False
    await asyncio.wait_for(owner.cancelled.wait(), timeout=0.5)

    owner.release.set()
    await asyncio.wait_for(owner.finished.wait(), timeout=0.5)
    await asyncio.sleep(0)
    assert runtime.queued_cycles == 0


@pytest.mark.asyncio
async def test_cleanup_runtime_requires_running_owner() -> None:
    owner = _ImmediateOwner()
    owner._running = False
    runtime = AgentWorkspaceCleanupRuntime(
        configuration=AgentWorkspaceCleanupRuntimeConfiguration(),
        owner=owner,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.start(RuntimeContext(services={}))

    assert runtime.running is False


def test_cleanup_runtime_configuration_is_strictly_bounded() -> None:
    with pytest.raises(ValueError, match="interval"):
        AgentWorkspaceCleanupRuntimeConfiguration(interval=timedelta(milliseconds=1))
    with pytest.raises(ValueError, match="interval"):
        AgentWorkspaceCleanupRuntimeConfiguration(
            interval=MAX_WORKSPACE_CLEANUP_RUNTIME_INTERVAL + timedelta(seconds=1)
        )
    with pytest.raises(ValueError, match="shutdown_timeout"):
        AgentWorkspaceCleanupRuntimeConfiguration(shutdown_timeout=timedelta(0))
    with pytest.raises(ValueError, match="shutdown_timeout"):
        AgentWorkspaceCleanupRuntimeConfiguration(
            shutdown_timeout=(MAX_WORKSPACE_CLEANUP_RUNTIME_SHUTDOWN_TIMEOUT + timedelta(seconds=1))
        )

    assert MIN_WORKSPACE_CLEANUP_RUNTIME_INTERVAL == timedelta(milliseconds=10)
