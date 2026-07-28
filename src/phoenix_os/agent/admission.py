"""Finite admission and saturation control for bounded agent work."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from phoenix_os.agent.contracts import AgentLimits
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentTimeoutError,
)
from phoenix_os.agent.state import AgentCancellationToken


def _require_positive_seconds(value: float, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} must be a number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError(f"{label} must be finite and greater than zero")
    return normalized


class _AdmissionKind(StrEnum):
    RUN = "run"
    MODEL = "model"
    TOOL = "tool"


@dataclass(frozen=True, slots=True)
class AgentAdmissionSnapshot:
    """Content-free counters for one bounded admission controller."""

    closed: bool
    active_runs: int
    active_model_calls: int
    active_tool_calls: int
    queued: int
    max_queue_depth: int
    max_concurrent_runs: int
    max_concurrent_model_calls: int
    max_concurrent_tool_calls: int

    def __post_init__(self) -> None:
        values = (
            self.active_runs,
            self.active_model_calls,
            self.active_tool_calls,
            self.queued,
            self.max_queue_depth,
            self.max_concurrent_runs,
            self.max_concurrent_model_calls,
            self.max_concurrent_tool_calls,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TypeError("admission counters and limits must be integers")
        if min(values) < 0:
            raise ValueError("admission counters and limits cannot be negative")
        if (
            self.max_queue_depth <= 0
            or self.max_concurrent_runs <= 0
            or self.max_concurrent_model_calls <= 0
            or self.max_concurrent_tool_calls <= 0
        ):
            raise ValueError("admission limits must be greater than zero")
        if self.active_runs > self.max_concurrent_runs:
            raise ValueError("active runs exceed configured capacity")
        if self.active_model_calls > self.max_concurrent_model_calls:
            raise ValueError("active model calls exceed configured capacity")
        if self.active_tool_calls > self.max_concurrent_tool_calls:
            raise ValueError("active tool calls exceed configured capacity")


class AgentAdmissionLease:
    """One idempotently releasable admission slot."""

    def __init__(
        self,
        controller: AgentAdmissionController,
        kind: _AdmissionKind,
    ) -> None:
        self._controller = controller
        self._kind = kind
        self._released = False
        self._lock = asyncio.Lock()

    @property
    def released(self) -> bool:
        return self._released

    async def release(self) -> None:
        async with self._lock:
            if self._released:
                return
            await self._controller._release(self._kind)
            self._released = True

    async def __aenter__(self) -> Self:
        if self._released:
            raise AgentStateConflictError()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.release()


class AgentAdmissionController:
    """Reject saturation and bound queued, model, tool, and run work."""

    def __init__(self, limits: AgentLimits | None = None) -> None:
        resolved = limits or AgentLimits()
        if not isinstance(resolved, AgentLimits):
            raise TypeError("limits must be AgentLimits")
        self._limits = resolved
        self._closed = False
        self._active = {
            _AdmissionKind.RUN: 0,
            _AdmissionKind.MODEL: 0,
            _AdmissionKind.TOOL: 0,
        }
        self._queued = 0
        self._lock = asyncio.Lock()
        self._changed = asyncio.Event()

    @property
    def limits(self) -> AgentLimits:
        return self._limits

    @property
    def closed(self) -> bool:
        return self._closed

    async def acquire_run(
        self,
        limits: AgentLimits | None = None,
        *,
        timeout_seconds: float,
        cancellation: AgentCancellationToken,
    ) -> AgentAdmissionLease:
        return await self._acquire(
            _AdmissionKind.RUN,
            limits,
            timeout_seconds=timeout_seconds,
            cancellation=cancellation,
        )

    async def acquire_model(
        self,
        limits: AgentLimits | None = None,
        *,
        timeout_seconds: float,
        cancellation: AgentCancellationToken,
    ) -> AgentAdmissionLease:
        return await self._acquire(
            _AdmissionKind.MODEL,
            limits,
            timeout_seconds=timeout_seconds,
            cancellation=cancellation,
        )

    async def acquire_tool(
        self,
        limits: AgentLimits | None = None,
        *,
        timeout_seconds: float,
        cancellation: AgentCancellationToken,
    ) -> AgentAdmissionLease:
        return await self._acquire(
            _AdmissionKind.TOOL,
            limits,
            timeout_seconds=timeout_seconds,
            cancellation=cancellation,
        )

    async def snapshot(self) -> AgentAdmissionSnapshot:
        async with self._lock:
            return AgentAdmissionSnapshot(
                closed=self._closed,
                active_runs=self._active[_AdmissionKind.RUN],
                active_model_calls=self._active[_AdmissionKind.MODEL],
                active_tool_calls=self._active[_AdmissionKind.TOOL],
                queued=self._queued,
                max_queue_depth=self._limits.max_queue_depth,
                max_concurrent_runs=self._limits.max_concurrent_runs,
                max_concurrent_model_calls=self._limits.max_concurrent_model_calls,
                max_concurrent_tool_calls=self._limits.max_concurrent_tool_calls,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._signal_locked()

    async def _acquire(
        self,
        kind: _AdmissionKind,
        limits: AgentLimits | None,
        *,
        timeout_seconds: float,
        cancellation: AgentCancellationToken,
    ) -> AgentAdmissionLease:
        requested = self._limits if limits is None else limits
        if not isinstance(requested, AgentLimits):
            raise TypeError("limits must be AgentLimits")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        timeout = _require_positive_seconds(timeout_seconds, "timeout_seconds")
        capacity = min(self._capacity(kind, self._limits), self._capacity(kind, requested))
        queue_limit = min(self._limits.max_queue_depth, requested.max_queue_depth)
        deadline = asyncio.get_running_loop().time() + timeout
        queued = False

        try:
            while True:
                cancellation.raise_if_cancelled()
                async with self._lock:
                    if self._closed:
                        raise AgentServiceUnavailableError()
                    cancellation.raise_if_cancelled()
                    if self._active[kind] < capacity:
                        self._active[kind] += 1
                        if queued:
                            self._queued -= 1
                            queued = False
                        return AgentAdmissionLease(self, kind)
                    if not queued:
                        if self._queued >= queue_limit:
                            raise AgentLimitExceededError()
                        self._queued += 1
                        queued = True
                    changed = self._changed

                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise AgentTimeoutError()
                await _wait_for_change(
                    changed,
                    cancellation,
                    timeout_seconds=remaining,
                )
        finally:
            if queued:
                async with self._lock:
                    self._queued -= 1
                    self._signal_locked()

    async def _release(self, kind: _AdmissionKind) -> None:
        async with self._lock:
            if self._active[kind] <= 0:
                raise AgentStateConflictError()
            self._active[kind] -= 1
            self._signal_locked()

    @staticmethod
    def _capacity(kind: _AdmissionKind, limits: AgentLimits) -> int:
        return {
            _AdmissionKind.RUN: limits.max_concurrent_runs,
            _AdmissionKind.MODEL: limits.max_concurrent_model_calls,
            _AdmissionKind.TOOL: limits.max_concurrent_tool_calls,
        }[kind]

    def _signal_locked(self) -> None:
        changed = self._changed
        self._changed = asyncio.Event()
        changed.set()


async def _wait_for_change(
    changed: asyncio.Event,
    cancellation: AgentCancellationToken,
    *,
    timeout_seconds: float,
) -> None:
    change_waiter = asyncio.create_task(changed.wait())
    cancellation_waiter = asyncio.create_task(cancellation.wait())
    try:
        done, _pending = await asyncio.wait(
            {change_waiter, cancellation_waiter},
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancellation_waiter in done:
            raise AgentCancelledError()
        if change_waiter not in done:
            raise AgentTimeoutError()
    finally:
        for waiter in (change_waiter, cancellation_waiter):
            if not waiter.done():
                waiter.cancel()
        await asyncio.gather(
            change_waiter,
            cancellation_waiter,
            return_exceptions=True,
        )
