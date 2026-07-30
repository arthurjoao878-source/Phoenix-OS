"""Deterministic fenced leases for durable agent recovery and mutation."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    DurableLease,
    DurableLeaseId,
    DurableRunLimits,
    FencingGeneration,
)
from phoenix_os.agent.errors import AgentLimitExceededError, AgentStateConflictError


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@runtime_checkable
class DurableLeaseManager(Protocol):
    """Time-bounded ownership and monotonic fencing for durable runs."""

    @property
    def closed(self) -> bool: ...

    def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> Awaitable[DurableLease]: ...

    def get_current(
        self,
        run_id: DurableAgentRunId,
        *,
        now: datetime,
    ) -> Awaitable[DurableLease | None]: ...

    def renew(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> Awaitable[DurableLease]: ...

    def require_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> Awaitable[DurableLease]: ...

    def guard_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> AbstractAsyncContextManager[DurableLease]: ...

    def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> Awaitable[None]: ...

    def close(self) -> Awaitable[None]: ...


class InMemoryDurableLeaseManager(DurableLeaseManager):
    """Atomic in-memory leases with fail-closed clock and fencing checks."""

    def __init__(self, *, limits: DurableRunLimits | None = None) -> None:
        selected_limits = DurableRunLimits() if limits is None else limits
        if not isinstance(selected_limits, DurableRunLimits):
            raise TypeError("limits must be DurableRunLimits")
        self._limits = selected_limits
        self._active: dict[DurableAgentRunId, DurableLease] = {}
        self._generations: dict[DurableAgentRunId, FencingGeneration] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def limits(self) -> DurableRunLimits:
        return self._limits

    @property
    def active_count(self) -> int:
        return len(self._active)

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        """Acquire an absent or expired lease and increment its fencing generation."""

        self._require_run_id(run_id)
        _require_timezone_aware(now, label="now")

        async with self._lock:
            self._ensure_open()
            current = self._active.get(run_id)
            if current is not None:
                if now < current.acquired_at:
                    raise AgentStateConflictError()
                if now < current.expires_at:
                    raise AgentStateConflictError()
                del self._active[run_id]

            previous_generation = self._generations.get(run_id)
            if previous_generation is None:
                generation = FencingGeneration(1)
            else:
                try:
                    generation = previous_generation.next()
                except ValueError as exc:
                    raise AgentLimitExceededError() from exc

            lease = DurableLease(
                run_id=run_id,
                lease_id=DurableLeaseId(),
                owner_id=owner_id,
                generation=generation,
                acquired_at=now,
                expires_at=now + self._limits.lease_duration,
            )
            self._generations[run_id] = generation
            self._active[run_id] = lease
            return lease

    async def get_current(
        self,
        run_id: DurableAgentRunId,
        *,
        now: datetime,
    ) -> DurableLease | None:
        """Return the current active lease, pruning only leases proven expired."""

        self._require_run_id(run_id)
        _require_timezone_aware(now, label="now")

        async with self._lock:
            self._ensure_open()
            current = self._active.get(run_id)
            if current is None:
                return None
            if now < current.acquired_at:
                raise AgentStateConflictError()
            if now >= current.expires_at:
                del self._active[run_id]
                return None
            return current

    async def renew(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> DurableLease:
        """Renew one current lease without changing its fencing generation."""

        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._lock:
            self._ensure_open()
            current = self._require_current_locked(lease, now=now)
            renewed = DurableLease(
                run_id=current.run_id,
                lease_id=current.lease_id,
                owner_id=current.owner_id,
                generation=current.generation,
                acquired_at=now,
                expires_at=now + self._limits.lease_duration,
            )
            self._active[current.run_id] = renewed
            return renewed

    async def require_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> DurableLease:
        """Return authoritative lease data only for the current fenced owner."""

        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._lock:
            self._ensure_open()
            return self._require_current_locked(lease, now=now)

    @asynccontextmanager
    async def guard_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> AsyncIterator[DurableLease]:
        """Hold exclusive lease authority across one fenced store mutation."""

        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._lock:
            self._ensure_open()
            yield self._require_current_locked(lease, now=now)

    async def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> None:
        """Release only the current active lease identity."""

        self._require_lease(lease)
        _require_timezone_aware(now, label="now")

        async with self._lock:
            self._ensure_open()
            current = self._require_current_locked(lease, now=now)
            del self._active[current.run_id]

    async def close(self) -> None:
        """Close the manager and invalidate every in-memory active lease."""

        async with self._lock:
            self._active.clear()
            self._closed = True

    def _require_current_locked(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> DurableLease:
        current = self._active.get(lease.run_id)
        if current is None:
            raise AgentStateConflictError()
        if not self._same_identity(current, lease):
            raise AgentStateConflictError()
        if now < current.acquired_at:
            raise AgentStateConflictError()
        if now >= current.expires_at:
            del self._active[current.run_id]
            raise AgentStateConflictError()
        return current

    @staticmethod
    def _same_identity(left: DurableLease, right: DurableLease) -> bool:
        return (
            left.run_id == right.run_id
            and left.lease_id == right.lease_id
            and left.owner_id == right.owner_id
            and left.generation == right.generation
        )

    @staticmethod
    def _require_run_id(run_id: DurableAgentRunId) -> None:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")

    @staticmethod
    def _require_lease(lease: DurableLease) -> None:
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("durable lease manager is closed")
