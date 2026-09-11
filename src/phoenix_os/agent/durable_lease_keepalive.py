"""Attempt-scoped durable lease renewal for one external call."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from phoenix_os.agent.durable_contracts import DurableLease
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentCancellationToken


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


class DurableSubmissionStartedSignal:
    """One-way signal armed only after durable STARTED is confirmed."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def started(self) -> bool:
        return self._event.is_set()

    def mark_started(self) -> None:
        if self._event.is_set():
            raise AgentStateConflictError()
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


class DurableLeaseCallKeepalive:
    """Renew one stable fenced lease only while an external call is in flight."""

    def __init__(
        self,
        *,
        lease_manager: DurableLeaseManager,
        lease: DurableLease,
        renewal_interval: timedelta,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(renewal_interval, timedelta):
            raise TypeError("renewal_interval must be timedelta")
        if renewal_interval <= timedelta(0):
            raise ValueError("renewal_interval must be greater than zero")
        if renewal_interval >= lease.expires_at - lease.acquired_at:
            raise ValueError("renewal_interval must be shorter than lease duration")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._lease_manager = lease_manager
        self._lease = lease
        self._renewal_interval = renewal_interval
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._failure: Exception | None = None

    @property
    def failure(self) -> Exception | None:
        return self._failure

    @property
    def lease(self) -> DurableLease:
        return self._lease

    def start(
        self,
        *,
        started_signal: DurableSubmissionStartedSignal,
        cancellation: AgentCancellationToken,
    ) -> None:
        if not isinstance(started_signal, DurableSubmissionStartedSignal):
            raise TypeError("started_signal must be DurableSubmissionStartedSignal")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        if self._task is not None:
            raise AgentStateConflictError()
        self._task = asyncio.create_task(
            self._run(
                started_signal=started_signal,
                cancellation=cancellation,
            )
        )

    async def stop(self) -> None:
        self._stop.set()
        task = self._task
        if task is None:
            return
        try:
            await task
        except asyncio.CancelledError:
            raise

    async def _run(
        self,
        *,
        started_signal: DurableSubmissionStartedSignal,
        cancellation: AgentCancellationToken,
    ) -> None:
        if not await self._wait_for_started(started_signal):
            return

        while not self._stop.is_set():
            if await self._wait_for_stop():
                return
            now = self._clock()
            _require_timezone_aware(now, label="clock result")
            try:
                renewed = await self._lease_manager.renew(
                    self._lease,
                    now=now,
                )
                self._require_valid_renewal(renewed)
            except Exception as exception:
                self._failure = exception
                cancellation.cancel()
                return
            self._lease = renewed

    async def _wait_for_started(
        self,
        started_signal: DurableSubmissionStartedSignal,
    ) -> bool:
        started_waiter = asyncio.create_task(started_signal.wait())
        stop_waiter = asyncio.create_task(self._stop.wait())
        try:
            done, _pending = await asyncio.wait(
                {started_waiter, stop_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if stop_waiter in done:
                return False
            await started_waiter
            return True
        finally:
            for waiter in (started_waiter, stop_waiter):
                if not waiter.done():
                    waiter.cancel()
            for waiter in (started_waiter, stop_waiter):
                try:
                    await waiter
                except asyncio.CancelledError:
                    pass

    async def _wait_for_stop(self) -> bool:
        try:
            await asyncio.wait_for(
                self._stop.wait(),
                timeout=self._renewal_interval.total_seconds(),
            )
        except TimeoutError:
            return False
        return True

    def _require_valid_renewal(self, renewed: DurableLease) -> None:
        current = self._lease
        if (
            not isinstance(renewed, DurableLease)
            or renewed.run_id != current.run_id
            or renewed.lease_id != current.lease_id
            or renewed.owner_id != current.owner_id
            or renewed.generation != current.generation
            or renewed.acquired_at < current.acquired_at
            or renewed.expires_at <= renewed.acquired_at
            or self._renewal_interval >= renewed.expires_at - renewed.acquired_at
        ):
            raise AgentStateConflictError()


class StoreBackedDurableLeaseKeepaliveFactory:
    """Create bounded per-call keepalives over one durable lease manager."""

    def __init__(
        self,
        *,
        lease_manager: DurableLeaseManager,
        renewal_interval: timedelta,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(renewal_interval, timedelta):
            raise TypeError("renewal_interval must be timedelta")
        if renewal_interval <= timedelta(0):
            raise ValueError("renewal_interval must be greater than zero")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._lease_manager = lease_manager
        self._renewal_interval = renewal_interval
        self._clock = clock

    def require_compatible(self, lease: DurableLease) -> None:
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if self._renewal_interval >= lease.expires_at - lease.acquired_at:
            raise ValueError("renewal_interval must be shorter than lease duration")

    def create(self, lease: DurableLease) -> DurableLeaseCallKeepalive:
        self.require_compatible(lease)
        return DurableLeaseCallKeepalive(
            lease_manager=self._lease_manager,
            lease=lease,
            renewal_interval=self._renewal_interval,
            clock=self._clock,
        )
