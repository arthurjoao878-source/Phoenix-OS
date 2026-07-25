"""Bounded global and per-source admission control for inbound events."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Self
from uuid import UUID

from phoenix_os.inbound_events.contracts import InboundEventSource
from phoenix_os.inbound_events.errors import (
    InboundAdmissionLimiterClosedError,
    InboundAdmissionRejectedError,
)

MAX_INBOUND_GLOBAL_CONCURRENCY = 4_096
MAX_INBOUND_GLOBAL_REQUESTS_PER_MINUTE = 10_000_000

type InboundAdmissionClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class InboundAdmissionLimitPolicy:
    """Finite process-wide admission limits."""

    global_max_concurrency: int = 64
    global_requests_per_minute: int = 10_000
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not 1 <= self.global_max_concurrency <= MAX_INBOUND_GLOBAL_CONCURRENCY:
            raise ValueError("inbound global concurrency is outside supported bounds")
        if not (1 <= self.global_requests_per_minute <= MAX_INBOUND_GLOBAL_REQUESTS_PER_MINUTE):
            raise ValueError("inbound global request rate is outside supported bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound admission limit policy version")


@dataclass(frozen=True, slots=True)
class InboundAdmissionLimiterSnapshot:
    """Safe aggregate admission diagnostics without source identities."""

    closed: bool
    active: int
    tracked_sources: int
    admitted: int
    rejected: int
    current_window_requests: int
    global_max_concurrency: int
    global_requests_per_minute: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        values = (
            self.active,
            self.tracked_sources,
            self.admitted,
            self.rejected,
            self.current_window_requests,
        )
        if any(value < 0 for value in values):
            raise ValueError("inbound admission snapshot counters cannot be negative")
        if self.active > self.global_max_concurrency:
            raise ValueError("inbound admission active count exceeds its limit")
        if self.current_window_requests > self.global_requests_per_minute:
            raise ValueError("inbound admission rate count exceeds its limit")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound admission limiter snapshot version")


@dataclass(slots=True)
class _SourceAdmissionState:
    window_started_at: datetime
    requests: int = 0
    active: int = 0


class InboundAdmissionLease:
    """Idempotently release one admitted request."""

    __slots__ = ("_closed", "_limiter", "_source_id")

    def __init__(
        self,
        limiter: InboundAdmissionLimiter,
        source_id: UUID,
    ) -> None:
        self._limiter = limiter
        self._source_id = source_id
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._limiter._release(self._source_id)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        await self.close()


class InboundAdmissionLimiter:
    """Immediate finite admission without unbounded waiting queues."""

    def __init__(
        self,
        policy: InboundAdmissionLimitPolicy | None = None,
        *,
        clock: InboundAdmissionClock | None = None,
    ) -> None:
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("inbound admission clock must be callable")
        self._policy = policy or InboundAdmissionLimitPolicy()
        self._clock = resolved_clock
        self._window_started_at = self._now()
        self._window_requests = 0
        self._active = 0
        self._admitted = 0
        self._rejected = 0
        self._sources: dict[UUID, _SourceAdmissionState] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def acquire(self, source: InboundEventSource) -> InboundAdmissionLease:
        if not isinstance(source, InboundEventSource):
            raise TypeError("inbound admission requires InboundEventSource")
        now = self._now()
        async with self._lock:
            if self._closed:
                raise InboundAdmissionLimiterClosedError("inbound admission limiter is closed")
            self._reset_global_window(now)
            state = self._sources.get(source.id)
            if state is None:
                state = _SourceAdmissionState(now)
                self._sources[source.id] = state
            self._reset_source_window(state, now)

            limited = (
                self._active >= self._policy.global_max_concurrency
                or state.active >= source.max_concurrency
                or self._window_requests >= self._policy.global_requests_per_minute
                or state.requests >= source.requests_per_minute
            )
            if limited:
                self._rejected += 1
                raise InboundAdmissionRejectedError

            self._active += 1
            state.active += 1
            self._window_requests += 1
            state.requests += 1
            self._admitted += 1
            return InboundAdmissionLease(self, source.id)

    async def snapshot(self) -> InboundAdmissionLimiterSnapshot:
        now = self._now()
        async with self._lock:
            self._reset_global_window(now)
            for state in self._sources.values():
                self._reset_source_window(state, now)
            return InboundAdmissionLimiterSnapshot(
                closed=self._closed,
                active=self._active,
                tracked_sources=len(self._sources),
                admitted=self._admitted,
                rejected=self._rejected,
                current_window_requests=self._window_requests,
                global_max_concurrency=self._policy.global_max_concurrency,
                global_requests_per_minute=(self._policy.global_requests_per_minute),
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _release(self, source_id: UUID) -> None:
        async with self._lock:
            state = self._sources.get(source_id)
            if state is None or state.active <= 0 or self._active <= 0:
                raise RuntimeError("inbound admission lease accounting is inconsistent")
            state.active -= 1
            self._active -= 1

    def _reset_global_window(self, now: datetime) -> None:
        if now - self._window_started_at >= timedelta(minutes=1):
            self._window_started_at = now
            self._window_requests = 0

    @staticmethod
    def _reset_source_window(
        state: _SourceAdmissionState,
        now: datetime,
    ) -> None:
        if now - state.window_started_at >= timedelta(minutes=1):
            state.window_started_at = now
            state.requests = 0

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("inbound admission clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inbound admission clock must return an aware datetime")
        return value.astimezone(UTC)


def _utc_now() -> datetime:
    return datetime.now(UTC)
