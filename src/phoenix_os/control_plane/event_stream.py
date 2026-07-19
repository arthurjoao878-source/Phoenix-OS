"""Bounded Event Bus feed for authenticated Phoenix dashboard clients."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from enum import StrEnum

from phoenix_os.control_plane.contracts import (
    DEFAULT_EVENT_STREAM_REQUEST,
    EventBatch,
    EventStreamRequest,
    EventView,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneEventStreamBackpressureError,
    ControlPlaneEventStreamStateError,
)
from phoenix_os.events import BusClosedError, Event, EventBus, Subscription


class ControlPlaneEventStreamState(StrEnum):
    """One-shot lifecycle states for the Event Bus dashboard feed."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneEventStreamConfig:
    """Hard memory and waiter limits for the dashboard event feed."""

    retention: int = 1024
    max_waiters: int = 32
    max_wait: float = 4.0

    def __post_init__(self) -> None:
        if self.retention <= 0 or self.retention > 100_000:
            raise ValueError("event retention must be between 1 and 100000")
        if self.max_waiters <= 0 or self.max_waiters > 10_000:
            raise ValueError("event max_waiters must be between 1 and 10000")
        if self.max_wait <= 0 or self.max_wait > 60:
            raise ValueError("event max_wait must be between 0 and 60 seconds")


@dataclass(frozen=True, slots=True)
class ControlPlaneEventStreamSnapshot:
    """Non-sensitive diagnostics for retained events and long-poll pressure."""

    state: ControlPlaneEventStreamState
    retention: int
    retained: int
    published: int
    evicted: int
    waiters: int
    rejected_waiters: int
    oldest_cursor: int | None
    latest_cursor: int | None

    def __post_init__(self) -> None:
        counters = (
            self.retention,
            self.retained,
            self.published,
            self.evicted,
            self.waiters,
            self.rejected_waiters,
        )
        if self.retention <= 0 or any(value < 0 for value in counters[1:]):
            raise ValueError("event stream counters cannot be negative")
        if self.retained > self.retention or self.evicted > self.published:
            raise ValueError("event stream counters are inconsistent")
        if self.retained == 0:
            if self.oldest_cursor is not None or self.latest_cursor is not None:
                raise ValueError("empty event stream cannot expose cursors")
        elif (
            self.oldest_cursor is None
            or self.latest_cursor is None
            or self.oldest_cursor <= 0
            or self.latest_cursor < self.oldest_cursor
        ):
            raise ValueError("retained event stream requires valid cursors")
        object.__setattr__(self, "state", ControlPlaneEventStreamState(self.state))


class ControlPlaneEventStream:
    """Retain safe event headers and serve bounded cursor-based long polls.

    Event payloads and metadata are deliberately discarded. Slow consumers do not
    receive private per-client queues: the shared ring buffer stays bounded and a
    cursor gap tells a client exactly when older event headers were evicted.
    """

    def __init__(
        self,
        events: EventBus,
        *,
        config: ControlPlaneEventStreamConfig | None = None,
        priority: int = -200,
    ) -> None:
        self._events = events
        self._config = config or ControlPlaneEventStreamConfig()
        self._priority = priority
        self._state = ControlPlaneEventStreamState.CREATED
        self._subscription: Subscription | None = None
        self._retained: deque[EventView] = deque(maxlen=self._config.retention)
        self._sequence = 0
        self._published = 0
        self._evicted = 0
        self._waiters = 0
        self._rejected_waiters = 0
        self._condition = asyncio.Condition()
        self._state_lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneEventStreamState:
        return self._state

    async def start(self, context: object = None) -> None:
        """Subscribe to the wildcard Event Bus feed exactly once."""

        del context
        async with self._state_lock:
            if self._state is not ControlPlaneEventStreamState.CREATED:
                raise ControlPlaneEventStreamStateError(
                    f"cannot start event stream from state {self._state.value}"
                )
            subscription = await self._events.subscribe(
                "*",
                self._observe,
                priority=self._priority,
            )
            self._subscription = subscription
            self._state = ControlPlaneEventStreamState.RUNNING

    async def stop(self, context: object = None) -> None:
        """Unsubscribe and wake bounded long-poll waiters."""

        del context
        async with self._state_lock:
            if self._state is ControlPlaneEventStreamState.STOPPED:
                return
            if self._state is ControlPlaneEventStreamState.CREATED:
                self._state = ControlPlaneEventStreamState.STOPPED
                return
            if self._state is not ControlPlaneEventStreamState.RUNNING:
                raise ControlPlaneEventStreamStateError(
                    f"cannot stop event stream from state {self._state.value}"
                )
            self._state = ControlPlaneEventStreamState.STOPPING
            subscription = self._subscription
            self._subscription = None

        if subscription is not None and not self._events.closed:
            try:
                await self._events.unsubscribe(subscription)
            except BusClosedError:
                pass

        async with self._condition:
            self._state = ControlPlaneEventStreamState.STOPPED
            self._condition.notify_all()

    async def read(
        self,
        request: EventStreamRequest = DEFAULT_EVENT_STREAM_REQUEST,
    ) -> EventBatch:
        """Return retained event headers after a cursor, optionally waiting briefly."""

        if request.wait > self._config.max_wait:
            raise ValueError("event wait exceeds configured maximum")

        async with self._condition:
            self._ensure_running()
            timed_out = False
            if not self._has_events_after(request.after) and request.wait > 0:
                if self._waiters >= self._config.max_waiters:
                    self._rejected_waiters += 1
                    raise ControlPlaneEventStreamBackpressureError(
                        "event stream waiter capacity exceeded"
                    )
                self._waiters += 1
                try:
                    try:
                        async with asyncio.timeout(request.wait):
                            await self._condition.wait_for(
                                lambda: (
                                    self._state is not ControlPlaneEventStreamState.RUNNING
                                    or self._has_events_after(request.after)
                                )
                            )
                    except TimeoutError:
                        timed_out = True
                finally:
                    self._waiters -= 1
                self._ensure_running()
            return self._batch(request, timed_out=timed_out)

    async def snapshot(self) -> ControlPlaneEventStreamSnapshot:
        """Return bounded feed diagnostics without event names or client cursors."""

        async with self._condition:
            oldest = self._retained[0].sequence if self._retained else None
            latest = self._retained[-1].sequence if self._retained else None
            return ControlPlaneEventStreamSnapshot(
                state=self._state,
                retention=self._config.retention,
                retained=len(self._retained),
                published=self._published,
                evicted=self._evicted,
                waiters=self._waiters,
                rejected_waiters=self._rejected_waiters,
                oldest_cursor=oldest,
                latest_cursor=latest,
            )

    async def _observe(self, event: Event) -> None:
        async with self._condition:
            if self._state is not ControlPlaneEventStreamState.RUNNING:
                return
            self._sequence += 1
            if len(self._retained) == self._config.retention:
                self._evicted += 1
            self._retained.append(EventView.from_event(self._sequence, event))
            self._published += 1
            self._condition.notify_all()

    def _batch(self, request: EventStreamRequest, *, timed_out: bool) -> EventBatch:
        oldest = self._retained[0].sequence if self._retained else None
        latest = self._retained[-1].sequence if self._retained else None
        dropped = 0
        if oldest is not None and request.after < oldest - 1:
            dropped = oldest - request.after - 1
        items = tuple(item for item in self._retained if item.sequence > request.after)[
            : request.limit
        ]
        cursor = items[-1].sequence if items else request.after
        return EventBatch(
            items=items,
            cursor=cursor,
            oldest_cursor=oldest,
            latest_cursor=latest,
            gap=dropped > 0,
            dropped=dropped,
            timed_out=timed_out and not items,
        )

    def _has_events_after(self, cursor: int) -> bool:
        return bool(self._retained and self._retained[-1].sequence > cursor)

    def _ensure_running(self) -> None:
        if self._state is not ControlPlaneEventStreamState.RUNNING:
            raise ControlPlaneEventStreamStateError(
                f"cannot read event stream from state {self._state.value}"
            )
