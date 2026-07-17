"""Reference observability sinks."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from phoenix_os.observability.contracts import MemorySinkSnapshot, Observation
from phoenix_os.observability.errors import ObservationSinkClosedError


class InMemorySink:
    """Deterministic bounded sink intended for tests and local diagnostics."""

    def __init__(
        self,
        records: Iterable[Observation] = (),
        *,
        capacity: int | None = None,
    ) -> None:
        if capacity is not None and capacity <= 0:
            raise ValueError("capacity must be greater than zero")
        initial = list(records)
        dropped = 0
        if capacity is not None and len(initial) > capacity:
            dropped = len(initial) - capacity
            initial = initial[-capacity:]
        self._records = initial
        self._capacity = capacity
        self._dropped = dropped
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def emit(self, observation: Observation) -> None:
        async with self._lock:
            if self._closed:
                raise ObservationSinkClosedError("in-memory sink is closed")
            self._records.append(observation)
            if self._capacity is not None and len(self._records) > self._capacity:
                overflow = len(self._records) - self._capacity
                del self._records[:overflow]
                self._dropped += overflow

    async def snapshot(self) -> MemorySinkSnapshot:
        async with self._lock:
            return MemorySinkSnapshot(
                records=tuple(self._records),
                dropped=self._dropped,
                closed=self._closed,
            )

    async def clear(self) -> None:
        async with self._lock:
            if self._closed:
                raise ObservationSinkClosedError("in-memory sink is closed")
            self._records.clear()
            self._dropped = 0

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
