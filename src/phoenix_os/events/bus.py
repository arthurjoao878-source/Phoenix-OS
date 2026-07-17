"""Deterministic, asynchronous, in-process event delivery."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID, uuid4

from phoenix_os.events.contracts import (
    DispatchFailure,
    DispatchReport,
    ErrorPolicy,
    Event,
    EventHandler,
    Subscription,
)
from phoenix_os.events.errors import BusClosedError, EventDispatchError

WILDCARD = "*"


@dataclass(slots=True)
class _RegisteredHandler:
    subscription: Subscription
    handler: EventHandler
    priority: int
    once: bool
    sequence: int


class EventBus:
    """Deliver events serially in priority and registration order.

    The bus is deliberately small: no persistence, retries, broker protocol,
    background workers, or schema registry are hidden inside it.
    """

    def __init__(self) -> None:
        self._handlers: dict[UUID, _RegisteredHandler] = {}
        self._sequence = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def subscribe(
        self,
        event_name: str,
        handler: EventHandler,
        *,
        priority: int = 0,
        once: bool = False,
    ) -> Subscription:
        self._ensure_open()
        normalized = event_name.strip()
        if not normalized:
            raise ValueError("event_name must not be blank")
        if not callable(handler):
            raise TypeError("handler must be callable")

        async with self._lock:
            self._ensure_open()
            subscription = Subscription(id=uuid4(), event_name=normalized)
            registered = _RegisteredHandler(
                subscription=subscription,
                handler=handler,
                priority=priority,
                once=once,
                sequence=self._sequence,
            )
            self._sequence += 1
            self._handlers[subscription.id] = registered
            return subscription

    async def unsubscribe(self, subscription: Subscription) -> bool:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            return self._handlers.pop(subscription.id, None) is not None

    async def publish(
        self,
        event: Event,
        *,
        error_policy: ErrorPolicy = ErrorPolicy.COLLECT,
    ) -> DispatchReport:
        self._ensure_open()
        handlers = await self._snapshot(event.name)
        failures: list[DispatchFailure] = []
        delivered = 0

        for registered in handlers:
            if registered.once:
                await self._remove_if_present(registered.subscription.id)

            try:
                result = registered.handler(event)
                if inspect.isawaitable(result):
                    await result
                delivered += 1
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                failures.append(
                    DispatchFailure(
                        subscription=registered.subscription,
                        exception=exception,
                    )
                )

        report = DispatchReport(
            event=event,
            matched=len(handlers),
            delivered=delivered,
            failures=tuple(failures),
        )
        if failures and error_policy is ErrorPolicy.RAISE:
            raise EventDispatchError(report)
        return report

    async def emit(
        self,
        name: str,
        *,
        source: str,
        payload: Mapping[str, object] | None = None,
        metadata: Mapping[str, str] | None = None,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
        error_policy: ErrorPolicy = ErrorPolicy.COLLECT,
    ) -> DispatchReport:
        event = Event(
            name=name,
            source=source,
            payload={} if payload is None else payload,
            metadata={} if metadata is None else metadata,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )
        return await self.publish(event, error_policy=error_policy)

    async def close(self) -> None:
        async with self._lock:
            self._handlers.clear()
            self._closed = True

    async def _snapshot(self, event_name: str) -> tuple[_RegisteredHandler, ...]:
        async with self._lock:
            matching = [
                item
                for item in self._handlers.values()
                if item.subscription.event_name in {event_name, WILDCARD}
            ]
        matching.sort(key=lambda item: (-item.priority, item.sequence))
        return tuple(matching)

    async def _remove_if_present(self, subscription_id: UUID) -> None:
        async with self._lock:
            self._handlers.pop(subscription_id, None)

    def _ensure_open(self) -> None:
        if self._closed:
            raise BusClosedError("event bus is closed")
