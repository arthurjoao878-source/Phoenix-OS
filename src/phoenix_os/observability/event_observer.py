"""Event Bus to observability lifecycle adapter."""

from __future__ import annotations

from collections.abc import Callable

from phoenix_os.events import BusClosedError, Event, EventBus, Subscription
from phoenix_os.observability.contracts import Severity
from phoenix_os.observability.hub import ObservabilityHub
from phoenix_os.runtime import RuntimeContext

type EventSeverityMapper = Callable[[Event], Severity]


def default_event_severity(event: Event) -> Severity:
    """Map lifecycle event names to conservative structured severities."""

    segments = set(event.name.lower().replace("-", ".").split("."))
    if segments.intersection({"failed", "failure", "error", "critical"}):
        return Severity.ERROR
    if segments.intersection({"cancelled", "denied", "rejected", "required", "warning"}):
        return Severity.WARNING
    return Severity.INFO


class EventObserver:
    """Observe every Event Bus event without changing Event Bus semantics."""

    def __init__(
        self,
        *,
        events: EventBus,
        observability: ObservabilityHub,
        severity_mapper: EventSeverityMapper = default_event_severity,
        source: str = "phoenix.observability.events",
        priority: int = -100,
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        if not callable(severity_mapper):
            raise TypeError("severity_mapper must be callable")
        self._events = events
        self._observability = observability
        self._severity_mapper = severity_mapper
        self._source = normalized_source
        self._priority = priority
        self._subscription: Subscription | None = None

    @property
    def active(self) -> bool:
        return self._subscription is not None

    async def start(self, context: RuntimeContext) -> None:
        del context
        if self._subscription is not None:
            return
        self._subscription = await self._events.subscribe(
            "*",
            self._observe,
            priority=self._priority,
        )

    async def stop(self, context: RuntimeContext) -> None:
        del context
        subscription = self._subscription
        self._subscription = None
        if subscription is None or self._events.closed:
            return
        try:
            await self._events.unsubscribe(subscription)
        except BusClosedError:
            return

    async def _observe(self, event: Event) -> None:
        attributes: dict[str, object] = {
            "event.id": str(event.id),
            "event.name": event.name,
            "event.source": event.source,
            "event.payload": event.payload,
            "event.metadata": event.metadata,
        }
        if event.causation_id is not None:
            attributes["event.causation_id"] = str(event.causation_id)
        await self._observability.log(
            event.name,
            source=self._source,
            message=event.name,
            severity=self._severity_mapper(event),
            attributes=attributes,
            correlation_id=event.correlation_id,
            causation_id=event.id,
        )
