"""Phoenix Event Bus public API."""

from phoenix_os.events.bus import WILDCARD, EventBus
from phoenix_os.events.contracts import (
    DispatchFailure,
    DispatchReport,
    ErrorPolicy,
    Event,
    EventHandler,
    EventMetadata,
    EventPayload,
    Subscription,
)
from phoenix_os.events.errors import BusClosedError, EventBusError, EventDispatchError

__all__ = [
    "WILDCARD",
    "BusClosedError",
    "DispatchFailure",
    "DispatchReport",
    "ErrorPolicy",
    "Event",
    "EventBus",
    "EventBusError",
    "EventDispatchError",
    "EventHandler",
    "EventMetadata",
    "EventPayload",
    "Subscription",
]
