"""Event Bus exceptions."""

from __future__ import annotations

from phoenix_os.events.contracts import DispatchReport


class EventBusError(RuntimeError):
    """Base class for Event Bus failures."""


class BusClosedError(EventBusError):
    """Raised when a closed bus receives a mutating operation."""


class EventDispatchError(EventBusError):
    """Raised after dispatch when ErrorPolicy.RAISE is requested."""

    def __init__(self, report: DispatchReport) -> None:
        self.report = report
        super().__init__(f"event {report.event.name!r} failed in {len(report.failures)} handler(s)")
