"""Phoenix observability exceptions."""

from __future__ import annotations

from phoenix_os.observability.contracts import ExportReport


class PhoenixObservabilityError(RuntimeError):
    """Base class for observability failures."""


class ObservabilityClosedError(PhoenixObservabilityError):
    """Raised when a closed observability hub receives new work."""


class ObservationSinkClosedError(PhoenixObservabilityError):
    """Raised when a closed sink receives a new observation."""


class ObservationExportError(PhoenixObservabilityError):
    """Aggregate error raised after all matching sinks were attempted."""

    def __init__(self, report: ExportReport) -> None:
        self.report = report
        super().__init__(f"{len(report.failures)} observability sink(s) failed")


class SpanStateError(PhoenixObservabilityError):
    """Raised when a span is entered, exited, or inspected in an invalid state."""
