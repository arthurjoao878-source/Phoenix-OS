"""Content-free operational observations for secure browser automation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
MAX_BROWSER_OBSERVATION_DURATION_MS = 2_147_483_647


class BrowserAutomationObservedOperation(StrEnum):
    """Finite operation classes emitted by the browser lifecycle observer."""

    SESSION_OPEN = "session.open"
    SESSION_CLOSE = "session.close"
    PAGE_READ = "page.read"
    PAGE_NAVIGATE = "page.navigate"
    ELEMENT_FILL = "element.fill"
    ELEMENT_CLICK = "element.click"


class BrowserAutomationObservationOutcome(StrEnum):
    """Finite content-free observation outcomes."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    STALE = "stale"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class BrowserAutomationOperationObservation:
    """Bounded operation metadata with no page, target, content, or network detail."""

    operation_id: UUID
    operation: BrowserAutomationObservedOperation
    outcome: BrowserAutomationObservationOutcome
    effect_started: bool | None = None
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, UUID):
            raise TypeError("operation_id must be UUID")
        object.__setattr__(
            self,
            "operation",
            BrowserAutomationObservedOperation(self.operation),
        )
        object.__setattr__(
            self,
            "outcome",
            BrowserAutomationObservationOutcome(self.outcome),
        )
        if self.effect_started is not None and type(self.effect_started) is not bool:
            raise TypeError("effect_started must be a boolean or None")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
            or not 0 <= self.duration_ms <= MAX_BROWSER_OBSERVATION_DURATION_MS
        ):
            raise ValueError("duration_ms must be a bounded non-negative integer")
        if self.outcome is BrowserAutomationObservationOutcome.STARTED:
            if self.effect_started is not False or self.duration_ms is not None:
                raise ValueError(
                    "started observations require effect_started=False and no duration"
                )
        elif self.duration_ms is None:
            raise ValueError("terminal observations require duration_ms")
        if (
            self.outcome is BrowserAutomationObservationOutcome.SUCCEEDED
            and self.effect_started is None
        ):
            raise ValueError("successful observations require a known effect_started value")
        if (
            self.outcome is BrowserAutomationObservationOutcome.INDETERMINATE
            and self.effect_started is not True
        ):
            raise ValueError("indeterminate observations require effect_started=True")

    @property
    def name(self) -> str:
        return f"browser.{self.operation.value}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "operation_id": str(self.operation_id),
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }
        if self.effect_started is not None:
            values["effect_started"] = self.effect_started
        if self.duration_ms is not None:
            values["duration_ms"] = self.duration_ms
        return values


@dataclass(frozen=True, slots=True)
class BrowserAutomationObservabilityConfiguration:
    """Content-free audit, metrics, log, and Event Bus switches."""

    audit_enabled: bool = True
    metrics_enabled: bool = True
    logs_enabled: bool = True
    events_enabled: bool = True
    source: str = "phoenix.browser_automation"

    def __post_init__(self) -> None:
        switches = (
            self.audit_enabled,
            self.metrics_enabled,
            self.logs_enabled,
            self.events_enabled,
        )
        if any(type(value) is not bool for value in switches):
            raise TypeError("browser observability switches must be booleans")
        if not isinstance(self.source, str):
            raise TypeError("browser observability source must be a string")
        source = self.source.strip().lower()
        if _SOURCE_PATTERN.fullmatch(source) is None:
            raise ValueError("browser observability source must be a lowercase Phoenix identifier")
        object.__setattr__(self, "source", source)

    @property
    def any_enabled(self) -> bool:
        return any(
            (
                self.audit_enabled,
                self.metrics_enabled,
                self.logs_enabled,
                self.events_enabled,
            )
        )


@runtime_checkable
class BrowserAutomationObserver(Protocol):
    """Best-effort sink for content-free browser operation facts."""

    async def record(
        self,
        observation: BrowserAutomationOperationObservation,
        context: SecurityContext,
    ) -> None: ...


class NullBrowserAutomationObserver:
    """Default no-op observer preserving standalone composition."""

    async def record(
        self,
        observation: BrowserAutomationOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, BrowserAutomationOperationObservation):
            raise TypeError("observation must be BrowserAutomationOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")


class ContentFreeBrowserAutomationObserver:
    """Emit only bounded content-free browser operation telemetry."""

    def __init__(
        self,
        configuration: BrowserAutomationObservabilityConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(configuration, BrowserAutomationObservabilityConfiguration):
            raise TypeError("configuration must be BrowserAutomationObservabilityConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("observability must be ObservabilityHub")
        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability

    async def record(
        self,
        observation: BrowserAutomationOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, BrowserAutomationOperationObservation):
            raise TypeError("observation must be BrowserAutomationOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        correlation_id = context.correlation_id or str(observation.operation_id)
        options = self._configuration

        if options.events_enabled:
            try:
                await self._events.emit(
                    observation.name,
                    source=options.source,
                    payload={},
                    metadata=event_metadata,
                    correlation_id=correlation_id,
                    causation_id=observation.operation_id,
                )
            except Exception:
                pass

        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=AuditCategory.OTHER,
                    action=observation.operation.value,
                    resource="browser-automation",
                    context=context,
                    outcome=_audit_outcome(observation.outcome),
                    severity=_audit_severity(observation.outcome),
                    details=metadata,
                    source=options.source,
                )
            except Exception:
                pass

        if self._observability is not None:
            try:
                if options.logs_enabled:
                    await self._observability.log(
                        observation.name,
                        source=options.source,
                        message="browser automation operation changed state",
                        severity=_observation_severity(observation.outcome),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=observation.operation_id,
                    )
                if options.metrics_enabled:
                    metric_attributes: dict[str, object] = {
                        "operation": observation.operation.value,
                        "outcome": observation.outcome.value,
                    }
                    if observation.effect_started is not None:
                        metric_attributes["effect_started"] = observation.effect_started
                    await self._observability.metric(
                        "browser_automation.operations",
                        1,
                        source=options.source,
                        kind=MetricKind.COUNTER,
                        unit="operation",
                        attributes=metric_attributes,
                        correlation_id=correlation_id,
                        causation_id=observation.operation_id,
                    )
                    if observation.duration_ms is not None:
                        await self._observability.metric(
                            "browser_automation.operation.duration_ms",
                            observation.duration_ms,
                            source=options.source,
                            kind=MetricKind.GAUGE,
                            unit="millisecond",
                            attributes={
                                "operation": observation.operation.value,
                                "outcome": observation.outcome.value,
                            },
                            correlation_id=correlation_id,
                            causation_id=observation.operation_id,
                        )
            except Exception:
                pass


def _audit_outcome(outcome: BrowserAutomationObservationOutcome) -> AuditOutcome:
    if outcome is BrowserAutomationObservationOutcome.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if outcome is BrowserAutomationObservationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome in {
        BrowserAutomationObservationOutcome.STALE,
        BrowserAutomationObservationOutcome.CANCELLED,
    }:
        return AuditOutcome.RESTRICTED
    if outcome is BrowserAutomationObservationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: BrowserAutomationObservationOutcome) -> AuditSeverity:
    if outcome in {
        BrowserAutomationObservationOutcome.FAILED,
        BrowserAutomationObservationOutcome.TIMED_OUT,
        BrowserAutomationObservationOutcome.INDETERMINATE,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        BrowserAutomationObservationOutcome.REJECTED,
        BrowserAutomationObservationOutcome.STALE,
        BrowserAutomationObservationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: BrowserAutomationObservationOutcome) -> Severity:
    if outcome in {
        BrowserAutomationObservationOutcome.FAILED,
        BrowserAutomationObservationOutcome.TIMED_OUT,
        BrowserAutomationObservationOutcome.INDETERMINATE,
    }:
        return Severity.ERROR
    if outcome in {
        BrowserAutomationObservationOutcome.REJECTED,
        BrowserAutomationObservationOutcome.STALE,
        BrowserAutomationObservationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO
