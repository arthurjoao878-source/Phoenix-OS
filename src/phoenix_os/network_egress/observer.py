"""Content-free operational observations for controlled network egress."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.network_egress.authorization import NETWORK_HTTP_REQUEST_ACTION
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
MAX_NETWORK_OBSERVATION_DURATION_MS = 2_147_483_647


class NetworkEgressOperationOutcome(StrEnum):
    """Fixed content-free outcomes for one observed network request."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class NetworkEgressObservabilityConfiguration:
    """Content-free network audit, metrics, log, and Event Bus switches."""

    audit_enabled: bool = True
    metrics_enabled: bool = True
    logs_enabled: bool = True
    events_enabled: bool = True
    source: str = "phoenix.network_egress"

    def __post_init__(self) -> None:
        switches = (
            self.audit_enabled,
            self.metrics_enabled,
            self.logs_enabled,
            self.events_enabled,
        )
        if any(type(value) is not bool for value in switches):
            raise TypeError("network observability switches must be booleans")
        if not isinstance(self.source, str):
            raise TypeError("network observability source must be a string")
        source = self.source.strip().lower()
        if _SOURCE_PATTERN.fullmatch(source) is None:
            raise ValueError("network observability source must be a lowercase Phoenix identifier")
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


@dataclass(frozen=True, slots=True)
class NetworkEgressOperationObservation:
    """Bounded metadata that cannot carry destination, body, header, or credential data."""

    request_id: UUID
    outcome: NetworkEgressOperationOutcome
    request_started: bool | None = None
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        object.__setattr__(self, "outcome", NetworkEgressOperationOutcome(self.outcome))
        if self.request_started is not None and type(self.request_started) is not bool:
            raise TypeError("request_started must be a boolean or None")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
            or not 0 <= self.duration_ms <= MAX_NETWORK_OBSERVATION_DURATION_MS
        ):
            raise ValueError("duration_ms must be a bounded non-negative integer")
        if self.outcome is NetworkEgressOperationOutcome.STARTED:
            if self.request_started is not False or self.duration_ms is not None:
                raise ValueError(
                    "started observations require request_started=False and no duration"
                )
        elif self.duration_ms is None:
            raise ValueError("terminal observations require duration_ms")
        if (
            self.outcome is NetworkEgressOperationOutcome.SUCCEEDED
            and self.request_started is not True
        ):
            raise ValueError("successful observations require request_started=True")

    @property
    def name(self) -> str:
        return f"{NETWORK_HTTP_REQUEST_ACTION}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "request_id": str(self.request_id),
            "action": NETWORK_HTTP_REQUEST_ACTION,
            "outcome": self.outcome.value,
        }
        if self.request_started is not None:
            values["request_started"] = self.request_started
        if self.duration_ms is not None:
            values["duration_ms"] = self.duration_ms
        return values


@runtime_checkable
class NetworkEgressObserver(Protocol):
    """Best-effort sink for typed content-free network request facts."""

    async def record(
        self,
        observation: NetworkEgressOperationObservation,
        context: SecurityContext,
    ) -> None: ...


class NullNetworkEgressObserver:
    """Default no-op observer preserving standalone composition."""

    async def record(
        self,
        observation: NetworkEgressOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, NetworkEgressOperationObservation):
            raise TypeError("observation must be NetworkEgressOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")


class ContentFreeNetworkEgressObserver:
    """Emit empty-payload events and bounded content-free network facts."""

    def __init__(
        self,
        configuration: NetworkEgressObservabilityConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(configuration, NetworkEgressObservabilityConfiguration):
            raise TypeError("configuration must be NetworkEgressObservabilityConfiguration")
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
        observation: NetworkEgressOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, NetworkEgressOperationObservation):
            raise TypeError("observation must be NetworkEgressOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        correlation_id = context.correlation_id or str(observation.request_id)
        options = self._configuration

        if options.events_enabled:
            try:
                await self._events.emit(
                    observation.name,
                    source=options.source,
                    payload={},
                    metadata=event_metadata,
                    correlation_id=correlation_id,
                    causation_id=observation.request_id,
                )
            except Exception:
                pass

        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=AuditCategory.OTHER,
                    action=NETWORK_HTTP_REQUEST_ACTION,
                    resource="network-egress",
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
                        message="network egress request changed state",
                        severity=_observation_severity(observation.outcome),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=observation.request_id,
                    )
                if options.metrics_enabled:
                    metric_attributes: dict[str, object] = {
                        "action": NETWORK_HTTP_REQUEST_ACTION,
                        "outcome": observation.outcome.value,
                    }
                    if observation.request_started is not None:
                        metric_attributes["request_started"] = observation.request_started
                    await self._observability.metric(
                        "network_egress.operations",
                        1,
                        source=options.source,
                        kind=MetricKind.COUNTER,
                        unit="operation",
                        attributes=metric_attributes,
                        correlation_id=correlation_id,
                        causation_id=observation.request_id,
                    )
                    if observation.duration_ms is not None:
                        await self._observability.metric(
                            "network_egress.operation.duration_ms",
                            observation.duration_ms,
                            source=options.source,
                            kind=MetricKind.GAUGE,
                            unit="millisecond",
                            attributes={"outcome": observation.outcome.value},
                            correlation_id=correlation_id,
                            causation_id=observation.request_id,
                        )
            except Exception:
                pass


def _audit_outcome(outcome: NetworkEgressOperationOutcome) -> AuditOutcome:
    if outcome is NetworkEgressOperationOutcome.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if outcome is NetworkEgressOperationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is NetworkEgressOperationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is NetworkEgressOperationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: NetworkEgressOperationOutcome) -> AuditSeverity:
    if outcome in {
        NetworkEgressOperationOutcome.FAILED,
        NetworkEgressOperationOutcome.TIMED_OUT,
        NetworkEgressOperationOutcome.INDETERMINATE,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        NetworkEgressOperationOutcome.REJECTED,
        NetworkEgressOperationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: NetworkEgressOperationOutcome) -> Severity:
    if outcome in {
        NetworkEgressOperationOutcome.FAILED,
        NetworkEgressOperationOutcome.TIMED_OUT,
        NetworkEgressOperationOutcome.INDETERMINATE,
    }:
        return Severity.ERROR
    if outcome in {
        NetworkEgressOperationOutcome.REJECTED,
        NetworkEgressOperationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO
