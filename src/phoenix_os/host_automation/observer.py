"""Content-free operational observations for secure host automation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.host_automation.authorization import (
    HOST_APPLICATION_CLOSE_ACTION,
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_FOCUS_ACTION,
    HOST_WINDOW_LIST_ACTION,
    host_clipboard_resource,
    host_process_collection_resource,
    host_resource,
    host_window_collection_resource,
)
from phoenix_os.host_automation.contracts import MAX_HOST_LIST_RESULTS, HostId
from phoenix_os.host_automation.errors import HostAutomationErrorCode
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class HostAutomationOperation(StrEnum):
    """Fixed Phoenix-owned host operations that may be observed."""

    PROCESS_LIST = HOST_PROCESS_LIST_ACTION
    WINDOW_LIST = HOST_WINDOW_LIST_ACTION
    APPLICATION_LAUNCH = HOST_APPLICATION_LAUNCH_ACTION
    WINDOW_FOCUS = HOST_WINDOW_FOCUS_ACTION
    APPLICATION_CLOSE = HOST_APPLICATION_CLOSE_ACTION
    CLIPBOARD_WRITE = HOST_CLIPBOARD_WRITE_ACTION
    CLIPBOARD_READ = HOST_CLIPBOARD_READ_ACTION


class HostAutomationOperationOutcome(StrEnum):
    """Safe fixed outcomes for one observed host operation."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    INDETERMINATE = "indeterminate"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class HostAutomationObservabilityConfiguration:
    """Content-free host audit, metrics, log, and Event Bus switches."""

    audit_enabled: bool = True
    metrics_enabled: bool = True
    logs_enabled: bool = True
    events_enabled: bool = True
    source: str = "phoenix.host_automation"

    def __post_init__(self) -> None:
        switches = (
            self.audit_enabled,
            self.metrics_enabled,
            self.logs_enabled,
            self.events_enabled,
        )
        if any(type(value) is not bool for value in switches):
            raise TypeError("host observability switches must be booleans")
        if not isinstance(self.source, str):
            raise TypeError("host observability source must be a string")
        source = self.source.strip().lower()
        if _SOURCE_PATTERN.fullmatch(source) is None:
            raise ValueError("host observability source must be a lowercase Phoenix identifier")
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
class HostAutomationOperationObservation:
    """Bounded metadata that cannot carry desktop or clipboard content."""

    operation: HostAutomationOperation
    outcome: HostAutomationOperationOutcome
    host_id: HostId
    request_id: UUID
    duration_ms: int | None = None
    result_count: int | None = None
    truncated: bool | None = None
    error_code: HostAutomationErrorCode | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", HostAutomationOperation(self.operation))
        object.__setattr__(self, "outcome", HostAutomationOperationOutcome(self.outcome))
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
            or self.duration_ms < 0
        ):
            raise ValueError("duration_ms must be a non-negative integer")
        if self.result_count is not None and (
            isinstance(self.result_count, bool)
            or not isinstance(self.result_count, int)
            or self.result_count < 0
            or self.result_count > MAX_HOST_LIST_RESULTS
        ):
            raise ValueError("result_count must be a bounded non-negative integer")
        if self.truncated is not None and type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")
        if self.error_code is not None:
            object.__setattr__(self, "error_code", HostAutomationErrorCode(self.error_code))

        list_operation = self.operation in {
            HostAutomationOperation.PROCESS_LIST,
            HostAutomationOperation.WINDOW_LIST,
        }
        if (self.result_count is not None or self.truncated is not None) and not list_operation:
            raise ValueError("result metadata is available only for bounded list operations")
        if self.truncated is not None and self.result_count is None:
            raise ValueError("truncated requires result_count")
        if (
            self.result_count is not None
            and self.outcome is not HostAutomationOperationOutcome.SUCCEEDED
        ):
            raise ValueError("result_count is available only for successful operations")
        if self.outcome is HostAutomationOperationOutcome.STARTED and any(
            value is not None
            for value in (
                self.duration_ms,
                self.result_count,
                self.truncated,
                self.error_code,
            )
        ):
            raise ValueError("started observations cannot contain terminal metadata")
        if self.outcome is HostAutomationOperationOutcome.SUCCEEDED and self.error_code is not None:
            raise ValueError("successful observations cannot contain an error code")

    @property
    def name(self) -> str:
        return f"{self.operation.value}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "host_id": str(self.host_id),
            "request_id": str(self.request_id),
            "action": self.operation.value,
            "outcome": self.outcome.value,
        }
        for key, value in (
            ("duration_ms", self.duration_ms),
            ("result_count", self.result_count),
            ("truncated", self.truncated),
            (
                "error_code",
                None if self.error_code is None else self.error_code.value,
            ),
        ):
            if value is not None:
                values[key] = value
        return values


@runtime_checkable
class HostAutomationObserver(Protocol):
    """Best-effort sink for typed content-free host operation facts."""

    async def record(
        self,
        observation: HostAutomationOperationObservation,
        context: SecurityContext,
    ) -> None: ...


class NullHostAutomationObserver:
    """Default no-op observer preserving existing service composition."""

    async def record(
        self,
        observation: HostAutomationOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, HostAutomationOperationObservation):
            raise TypeError("observation must be HostAutomationOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")


class ContentFreeHostAutomationObserver:
    """Emit empty-payload events and bounded content-free operational facts."""

    def __init__(
        self,
        host_id: HostId,
        configuration: HostAutomationObservabilityConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(configuration, HostAutomationObservabilityConfiguration):
            raise TypeError("configuration must be HostAutomationObservabilityConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("observability must be ObservabilityHub")
        self._host_id = host_id
        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability

    async def record(
        self,
        observation: HostAutomationOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, HostAutomationOperationObservation):
            raise TypeError("observation must be HostAutomationOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if observation.host_id != self._host_id:
            raise ValueError("observation host_id does not match configured host")

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
                    category=_audit_category(observation),
                    action=observation.operation.value,
                    resource=_audit_resource(observation),
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
                        message="host automation operation changed state",
                        severity=_observation_severity(observation.outcome),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=observation.request_id,
                    )
                if options.metrics_enabled:
                    metric_attributes: dict[str, object] = {
                        "action": observation.operation.value,
                        "outcome": observation.outcome.value,
                    }
                    if observation.error_code is not None:
                        metric_attributes["error_code"] = observation.error_code.value
                    await self._observability.metric(
                        "host_automation.operations",
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
                            "host_automation.operation.duration_ms",
                            observation.duration_ms,
                            source=options.source,
                            kind=MetricKind.GAUGE,
                            unit="millisecond",
                            attributes={"action": observation.operation.value},
                            correlation_id=correlation_id,
                            causation_id=observation.request_id,
                        )
            except Exception:
                pass


def _audit_category(observation: HostAutomationOperationObservation) -> AuditCategory:
    if observation.error_code is HostAutomationErrorCode.AUTHORIZATION_REJECTED:
        return AuditCategory.AUTHORIZATION
    return AuditCategory.OTHER


def _audit_resource(observation: HostAutomationOperationObservation) -> str:
    if observation.operation is HostAutomationOperation.PROCESS_LIST:
        return host_process_collection_resource(observation.host_id)
    if observation.operation is HostAutomationOperation.WINDOW_LIST:
        return host_window_collection_resource(observation.host_id)
    if observation.operation in {
        HostAutomationOperation.CLIPBOARD_READ,
        HostAutomationOperation.CLIPBOARD_WRITE,
    }:
        return host_clipboard_resource(observation.host_id)
    return host_resource(observation.host_id)


def _audit_outcome(outcome: HostAutomationOperationOutcome) -> AuditOutcome:
    if outcome is HostAutomationOperationOutcome.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if outcome is HostAutomationOperationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is HostAutomationOperationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is HostAutomationOperationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: HostAutomationOperationOutcome) -> AuditSeverity:
    if outcome in {
        HostAutomationOperationOutcome.FAILED,
        HostAutomationOperationOutcome.TIMED_OUT,
        HostAutomationOperationOutcome.INDETERMINATE,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        HostAutomationOperationOutcome.REJECTED,
        HostAutomationOperationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: HostAutomationOperationOutcome) -> Severity:
    if outcome in {
        HostAutomationOperationOutcome.FAILED,
        HostAutomationOperationOutcome.TIMED_OUT,
        HostAutomationOperationOutcome.INDETERMINATE,
    }:
        return Severity.ERROR
    if outcome in {
        HostAutomationOperationOutcome.REJECTED,
        HostAutomationOperationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO
