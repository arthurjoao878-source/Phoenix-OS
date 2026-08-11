"""Content-free operational observations for secure agent coordination."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.coordination_authorization import agent_delegation_resource
from phoenix_os.agent.coordination_contracts import CoordinationNamespace, DelegationId
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SAFE_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class CoordinationOperation(StrEnum):
    AUTHORIZATION = "authorization"
    ADMISSION = "admission"
    CHILD_RUN = "child_run"
    CHILD_RESULT = "child_result"
    CANCELLATION = "cancellation"
    SHUTDOWN = "shutdown"


class CoordinationOperationOutcome(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class CoordinationObservation:
    """Typed content-free coordination fact suitable for operational surfaces."""

    operation: CoordinationOperation
    outcome: CoordinationOperationOutcome
    namespace: CoordinationNamespace
    delegation_id: DelegationId
    parent_agent_id: AgentId
    parent_run_id: AgentRunId
    child_agent_id: AgentId
    child_run_id: AgentRunId | None = None
    duration_ms: int | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation, CoordinationOperation):
            raise TypeError("operation must be CoordinationOperation")
        if not isinstance(self.outcome, CoordinationOperationOutcome):
            raise TypeError("outcome must be CoordinationOperationOutcome")
        if not isinstance(self.namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        for label, agent_id in (
            ("parent_agent_id", self.parent_agent_id),
            ("child_agent_id", self.child_agent_id),
        ):
            if not isinstance(agent_id, AgentId):
                raise TypeError(f"{label} must be AgentId")
        if not isinstance(self.parent_run_id, AgentRunId):
            raise TypeError("parent_run_id must be AgentRunId")
        if self.child_run_id is not None and not isinstance(self.child_run_id, AgentRunId):
            raise TypeError("child_run_id must be AgentRunId or None")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
            or self.duration_ms < 0
        ):
            raise ValueError("duration_ms must be a non-negative integer")
        if self.error_code is not None:
            normalized = self.error_code.strip().lower()
            if _SAFE_CODE_PATTERN.fullmatch(normalized) is None:
                raise ValueError("error_code must be a safe bounded identifier")
            object.__setattr__(self, "error_code", normalized)

    @property
    def name(self) -> str:
        return f"agent.coordination.{self.operation.value}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "namespace": str(self.namespace),
            "delegation_id": str(self.delegation_id),
            "parent_agent_id": str(self.parent_agent_id),
            "parent_run_id": str(self.parent_run_id),
            "child_agent_id": str(self.child_agent_id),
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }
        if self.child_run_id is not None:
            values["child_run_id"] = str(self.child_run_id)
        if self.duration_ms is not None:
            values["duration_ms"] = self.duration_ms
        if self.error_code is not None:
            values["error_code"] = self.error_code
        return values


@runtime_checkable
class AgentCoordinationObserver(Protocol):
    async def record(
        self,
        observation: CoordinationObservation,
        context: SecurityContext,
    ) -> None: ...


class NullAgentCoordinationObserver:
    async def record(
        self,
        observation: CoordinationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, CoordinationObservation):
            raise TypeError("observation must be CoordinationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")


class ContentFreeAgentCoordinationObserver:
    """Best-effort events/audit/log/metric sink with metadata only."""

    def __init__(
        self,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
        source: str = "phoenix.agent.coordination",
    ) -> None:
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("observability must be ObservabilityHub")
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        self._events = events
        self._audit = audit
        self._observability = observability
        self._source = normalized_source

    async def record(
        self,
        observation: CoordinationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, CoordinationObservation):
            raise TypeError("observation must be CoordinationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        resource = agent_delegation_resource(
            namespace=observation.namespace,
            parent_agent_id=observation.parent_agent_id,
            child_agent_id=observation.child_agent_id,
        )

        try:
            await self._events.emit(
                observation.name,
                source=self._source,
                payload={},
                metadata=event_metadata,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )
        except Exception:
            pass

        if self._audit is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=AuditCategory.OTHER,
                    action=f"agent.coordination.{observation.operation.value}",
                    resource=resource,
                    context=context,
                    outcome=_audit_outcome(observation.outcome),
                    severity=_audit_severity(observation.outcome),
                    details=metadata,
                    source=self._source,
                )
            except Exception:
                pass

        if self._observability is not None:
            try:
                await self._observability.log(
                    observation.name,
                    source=self._source,
                    message="agent coordination operation changed state",
                    severity=_severity(observation.outcome),
                    attributes=metadata,
                    correlation_id=context.correlation_id,
                    causation_id=context.causation_id,
                )
                await self._observability.metric(
                    "agent.coordination.operations",
                    1,
                    source=self._source,
                    kind=MetricKind.COUNTER,
                    unit="operation",
                    attributes={
                        "operation": observation.operation.value,
                        "outcome": observation.outcome.value,
                    },
                    correlation_id=context.correlation_id,
                    causation_id=context.causation_id,
                )
            except Exception:
                pass


def _audit_outcome(outcome: CoordinationOperationOutcome) -> AuditOutcome:
    if outcome is CoordinationOperationOutcome.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if outcome is CoordinationOperationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is CoordinationOperationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is CoordinationOperationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: CoordinationOperationOutcome) -> AuditSeverity:
    if outcome in {
        CoordinationOperationOutcome.FAILED,
        CoordinationOperationOutcome.TIMED_OUT,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        CoordinationOperationOutcome.REJECTED,
        CoordinationOperationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _severity(outcome: CoordinationOperationOutcome) -> Severity:
    if outcome in {
        CoordinationOperationOutcome.FAILED,
        CoordinationOperationOutcome.TIMED_OUT,
    }:
        return Severity.ERROR
    if outcome in {
        CoordinationOperationOutcome.REJECTED,
        CoordinationOperationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO
