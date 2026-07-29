"""Content-free operational observations for the bounded agent loop."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.authorization import agent_run_resource
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolApprovalId,
    ToolCallId,
    ToolEffect,
    ToolId,
)
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SAFE_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_CATEGORY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class AgentOperation(StrEnum):
    """Fixed Phoenix-owned agent operations that may be observed."""

    RUN_AUTHORIZATION = "authorization.run"
    RUN_ADMISSION = "admission.run"
    MODEL_AUTHORIZATION = "authorization.model"
    MODEL_TURN = "model.turn"
    PROPOSAL_VALIDATION = "proposal.validation"
    TOOL_AUTHORIZATION = "authorization.tool"
    APPROVAL = "approval"
    TOOL_INVOCATION = "tool.invocation"


class AgentOperationOutcome(StrEnum):
    """Safe terminal or progress categories for one observed operation."""

    STARTED = "started"
    REQUESTED = "requested"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    APPROVED = "approved"
    CONSUMED = "consumed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    INDETERMINATE = "indeterminate"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AgentOperationObservation:
    """Typed content-free metadata for one internal agent operation."""

    operation: AgentOperation
    outcome: AgentOperationOutcome
    agent_id: AgentId
    run_id: AgentRunId
    step_id: AgentStepId | None = None
    call_id: ToolCallId | None = None
    tool_id: ToolId | None = None
    approval_id: ToolApprovalId | None = None
    effect: ToolEffect | None = None
    argument_digest: str | None = None
    resource_category: str | None = None
    duration_ms: int | None = None
    model_turn: int | None = None
    tool_call: int | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", AgentOperation(self.operation))
        object.__setattr__(self, "outcome", AgentOperationOutcome(self.outcome))
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if self.step_id is not None and not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if self.call_id is not None and not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if self.tool_id is not None and not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if self.approval_id is not None and not isinstance(
            self.approval_id,
            ToolApprovalId,
        ):
            raise TypeError("approval_id must be ToolApprovalId")
        if self.effect is not None and not isinstance(self.effect, ToolEffect):
            raise TypeError("effect must be ToolEffect")
        for label, value in (
            ("duration_ms", self.duration_ms),
            ("model_turn", self.model_turn),
            ("tool_call", self.tool_call),
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{label} must be a non-negative integer")
        if self.argument_digest is not None:
            normalized_digest = self.argument_digest.strip().lower()
            if _DIGEST_PATTERN.fullmatch(normalized_digest) is None:
                raise ValueError("argument_digest must be a canonical SHA-256 digest")
            object.__setattr__(self, "argument_digest", normalized_digest)
        if self.resource_category is not None:
            normalized_category = self.resource_category.strip().lower()
            if _RESOURCE_CATEGORY_PATTERN.fullmatch(normalized_category) is None:
                raise ValueError("resource_category must be a safe bounded identifier")
            object.__setattr__(self, "resource_category", normalized_category)
        if self.error_code is not None:
            normalized_code = self.error_code.strip().lower()
            if _SAFE_CODE_PATTERN.fullmatch(normalized_code) is None:
                raise ValueError("error_code must be a safe bounded identifier")
            object.__setattr__(self, "error_code", normalized_code)
        if (
            any(
                value is not None
                for value in (
                    self.call_id,
                    self.tool_id,
                    self.approval_id,
                    self.effect,
                    self.argument_digest,
                    self.resource_category,
                    self.tool_call,
                )
            )
            and self.step_id is None
        ):
            raise ValueError("tool operation metadata requires step_id")
        if self.approval_id is not None and self.call_id is None:
            raise ValueError("approval_id requires call_id")
        if self.effect is not None and self.tool_id is None:
            raise ValueError("effect requires tool_id")

    @property
    def name(self) -> str:
        return f"agent.{self.operation.value}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "agent_id": str(self.agent_id),
            "run_id": str(self.run_id),
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }
        for key, value in (
            ("step_id", self.step_id),
            ("call_id", self.call_id),
            ("tool_id", self.tool_id),
            ("approval_id", self.approval_id),
            ("effect", None if self.effect is None else self.effect.value),
            ("argument_digest", self.argument_digest),
            ("resource_category", self.resource_category),
            ("duration_ms", self.duration_ms),
            ("model_turn", self.model_turn),
            ("tool_call", self.tool_call),
            ("error_code", self.error_code),
        ):
            if value is not None:
                values[key] = str(value) if key.endswith("_id") else value
        return values


@runtime_checkable
class AgentObserver(Protocol):
    """Best-effort sink for typed content-free agent operation facts."""

    async def record(
        self,
        observation: AgentOperationObservation,
        context: SecurityContext,
    ) -> None: ...


class NullAgentObserver:
    """Default observer preserving direct AgentLoop compatibility."""

    async def record(
        self,
        observation: AgentOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, AgentOperationObservation):
            raise TypeError("observation must be AgentOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")


class ContentFreeAgentObserver:
    """Emit fixed empty-payload events, audit facts, logs, and bounded metrics."""

    def __init__(
        self,
        configuration: AgentServiceConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(configuration, AgentServiceConfiguration):
            raise TypeError("configuration must be AgentServiceConfiguration")
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
        observation: AgentOperationObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, AgentOperationObservation):
            raise TypeError("observation must be AgentOperationObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if observation.agent_id != self._configuration.agent_id:
            raise ValueError("observation agent_id does not match configuration")

        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        correlation_id = context.correlation_id or str(observation.run_id)
        causation_id = _causation_id(observation)
        options = self._configuration.observability

        if options.events_enabled:
            try:
                await self._events.emit(
                    observation.name,
                    source=self._configuration.source,
                    payload={},
                    metadata=event_metadata,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
            except Exception:
                pass

        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=_audit_category(observation.operation),
                    action=f"agent.{observation.operation.value}",
                    resource=_audit_resource(observation),
                    context=context,
                    outcome=_audit_outcome(observation.outcome),
                    severity=_audit_severity(observation.outcome),
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass

        if self._observability is not None:
            try:
                if options.logs_enabled:
                    await self._observability.log(
                        observation.name,
                        source=self._configuration.source,
                        message="agent operation changed state",
                        severity=_observation_severity(observation.outcome),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=causation_id,
                    )
                if options.metrics_enabled:
                    metric_attributes: dict[str, object] = {
                        "operation": observation.operation.value,
                        "outcome": observation.outcome.value,
                    }
                    if observation.effect is not None:
                        metric_attributes["effect"] = observation.effect.value
                    await self._observability.metric(
                        "agent.operations",
                        1,
                        source=self._configuration.source,
                        kind=MetricKind.COUNTER,
                        unit="operation",
                        attributes=metric_attributes,
                        correlation_id=correlation_id,
                        causation_id=causation_id,
                    )
                    if observation.duration_ms is not None:
                        await self._observability.metric(
                            "agent.operation.duration_ms",
                            observation.duration_ms,
                            source=self._configuration.source,
                            kind=MetricKind.GAUGE,
                            unit="millisecond",
                            attributes={"operation": observation.operation.value},
                            correlation_id=correlation_id,
                            causation_id=causation_id,
                        )
            except Exception:
                pass


def resolved_resource_category(resource: str) -> str:
    """Return only the leading safe category of a trusted resolved resource."""

    if not isinstance(resource, str):
        raise TypeError("resource must be str")
    normalized = resource.strip().lower()
    if not normalized:
        raise ValueError("resource must not be blank")
    head = re.split(r"[:/]", normalized, maxsplit=1)[0]
    category = re.sub(r"[^a-z0-9_.-]", "-", head).strip("-._")
    if not category or _RESOURCE_CATEGORY_PATTERN.fullmatch(category) is None:
        return "other"
    return category


def _causation_id(observation: AgentOperationObservation) -> UUID:
    if observation.call_id is not None:
        return observation.call_id.value
    if observation.step_id is not None:
        return observation.step_id.value
    return observation.run_id.value


def _audit_category(operation: AgentOperation) -> AuditCategory:
    if operation in {
        AgentOperation.RUN_AUTHORIZATION,
        AgentOperation.MODEL_AUTHORIZATION,
        AgentOperation.TOOL_AUTHORIZATION,
    }:
        return AuditCategory.AUTHORIZATION
    return AuditCategory.OTHER


def _audit_resource(observation: AgentOperationObservation) -> str:
    if observation.tool_id is not None:
        return f"agent:{observation.agent_id}/tool:{observation.tool_id}"
    return agent_run_resource(observation.agent_id)


def _audit_outcome(outcome: AgentOperationOutcome) -> AuditOutcome:
    if outcome in {
        AgentOperationOutcome.SUCCEEDED,
        AgentOperationOutcome.REQUESTED,
        AgentOperationOutcome.APPROVED,
        AgentOperationOutcome.CONSUMED,
    }:
        return AuditOutcome.SUCCEEDED
    if outcome is AgentOperationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is AgentOperationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is AgentOperationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: AgentOperationOutcome) -> AuditSeverity:
    if outcome in {
        AgentOperationOutcome.FAILED,
        AgentOperationOutcome.TIMED_OUT,
        AgentOperationOutcome.INDETERMINATE,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        AgentOperationOutcome.REJECTED,
        AgentOperationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: AgentOperationOutcome) -> Severity:
    if outcome in {
        AgentOperationOutcome.FAILED,
        AgentOperationOutcome.TIMED_OUT,
        AgentOperationOutcome.INDETERMINATE,
    }:
        return Severity.ERROR
    if outcome in {
        AgentOperationOutcome.REJECTED,
        AgentOperationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO
