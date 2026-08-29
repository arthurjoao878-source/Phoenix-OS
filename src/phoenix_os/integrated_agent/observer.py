"""Content-free operational observations for RFC-0036 integrated execution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolId
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedEffectDisposition,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedFailureClass,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
    IntegratedWaitingReason,
    PlanRevision,
)
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_CATEGORY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
MAX_INTEGRATED_OBSERVATION_DURATION_MS = 2_147_483_647


def _normalize_category(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if _CATEGORY_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a bounded lowercase Phoenix identifier")
    return normalized


@dataclass(frozen=True, slots=True)
class IntegratedAgentObservation:
    """Bounded operational metadata that cannot carry integrated content."""

    task_id: IntegratedTaskId
    run_id: AgentRunId
    phase: IntegratedOrchestrationPhase
    profile_id: IntegratedExecutionProfileId
    profile_generation: IntegratedExecutionProfileGeneration
    step_id: AgentStepId | None = None
    plan_revision: PlanRevision | None = None
    capability_id: str | None = None
    tool_id: ToolId | None = None
    action_category: str | None = None
    effect_disposition: IntegratedEffectDisposition | None = None
    failure_class: IntegratedFailureClass | None = None
    budget_usage: IntegratedBudgetUsage | None = None
    duration_ms: int | None = None
    waiting_reason: IntegratedWaitingReason | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, IntegratedTaskId):
            raise TypeError("task_id must be IntegratedTaskId")
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.phase, IntegratedOrchestrationPhase):
            raise TypeError("phase must be IntegratedOrchestrationPhase")
        if not isinstance(self.profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        if not isinstance(
            self.profile_generation,
            IntegratedExecutionProfileGeneration,
        ):
            raise TypeError("profile_generation must be IntegratedExecutionProfileGeneration")
        if self.step_id is not None and not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId or None")
        if self.plan_revision is not None and not isinstance(
            self.plan_revision,
            PlanRevision,
        ):
            raise TypeError("plan_revision must be PlanRevision or None")
        if self.capability_id is not None:
            object.__setattr__(
                self,
                "capability_id",
                _normalize_category(
                    self.capability_id,
                    label="integrated observation capability id",
                ),
            )
        if self.tool_id is not None and not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId or None")
        if self.action_category is not None:
            object.__setattr__(
                self,
                "action_category",
                _normalize_category(
                    self.action_category,
                    label="integrated observation action category",
                ),
            )
        if self.effect_disposition is not None and not isinstance(
            self.effect_disposition,
            IntegratedEffectDisposition,
        ):
            raise TypeError("effect_disposition must be IntegratedEffectDisposition or None")
        if self.failure_class is not None and not isinstance(
            self.failure_class,
            IntegratedFailureClass,
        ):
            raise TypeError("failure_class must be IntegratedFailureClass or None")
        if self.budget_usage is not None and not isinstance(
            self.budget_usage,
            IntegratedBudgetUsage,
        ):
            raise TypeError("budget_usage must be IntegratedBudgetUsage or None")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
            or not 0 <= self.duration_ms <= MAX_INTEGRATED_OBSERVATION_DURATION_MS
        ):
            raise ValueError("duration_ms must be a bounded non-negative integer")
        if self.waiting_reason is not None and not isinstance(
            self.waiting_reason,
            IntegratedWaitingReason,
        ):
            raise TypeError("waiting_reason must be IntegratedWaitingReason or None")
        if self.phase is IntegratedOrchestrationPhase.WAITING:
            if self.waiting_reason is None:
                raise ValueError("WAITING observations require a waiting reason")
        elif self.waiting_reason is not None:
            raise ValueError("waiting reason is valid only for WAITING observations")
        if self.schema_version != 1:
            raise ValueError("unsupported integrated observation version")

    @property
    def name(self) -> str:
        return f"integrated_agent.observation.{self.phase.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "task_id": str(self.task_id),
            "run_id": str(self.run_id),
            "profile_id": str(self.profile_id),
            "profile_generation": self.profile_generation.value,
            "orchestration_phase": self.phase.value,
        }
        if self.step_id is not None:
            values["step_id"] = str(self.step_id)
        if self.plan_revision is not None:
            values["plan_revision"] = self.plan_revision.value
        if self.capability_id is not None:
            values["capability_id"] = self.capability_id
        if self.tool_id is not None:
            values["tool_id"] = str(self.tool_id)
        if self.action_category is not None:
            values["action_category"] = self.action_category
        if self.effect_disposition is not None:
            values["effect_disposition"] = self.effect_disposition.value
        if self.failure_class is not None:
            values["failure_class"] = self.failure_class.value
        if self.duration_ms is not None:
            values["duration_ms"] = self.duration_ms
        if self.waiting_reason is not None:
            values["waiting_reason"] = self.waiting_reason.value
        if self.budget_usage is not None:
            usage = self.budget_usage
            values.update(
                {
                    "budget_plan_revisions": usage.plan_revisions,
                    "budget_integrated_steps": usage.integrated_steps,
                    "budget_browser_operations": usage.browser_operations,
                    "budget_network_operations": usage.network_operations,
                    "budget_memory_operations": usage.memory_operations,
                    "budget_workspace_operations": usage.workspace_operations,
                    "budget_workspace_mutation_bytes": usage.workspace_mutation_bytes,
                    "budget_host_operations": usage.host_operations,
                }
            )
        return values


@dataclass(frozen=True, slots=True)
class IntegratedAgentObservabilityConfiguration:
    """Explicit content-free audit, metrics, log, and Event Bus switches."""

    audit_enabled: bool = True
    metrics_enabled: bool = True
    logs_enabled: bool = True
    events_enabled: bool = True
    source: str = "phoenix.integrated_agent"

    def __post_init__(self) -> None:
        switches = (
            self.audit_enabled,
            self.metrics_enabled,
            self.logs_enabled,
            self.events_enabled,
        )
        if any(type(value) is not bool for value in switches):
            raise TypeError("integrated observability switches must be booleans")
        if not isinstance(self.source, str):
            raise TypeError("integrated observability source must be a string")
        source = self.source.strip().lower()
        if _SOURCE_PATTERN.fullmatch(source) is None:
            raise ValueError(
                "integrated observability source must be a lowercase Phoenix identifier"
            )
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
class IntegratedAgentObserver(Protocol):
    """Best-effort sink for bounded content-free integrated execution facts."""

    async def record(
        self,
        observation: IntegratedAgentObservation,
        context: SecurityContext,
    ) -> None: ...


class NullIntegratedAgentObserver:
    """Default no-op observer preserving standalone integrated composition."""

    async def record(
        self,
        observation: IntegratedAgentObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, IntegratedAgentObservation):
            raise TypeError("observation must be IntegratedAgentObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")


class ContentFreeIntegratedAgentObserver:
    """Emit only the closed RFC-0036 operational metadata vocabulary."""

    def __init__(
        self,
        configuration: IntegratedAgentObservabilityConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(configuration, IntegratedAgentObservabilityConfiguration):
            raise TypeError("configuration must be IntegratedAgentObservabilityConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(
            observability,
            ObservabilityHub,
        ):
            raise TypeError("observability must be ObservabilityHub")
        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability

    async def record(
        self,
        observation: IntegratedAgentObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, IntegratedAgentObservation):
            raise TypeError("observation must be IntegratedAgentObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        correlation_id = context.correlation_id or str(observation.run_id)
        options = self._configuration

        if options.events_enabled:
            try:
                await self._events.emit(
                    observation.name,
                    source=options.source,
                    payload={},
                    metadata=event_metadata,
                    correlation_id=correlation_id,
                    causation_id=None,
                )
            except Exception:
                pass

        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=AuditCategory.OTHER,
                    action=observation.phase.value,
                    resource="integrated-agent",
                    context=context,
                    outcome=_audit_outcome(observation),
                    severity=_audit_severity(observation),
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
                        message="integrated agent orchestration changed state",
                        severity=_observation_severity(observation),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=None,
                    )
                if options.metrics_enabled:
                    metric_attributes: dict[str, object] = {
                        "phase": observation.phase.value,
                    }
                    if observation.failure_class is not None:
                        metric_attributes["failure_class"] = observation.failure_class.value
                    if observation.effect_disposition is not None:
                        metric_attributes["effect_disposition"] = (
                            observation.effect_disposition.value
                        )
                    if observation.waiting_reason is not None:
                        metric_attributes["waiting_reason"] = observation.waiting_reason.value
                    await self._observability.metric(
                        "integrated_agent.observations",
                        1,
                        source=options.source,
                        kind=MetricKind.COUNTER,
                        unit="observation",
                        attributes=metric_attributes,
                        correlation_id=correlation_id,
                        causation_id=None,
                    )
                    if observation.duration_ms is not None:
                        await self._observability.metric(
                            "integrated_agent.observation.duration_ms",
                            observation.duration_ms,
                            source=options.source,
                            kind=MetricKind.GAUGE,
                            unit="millisecond",
                            attributes=metric_attributes,
                            correlation_id=correlation_id,
                            causation_id=None,
                        )
            except Exception:
                pass


def _audit_outcome(observation: IntegratedAgentObservation) -> AuditOutcome:
    if observation.failure_class is not None:
        return AuditOutcome.FAILED
    if observation.phase is IntegratedOrchestrationPhase.WAITING:
        return AuditOutcome.RESTRICTED
    if observation.phase is IntegratedOrchestrationPhase.TERMINAL:
        return AuditOutcome.SUCCEEDED
    return AuditOutcome.UNKNOWN


def _audit_severity(observation: IntegratedAgentObservation) -> AuditSeverity:
    if observation.failure_class is not None:
        return AuditSeverity.ERROR
    if observation.phase is IntegratedOrchestrationPhase.WAITING:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(observation: IntegratedAgentObservation) -> Severity:
    if observation.failure_class is not None:
        return Severity.ERROR
    if observation.phase is IntegratedOrchestrationPhase.WAITING:
        return Severity.WARNING
    return Severity.INFO
