"""Content-free operational observations for durable agent runs."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointId,
    CheckpointPayloadProfile,
    CheckpointSequence,
    DurableAgentRunId,
    DurableRunStatus,
    FencingGeneration,
)
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext

_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class DurableRunOperation(StrEnum):
    """Fixed Phoenix-owned durable operation categories."""

    CHECKPOINT = "checkpoint"
    RECONCILIATION = "reconciliation"


class DurableRunObservationOutcome(StrEnum):
    """Content-free outcome categories for durable operations."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class DurableRunObservation:
    """Typed content-free metadata for one durable-run operation."""

    operation: DurableRunOperation
    outcome: DurableRunObservationOutcome
    run_id: DurableAgentRunId
    status: DurableRunStatus | None = None
    checkpoint_id: CheckpointId | None = None
    sequence: CheckpointSequence | None = None
    fencing_generation: FencingGeneration | None = None
    payload_profile: CheckpointPayloadProfile | None = None
    checkpoint_digest: CheckpointDigest | None = None
    duration_ms: int | None = None
    category: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", DurableRunOperation(self.operation))
        object.__setattr__(
            self,
            "outcome",
            DurableRunObservationOutcome(self.outcome),
        )

        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if self.status is not None and not isinstance(self.status, DurableRunStatus):
            raise TypeError("status must be DurableRunStatus")
        if self.checkpoint_id is not None and not isinstance(
            self.checkpoint_id,
            CheckpointId,
        ):
            raise TypeError("checkpoint_id must be CheckpointId")
        if self.sequence is not None and not isinstance(
            self.sequence,
            CheckpointSequence,
        ):
            raise TypeError("sequence must be CheckpointSequence")
        if self.fencing_generation is not None and not isinstance(
            self.fencing_generation,
            FencingGeneration,
        ):
            raise TypeError("fencing_generation must be FencingGeneration")
        if self.payload_profile is not None and not isinstance(
            self.payload_profile,
            CheckpointPayloadProfile,
        ):
            raise TypeError("payload_profile must be CheckpointPayloadProfile")
        if self.checkpoint_digest is not None and not isinstance(
            self.checkpoint_digest,
            CheckpointDigest,
        ):
            raise TypeError("checkpoint_digest must be CheckpointDigest")

        if self.duration_ms is not None:
            if (
                isinstance(self.duration_ms, bool)
                or not isinstance(self.duration_ms, int)
                or self.duration_ms < 0
            ):
                raise ValueError("duration_ms must be a non-negative integer")

        if self.category is not None:
            object.__setattr__(
                self,
                "category",
                _normalize_safe_identifier(self.category, label="category"),
            )

        if self.error_code is not None:
            object.__setattr__(
                self,
                "error_code",
                _normalize_safe_identifier(self.error_code, label="error_code"),
            )

    @property
    def name(self) -> str:
        return f"agent.durable.{self.operation.value}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "run_id": str(self.run_id),
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }

        for key, value in (
            ("status", None if self.status is None else self.status.value),
            ("checkpoint_id", self.checkpoint_id),
            ("sequence", None if self.sequence is None else self.sequence.value),
            (
                "fencing_generation",
                (None if self.fencing_generation is None else self.fencing_generation.value),
            ),
            (
                "payload_profile",
                None if self.payload_profile is None else self.payload_profile.value,
            ),
            ("checkpoint_digest", self.checkpoint_digest),
            ("duration_ms", self.duration_ms),
            ("category", self.category),
            ("error_code", self.error_code),
        ):
            if value is None:
                continue
            if key in {"checkpoint_id", "checkpoint_digest"}:
                values[key] = str(value)
            else:
                values[key] = value

        return values


@dataclass(frozen=True, slots=True)
class DurableRunObserverSnapshot:
    """Content-free durable observer health counters."""

    observations: int = 0
    event_failures: int = 0
    audit_failures: int = 0
    observability_failures: int = 0
    schema_version: int = 1

    def __post_init__(self) -> None:
        for label, value in (
            ("observations", self.observations),
            ("event_failures", self.event_failures),
            ("audit_failures", self.audit_failures),
            ("observability_failures", self.observability_failures),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0:
                raise ValueError(f"{label} must not be negative")

        if self.schema_version != 1:
            raise ValueError("unsupported durable observer snapshot version")

    @property
    def degraded(self) -> bool:
        return any(
            (
                self.event_failures,
                self.audit_failures,
                self.observability_failures,
            )
        )


@runtime_checkable
class DurableRunObserver(Protocol):
    """Best-effort sink for typed content-free durable-run facts."""

    async def record(
        self,
        observation: DurableRunObservation,
        context: SecurityContext,
    ) -> None: ...

    async def snapshot(self) -> DurableRunObserverSnapshot: ...


class NullDurableRunObserver:
    """Default no-op observer for durable composition without observation."""

    async def record(
        self,
        observation: DurableRunObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, DurableRunObservation):
            raise TypeError("observation must be DurableRunObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

    async def snapshot(self) -> DurableRunObserverSnapshot:
        return DurableRunObserverSnapshot()


class ContentFreeDurableRunObserver:
    """Emit fixed empty-payload events, audit, logs, and bounded metrics."""

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
        if observability is not None and not isinstance(
            observability,
            ObservabilityHub,
        ):
            raise TypeError("observability must be ObservabilityHub")

        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability
        self._observations = 0
        self._event_failures = 0
        self._audit_failures = 0
        self._observability_failures = 0
        self._lock = asyncio.Lock()

    async def record(
        self,
        observation: DurableRunObservation,
        context: SecurityContext,
    ) -> None:
        if not isinstance(observation, DurableRunObservation):
            raise TypeError("observation must be DurableRunObservation")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        correlation_id = str(observation.run_id)
        causation_id = _causation_id(observation)
        audit_context = replace(
            context,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )
        options = self._configuration.observability

        event_failed = False
        audit_failed = False
        observability_failed = False

        if options.events_enabled:
            try:
                report = await self._events.emit(
                    observation.name,
                    source=self._configuration.source,
                    payload={},
                    metadata=event_metadata,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
                event_failed = bool(report.failures)
            except Exception:
                event_failed = True

        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=AuditCategory.STATE,
                    action=f"agent.durable.{observation.operation.value}",
                    resource=f"durable-agent-run:{observation.run_id}",
                    context=audit_context,
                    outcome=_audit_outcome(observation.outcome),
                    severity=_audit_severity(observation.outcome),
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                audit_failed = True

        if self._observability is not None:
            try:
                if options.logs_enabled:
                    log_report = await self._observability.log(
                        observation.name,
                        source=self._configuration.source,
                        message="durable agent operation changed state",
                        severity=_observation_severity(observation.outcome),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=causation_id,
                    )
                    observability_failed = observability_failed or bool(log_report.failures)

                if options.metrics_enabled:
                    metric_attributes: dict[str, object] = {
                        "operation": observation.operation.value,
                        "outcome": observation.outcome.value,
                    }

                    if observation.status is not None:
                        metric_attributes["status"] = observation.status.value
                    if observation.payload_profile is not None:
                        metric_attributes["payload_profile"] = observation.payload_profile.value
                    if observation.category is not None:
                        metric_attributes["category"] = observation.category

                    metric_report = await self._observability.metric(
                        "agent.durable.operations",
                        1,
                        source=self._configuration.source,
                        kind=MetricKind.COUNTER,
                        unit="operation",
                        attributes=metric_attributes,
                        correlation_id=correlation_id,
                        causation_id=causation_id,
                    )
                    observability_failed = observability_failed or bool(metric_report.failures)

                    if observation.duration_ms is not None:
                        duration_report = await self._observability.metric(
                            "agent.durable.operation.duration_ms",
                            observation.duration_ms,
                            source=self._configuration.source,
                            kind=MetricKind.GAUGE,
                            unit="millisecond",
                            attributes={
                                "operation": observation.operation.value,
                                "outcome": observation.outcome.value,
                            },
                            correlation_id=correlation_id,
                            causation_id=causation_id,
                        )
                        observability_failed = observability_failed or bool(
                            duration_report.failures
                        )
            except Exception:
                observability_failed = True

        async with self._lock:
            self._observations += 1
            self._event_failures += int(event_failed)
            self._audit_failures += int(audit_failed)
            self._observability_failures += int(observability_failed)

    async def snapshot(self) -> DurableRunObserverSnapshot:
        async with self._lock:
            return DurableRunObserverSnapshot(
                observations=self._observations,
                event_failures=self._event_failures,
                audit_failures=self._audit_failures,
                observability_failures=self._observability_failures,
            )


def _normalize_safe_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")

    normalized = value.strip().lower()
    if _SAFE_IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a safe bounded identifier")

    return normalized


def _causation_id(observation: DurableRunObservation) -> UUID:
    if observation.checkpoint_id is not None:
        return observation.checkpoint_id.value
    return observation.run_id.value


def _audit_outcome(
    outcome: DurableRunObservationOutcome,
) -> AuditOutcome:
    if outcome is DurableRunObservationOutcome.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if outcome is DurableRunObservationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is DurableRunObservationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is DurableRunObservationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(
    outcome: DurableRunObservationOutcome,
) -> AuditSeverity:
    if outcome in {
        DurableRunObservationOutcome.FAILED,
        DurableRunObservationOutcome.TIMED_OUT,
        DurableRunObservationOutcome.INDETERMINATE,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        DurableRunObservationOutcome.REJECTED,
        DurableRunObservationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(
    outcome: DurableRunObservationOutcome,
) -> Severity:
    if outcome in {
        DurableRunObservationOutcome.FAILED,
        DurableRunObservationOutcome.TIMED_OUT,
        DurableRunObservationOutcome.INDETERMINATE,
    }:
        return Severity.ERROR
    if outcome in {
        DurableRunObservationOutcome.REJECTED,
        DurableRunObservationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO
