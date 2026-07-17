"""Immutable contracts for Phoenix observability signals and exporters."""

from __future__ import annotations

import math
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4


def _normalize_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank")
    return normalized


def _freeze_value(value: object) -> object:
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            normalized = _normalize_text(str(key), "attribute key")
            if normalized in frozen:
                raise ValueError(f"duplicate attribute key: {normalized}")
            frozen[normalized] = _freeze_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        raise TypeError("set values are not deterministic observability attributes")
    return value


def _freeze_attributes(value: Mapping[str, object]) -> Mapping[str, object]:
    frozen = _freeze_value(value)
    if not isinstance(frozen, Mapping):  # pragma: no cover - defensive invariant
        raise TypeError("attributes must be a mapping")
    return frozen


def _validate_timestamp(value: datetime, field_name: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")


class Severity(StrEnum):
    """Portable severity levels independent of a logging framework."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricKind(StrEnum):
    """Semantic kind of a numeric metric observation."""

    COUNTER = "counter"
    GAUGE = "gauge"


class SpanStatus(StrEnum):
    """Terminal status of one completed trace span."""

    OK = "ok"
    ERROR = "error"
    CANCELLED = "cancelled"


class ExportErrorPolicy(StrEnum):
    """How the observability hub reacts after exporter failures."""

    COLLECT = "collect"
    RAISE = "raise"


@dataclass(frozen=True, slots=True)
class SpanContext:
    """Trace identity propagated through nested asynchronous spans."""

    trace_id: UUID = field(default_factory=uuid4)
    span_id: UUID = field(default_factory=uuid4)
    parent_span_id: UUID | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if self.correlation_id is not None:
            normalized = _normalize_text(self.correlation_id, "correlation_id")
            object.__setattr__(self, "correlation_id", normalized)


@dataclass(frozen=True, slots=True)
class LogRecord:
    """Structured diagnostic record without dependency on Python logging."""

    name: str
    source: str
    message: str
    severity: Severity = Severity.INFO
    attributes: Mapping[str, object] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    causation_id: UUID | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_text(self.name, "log name"))
        object.__setattr__(self, "source", _normalize_text(self.source, "log source"))
        object.__setattr__(self, "message", _normalize_text(self.message, "log message"))
        _validate_timestamp(self.occurred_at, "occurred_at")
        if self.correlation_id is not None:
            object.__setattr__(
                self,
                "correlation_id",
                _normalize_text(self.correlation_id, "correlation_id"),
            )
        object.__setattr__(self, "attributes", _freeze_attributes(self.attributes))


@dataclass(frozen=True, slots=True)
class MetricRecord:
    """One numeric metric sample with explicit semantics and unit."""

    name: str
    source: str
    value: int | float
    kind: MetricKind = MetricKind.GAUGE
    unit: str | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    causation_id: UUID | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_text(self.name, "metric name"))
        object.__setattr__(self, "source", _normalize_text(self.source, "metric source"))
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise TypeError("metric value must be an integer or float")
        if not math.isfinite(float(self.value)):
            raise ValueError("metric value must be finite")
        if self.kind is MetricKind.COUNTER and self.value < 0:
            raise ValueError("counter metric values must not be negative")
        if self.unit is not None:
            object.__setattr__(self, "unit", _normalize_text(self.unit, "metric unit"))
        _validate_timestamp(self.occurred_at, "occurred_at")
        if self.correlation_id is not None:
            object.__setattr__(
                self,
                "correlation_id",
                _normalize_text(self.correlation_id, "correlation_id"),
            )
        object.__setattr__(self, "attributes", _freeze_attributes(self.attributes))


@dataclass(frozen=True, slots=True)
class SpanRecord:
    """Completed trace span exported as one immutable observation."""

    name: str
    source: str
    context: SpanContext
    status: SpanStatus
    started_at: datetime
    ended_at: datetime
    attributes: Mapping[str, object] = field(default_factory=dict)
    exception_type: str | None = None
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_text(self.name, "span name"))
        object.__setattr__(self, "source", _normalize_text(self.source, "span source"))
        _validate_timestamp(self.started_at, "started_at")
        _validate_timestamp(self.ended_at, "ended_at")
        if self.ended_at < self.started_at:
            raise ValueError("ended_at must not be earlier than started_at")
        if self.exception_type is not None:
            object.__setattr__(
                self,
                "exception_type",
                _normalize_text(self.exception_type, "exception_type"),
            )
        object.__setattr__(self, "attributes", _freeze_attributes(self.attributes))

    @property
    def duration_seconds(self) -> float:
        """Elapsed wall-clock duration represented by the span."""

        return (self.ended_at - self.started_at).total_seconds()

    @property
    def correlation_id(self) -> str | None:
        return self.context.correlation_id

    @property
    def causation_id(self) -> UUID | None:
        return self.context.parent_span_id


type Observation = LogRecord | MetricRecord | SpanRecord


class ObservationSink(Protocol):
    """Exporter boundary implemented by adapters outside the core."""

    def emit(self, observation: Observation) -> Awaitable[None] | None: ...


@dataclass(frozen=True, slots=True)
class SinkRegistration:
    """Opaque registration handle returned for one observability sink."""

    id: UUID


@dataclass(frozen=True, slots=True)
class ExportFailure:
    """Failure captured from one sink while later sinks continue."""

    registration: SinkRegistration
    exception: Exception


@dataclass(frozen=True, slots=True)
class ExportReport:
    """Deterministic result after all registered sinks receive a signal."""

    observation: Observation
    matched: int
    exported: int
    failures: tuple[ExportFailure, ...]

    @property
    def succeeded(self) -> bool:
        return not self.failures


@dataclass(frozen=True, slots=True)
class ObservabilitySnapshot:
    """Point-in-time internal status of the observability hub."""

    closed: bool
    sinks: int
    observations: int
    export_failures: int


@dataclass(frozen=True, slots=True)
class MemorySinkSnapshot:
    """Immutable contents and overflow count of an in-memory sink."""

    records: tuple[Observation, ...]
    dropped: int
    closed: bool
