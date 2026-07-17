"""Deterministic, asynchronous observability signal delivery."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from uuid import UUID, uuid4

from phoenix_os.observability.context import current_span_context
from phoenix_os.observability.contracts import (
    ExportErrorPolicy,
    ExportFailure,
    ExportReport,
    LogRecord,
    MetricKind,
    MetricRecord,
    ObservabilitySnapshot,
    Observation,
    ObservationSink,
    Severity,
    SinkRegistration,
    SpanRecord,
)
from phoenix_os.observability.errors import ObservabilityClosedError, ObservationExportError
from phoenix_os.observability.redaction import RedactionPolicy
from phoenix_os.observability.span import Span


@dataclass(slots=True)
class _RegisteredSink:
    registration: SinkRegistration
    sink: ObservationSink
    priority: int
    sequence: int


class ObservabilityHub:
    """Export structured logs, metrics, and spans in deterministic sink order."""

    def __init__(
        self,
        sinks: Iterable[ObservationSink] = (),
        *,
        redaction: RedactionPolicy | None = None,
    ) -> None:
        self._sinks: dict[UUID, _RegisteredSink] = {}
        self._sequence = 0
        self._closed = False
        self._observations = 0
        self._export_failures = 0
        self._redaction = RedactionPolicy() if redaction is None else redaction
        self._lock = asyncio.Lock()
        for sink in sinks:
            self._register_initial(sink)

    @property
    def closed(self) -> bool:
        return self._closed

    async def add_sink(
        self,
        sink: ObservationSink,
        *,
        priority: int = 0,
    ) -> SinkRegistration:
        self._ensure_open()
        self._validate_sink(sink)
        async with self._lock:
            self._ensure_open()
            return self._register(sink, priority)

    async def remove_sink(self, registration: SinkRegistration) -> bool:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            return self._sinks.pop(registration.id, None) is not None

    async def emit(
        self,
        observation: Observation,
        *,
        error_policy: ExportErrorPolicy = ExportErrorPolicy.COLLECT,
    ) -> ExportReport:
        self._ensure_open()
        sanitized = self._sanitize(observation)
        sinks = await self._snapshot_sinks()
        failures: list[ExportFailure] = []
        exported = 0

        for registered in sinks:
            try:
                result = registered.sink.emit(sanitized)
                if inspect.isawaitable(result):
                    await result
                exported += 1
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                failures.append(
                    ExportFailure(
                        registration=registered.registration,
                        exception=exception,
                    )
                )

        async with self._lock:
            self._observations += 1
            self._export_failures += len(failures)

        report = ExportReport(
            observation=sanitized,
            matched=len(sinks),
            exported=exported,
            failures=tuple(failures),
        )
        if failures and error_policy is ExportErrorPolicy.RAISE:
            raise ObservationExportError(report)
        return report

    async def log(
        self,
        name: str,
        *,
        source: str,
        message: str,
        severity: Severity = Severity.INFO,
        attributes: Mapping[str, object] | None = None,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
        error_policy: ExportErrorPolicy = ExportErrorPolicy.COLLECT,
    ) -> ExportReport:
        correlation_id, causation_id = self._inherit_context(correlation_id, causation_id)
        return await self.emit(
            LogRecord(
                name=name,
                source=source,
                message=message,
                severity=severity,
                attributes={} if attributes is None else attributes,
                correlation_id=correlation_id,
                causation_id=causation_id,
            ),
            error_policy=error_policy,
        )

    async def metric(
        self,
        name: str,
        value: int | float,
        *,
        source: str,
        kind: MetricKind = MetricKind.GAUGE,
        unit: str | None = None,
        attributes: Mapping[str, object] | None = None,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
        error_policy: ExportErrorPolicy = ExportErrorPolicy.COLLECT,
    ) -> ExportReport:
        correlation_id, causation_id = self._inherit_context(correlation_id, causation_id)
        return await self.emit(
            MetricRecord(
                name=name,
                source=source,
                value=value,
                kind=kind,
                unit=unit,
                attributes={} if attributes is None else attributes,
                correlation_id=correlation_id,
                causation_id=causation_id,
            ),
            error_policy=error_policy,
        )

    def span(
        self,
        name: str,
        *,
        source: str,
        attributes: Mapping[str, object] | None = None,
        correlation_id: str | None = None,
        error_policy: ExportErrorPolicy = ExportErrorPolicy.COLLECT,
    ) -> Span:
        self._ensure_open()
        return Span(
            self,
            name=name,
            source=source,
            attributes={} if attributes is None else attributes,
            correlation_id=correlation_id,
            error_policy=error_policy,
        )

    async def snapshot(self) -> ObservabilitySnapshot:
        async with self._lock:
            return ObservabilitySnapshot(
                closed=self._closed,
                sinks=len(self._sinks),
                observations=self._observations,
                export_failures=self._export_failures,
            )

    async def close(self) -> None:
        async with self._lock:
            self._sinks.clear()
            self._closed = True

    async def start(self, context: object) -> None:
        """Runtime lifecycle hook; the hub is ready immediately after construction."""

        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        """Runtime lifecycle hook that closes registrations after observers stop."""

        del context
        await self.close()

    async def _snapshot_sinks(self) -> tuple[_RegisteredSink, ...]:
        async with self._lock:
            self._ensure_open()
            result = tuple(self._sinks.values())
        return tuple(sorted(result, key=lambda item: (-item.priority, item.sequence)))

    def _register_initial(self, sink: ObservationSink) -> None:
        self._validate_sink(sink)
        self._register(sink, 0)

    def _register(self, sink: ObservationSink, priority: int) -> SinkRegistration:
        registration = SinkRegistration(uuid4())
        self._sinks[registration.id] = _RegisteredSink(
            registration=registration,
            sink=sink,
            priority=priority,
            sequence=self._sequence,
        )
        self._sequence += 1
        return registration

    @staticmethod
    def _validate_sink(sink: ObservationSink) -> None:
        if not callable(getattr(sink, "emit", None)):
            raise TypeError("sink must expose a callable emit method")

    def _sanitize(self, observation: Observation) -> Observation:
        attributes = self._redaction.redact(observation.attributes)
        if isinstance(observation, LogRecord):
            return replace(observation, attributes=attributes)
        if isinstance(observation, MetricRecord):
            return replace(observation, attributes=attributes)
        if isinstance(observation, SpanRecord):
            return replace(observation, attributes=attributes)
        raise TypeError("unsupported observation type")

    @staticmethod
    def _inherit_context(
        correlation_id: str | None,
        causation_id: UUID | None,
    ) -> tuple[str | None, UUID | None]:
        context = current_span_context()
        if context is None:
            return correlation_id, causation_id
        effective_correlation = correlation_id or context.correlation_id or str(context.trace_id)
        effective_causation = causation_id or context.span_id
        return effective_correlation, effective_causation

    def _ensure_open(self) -> None:
        if self._closed:
            raise ObservabilityClosedError("observability hub is closed")
