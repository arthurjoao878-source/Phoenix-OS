"""Runtime-owned inference service with content-free operational signals."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import UUID, uuid4

from phoenix_os.audit import (
    AuditCategory,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.events import EventBus
from phoenix_os.inference.authorization import inference_model_resource
from phoenix_os.inference.configuration import InferenceServiceConfiguration
from phoenix_os.inference.contracts import (
    InferenceChunk,
    InferenceFinishReason,
    InferenceRequest,
    InferenceResponse,
    InferenceUsage,
)
from phoenix_os.inference.errors import (
    InferenceAuthorizationRejectedError,
    InferenceCancelledError,
    InferenceError,
    InferenceLimitExceededError,
    InferenceSaturatedError,
    InferenceServiceUnavailableError,
    InferenceTimeoutError,
)
from phoenix_os.inference.execution import InferenceRuntime
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext


class InferenceServiceState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


class InferenceInvocationOutcome(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class InferenceServiceSnapshot:
    """Content-free health and lifecycle snapshot."""

    state: InferenceServiceState
    providers: int
    models: int
    active: int
    started: int
    completed: int
    rejected: int
    failed: int
    cancelled: int
    timed_out: int
    forced_cancellations: int
    last_started_at: datetime | None
    last_completed_at: datetime | None

    def __post_init__(self) -> None:
        for label, value in (
            ("providers", self.providers),
            ("models", self.models),
            ("active", self.active),
            ("started", self.started),
            ("completed", self.completed),
            ("rejected", self.rejected),
            ("failed", self.failed),
            ("cancelled", self.cancelled),
            ("timed_out", self.timed_out),
            ("forced_cancellations", self.forced_cancellations),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0:
                raise ValueError(f"{label} must not be negative")
        if self.active > self.started:
            raise ValueError("active inference count cannot exceed started count")
        terminal = self.completed + self.rejected + self.failed + self.cancelled + self.timed_out
        if terminal + self.active > self.started:
            raise ValueError("inference outcome counts exceed started count")
        for label, timestamp in (
            ("last_started_at", self.last_started_at),
            ("last_completed_at", self.last_completed_at),
        ):
            if timestamp is not None and (
                not isinstance(timestamp, datetime)
                or timestamp.tzinfo is None
                or timestamp.utcoffset() is None
            ):
                raise ValueError(f"{label} must be timezone-aware")

    @property
    def accepting(self) -> bool:
        return self.state is InferenceServiceState.RUNNING


class InferenceService:
    """Own inference lifecycle, health, cancellation, audit, and observations."""

    def __init__(
        self,
        runtime: InferenceRuntime,
        registry: ModelProviderRegistry,
        configuration: InferenceServiceConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(runtime, InferenceRuntime):
            raise TypeError("runtime must be InferenceRuntime")
        if not isinstance(registry, ModelProviderRegistry):
            raise TypeError("registry must be ModelProviderRegistry")
        if not isinstance(configuration, InferenceServiceConfiguration):
            raise TypeError("configuration must be InferenceServiceConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(
            observability,
            ObservabilityHub,
        ):
            raise TypeError("observability must be ObservabilityHub")

        self._runtime = runtime
        self._registry = registry
        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability
        self._state = InferenceServiceState.CREATED
        self._active: dict[UUID, asyncio.Task[object]] = {}
        self._started = 0
        self._completed = 0
        self._rejected = 0
        self._failed = 0
        self._cancelled = 0
        self._timed_out = 0
        self._forced_cancellations = 0
        self._last_started_at: datetime | None = None
        self._last_completed_at: datetime | None = None
        self._lock = asyncio.Lock()

    @property
    def runtime(self) -> InferenceRuntime:
        return self._runtime

    @property
    def registry(self) -> ModelProviderRegistry:
        return self._registry

    @property
    def configuration(self) -> InferenceServiceConfiguration:
        return self._configuration

    @property
    def state(self) -> InferenceServiceState:
        return self._state

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        async with self._lock:
            if self._state is InferenceServiceState.RUNNING:
                return
            if self._state is not InferenceServiceState.CREATED:
                raise InferenceServiceUnavailableError()
            self._state = InferenceServiceState.RUNNING
        await self._signal_lifecycle("started")

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        async with self._lock:
            if self._state is InferenceServiceState.STOPPED:
                return
            if self._state is InferenceServiceState.STOPPING:
                return
            self._state = InferenceServiceState.STOPPING
            tasks = set(self._active.values())

        await self._signal_lifecycle("stopping")
        await self._drain_and_cancel(tasks)
        self._registry.close()

        async with self._lock:
            self._active.clear()
            self._state = InferenceServiceState.STOPPED
        await self._signal_lifecycle("stopped")

    async def snapshot(self) -> InferenceServiceSnapshot:
        async with self._lock:
            return InferenceServiceSnapshot(
                state=self._state,
                providers=len(self._configuration.providers),
                models=len(self._configuration.models),
                active=len(self._active),
                started=self._started,
                completed=self._completed,
                rejected=self._rejected,
                failed=self._failed,
                cancelled=self._cancelled,
                timed_out=self._timed_out,
                forced_cancellations=self._forced_cancellations,
                last_started_at=self._last_started_at,
                last_completed_at=self._last_completed_at,
            )

    async def infer(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> InferenceResponse:
        invocation_id, started_at = await self._begin(request, context, mode="complete")
        try:
            response = await self._runtime.infer(request, context)
        except asyncio.CancelledError:
            await self._finish(
                invocation_id,
                request,
                context,
                mode="complete",
                outcome=InferenceInvocationOutcome.CANCELLED,
                started_at=started_at,
            )
            raise
        except InferenceError as exception:
            await self._finish(
                invocation_id,
                request,
                context,
                mode="complete",
                outcome=_outcome_for_error(exception),
                started_at=started_at,
            )
            raise
        except Exception:
            await self._finish(
                invocation_id,
                request,
                context,
                mode="complete",
                outcome=InferenceInvocationOutcome.FAILED,
                started_at=started_at,
            )
            raise
        await self._finish(
            invocation_id,
            request,
            context,
            mode="complete",
            outcome=InferenceInvocationOutcome.COMPLETED,
            started_at=started_at,
            finish_reason=response.finish_reason,
            usage=response.usage,
        )
        return response

    async def stream(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> AsyncGenerator[InferenceChunk, None]:
        invocation_id, started_at = await self._begin(request, context, mode="stream")
        terminal: InferenceChunk | None = None
        try:
            async for chunk in self._runtime.stream(request, context):
                if chunk.terminal:
                    terminal = chunk
                yield chunk
        except (GeneratorExit, asyncio.CancelledError):
            await self._finish(
                invocation_id,
                request,
                context,
                mode="stream",
                outcome=InferenceInvocationOutcome.CANCELLED,
                started_at=started_at,
            )
            raise
        except InferenceError as exception:
            await self._finish(
                invocation_id,
                request,
                context,
                mode="stream",
                outcome=_outcome_for_error(exception),
                started_at=started_at,
            )
            raise
        except Exception:
            await self._finish(
                invocation_id,
                request,
                context,
                mode="stream",
                outcome=InferenceInvocationOutcome.FAILED,
                started_at=started_at,
            )
            raise

        if terminal is None or terminal.finish_reason is None or terminal.usage is None:
            await self._finish(
                invocation_id,
                request,
                context,
                mode="stream",
                outcome=InferenceInvocationOutcome.FAILED,
                started_at=started_at,
            )
            raise RuntimeError("validated inference stream lost its terminal record")

        await self._finish(
            invocation_id,
            request,
            context,
            mode="stream",
            outcome=InferenceInvocationOutcome.COMPLETED,
            started_at=started_at,
            finish_reason=terminal.finish_reason,
            usage=terminal.usage,
        )

    async def _begin(
        self,
        request: InferenceRequest,
        context: SecurityContext,
        *,
        mode: str,
    ) -> tuple[UUID, float]:
        if not isinstance(request, InferenceRequest):
            raise TypeError("request must be InferenceRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        task = asyncio.current_task()
        if task is None:  # pragma: no cover - async invariant
            raise RuntimeError("inference invocation requires an asyncio task")
        invocation_id = uuid4()
        now = datetime.now(UTC)

        async with self._lock:
            if self._state is not InferenceServiceState.RUNNING:
                raise InferenceServiceUnavailableError()
            self._active[invocation_id] = cast(asyncio.Task[object], task)
            self._started += 1
            self._last_started_at = now
            active = len(self._active)

        started_at = time.perf_counter()
        await self._signal_invocation(
            request,
            context,
            mode=mode,
            outcome=InferenceInvocationOutcome.STARTED,
            active=active,
        )
        return invocation_id, started_at

    async def _finish(
        self,
        invocation_id: UUID,
        request: InferenceRequest,
        context: SecurityContext,
        *,
        mode: str,
        outcome: InferenceInvocationOutcome,
        started_at: float,
        finish_reason: InferenceFinishReason | None = None,
        usage: InferenceUsage | None = None,
    ) -> None:
        duration_ms = max(0, round((time.perf_counter() - started_at) * 1_000))
        now = datetime.now(UTC)
        async with self._lock:
            self._active.pop(invocation_id, None)
            if outcome is InferenceInvocationOutcome.COMPLETED:
                self._completed += 1
            elif outcome is InferenceInvocationOutcome.REJECTED:
                self._rejected += 1
            elif outcome is InferenceInvocationOutcome.CANCELLED:
                self._cancelled += 1
            elif outcome is InferenceInvocationOutcome.TIMED_OUT:
                self._timed_out += 1
            else:
                self._failed += 1
            self._last_completed_at = now
            active = len(self._active)

        await self._signal_invocation(
            request,
            context,
            mode=mode,
            outcome=outcome,
            active=active,
            duration_ms=duration_ms,
            finish_reason=finish_reason,
            usage=usage,
        )

    async def _drain_and_cancel(
        self,
        tasks: set[asyncio.Task[object]],
    ) -> None:
        current = asyncio.current_task()
        if current is not None:
            tasks.discard(cast(asyncio.Task[object], current))
        if not tasks:
            return

        _done, pending = await asyncio.wait(
            tasks,
            timeout=self._configuration.drain_timeout.total_seconds(),
        )
        if not pending:
            return

        async with self._lock:
            self._forced_cancellations += len(pending)
        for task in pending:
            task.cancel()

        _done, stubborn = await asyncio.wait(
            pending,
            timeout=(self._configuration.execution_limits.cancellation_grace.total_seconds()),
        )
        for task in stubborn:
            task.add_done_callback(_consume_task)

    async def _signal_lifecycle(self, phase: str) -> None:
        snapshot = await self.snapshot()
        metadata = {
            "state": snapshot.state.value,
            "providers": str(snapshot.providers),
            "models": str(snapshot.models),
            "active": str(snapshot.active),
        }
        name = f"inference.runtime.{phase}"

        try:
            await self._events.emit(
                name,
                source=self._configuration.source,
                payload={},
                metadata=metadata,
            )
        except Exception:
            pass

        if self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.SYSTEM,
                    action=f"inference.runtime.{phase}",
                    resource="inference:runtime",
                    actor="phoenix",
                    outcome=AuditOutcome.SUCCEEDED,
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass

        if self._observability is not None:
            try:
                await self._observability.log(
                    name,
                    source=self._configuration.source,
                    message=f"inference runtime {phase}",
                    attributes=metadata,
                )
            except Exception:
                pass

    async def _signal_invocation(
        self,
        request: InferenceRequest,
        context: SecurityContext,
        *,
        mode: str,
        outcome: InferenceInvocationOutcome,
        active: int,
        duration_ms: int | None = None,
        finish_reason: InferenceFinishReason | None = None,
        usage: InferenceUsage | None = None,
    ) -> None:
        name = f"inference.invocation.{outcome.value}"
        metadata = _safe_invocation_metadata(
            request,
            mode=mode,
            outcome=outcome,
            active=active,
            duration_ms=duration_ms,
            finish_reason=finish_reason,
            usage=usage,
        )
        correlation_id = request.correlation_id or context.correlation_id

        try:
            await self._events.emit(
                name,
                source=self._configuration.source,
                payload={},
                metadata={key: str(value) for key, value in metadata.items()},
                correlation_id=correlation_id,
                causation_id=request.request_id,
            )
        except Exception:
            pass

        if self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.OTHER,
                    action="model.infer",
                    resource=inference_model_resource(
                        request.provider_id,
                        request.model_id,
                    ),
                    context=context,
                    outcome=_audit_outcome(outcome),
                    severity=_audit_severity(outcome),
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass

        if self._observability is not None:
            try:
                await self._observability.log(
                    name,
                    source=self._configuration.source,
                    message=f"inference invocation {outcome.value}",
                    severity=_observation_severity(outcome),
                    attributes=metadata,
                    correlation_id=correlation_id,
                    causation_id=request.request_id,
                )
                await self._observability.metric(
                    "inference.invocations",
                    1,
                    source=self._configuration.source,
                    kind=MetricKind.COUNTER,
                    unit="invocation",
                    attributes={
                        "mode": mode,
                        "outcome": outcome.value,
                    },
                    correlation_id=correlation_id,
                    causation_id=request.request_id,
                )
                await self._observability.metric(
                    "inference.active",
                    active,
                    source=self._configuration.source,
                    kind=MetricKind.GAUGE,
                    unit="invocation",
                    correlation_id=correlation_id,
                    causation_id=request.request_id,
                )
            except Exception:
                pass


def _safe_invocation_metadata(
    request: InferenceRequest,
    *,
    mode: str,
    outcome: InferenceInvocationOutcome,
    active: int,
    duration_ms: int | None,
    finish_reason: InferenceFinishReason | None,
    usage: InferenceUsage | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "request_id": str(request.request_id),
        "provider_id": str(request.provider_id),
        "model_id": str(request.model_id),
        "mode": mode,
        "outcome": outcome.value,
        "active": active,
    }
    if duration_ms is not None:
        metadata["duration_ms"] = duration_ms
    if finish_reason is not None:
        metadata["finish_reason"] = finish_reason.value
    if usage is not None:
        metadata["input_tokens"] = usage.input_tokens
        metadata["output_tokens"] = usage.output_tokens
        metadata["cached_input_tokens"] = usage.cached_input_tokens
    return metadata


def _outcome_for_error(error: InferenceError) -> InferenceInvocationOutcome:
    if isinstance(
        error,
        (
            InferenceAuthorizationRejectedError,
            InferenceLimitExceededError,
            InferenceSaturatedError,
            InferenceServiceUnavailableError,
        ),
    ):
        return InferenceInvocationOutcome.REJECTED
    if isinstance(error, InferenceTimeoutError):
        return InferenceInvocationOutcome.TIMED_OUT
    if isinstance(error, InferenceCancelledError):
        return InferenceInvocationOutcome.CANCELLED
    return InferenceInvocationOutcome.FAILED


def _audit_outcome(outcome: InferenceInvocationOutcome) -> AuditOutcome:
    if outcome is InferenceInvocationOutcome.COMPLETED:
        return AuditOutcome.SUCCEEDED
    if outcome is InferenceInvocationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is InferenceInvocationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is InferenceInvocationOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: InferenceInvocationOutcome) -> AuditSeverity:
    if outcome in {
        InferenceInvocationOutcome.FAILED,
        InferenceInvocationOutcome.TIMED_OUT,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        InferenceInvocationOutcome.REJECTED,
        InferenceInvocationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: InferenceInvocationOutcome) -> Severity:
    if outcome in {
        InferenceInvocationOutcome.FAILED,
        InferenceInvocationOutcome.TIMED_OUT,
    }:
        return Severity.ERROR
    if outcome in {
        InferenceInvocationOutcome.REJECTED,
        InferenceInvocationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO


def _consume_task(task: asyncio.Task[object]) -> None:
    if task.cancelled():
        return
    try:
        task.exception()
    except Exception:
        pass
