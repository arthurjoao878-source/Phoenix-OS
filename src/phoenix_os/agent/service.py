"""Runtime-owned agent service with content-free health and bounded shutdown."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast

from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.approval import ToolApprovalService
from phoenix_os.agent.authorization import (
    AGENT_RUN_ACTION,
    AgentRunAuthorityBinding,
    agent_run_resource,
)
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentError,
    AgentErrorCode,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.fake import AgentModelTurnAdapter
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import ToolAdapter, ToolDescriptor
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext


class AgentServiceState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


class AgentRunOutcome(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class AgentServiceSnapshot:
    """Content-free health, lifecycle, and bounded admission counters."""

    state: AgentServiceState
    tools: int
    enabled_tools: int
    active: int
    queued: int
    active_model_calls: int
    active_tool_calls: int
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
        object.__setattr__(self, "state", AgentServiceState(self.state))
        values = (
            self.tools,
            self.enabled_tools,
            self.active,
            self.queued,
            self.active_model_calls,
            self.active_tool_calls,
            self.started,
            self.completed,
            self.rejected,
            self.failed,
            self.cancelled,
            self.timed_out,
            self.forced_cancellations,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TypeError("agent health counters must be integers")
        if min(values) < 0:
            raise ValueError("agent health counters must not be negative")
        if self.enabled_tools > self.tools or self.active > self.started:
            raise ValueError("agent health counters are inconsistent")
        terminal = self.completed + self.rejected + self.failed + self.cancelled + self.timed_out
        if terminal + self.active > self.started:
            raise ValueError("agent outcome counts exceed started count")
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
        return self.state is AgentServiceState.RUNNING


@dataclass(frozen=True, slots=True)
class _ActiveRun:
    task: asyncio.Task[object]
    cancellation: AgentCancellationToken


class AgentService:
    """Own safe run exposure, observations, cancellation, and finite cleanup."""

    def __init__(
        self,
        runtime: AgentLoop,
        registry: ToolRegistry,
        admission: AgentAdmissionController,
        configuration: AgentServiceConfiguration,
        *,
        events: EventBus,
        model_adapter: AgentModelTurnAdapter,
        tool_adapters: tuple[ToolAdapter, ...] = (),
        approval_service: ToolApprovalService | None = None,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(runtime, AgentLoop):
            raise TypeError("runtime must be AgentLoop")
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be ToolRegistry")
        if not isinstance(admission, AgentAdmissionController):
            raise TypeError("admission must be AgentAdmissionController")
        if not isinstance(configuration, AgentServiceConfiguration):
            raise TypeError("configuration must be AgentServiceConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if not isinstance(model_adapter, AgentModelTurnAdapter):
            raise TypeError("model_adapter must implement AgentModelTurnAdapter")
        normalized_adapters = tuple(tool_adapters)
        if any(not isinstance(adapter, ToolAdapter) for adapter in normalized_adapters):
            raise TypeError("tool_adapters must implement ToolAdapter")
        if approval_service is not None and not isinstance(
            approval_service,
            ToolApprovalService,
        ):
            raise TypeError("approval_service must implement ToolApprovalService")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("observability must be ObservabilityHub")

        self._runtime = runtime
        self._registry = registry
        self._admission = admission
        self._configuration = configuration
        self._events = events
        self._model_adapter = model_adapter
        self._tool_adapters = normalized_adapters
        self._approval_service = approval_service
        self._audit = audit
        self._observability = observability
        self._state = AgentServiceState.CREATED
        self._active: dict[AgentRunId, _ActiveRun] = {}
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
    def runtime(self) -> AgentLoop:
        return self._runtime

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def admission(self) -> AgentAdmissionController:
        return self._admission

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    @property
    def state(self) -> AgentServiceState:
        return self._state

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        async with self._lock:
            if self._state is AgentServiceState.RUNNING:
                return
            if self._state is not AgentServiceState.CREATED:
                raise AgentServiceUnavailableError()
            self._state = AgentServiceState.RUNNING
        await self._signal_lifecycle("started")
        for descriptor in self._configuration.descriptors:
            await self._signal_tool_registration(descriptor)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        async with self._lock:
            if self._state is AgentServiceState.STOPPED:
                return
            if self._state is AgentServiceState.STOPPING:
                return
            self._state = AgentServiceState.STOPPING
            active = tuple(self._active.values())

        await self._signal_lifecycle("stopping")
        await self._admission.close()
        await self._drain_and_cancel(active)

        failure: BaseException | None = None
        close_timeout = self._configuration.limits.shutdown_grace.total_seconds()
        close_cancellation_grace = self._configuration.limits.cancellation_grace.total_seconds()
        approval = self._approval_service
        if approval is not None:
            try:
                await _close_bounded(
                    approval,
                    timeout_seconds=close_timeout,
                    cancellation_grace_seconds=close_cancellation_grace,
                )
            except (Exception, asyncio.CancelledError) as exception:
                failure = exception

        for adapter in reversed(self._tool_adapters):
            try:
                await _close_bounded(
                    adapter,
                    timeout_seconds=close_timeout,
                    cancellation_grace_seconds=close_cancellation_grace,
                )
            except (Exception, asyncio.CancelledError) as exception:
                if failure is None:
                    failure = exception
        try:
            await _close_bounded(
                self._model_adapter,
                timeout_seconds=close_timeout,
                cancellation_grace_seconds=close_cancellation_grace,
            )
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception
        try:
            self._registry.close()
        except Exception as exception:
            if failure is None:
                failure = exception

        async with self._lock:
            self._active.clear()
            self._state = AgentServiceState.STOPPED
        await self._signal_lifecycle("stopped")
        if failure is not None:
            raise failure

    async def snapshot(self) -> AgentServiceSnapshot:
        admission = await self._admission.snapshot()
        if self._registry.closed:
            tools = len(self._configuration.tools)
            enabled_tools = 0
        else:
            states = self._registry.list_states()
            tools = len(states)
            enabled_tools = sum(item.enabled for item in states)
        async with self._lock:
            return AgentServiceSnapshot(
                state=self._state,
                tools=tools,
                enabled_tools=enabled_tools,
                active=len(self._active),
                queued=admission.queued,
                active_model_calls=admission.active_model_calls,
                active_tool_calls=admission.active_tool_calls,
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

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult:
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        token = cancellation or AgentCancellationToken()
        if not isinstance(token, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        if _authority_binding is not None and not isinstance(
            _authority_binding,
            AgentRunAuthorityBinding,
        ):
            raise TypeError("_authority_binding must be AgentRunAuthorityBinding")

        started_at, started_clock = await self._begin(request, context, token)
        try:
            validation_error = _validate_configured_request(request, self._configuration)
            if validation_error is not None:
                result = AgentRunResult(
                    run_id=request.run_id,
                    status=AgentRunStatus.FAILED,
                    model_turns=0,
                    tool_calls=0,
                    error_code=validation_error.code.value,
                    started_at=started_at,
                    completed_at=datetime.now(UTC),
                )
            else:
                result = await self._runtime.run(
                    request,
                    context,
                    cancellation=token,
                    _authority_binding=_authority_binding,
                )
        except asyncio.CancelledError:
            token.cancel()
            await self._finish(
                request,
                context,
                outcome=AgentRunOutcome.CANCELLED,
                started_clock=started_clock,
            )
            raise
        except Exception:
            await self._finish(
                request,
                context,
                outcome=AgentRunOutcome.FAILED,
                started_clock=started_clock,
            )
            raise

        await self._finish(
            request,
            context,
            outcome=_outcome_for_result(result),
            started_clock=started_clock,
            result=result,
        )
        return result

    async def _begin(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> tuple[datetime, float]:
        task = asyncio.current_task()
        if task is None:  # pragma: no cover - asyncio invariant
            raise RuntimeError("agent run requires an asyncio task")
        now = datetime.now(UTC)
        async with self._lock:
            if self._state is not AgentServiceState.RUNNING:
                raise AgentServiceUnavailableError()
            if request.run_id in self._active:
                raise AgentServiceUnavailableError()
            self._active[request.run_id] = _ActiveRun(
                task=cast(asyncio.Task[object], task),
                cancellation=cancellation,
            )
            self._started += 1
            self._last_started_at = now
            active = len(self._active)
        await self._signal_run(
            request,
            context,
            outcome=AgentRunOutcome.STARTED,
            active=active,
        )
        return now, time.perf_counter()

    async def _finish(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        outcome: AgentRunOutcome,
        started_clock: float,
        result: AgentRunResult | None = None,
    ) -> None:
        duration_ms = max(0, round((time.perf_counter() - started_clock) * 1_000))
        async with self._lock:
            self._active.pop(request.run_id, None)
            if outcome is AgentRunOutcome.COMPLETED:
                self._completed += 1
            elif outcome is AgentRunOutcome.REJECTED:
                self._rejected += 1
            elif outcome is AgentRunOutcome.CANCELLED:
                self._cancelled += 1
            elif outcome is AgentRunOutcome.TIMED_OUT:
                self._timed_out += 1
            else:
                self._failed += 1
            self._last_completed_at = datetime.now(UTC)
            active = len(self._active)
        await self._signal_run(
            request,
            context,
            outcome=outcome,
            active=active,
            duration_ms=duration_ms,
            result=result,
        )

    async def _drain_and_cancel(self, active: tuple[_ActiveRun, ...]) -> None:
        current = asyncio.current_task()
        runs = tuple(item for item in active if item.task is not current)
        if not runs:
            return
        for item in runs:
            item.cancellation.cancel()
        tasks = {item.task for item in runs}
        _done, pending = await asyncio.wait(
            tasks,
            timeout=self._configuration.limits.shutdown_grace.total_seconds(),
        )
        if not pending:
            return
        async with self._lock:
            self._forced_cancellations += len(pending)
        for task in pending:
            task.cancel()
        _done, stubborn = await asyncio.wait(
            pending,
            timeout=self._configuration.limits.cancellation_grace.total_seconds(),
        )
        for task in stubborn:
            task.add_done_callback(_consume_task)

    async def _signal_lifecycle(self, phase: str) -> None:
        snapshot = await self.snapshot()
        metadata = {
            "agent_id": str(self._configuration.agent_id),
            "state": snapshot.state.value,
            "tools": str(snapshot.tools),
            "enabled_tools": str(snapshot.enabled_tools),
            "active": str(snapshot.active),
        }
        name = f"agent.runtime.{phase}"
        options = self._configuration.observability
        if options.events_enabled:
            try:
                await self._events.emit(
                    name,
                    source=self._configuration.source,
                    payload={},
                    metadata=metadata,
                )
            except Exception:
                pass
        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.SYSTEM,
                    action=name,
                    resource=agent_run_resource(self._configuration.agent_id),
                    actor="phoenix",
                    outcome=AuditOutcome.SUCCEEDED,
                    severity=AuditSeverity.INFO,
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass
        if options.logs_enabled and self._observability is not None:
            try:
                await self._observability.log(
                    name,
                    source=self._configuration.source,
                    message=f"agent runtime {phase}",
                    attributes=metadata,
                )
            except Exception:
                pass

    async def _signal_tool_registration(self, descriptor: ToolDescriptor) -> None:
        metadata = {
            "agent_id": str(self._configuration.agent_id),
            "tool_id": str(descriptor.tool_id),
            "effect": descriptor.effect.value,
            "availability": descriptor.availability.value,
            "approval_may_be_required": str(descriptor.approval_may_be_required).lower(),
        }
        name = "agent.tool.registered"
        options = self._configuration.observability
        if options.events_enabled:
            try:
                await self._events.emit(
                    name,
                    source=self._configuration.source,
                    payload={},
                    metadata=metadata,
                )
            except Exception:
                pass
        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.CONFIGURATION,
                    action="agent.tool.register",
                    resource=(f"agent:{self._configuration.agent_id}/tool:{descriptor.tool_id}"),
                    actor="phoenix",
                    outcome=AuditOutcome.SUCCEEDED,
                    severity=AuditSeverity.INFO,
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass
        if self._observability is not None:
            try:
                if options.logs_enabled:
                    await self._observability.log(
                        name,
                        source=self._configuration.source,
                        message="agent tool registration activated",
                        severity=Severity.INFO,
                        attributes=metadata,
                    )
                if options.metrics_enabled:
                    await self._observability.metric(
                        "agent.tools.registered",
                        1,
                        source=self._configuration.source,
                        kind=MetricKind.COUNTER,
                        unit="tool",
                        attributes={
                            "effect": descriptor.effect.value,
                            "availability": descriptor.availability.value,
                        },
                    )
            except Exception:
                pass

    async def _signal_run(
        self,
        request: AgentRunRequest,
        context: SecurityContext | None,
        *,
        outcome: AgentRunOutcome,
        active: int,
        duration_ms: int | None = None,
        result: AgentRunResult | None = None,
    ) -> None:
        name = f"agent.run.{outcome.value}"
        metadata = _safe_run_metadata(
            request,
            outcome=outcome,
            active=active,
            duration_ms=duration_ms,
            result=result,
        )
        correlation_id = None if context is None else context.correlation_id
        if correlation_id is None:
            correlation_id = str(request.run_id)
        options = self._configuration.observability
        if options.events_enabled:
            try:
                await self._events.emit(
                    name,
                    source=self._configuration.source,
                    payload={},
                    metadata={key: str(value) for key, value in metadata.items()},
                    correlation_id=correlation_id,
                    causation_id=request.run_id.value,
                )
            except Exception:
                pass
        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.OTHER,
                    action=AGENT_RUN_ACTION,
                    resource=agent_run_resource(request.agent_id),
                    context=context,
                    actor="phoenix" if context is None else None,
                    outcome=_audit_outcome(outcome),
                    severity=_audit_severity(outcome),
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass
        if self._observability is not None:
            try:
                if options.logs_enabled:
                    await self._observability.log(
                        name,
                        source=self._configuration.source,
                        message=f"agent run {outcome.value}",
                        severity=_observation_severity(outcome),
                        attributes=metadata,
                        correlation_id=correlation_id,
                        causation_id=request.run_id.value,
                    )
                if options.metrics_enabled:
                    await self._observability.metric(
                        "agent.runs",
                        1,
                        source=self._configuration.source,
                        kind=MetricKind.COUNTER,
                        unit="run",
                        attributes={"outcome": outcome.value},
                        correlation_id=correlation_id,
                        causation_id=request.run_id.value,
                    )
                    await self._observability.metric(
                        "agent.active",
                        active,
                        source=self._configuration.source,
                        kind=MetricKind.GAUGE,
                        unit="run",
                        correlation_id=correlation_id,
                        causation_id=request.run_id.value,
                    )
            except Exception:
                pass


def _validate_configured_request(
    request: AgentRunRequest,
    configuration: AgentServiceConfiguration,
) -> AgentError | None:
    if (
        request.agent_id != configuration.agent_id
        or request.provider_id != configuration.provider_id
        or request.model_id != configuration.model_id
    ):
        return AgentAuthorizationRejectedError()
    if not configuration.limits.contains(request.limits):
        return AgentLimitExceededError()
    return None


def _outcome_for_result(result: AgentRunResult) -> AgentRunOutcome:
    if result.status is AgentRunStatus.COMPLETED:
        return AgentRunOutcome.COMPLETED
    if result.status is AgentRunStatus.CANCELLED:
        return AgentRunOutcome.CANCELLED
    if result.error_code == AgentErrorCode.TIMEOUT.value:
        return AgentRunOutcome.TIMED_OUT
    if result.error_code in {
        AgentErrorCode.AUTHORIZATION_REJECTED.value,
        AgentErrorCode.APPROVAL_REJECTED.value,
        AgentErrorCode.LIMIT_EXCEEDED.value,
        AgentErrorCode.MALFORMED_PROPOSAL.value,
        AgentErrorCode.SCHEMA_INVALID.value,
        AgentErrorCode.TOOL_NOT_FOUND.value,
    }:
        return AgentRunOutcome.REJECTED
    return AgentRunOutcome.FAILED


def _safe_run_metadata(
    request: AgentRunRequest,
    *,
    outcome: AgentRunOutcome,
    active: int,
    duration_ms: int | None,
    result: AgentRunResult | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "agent_id": str(request.agent_id),
        "run_id": str(request.run_id),
        "provider_id": str(request.provider_id),
        "model_id": str(request.model_id),
        "outcome": outcome.value,
        "active": active,
    }
    if duration_ms is not None:
        metadata["duration_ms"] = duration_ms
    if result is not None:
        metadata["status"] = result.status.value
        metadata["model_turns"] = result.model_turns
        metadata["tool_calls"] = result.tool_calls
        if result.error_code is not None:
            metadata["error_code"] = result.error_code
    return metadata


def _audit_outcome(outcome: AgentRunOutcome) -> AuditOutcome:
    if outcome is AgentRunOutcome.COMPLETED:
        return AuditOutcome.SUCCEEDED
    if outcome is AgentRunOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is AgentRunOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    if outcome is AgentRunOutcome.STARTED:
        return AuditOutcome.UNKNOWN
    return AuditOutcome.FAILED


def _audit_severity(outcome: AgentRunOutcome) -> AuditSeverity:
    if outcome in {AgentRunOutcome.FAILED, AgentRunOutcome.TIMED_OUT}:
        return AuditSeverity.ERROR
    if outcome in {AgentRunOutcome.REJECTED, AgentRunOutcome.CANCELLED}:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: AgentRunOutcome) -> Severity:
    if outcome in {AgentRunOutcome.FAILED, AgentRunOutcome.TIMED_OUT}:
        return Severity.ERROR
    if outcome in {AgentRunOutcome.REJECTED, AgentRunOutcome.CANCELLED}:
        return Severity.WARNING
    return Severity.INFO


async def _close_bounded(
    resource: object,
    *,
    timeout_seconds: float,
    cancellation_grace_seconds: float,
) -> None:
    operation = asyncio.create_task(_close_resource(resource))
    try:
        done, _pending = await asyncio.wait({operation}, timeout=timeout_seconds)
        if operation in done:
            operation.result()
            return
        operation.cancel()
        done, _pending = await asyncio.wait(
            {operation},
            timeout=cancellation_grace_seconds,
        )
        if operation in done:
            try:
                operation.result()
            except asyncio.CancelledError as exception:
                raise TimeoutError("agent shutdown close timed out") from exception
            return
        operation.add_done_callback(_consume_task)
        raise TimeoutError("agent shutdown close timed out")
    except asyncio.CancelledError:
        if not operation.done():
            operation.cancel()
            operation.add_done_callback(_consume_task)
        raise


async def _close_resource(resource: object) -> None:
    close = getattr(resource, "aclose", None)
    if callable(close):
        if inspect.iscoroutinefunction(close):
            await cast(Awaitable[object], close())
        else:
            result = await asyncio.to_thread(close)
            if inspect.isawaitable(result):
                await cast(Awaitable[object], result)
        return
    close = getattr(resource, "close", None)
    if callable(close):
        if inspect.iscoroutinefunction(close):
            await cast(Awaitable[object], close())
        else:
            result = await asyncio.to_thread(close)
            if inspect.isawaitable(result):
                await cast(Awaitable[object], result)


def _consume_task[T](task: asyncio.Task[T]) -> None:
    if task.cancelled():
        return
    try:
        task.exception()
    except BaseException:
        pass
