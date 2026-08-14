"""Content-free bounded operational observations for secure agent workspaces."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentError,
    AgentErrorCode,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentTimeoutError,
)
from phoenix_os.agent.workspace_authorization import (
    workspace_artifact_resource,
    workspace_scope_resource,
)
from phoenix_os.agent.workspace_contracts import (
    MAX_WORKSPACE_ARTIFACT_BYTES,
    MAX_WORKSPACE_RECOVERY_RECORDS,
    ArtifactId,
    ArtifactStatus,
    ArtifactTransferDirection,
    ArtifactVersion,
    WorkspaceNamespace,
    WorkspaceScope,
)
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext

WORKSPACE_OBSERVER_QUEUE_CAPACITY = 256
WORKSPACE_OBSERVER_SHUTDOWN_TIMEOUT = timedelta(seconds=5)
MAX_WORKSPACE_OBSERVATION_DURATION_MS = 2**63 - 1
_SAFE_REASON_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SOURCE = "phoenix.agent.workspace"


class AgentWorkspaceOperation(StrEnum):
    """Fixed Phoenix-owned workspace operations safe for telemetry."""

    LIST = "list"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    IMPORT = "import"
    EXPORT = "export"
    TRANSFER_IMPORT = "transfer.import"
    TRANSFER_EXPORT = "transfer.export"
    CLEANUP = "cleanup"


class AgentWorkspaceOperationOutcome(StrEnum):
    """Safe terminal categories for one workspace operation."""

    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AgentWorkspaceOperationObservation:
    """Typed content-free workspace operation metadata."""

    operation: AgentWorkspaceOperation
    outcome: AgentWorkspaceOperationOutcome
    namespace: WorkspaceNamespace
    scope: WorkspaceScope | None = None
    artifact_id: ArtifactId | None = None
    version: ArtifactVersion | None = None
    byte_count: int | None = None
    status: ArtifactStatus | None = None
    expires_at: datetime | None = None
    transfer_direction: ArtifactTransferDirection | None = None
    item_count: int | None = None
    truncated: bool | None = None
    duration_ms: int | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", AgentWorkspaceOperation(self.operation))
        object.__setattr__(self, "outcome", AgentWorkspaceOperationOutcome(self.outcome))
        if not isinstance(self.namespace, WorkspaceNamespace):
            raise TypeError("namespace must be WorkspaceNamespace")
        if self.scope is not None:
            if not isinstance(self.scope, WorkspaceScope):
                raise TypeError("scope must be WorkspaceScope")
            if self.scope.namespace != self.namespace:
                raise ValueError("scope namespace does not match observation namespace")
        if self.artifact_id is not None:
            if not isinstance(self.artifact_id, ArtifactId):
                raise TypeError("artifact_id must be ArtifactId")
            if self.scope is None:
                raise ValueError("artifact_id requires scope")
        if self.version is not None and not isinstance(self.version, ArtifactVersion):
            raise TypeError("version must be ArtifactVersion")
        if self.status is not None and not isinstance(self.status, ArtifactStatus):
            raise TypeError("status must be ArtifactStatus")
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime):
                raise TypeError("expires_at must be datetime")
            if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
                raise ValueError("expires_at must be timezone-aware")
        if self.transfer_direction is not None and not isinstance(
            self.transfer_direction,
            ArtifactTransferDirection,
        ):
            raise TypeError("transfer_direction must be ArtifactTransferDirection")
        _optional_non_negative_int(
            self.byte_count,
            label="byte_count",
            maximum=MAX_WORKSPACE_ARTIFACT_BYTES,
        )
        _optional_non_negative_int(
            self.item_count,
            label="item_count",
            maximum=MAX_WORKSPACE_RECOVERY_RECORDS,
        )
        _optional_non_negative_int(
            self.duration_ms,
            label="duration_ms",
            maximum=MAX_WORKSPACE_OBSERVATION_DURATION_MS,
        )
        if self.truncated is not None and not isinstance(self.truncated, bool):
            raise TypeError("truncated must be bool or None")
        if self.reason_code is not None:
            if not isinstance(self.reason_code, str):
                raise TypeError("reason_code must be str")
            normalized = self.reason_code.strip().lower()
            if _SAFE_REASON_CODE_PATTERN.fullmatch(normalized) is None:
                raise ValueError("reason_code must be a safe bounded identifier")
            object.__setattr__(self, "reason_code", normalized)

        expected_direction = {
            AgentWorkspaceOperation.IMPORT: ArtifactTransferDirection.IMPORT,
            AgentWorkspaceOperation.EXPORT: ArtifactTransferDirection.EXPORT,
            AgentWorkspaceOperation.TRANSFER_IMPORT: ArtifactTransferDirection.IMPORT,
            AgentWorkspaceOperation.TRANSFER_EXPORT: ArtifactTransferDirection.EXPORT,
        }.get(self.operation)
        if expected_direction is None:
            if self.transfer_direction is not None:
                raise ValueError("transfer_direction requires a transfer operation")
        elif self.transfer_direction is not expected_direction:
            raise ValueError("transfer operation requires its exact direction")

    @property
    def name(self) -> str:
        return f"agent.workspace.{self.operation.value}.{self.outcome.value}"

    def metadata(self) -> dict[str, object]:
        values: dict[str, object] = {
            "namespace": self.namespace.value,
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }
        if self.scope is not None:
            values["scope_kind"] = self.scope.kind.value
            values["scope_id"] = self.scope.scope_id.value
        if self.artifact_id is not None:
            values["artifact_id"] = str(self.artifact_id)
        if self.version is not None:
            values["version"] = self.version.value
        if self.byte_count is not None:
            values["byte_count"] = self.byte_count
        if self.status is not None:
            values["status"] = self.status.value
        if self.expires_at is not None:
            values["expires_at"] = self.expires_at.isoformat()
        if self.transfer_direction is not None:
            values["transfer_direction"] = self.transfer_direction.value
        if self.item_count is not None:
            values["item_count"] = self.item_count
        if self.truncated is not None:
            values["truncated"] = self.truncated
        if self.duration_ms is not None:
            values["duration_ms"] = self.duration_ms
        if self.reason_code is not None:
            values["reason_code"] = self.reason_code
        return values


@runtime_checkable
class AgentWorkspaceObserver(Protocol):
    """Non-blocking best-effort sink for content-free workspace facts."""

    def record(
        self,
        observation: AgentWorkspaceOperationObservation,
        context: SecurityContext | None = None,
    ) -> None: ...


class NullAgentWorkspaceObserver:
    """Default synchronous no-op preserving direct workspace compatibility."""

    def record(
        self,
        observation: AgentWorkspaceOperationObservation,
        context: SecurityContext | None = None,
    ) -> None:
        if not isinstance(observation, AgentWorkspaceOperationObservation):
            raise TypeError("observation must be AgentWorkspaceOperationObservation")
        if context is not None and not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext or None")


@dataclass(frozen=True, slots=True)
class _QueuedObservation:
    observation: AgentWorkspaceOperationObservation
    context: SecurityContext | None


class ContentFreeAgentWorkspaceObserver:
    """Deliver workspace telemetry through one finite best-effort Runtime worker."""

    def __init__(
        self,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("observability must be ObservabilityHub")
        self._events = events
        self._audit = audit
        self._observability = observability
        self._queue: asyncio.Queue[_QueuedObservation] = asyncio.Queue(
            maxsize=WORKSPACE_OBSERVER_QUEUE_CAPACITY
        )
        self._worker: asyncio.Task[None] | None = None
        self._started = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._started and not self._closed

    @property
    def queued_observations(self) -> int:
        return self._queue.qsize()

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._closed:
            raise AgentServiceUnavailableError()
        if self._started:
            return
        self._worker = asyncio.create_task(
            self._worker_loop(),
            name="phoenix-agent-workspace-observer",
        )
        self._started = True

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    def record(
        self,
        observation: AgentWorkspaceOperationObservation,
        context: SecurityContext | None = None,
    ) -> None:
        if not isinstance(observation, AgentWorkspaceOperationObservation):
            raise TypeError("observation must be AgentWorkspaceOperationObservation")
        if context is not None and not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext or None")
        if not self.running:
            return
        try:
            self._queue.put_nowait(_QueuedObservation(observation, context))
        except asyncio.QueueFull:
            # Observability is best effort. Fixed capacity prevents telemetry from
            # becoming a new availability or memory-pressure authority.
            pass

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._started = False

        worker = self._worker
        self._worker = None
        if worker is None:
            self._drop_queued()
            return

        loop = asyncio.get_running_loop()
        deadline = loop.time() + WORKSPACE_OBSERVER_SHUTDOWN_TIMEOUT.total_seconds()
        join_task = asyncio.create_task(
            self._queue.join(),
            name="phoenix-agent-workspace-observer-drain",
        )
        try:
            done, _pending = await asyncio.wait(
                {join_task},
                timeout=max(0.0, deadline - loop.time()),
            )
        except asyncio.CancelledError:
            join_task.cancel()
            join_task.add_done_callback(_consume_observer_join_result)
            worker.cancel()
            worker.add_done_callback(_consume_observer_worker_result)
            self._drop_queued()
            raise

        if join_task in done:
            _consume_observer_join_result(join_task)
        else:
            join_task.cancel()
            join_task.add_done_callback(_consume_observer_join_result)

        worker.cancel()
        try:
            await asyncio.wait(
                {worker},
                timeout=max(0.0, deadline - loop.time()),
            )
        except asyncio.CancelledError:
            worker.add_done_callback(_consume_observer_worker_result)
            self._drop_queued()
            raise
        if worker.done():
            _consume_observer_worker_result(worker)
        else:
            worker.add_done_callback(_consume_observer_worker_result)
        self._drop_queued()

    async def _worker_loop(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                await self._deliver(item)
            finally:
                self._queue.task_done()
            # close() stops admission before draining. If cancellation is suppressed
            # by a downstream observer dependency, a worker that eventually returns
            # must not park forever on another queue.get() after shutdown.
            if self._closed and self._queue.empty():
                return

    async def _deliver(self, item: _QueuedObservation) -> None:
        observation = item.observation
        context = item.context
        metadata = observation.metadata()
        event_metadata = {key: str(value) for key, value in metadata.items()}
        correlation_id = None if context is None else context.correlation_id
        causation_id = _causation_id(observation)

        try:
            await self._events.emit(
                observation.name,
                source=_SOURCE,
                payload={},
                metadata=event_metadata,
                correlation_id=correlation_id,
                causation_id=causation_id,
            )
        except Exception:
            pass

        if self._audit is not None and context is not None:
            try:
                await self._audit.record_security(
                    observation.name,
                    category=AuditCategory.OTHER,
                    action=f"workspace.{observation.operation.value}",
                    resource=_audit_resource(observation),
                    context=context,
                    outcome=_audit_outcome(observation.outcome),
                    severity=_audit_severity(observation.outcome),
                    details=metadata,
                    source=_SOURCE,
                )
            except Exception:
                pass

        if self._observability is not None:
            try:
                await self._observability.log(
                    observation.name,
                    source=_SOURCE,
                    message="workspace operation changed state",
                    severity=_observation_severity(observation.outcome),
                    attributes=metadata,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
                metric_attributes: dict[str, object] = {
                    "operation": observation.operation.value,
                    "outcome": observation.outcome.value,
                }
                if observation.transfer_direction is not None:
                    metric_attributes["transfer_direction"] = observation.transfer_direction.value
                await self._observability.metric(
                    "agent.workspace.operations",
                    1,
                    source=_SOURCE,
                    kind=MetricKind.COUNTER,
                    unit="operation",
                    attributes=metric_attributes,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
                if observation.duration_ms is not None:
                    await self._observability.metric(
                        "agent.workspace.operation.duration_ms",
                        observation.duration_ms,
                        source=_SOURCE,
                        kind=MetricKind.GAUGE,
                        unit="millisecond",
                        attributes={"operation": observation.operation.value},
                        correlation_id=correlation_id,
                        causation_id=causation_id,
                    )
            except Exception:
                pass

    def _drop_queued(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            else:
                self._queue.task_done()


def workspace_observation_failure(
    exception: BaseException,
) -> tuple[AgentWorkspaceOperationOutcome, str]:
    """Map arbitrary failures to fixed content-free telemetry categories."""

    if isinstance(exception, (asyncio.CancelledError, AgentCancelledError)):
        return AgentWorkspaceOperationOutcome.CANCELLED, AgentErrorCode.CANCELLED.value
    if isinstance(exception, AgentTimeoutError):
        return AgentWorkspaceOperationOutcome.TIMED_OUT, AgentErrorCode.TIMEOUT.value
    if isinstance(exception, AgentAuthorizationRejectedError):
        return (
            AgentWorkspaceOperationOutcome.REJECTED,
            AgentErrorCode.AUTHORIZATION_REJECTED.value,
        )
    if isinstance(exception, (AgentLimitExceededError, AgentStateConflictError)):
        return AgentWorkspaceOperationOutcome.REJECTED, exception.code.value
    if isinstance(exception, AgentError):
        return AgentWorkspaceOperationOutcome.FAILED, exception.code.value
    return AgentWorkspaceOperationOutcome.FAILED, AgentErrorCode.SERVICE_UNAVAILABLE.value


def _optional_non_negative_int(
    value: int | None,
    *,
    label: str,
    maximum: int,
) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer or None")
    if value < 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")


def _causation_id(observation: AgentWorkspaceOperationObservation) -> UUID | None:
    if observation.artifact_id is None:
        return None
    return observation.artifact_id.value


def _audit_resource(observation: AgentWorkspaceOperationObservation) -> str:
    if observation.scope is None:
        return f"agent-workspace:{observation.namespace.value}"
    if observation.artifact_id is None:
        return workspace_scope_resource(observation.scope)
    return workspace_artifact_resource(observation.scope, observation.artifact_id)


def _audit_outcome(outcome: AgentWorkspaceOperationOutcome) -> AuditOutcome:
    if outcome is AgentWorkspaceOperationOutcome.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if outcome is AgentWorkspaceOperationOutcome.REJECTED:
        return AuditOutcome.DENIED
    if outcome is AgentWorkspaceOperationOutcome.CANCELLED:
        return AuditOutcome.RESTRICTED
    return AuditOutcome.FAILED


def _audit_severity(outcome: AgentWorkspaceOperationOutcome) -> AuditSeverity:
    if outcome in {
        AgentWorkspaceOperationOutcome.FAILED,
        AgentWorkspaceOperationOutcome.TIMED_OUT,
    }:
        return AuditSeverity.ERROR
    if outcome in {
        AgentWorkspaceOperationOutcome.REJECTED,
        AgentWorkspaceOperationOutcome.CANCELLED,
    }:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _observation_severity(outcome: AgentWorkspaceOperationOutcome) -> Severity:
    if outcome in {
        AgentWorkspaceOperationOutcome.FAILED,
        AgentWorkspaceOperationOutcome.TIMED_OUT,
    }:
        return Severity.ERROR
    if outcome in {
        AgentWorkspaceOperationOutcome.REJECTED,
        AgentWorkspaceOperationOutcome.CANCELLED,
    }:
        return Severity.WARNING
    return Severity.INFO


def _consume_observer_worker_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


def _consume_observer_join_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
