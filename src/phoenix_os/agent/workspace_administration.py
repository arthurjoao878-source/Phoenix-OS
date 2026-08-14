"""Content-free bounded administration for secure agent workspaces."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from phoenix_os.agent.errors import (
    AgentError,
    AgentServiceUnavailableError,
    AgentTimeoutError,
)
from phoenix_os.agent.workspace_authorization import WorkspaceAuthorizer
from phoenix_os.agent.workspace_contracts import (
    MAX_WORKSPACE_ARTIFACT_BYTES,
    MAX_WORKSPACE_ARTIFACTS_PER_SCOPE,
    MAX_WORKSPACE_SCOPE_TOTAL_BYTES,
    WorkspaceLimits,
    WorkspaceScope,
)
from phoenix_os.agent.workspace_observer import (
    AgentWorkspaceObserver,
    AgentWorkspaceOperation,
    AgentWorkspaceOperationObservation,
    AgentWorkspaceOperationOutcome,
    NullAgentWorkspaceObserver,
    workspace_observation_failure,
)
from phoenix_os.agent.workspace_runtime import MAX_WORKSPACE_RUNTIME_OPERATION_TIMEOUT
from phoenix_os.policy import SecurityContext

DEFAULT_WORKSPACE_ADMINISTRATION_RECORDS = 256
MAX_WORKSPACE_ADMINISTRATION_RECORDS = 4_096


def _aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _bounded_non_negative(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")


def _duration_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1_000))


def _consume_administration_task_result(
    task: asyncio.Task[WorkspaceAdministrationScan],
) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


def _consume_administration_authorization_task_result(
    task: asyncio.Task[None],
) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@dataclass(frozen=True, slots=True)
class WorkspaceAdministrationScan:
    """Internal content-free result from one bounded authoritative metadata scan."""

    scope: WorkspaceScope
    scanned_records: int
    active_artifacts: int
    active_bytes: int
    expired_artifacts: int
    tombstones: int
    truncated: bool
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        for label, value in (
            ("scanned_records", self.scanned_records),
            ("active_artifacts", self.active_artifacts),
            ("expired_artifacts", self.expired_artifacts),
            ("tombstones", self.tombstones),
        ):
            _bounded_non_negative(
                value,
                label=label,
                maximum=MAX_WORKSPACE_ADMINISTRATION_RECORDS,
            )
        _bounded_non_negative(
            self.active_bytes,
            label="active_bytes",
            maximum=MAX_WORKSPACE_SCOPE_TOTAL_BYTES,
        )
        if self.active_bytes > self.active_artifacts * MAX_WORKSPACE_ARTIFACT_BYTES:
            raise ValueError("workspace administration active byte counters are inconsistent")
        if self.active_artifacts + self.expired_artifacts + self.tombstones != self.scanned_records:
            raise ValueError("workspace administration counters are inconsistent")
        if not isinstance(self.truncated, bool):
            raise TypeError("truncated must be bool")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class AgentWorkspaceAdministrationSnapshot:
    """Reviewed content-free bounded administration for one exact workspace scope."""

    scope: WorkspaceScope
    scanned_records: int
    active_artifacts: int
    active_bytes: int
    expired_artifacts: int
    tombstones: int
    truncated: bool
    record_limit: int
    max_artifact_bytes: int
    max_artifacts_per_scope: int
    max_total_bytes_per_scope: int
    created_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        for label, value in (
            ("scanned_records", self.scanned_records),
            ("active_artifacts", self.active_artifacts),
            ("expired_artifacts", self.expired_artifacts),
            ("tombstones", self.tombstones),
        ):
            _bounded_non_negative(
                value,
                label=label,
                maximum=MAX_WORKSPACE_ADMINISTRATION_RECORDS,
            )
        if self.active_artifacts + self.expired_artifacts + self.tombstones != self.scanned_records:
            raise ValueError("workspace administration counters are inconsistent")
        if (
            isinstance(self.record_limit, bool)
            or not isinstance(self.record_limit, int)
            or not 1 <= self.record_limit <= MAX_WORKSPACE_ADMINISTRATION_RECORDS
        ):
            raise ValueError("record_limit is outside supported bounds")
        if self.scanned_records > self.record_limit:
            raise ValueError("scanned_records exceeds record_limit")
        if not isinstance(self.truncated, bool):
            raise TypeError("truncated must be bool")
        if self.truncated and self.scanned_records != self.record_limit:
            raise ValueError("truncated administration snapshot must fill record_limit")
        _bounded_non_negative(
            self.active_bytes,
            label="active_bytes",
            maximum=MAX_WORKSPACE_SCOPE_TOTAL_BYTES,
        )
        if (
            isinstance(self.max_artifact_bytes, bool)
            or not isinstance(self.max_artifact_bytes, int)
            or not 1 <= self.max_artifact_bytes <= MAX_WORKSPACE_ARTIFACT_BYTES
        ):
            raise ValueError("max_artifact_bytes is outside supported bounds")
        if (
            isinstance(self.max_artifacts_per_scope, bool)
            or not isinstance(self.max_artifacts_per_scope, int)
            or not 1 <= self.max_artifacts_per_scope <= MAX_WORKSPACE_ARTIFACTS_PER_SCOPE
        ):
            raise ValueError("max_artifacts_per_scope is outside supported bounds")
        if (
            isinstance(self.max_total_bytes_per_scope, bool)
            or not isinstance(self.max_total_bytes_per_scope, int)
            or not 1 <= self.max_total_bytes_per_scope <= MAX_WORKSPACE_SCOPE_TOTAL_BYTES
        ):
            raise ValueError("max_total_bytes_per_scope is outside supported bounds")
        if self.active_artifacts > self.max_artifacts_per_scope:
            raise ValueError("active_artifacts exceeds configured workspace bounds")
        if self.active_bytes > self.active_artifacts * self.max_artifact_bytes:
            raise ValueError("active_bytes exceeds configured active artifact bounds")
        if self.active_bytes > self.max_total_bytes_per_scope:
            raise ValueError("active_bytes exceeds configured workspace bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported workspace administration snapshot version")
        _aware(self.created_at, label="created_at")


@runtime_checkable
class _WorkspaceAdministrationRuntime(Protocol):
    @property
    def running(self) -> bool: ...

    @property
    def limits(self) -> WorkspaceLimits: ...


@runtime_checkable
class _WorkspaceAdministrableStore(Protocol):
    @property
    def closed(self) -> bool: ...

    async def administration_scan(
        self,
        *,
        scope: WorkspaceScope,
        max_records: int,
    ) -> WorkspaceAdministrationScan: ...


class AgentWorkspaceAdministration:
    """Expose only exact-scope, content-free, bounded workspace administration."""

    def __init__(
        self,
        *,
        runtime: _WorkspaceAdministrationRuntime,
        store: _WorkspaceAdministrableStore,
        authorizer: WorkspaceAuthorizer,
        observer: AgentWorkspaceObserver | None = None,
        max_records_per_snapshot: int = DEFAULT_WORKSPACE_ADMINISTRATION_RECORDS,
        operation_timeout: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(runtime, _WorkspaceAdministrationRuntime):
            raise TypeError("runtime must implement the workspace administration runtime")
        if not isinstance(store, _WorkspaceAdministrableStore):
            raise TypeError("store must implement the workspace administration store")
        if not isinstance(authorizer, WorkspaceAuthorizer):
            raise TypeError("authorizer must implement WorkspaceAuthorizer")
        resolved_observer = NullAgentWorkspaceObserver() if observer is None else observer
        if not isinstance(resolved_observer, AgentWorkspaceObserver):
            raise TypeError("observer must implement AgentWorkspaceObserver")
        if (
            isinstance(max_records_per_snapshot, bool)
            or not isinstance(max_records_per_snapshot, int)
            or not 1 <= max_records_per_snapshot <= MAX_WORKSPACE_ADMINISTRATION_RECORDS
        ):
            raise ValueError("max_records_per_snapshot is outside supported bounds")
        if not isinstance(operation_timeout, timedelta):
            raise TypeError("operation_timeout must be timedelta")
        if (
            operation_timeout <= timedelta(0)
            or operation_timeout > MAX_WORKSPACE_RUNTIME_OPERATION_TIMEOUT
        ):
            raise ValueError("operation_timeout is outside supported bounds")
        self._runtime = runtime
        self._store = store
        self._authorizer = authorizer
        self._observer = resolved_observer
        self._max_records_per_snapshot = max_records_per_snapshot
        self._operation_timeout = operation_timeout

    async def snapshot(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        max_records: int | None = None,
    ) -> AgentWorkspaceAdministrationSnapshot:
        if not isinstance(scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        resolved_max_records = (
            self._max_records_per_snapshot if max_records is None else max_records
        )
        if (
            isinstance(resolved_max_records, bool)
            or not isinstance(resolved_max_records, int)
            or not 1 <= resolved_max_records <= self._max_records_per_snapshot
        ):
            raise ValueError("max_records is outside configured administration bounds")

        started = time.perf_counter()
        deadline = started + self._operation_timeout.total_seconds()
        try:
            self._ensure_running()
            await self._authorize_with_deadline(
                scope,
                context,
                deadline=deadline,
            )
            self._ensure_running()
            scan = await self._scan_with_deadline(
                scope=scope,
                max_records=resolved_max_records,
                deadline=deadline,
            )
            self._ensure_running()
            if not isinstance(scan, WorkspaceAdministrationScan):
                raise AgentServiceUnavailableError()
            if scan.scope != scope or scan.scanned_records > resolved_max_records:
                raise AgentServiceUnavailableError()
            limits = self._runtime.limits
            snapshot = AgentWorkspaceAdministrationSnapshot(
                scope=scope,
                scanned_records=scan.scanned_records,
                active_artifacts=scan.active_artifacts,
                active_bytes=scan.active_bytes,
                expired_artifacts=scan.expired_artifacts,
                tombstones=scan.tombstones,
                truncated=scan.truncated,
                record_limit=resolved_max_records,
                max_artifact_bytes=limits.max_artifact_bytes,
                max_artifacts_per_scope=limits.max_artifacts_per_scope,
                max_total_bytes_per_scope=limits.max_total_bytes_per_scope,
                created_at=scan.created_at,
            )
        except asyncio.CancelledError as exception:
            self._observe_failure(scope, context, exception, started=started)
            raise
        except AgentError as exception:
            self._observe_failure(scope, context, exception, started=started)
            raise
        except Exception:
            sanitized = AgentServiceUnavailableError()
            self._observe_failure(scope, context, sanitized, started=started)
            raise sanitized from None

        self._observe(
            AgentWorkspaceOperationObservation(
                operation=AgentWorkspaceOperation.ADMIN,
                outcome=AgentWorkspaceOperationOutcome.SUCCEEDED,
                namespace=scope.namespace,
                scope=scope,
                item_count=snapshot.scanned_records,
                truncated=snapshot.truncated,
                duration_ms=_duration_ms(started),
            ),
            context,
        )
        return snapshot

    @staticmethod
    def _remaining_operation_seconds(deadline: float) -> float:
        return max(0.0, deadline - time.perf_counter())

    async def _authorize_with_deadline(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        deadline: float,
    ) -> None:
        remaining = self._remaining_operation_seconds(deadline)
        if remaining <= 0:
            raise AgentTimeoutError()

        task = asyncio.create_task(
            self._authorizer.authorize_admin(scope, context),
            name="phoenix-agent-workspace-administration-authorization",
        )
        try:
            done, pending = await asyncio.wait({task}, timeout=remaining)
        except asyncio.CancelledError:
            task.cancel()
            task.add_done_callback(_consume_administration_authorization_task_result)
            raise

        if pending or task not in done:
            task.cancel()
            task.add_done_callback(_consume_administration_authorization_task_result)
            raise AgentTimeoutError()

        try:
            task.result()
        except asyncio.CancelledError:
            raise
        except AgentError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

    async def _scan_with_deadline(
        self,
        *,
        scope: WorkspaceScope,
        max_records: int,
        deadline: float,
    ) -> WorkspaceAdministrationScan:
        remaining = self._remaining_operation_seconds(deadline)
        if remaining <= 0:
            raise AgentTimeoutError()

        task = asyncio.create_task(
            self._store.administration_scan(
                scope=scope,
                max_records=max_records,
            ),
            name="phoenix-agent-workspace-administration",
        )
        try:
            done, pending = await asyncio.wait(
                {task},
                timeout=remaining,
            )
        except asyncio.CancelledError:
            task.cancel()
            task.add_done_callback(_consume_administration_task_result)
            raise

        if pending or task not in done:
            task.cancel()
            task.add_done_callback(_consume_administration_task_result)
            raise AgentTimeoutError()

        try:
            return task.result()
        except asyncio.CancelledError:
            raise
        except AgentError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

    def _ensure_running(self) -> None:
        if not self._runtime.running or self._store.closed:
            raise AgentServiceUnavailableError()

    def _observe_failure(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        exception: BaseException,
        *,
        started: float,
    ) -> None:
        outcome, reason_code = workspace_observation_failure(exception)
        self._observe(
            AgentWorkspaceOperationObservation(
                operation=AgentWorkspaceOperation.ADMIN,
                outcome=outcome,
                namespace=scope.namespace,
                scope=scope,
                duration_ms=_duration_ms(started),
                reason_code=reason_code,
            ),
            context,
        )

    def _observe(
        self,
        observation: AgentWorkspaceOperationObservation,
        context: SecurityContext,
    ) -> None:
        try:
            self._observer.record(observation, context)
        except Exception:
            pass
