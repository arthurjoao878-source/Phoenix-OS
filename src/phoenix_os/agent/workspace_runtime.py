"""Fail-closed Runtime-owned startup recovery for secure agent workspaces."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol, runtime_checkable

from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.workspace_contracts import (
    MAX_WORKSPACE_CLEANUP_RECORDS,
    MAX_WORKSPACE_RECOVERY_RECORDS,
    MAX_WORKSPACE_RECOVERY_SCOPES,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceRecoverySnapshot,
)
from phoenix_os.runtime import RuntimeContext

MAX_WORKSPACE_RUNTIME_OPERATION_TIMEOUT = timedelta(minutes=5)


def _consume_recovery_task_result(
    task: asyncio.Task[WorkspaceRecoverySnapshot],
) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


def _consume_close_task_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


def _consume_cleanup_task_result(
    task: asyncio.Task[tuple[str | None, int, int]],
) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@runtime_checkable
class WorkspaceRecoverableStore(Protocol):
    """Runtime-only recovery capability; normal WorkspaceStore stays unchanged."""

    @property
    def closed(self) -> bool: ...

    @property
    def limits(self) -> WorkspaceLimits: ...

    async def recover(
        self,
        *,
        namespace: WorkspaceNamespace,
        max_scopes: int,
        max_records: int,
    ) -> WorkspaceRecoverySnapshot: ...

    async def close(self) -> None: ...


@runtime_checkable
class _WorkspaceMaintainableStore(Protocol):
    """Runtime-only bounded cleanup capability kept off WorkspaceStore."""

    async def cleanup_expired_batch(
        self,
        *,
        namespace: WorkspaceNamespace,
        after: str | None,
        max_records: int,
    ) -> tuple[str | None, int, int]: ...


@dataclass(frozen=True, slots=True)
class AgentWorkspaceRuntimeConfiguration:
    """Finite opt-in startup recovery configuration for one workspace namespace."""

    namespace: WorkspaceNamespace
    limits: WorkspaceLimits = field(default_factory=WorkspaceLimits)
    operation_timeout: timedelta = timedelta(seconds=30)
    max_scopes_per_recovery: int = 1_024
    max_records_per_recovery: int = 100_000
    max_cleanup_records_per_cycle: int = 256

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, WorkspaceNamespace):
            raise TypeError("namespace must be WorkspaceNamespace")
        if not isinstance(self.limits, WorkspaceLimits):
            raise TypeError("limits must be WorkspaceLimits")
        if not isinstance(self.operation_timeout, timedelta):
            raise TypeError("operation_timeout must be timedelta")
        if (
            self.operation_timeout <= timedelta(0)
            or self.operation_timeout > MAX_WORKSPACE_RUNTIME_OPERATION_TIMEOUT
        ):
            raise ValueError("operation_timeout is outside supported bounds")
        if (
            isinstance(self.max_scopes_per_recovery, bool)
            or not isinstance(self.max_scopes_per_recovery, int)
            or not 1 <= self.max_scopes_per_recovery <= MAX_WORKSPACE_RECOVERY_SCOPES
        ):
            raise ValueError("max_scopes_per_recovery is outside supported bounds")
        if (
            isinstance(self.max_records_per_recovery, bool)
            or not isinstance(self.max_records_per_recovery, int)
            or not 1 <= self.max_records_per_recovery <= MAX_WORKSPACE_RECOVERY_RECORDS
        ):
            raise ValueError("max_records_per_recovery is outside supported bounds")
        if (
            isinstance(self.max_cleanup_records_per_cycle, bool)
            or not isinstance(self.max_cleanup_records_per_cycle, int)
            or not 1 <= self.max_cleanup_records_per_cycle <= MAX_WORKSPACE_CLEANUP_RECORDS
        ):
            raise ValueError("max_cleanup_records_per_cycle is outside supported bounds")


class AgentWorkspaceRuntimeOwner:
    """Runtime component that admits a workspace only after complete safe recovery."""

    def __init__(
        self,
        *,
        configuration: AgentWorkspaceRuntimeConfiguration,
        store: WorkspaceRecoverableStore,
    ) -> None:
        if not isinstance(configuration, AgentWorkspaceRuntimeConfiguration):
            raise TypeError("configuration must be AgentWorkspaceRuntimeConfiguration")
        if not isinstance(store, WorkspaceRecoverableStore):
            raise TypeError("store must implement WorkspaceRecoverableStore")
        if store.limits != configuration.limits:
            raise ValueError("runtime configuration and store limits must match")
        self._configuration = configuration
        self._store = store
        self._started = False
        self._closed = False
        self._last_recovery: WorkspaceRecoverySnapshot | None = None
        self._cleanup_cursor: str | None = None
        self._cleanup_task: asyncio.Task[tuple[str | None, int, int]] | None = None

    @property
    def running(self) -> bool:
        return self._started and not self._closed

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def last_recovery(self) -> WorkspaceRecoverySnapshot | None:
        return self._last_recovery

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._closed or self._store.closed:
            raise AgentServiceUnavailableError()
        if self._started:
            return
        try:
            recovery = await self.recover_once()
        except asyncio.CancelledError:
            await self.close()
            raise
        except Exception:
            await self.close()
            raise
        self._last_recovery = recovery
        self._started = True

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def recover_once(self) -> WorkspaceRecoverySnapshot:
        if self._closed or self._store.closed:
            raise AgentServiceUnavailableError()

        task = asyncio.create_task(
            self._store.recover(
                namespace=self._configuration.namespace,
                max_scopes=self._configuration.max_scopes_per_recovery,
                max_records=self._configuration.max_records_per_recovery,
            ),
            name="phoenix-agent-workspace-recovery",
        )
        try:
            done, pending = await asyncio.wait(
                {task},
                timeout=self._configuration.operation_timeout.total_seconds(),
            )
        except asyncio.CancelledError:
            task.cancel()
            task.add_done_callback(_consume_recovery_task_result)
            raise

        if pending:
            task.cancel()
            task.add_done_callback(_consume_recovery_task_result)
            raise AgentServiceUnavailableError()
        if task not in done:
            task.cancel()
            task.add_done_callback(_consume_recovery_task_result)
            raise AgentServiceUnavailableError()

        try:
            snapshot = task.result()
        except asyncio.CancelledError:
            raise
        except AgentError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None
        return self._validate_recovery_snapshot(snapshot)

    async def cleanup_once(self) -> int:
        """Process at most one deterministic bounded page of expired records."""

        if self._closed or self._store.closed or not self._started:
            raise AgentServiceUnavailableError()
        store = self._store
        if not isinstance(store, _WorkspaceMaintainableStore):
            raise AgentServiceUnavailableError()

        existing_task = self._cleanup_task
        if existing_task is not None:
            if not existing_task.done():
                raise AgentServiceUnavailableError()
            _consume_cleanup_task_result(existing_task)
            self._cleanup_task = None

        task = asyncio.create_task(
            store.cleanup_expired_batch(
                namespace=self._configuration.namespace,
                after=self._cleanup_cursor,
                max_records=self._configuration.max_cleanup_records_per_cycle,
            ),
            name="phoenix-agent-workspace-cleanup",
        )
        self._cleanup_task = task
        try:
            done, pending = await asyncio.wait(
                {task},
                timeout=self._configuration.operation_timeout.total_seconds(),
            )
        except asyncio.CancelledError:
            task.cancel()
            task.add_done_callback(_consume_cleanup_task_result)
            raise

        if pending or task not in done:
            task.cancel()
            task.add_done_callback(_consume_cleanup_task_result)
            raise AgentServiceUnavailableError()

        self._cleanup_task = None
        try:
            result = task.result()
        except asyncio.CancelledError:
            raise
        except AgentError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

        try:
            next_cursor, scanned, cleaned = result
        except Exception:
            raise AgentCodecError("workspace cleanup evidence is invalid") from None

        if (
            isinstance(scanned, bool)
            or not isinstance(scanned, int)
            or isinstance(cleaned, bool)
            or not isinstance(cleaned, int)
            or scanned < 0
            or scanned > self._configuration.max_cleanup_records_per_cycle
            or cleaned < 0
            or cleaned > scanned
        ):
            raise AgentCodecError("workspace cleanup evidence is invalid")

        if next_cursor is not None:
            if (
                not isinstance(next_cursor, str)
                or next_cursor != next_cursor.strip().lower()
                or not next_cursor.startswith("agent-workspace:record.")
                or len(next_cursor) > 512
                or (self._cleanup_cursor is not None and next_cursor <= self._cleanup_cursor)
            ):
                raise AgentCodecError("workspace cleanup evidence is invalid")

        page_is_full = scanned == self._configuration.max_cleanup_records_per_cycle
        if page_is_full != (next_cursor is not None):
            raise AgentCodecError("workspace cleanup evidence is invalid")

        self._cleanup_cursor = next_cursor
        return cleaned

    def _validate_recovery_snapshot(
        self,
        snapshot: WorkspaceRecoverySnapshot,
    ) -> WorkspaceRecoverySnapshot:
        if not isinstance(snapshot, WorkspaceRecoverySnapshot):
            raise AgentCodecError("workspace recovery evidence is invalid")
        if snapshot.namespace != self._configuration.namespace:
            raise AgentCodecError("workspace recovery evidence is invalid")
        if (
            snapshot.scopes > self._configuration.max_scopes_per_recovery
            or snapshot.records > self._configuration.max_records_per_recovery
        ):
            raise AgentCodecError("workspace recovery evidence is invalid")

        limits = self._configuration.limits
        if snapshot.active_artifacts > snapshot.scopes * limits.max_artifacts_per_scope:
            raise AgentCodecError("workspace recovery evidence is invalid")
        if snapshot.active_bytes > snapshot.scopes * limits.max_total_bytes_per_scope:
            raise AgentCodecError("workspace recovery evidence is invalid")
        return snapshot

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        cleanup_task = self._cleanup_task
        self._cleanup_task = None
        if cleanup_task is not None:
            cleanup_task.cancel()
            if cleanup_task.done():
                _consume_cleanup_task_result(cleanup_task)
            else:
                try:
                    cleanup_done, cleanup_pending = await asyncio.wait(
                        {cleanup_task},
                        timeout=self._configuration.operation_timeout.total_seconds(),
                    )
                except asyncio.CancelledError:
                    cleanup_task.add_done_callback(_consume_cleanup_task_result)
                    raise

                if cleanup_pending or cleanup_task not in cleanup_done:
                    cleanup_task.add_done_callback(_consume_cleanup_task_result)
                else:
                    _consume_cleanup_task_result(cleanup_task)

        task = asyncio.create_task(
            self._store.close(),
            name="phoenix-agent-workspace-close",
        )
        try:
            done, pending = await asyncio.wait(
                {task},
                timeout=self._configuration.operation_timeout.total_seconds(),
            )
        except asyncio.CancelledError:
            task.cancel()
            task.add_done_callback(_consume_close_task_result)
            raise

        if pending or task not in done:
            task.cancel()
            task.add_done_callback(_consume_close_task_result)
            return

        _consume_close_task_result(task)
