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


@dataclass(frozen=True, slots=True)
class AgentWorkspaceRuntimeConfiguration:
    """Finite opt-in startup recovery configuration for one workspace namespace."""

    namespace: WorkspaceNamespace
    limits: WorkspaceLimits = field(default_factory=WorkspaceLimits)
    operation_timeout: timedelta = timedelta(seconds=30)
    max_scopes_per_recovery: int = 1_024
    max_records_per_recovery: int = 100_000

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
        await self._store.close()
