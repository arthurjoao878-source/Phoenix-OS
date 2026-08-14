"""Opt-in Runtime composition for secure Phoenix agent workspaces."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from phoenix_os.agent.errors import AgentServiceUnavailableError
from phoenix_os.agent.workspace_administration import AgentWorkspaceAdministration
from phoenix_os.agent.workspace_authorization import PolicyEngineWorkspaceAuthorizer
from phoenix_os.agent.workspace_backing import (
    InMemoryWorkspaceBackingAdapter,
    WorkspaceBackingAdapter,
)
from phoenix_os.agent.workspace_cleanup_runtime import (
    AgentWorkspaceCleanupRuntime,
    AgentWorkspaceCleanupRuntimeConfiguration,
)
from phoenix_os.agent.workspace_contracts import (
    ArtifactDeleteRequest,
    ArtifactExportRequest,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactListResult,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactRecord,
    ArtifactTransferReceipt,
    ArtifactWriteRequest,
    WorkspaceLimits,
)
from phoenix_os.agent.workspace_observer import ContentFreeAgentWorkspaceObserver
from phoenix_os.agent.workspace_runtime import (
    AgentWorkspaceRuntimeConfiguration,
    AgentWorkspaceRuntimeOwner,
)
from phoenix_os.agent.workspace_service import AgentWorkspaceService
from phoenix_os.agent.workspace_store import StateStoreWorkspaceStore
from phoenix_os.agent.workspace_transfer import WorkspaceTransferAdapter
from phoenix_os.agent.workspace_transfer_runtime import (
    AgentWorkspaceTransferRuntime,
    AgentWorkspaceTransferRuntimeConfiguration,
)
from phoenix_os.audit import AuditLedger
from phoenix_os.events import EventBus
from phoenix_os.observability import ObservabilityHub
from phoenix_os.policy import PolicyEngine, SecurityContext
from phoenix_os.runtime import ComponentSpec, RuntimeContext
from phoenix_os.state import MemoryStateStore, StateStore

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AgentWorkspaceRuntimeService:
    """Runtime-gated authorized workspace service.

    The core service is intentionally unavailable until authoritative recovery has
    succeeded and the owner is running. Runtime shutdown closes this boundary before
    the owner closes its authoritative store and backing adapter.
    """

    def __init__(
        self,
        *,
        core: AgentWorkspaceService,
        owner: AgentWorkspaceRuntimeOwner,
        transfer: AgentWorkspaceTransferRuntime | None,
    ) -> None:
        if not isinstance(core, AgentWorkspaceService):
            raise TypeError("core must be AgentWorkspaceService")
        if not isinstance(owner, AgentWorkspaceRuntimeOwner):
            raise TypeError("owner must be AgentWorkspaceRuntimeOwner")
        if transfer is not None and not isinstance(
            transfer,
            AgentWorkspaceTransferRuntime,
        ):
            raise TypeError("transfer must be AgentWorkspaceTransferRuntime or None")
        self._core = core
        self._owner = owner
        self._transfer = transfer
        self._started = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed or self._core.closed or self._owner.closed

    @property
    def running(self) -> bool:
        return self._started and not self._closed and not self._core.closed and self._owner.running

    @property
    def limits(self) -> WorkspaceLimits:
        return self._core.limits

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._closed or self._core.closed or not self._owner.running:
            raise AgentServiceUnavailableError()
        if self._started:
            return
        self._started = True

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._started = False
        await self._core.close()

    async def list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
    ) -> ArtifactListResult:
        self._ensure_running()
        return await self._core.list(request, context)

    async def read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> ArtifactReadResult | None:
        self._ensure_running()
        return await self._core.read(request, context)

    async def write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> ArtifactRecord:
        self._ensure_running()
        return await self._core.write(request, context)

    async def delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
    ) -> None:
        self._ensure_running()
        await self._core.delete(request, context)

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        self._ensure_running()
        transfer = self._transfer
        if transfer is None:
            raise AgentServiceUnavailableError()
        return await transfer.import_artifact(request, context)

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        self._ensure_running()
        transfer = self._transfer
        if transfer is None:
            raise AgentServiceUnavailableError()
        return await transfer.export_artifact(request, context)

    def _ensure_running(self) -> None:
        if not self.running:
            raise AgentServiceUnavailableError()


@dataclass(frozen=True, slots=True)
class AgentWorkspaceRuntimeStack:
    """Reviewed Runtime-owned workspace services for explicit opt-in composition."""

    configuration: AgentWorkspaceRuntimeConfiguration
    backing: WorkspaceBackingAdapter
    store: StateStoreWorkspaceStore
    core: AgentWorkspaceService
    service: AgentWorkspaceRuntimeService
    owner: AgentWorkspaceRuntimeOwner
    observer: ContentFreeAgentWorkspaceObserver
    administration: AgentWorkspaceAdministration
    cleanup: AgentWorkspaceCleanupRuntime
    transfer: AgentWorkspaceTransferRuntime | None
    components: tuple[ComponentSpec, ...]


def create_agent_workspace_runtime_stack(
    *,
    configuration: AgentWorkspaceRuntimeConfiguration,
    policy: PolicyEngine,
    events: EventBus | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
    state_store: StateStore | None = None,
    backing: WorkspaceBackingAdapter | None = None,
    transfer_adapter: WorkspaceTransferAdapter | None = None,
    transfer_configuration: AgentWorkspaceTransferRuntimeConfiguration | None = None,
    cleanup_configuration: AgentWorkspaceCleanupRuntimeConfiguration | None = None,
    clock: Clock = _utc_now,
) -> AgentWorkspaceRuntimeStack:
    """Compose one workspace stack with explicit finite Runtime ownership."""

    if not isinstance(configuration, AgentWorkspaceRuntimeConfiguration):
        raise TypeError("configuration must be AgentWorkspaceRuntimeConfiguration")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    if events is not None and not isinstance(events, EventBus):
        raise TypeError("events must be EventBus or None")
    if audit is not None and not isinstance(audit, AuditLedger):
        raise TypeError("audit must be AuditLedger or None")
    if observability is not None and not isinstance(observability, ObservabilityHub):
        raise TypeError("observability must be ObservabilityHub or None")
    if backing is not None and not isinstance(backing, WorkspaceBackingAdapter):
        raise TypeError("backing must implement WorkspaceBackingAdapter")
    if transfer_adapter is not None and not isinstance(
        transfer_adapter,
        WorkspaceTransferAdapter,
    ):
        raise TypeError("transfer_adapter must implement WorkspaceTransferAdapter")
    if transfer_configuration is not None and not isinstance(
        transfer_configuration,
        AgentWorkspaceTransferRuntimeConfiguration,
    ):
        raise TypeError("transfer_configuration must be AgentWorkspaceTransferRuntimeConfiguration")
    if transfer_configuration is not None and transfer_adapter is None:
        raise ValueError("transfer_configuration requires transfer_adapter")
    if cleanup_configuration is not None and not isinstance(
        cleanup_configuration,
        AgentWorkspaceCleanupRuntimeConfiguration,
    ):
        raise TypeError("cleanup_configuration must be AgentWorkspaceCleanupRuntimeConfiguration")
    if not callable(clock):
        raise TypeError("clock must be callable")

    owns_state_store = state_store is None
    resolved_state = MemoryStateStore(clock=clock) if state_store is None else state_store
    resolved_backing: WorkspaceBackingAdapter = (
        InMemoryWorkspaceBackingAdapter() if backing is None else backing
    )
    observer = ContentFreeAgentWorkspaceObserver(
        events=EventBus() if events is None else events,
        audit=audit,
        observability=observability,
    )

    store = StateStoreWorkspaceStore(
        resolved_state,
        resolved_backing,
        limits=configuration.limits,
        clock=clock,
        owns_state_store=owns_state_store,
        owns_backing=True,
    )
    owner = AgentWorkspaceRuntimeOwner(
        configuration=configuration,
        store=store,
    )
    authorizer = PolicyEngineWorkspaceAuthorizer(policy)
    core = AgentWorkspaceService(
        store=store,
        authorizer=authorizer,
        transfer_adapter=transfer_adapter,
        limits=configuration.limits,
        observer=observer,
        clock=clock,
    )
    cleanup = AgentWorkspaceCleanupRuntime(
        configuration=(
            AgentWorkspaceCleanupRuntimeConfiguration()
            if cleanup_configuration is None
            else cleanup_configuration
        ),
        owner=owner,
        namespace=configuration.namespace,
        observer=observer,
    )

    transfer: AgentWorkspaceTransferRuntime | None = None
    if transfer_adapter is not None:
        transfer = AgentWorkspaceTransferRuntime(
            configuration=(
                AgentWorkspaceTransferRuntimeConfiguration()
                if transfer_configuration is None
                else transfer_configuration
            ),
            service=core,
            observer=observer,
        )

    service = AgentWorkspaceRuntimeService(
        core=core,
        owner=owner,
        transfer=transfer,
    )
    administration = AgentWorkspaceAdministration(
        runtime=service,
        store=store,
        authorizer=authorizer,
        observer=observer,
        operation_timeout=configuration.operation_timeout,
    )

    components: tuple[ComponentSpec, ...] = (
        ComponentSpec("agent.workspace.owner", owner),
        ComponentSpec("agent.workspace.observer", observer),
        ComponentSpec("agent.workspace.cleanup", cleanup),
        *(() if transfer is None else (ComponentSpec("agent.workspace.transfer", transfer),)),
        ComponentSpec("agent.workspace.service", service),
    )

    return AgentWorkspaceRuntimeStack(
        configuration=configuration,
        backing=resolved_backing,
        store=store,
        core=core,
        service=service,
        owner=owner,
        observer=observer,
        administration=administration,
        cleanup=cleanup,
        transfer=transfer,
        components=components,
    )
