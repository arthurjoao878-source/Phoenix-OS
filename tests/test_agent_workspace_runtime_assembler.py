from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
)
from phoenix_os.agent import (
    AgentId,
    AgentServiceConfiguration,
    AgentServiceUnavailableError,
    AgentWorkspaceCleanupRuntime,
    AgentWorkspaceCleanupRuntimeConfiguration,
    AgentWorkspaceRuntimeConfiguration,
    AgentWorkspaceRuntimeOwner,
    AgentWorkspaceRuntimeService,
    AgentWorkspaceTransferRuntime,
    AgentWorkspaceTransferRuntimeConfiguration,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactReadRequest,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    InMemoryWorkspaceBackingAdapter,
    StateStoreWorkspaceStore,
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceNamespace,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    agent_workspace_scope,
    create_agent_workspace_runtime_stack,
)
from phoenix_os.configuration import (
    Configuration,
    DependencyResolver,
    ServiceDefinition,
)
from phoenix_os.events import Event
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine, SecurityContext
from phoenix_os.runtime import RuntimeContext
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 8, 14, 5, tzinfo=UTC)


async def _base() -> tuple[Configuration, EventBus, Kernel, CapabilityRegistry]:
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    events = EventBus()
    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )
    capabilities = CapabilityRegistry(events=events)
    return configuration, events, kernel, capabilities


def _agent_configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
    )


def _model_adapter() -> DeterministicModelTurnAdapter:
    return DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))


def _workspace_configuration() -> AgentWorkspaceRuntimeConfiguration:
    return AgentWorkspaceRuntimeConfiguration(
        namespace=WorkspaceNamespace("assistant-workspace"),
        operation_timeout=timedelta(seconds=1),
    )


class _TransferAdapter:
    def __init__(self) -> None:
        self._closed = False

    @property
    def adapter_id(self) -> WorkspaceTransferAdapterId:
        return WorkspaceTransferAdapterId("runtime-assembler")

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        del source_reference, max_bytes
        raise AssertionError("transfer invocation not expected")

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        del payload
        raise AssertionError("transfer invocation not expected")


_WORKSPACE_SERVICE_NAMES = (
    "agent.workspace",
    "agent.workspace.backing",
    "agent.workspace.cleanup",
    "agent.workspace.owner",
    "agent.workspace.service",
    "agent.workspace.store",
    "agent.workspace.transfer",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", _WORKSPACE_SERVICE_NAMES)
async def test_workspace_service_names_remain_custom_when_workspace_is_omitted(
    name: str,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    marker = object()

    def factory(
        resolver: DependencyResolver,
        current: Configuration,
    ) -> object:
        del resolver, current
        return marker

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        definitions=(ServiceDefinition(name=name, factory=factory),),
        policy=PolicyEngine(),
    ).assemble()

    assert runtime.service(name) is marker
    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_workspace_service_names_are_reserved_only_when_workspace_is_enabled() -> None:
    configuration, events, kernel, capabilities = await _base()

    def factory(
        resolver: DependencyResolver,
        current: Configuration,
    ) -> object:
        del resolver, current
        return object()

    definition = ServiceDefinition(name="agent.workspace", factory=factory)
    with pytest.raises(ValueError, match="workspace services conflict with definitions"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            definitions=(definition,),
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_workspace_configuration=_workspace_configuration(),
        )


@pytest.mark.asyncio
async def test_runtime_workspace_is_absent_when_configuration_is_omitted() -> None:
    configuration, events, kernel, capabilities = await _base()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
    ).assemble()

    for name in (
        "agent.workspace",
        "agent.workspace.backing",
        "agent.workspace.cleanup",
        "agent.workspace.owner",
        "agent.workspace.store",
        "agent.workspace.transfer",
    ):
        assert name not in runtime.services
    assert not any(
        component.startswith("agent.workspace")
        for component in (await runtime.snapshot()).components
    )

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_owns_workspace_and_stops_agent_before_workspace() -> None:
    configuration, events, kernel, capabilities = await _base()
    stopped: list[str] = []

    async def capture(event: Event) -> None:
        if event.name == "runtime.component.stopped":
            component = event.payload.get("component")
            if isinstance(component, str):
                stopped.append(component)

    await events.subscribe("*", capture)
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_workspace_configuration=_workspace_configuration(),
        agent_workspace_cleanup_configuration=(
            AgentWorkspaceCleanupRuntimeConfiguration(interval=timedelta(hours=1))
        ),
    ).assemble()

    service = runtime.service("agent.workspace")
    owner = runtime.service("agent.workspace.owner")
    store = runtime.service("agent.workspace.store")
    backing = runtime.service("agent.workspace.backing")
    cleanup = runtime.service("agent.workspace.cleanup")

    assert isinstance(service, AgentWorkspaceRuntimeService)
    assert isinstance(owner, AgentWorkspaceRuntimeOwner)
    assert isinstance(store, StateStoreWorkspaceStore)
    assert isinstance(backing, InMemoryWorkspaceBackingAdapter)
    assert isinstance(cleanup, AgentWorkspaceCleanupRuntime)
    assert "agent.workspace.transfer" not in runtime.services

    scope = agent_workspace_scope(
        namespace=_workspace_configuration().namespace,
        agent_id=AgentId("assistant"),
    )
    with pytest.raises(AgentServiceUnavailableError):
        await service.read(
            ArtifactReadRequest(
                scope=scope,
                artifact_id=ArtifactId(UUID("d0000000-0000-0000-0000-000000000001")),
                created_at=_NOW,
            ),
            SecurityContext(),
        )

    components = (await runtime.snapshot()).components
    assert components.index("agent.workspace.owner") < components.index("agent.workspace.cleanup")
    assert components.index("agent.workspace.cleanup") < components.index("agent.workspace.service")
    assert components.index("agent.workspace.service") < components.index("agent")

    await runtime.start()
    assert service.running is True
    await runtime.stop()

    assert service.closed is True
    assert owner.closed is True
    assert backing.closed is True
    assert stopped.index("agent") < stopped.index("agent.workspace.service")
    assert stopped.index("agent.workspace.service") < stopped.index("agent.workspace.cleanup")
    assert stopped.index("agent.workspace.cleanup") < stopped.index("agent.workspace.owner")


@pytest.mark.asyncio
async def test_runtime_transfer_workers_stop_before_cleanup_and_owner() -> None:
    configuration, events, kernel, capabilities = await _base()
    stopped: list[str] = []

    async def capture(event: Event) -> None:
        if event.name == "runtime.component.stopped":
            component = event.payload.get("component")
            if isinstance(component, str):
                stopped.append(component)

    await events.subscribe("*", capture)
    adapter = _TransferAdapter()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_workspace_configuration=_workspace_configuration(),
        agent_workspace_transfer_adapter=adapter,
        agent_workspace_transfer_configuration=(
            AgentWorkspaceTransferRuntimeConfiguration(
                operation_timeout=timedelta(seconds=1),
                settlement_timeout=timedelta(milliseconds=50),
                worker_count=1,
                queue_capacity=1,
            )
        ),
        agent_workspace_cleanup_configuration=(
            AgentWorkspaceCleanupRuntimeConfiguration(interval=timedelta(hours=1))
        ),
    ).assemble()

    transfer = runtime.service("agent.workspace.transfer")
    assert isinstance(transfer, AgentWorkspaceTransferRuntime)

    components = (await runtime.snapshot()).components
    assert components.index("agent.workspace.owner") < components.index("agent.workspace.cleanup")
    assert components.index("agent.workspace.cleanup") < components.index(
        "agent.workspace.transfer"
    )
    assert components.index("agent.workspace.transfer") < components.index(
        "agent.workspace.service"
    )
    assert components.index("agent.workspace.service") < components.index("agent")

    await runtime.start()
    assert transfer.running is True
    await runtime.stop()

    assert transfer.closed is True
    assert stopped.index("agent") < stopped.index("agent.workspace.service")
    assert stopped.index("agent.workspace.service") < stopped.index("agent.workspace.transfer")
    assert stopped.index("agent.workspace.transfer") < stopped.index("agent.workspace.cleanup")
    assert stopped.index("agent.workspace.cleanup") < stopped.index("agent.workspace.owner")


@pytest.mark.asyncio
async def test_public_workspace_transfer_uses_bounded_transfer_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_workspace_configuration=_workspace_configuration(),
        agent_workspace_transfer_adapter=_TransferAdapter(),
        agent_workspace_transfer_configuration=(
            AgentWorkspaceTransferRuntimeConfiguration(
                operation_timeout=timedelta(seconds=1),
                settlement_timeout=timedelta(milliseconds=50),
                worker_count=1,
                queue_capacity=1,
            )
        ),
        agent_workspace_cleanup_configuration=(
            AgentWorkspaceCleanupRuntimeConfiguration(interval=timedelta(hours=1))
        ),
    ).assemble()

    service = runtime.service("agent.workspace")
    transfer = runtime.service("agent.workspace.transfer")
    assert isinstance(service, AgentWorkspaceRuntimeService)
    assert isinstance(transfer, AgentWorkspaceTransferRuntime)

    class _TransferRouteReached(Exception):
        pass

    async def routed_import(request: object, context: object) -> object:
        del request, context
        raise _TransferRouteReached

    await runtime.start()
    monkeypatch.setattr(transfer, "import_artifact", routed_import)

    scope = agent_workspace_scope(
        namespace=_workspace_configuration().namespace,
        agent_id=AgentId("assistant"),
    )
    with pytest.raises(_TransferRouteReached):
        await service.import_artifact(
            ArtifactImportRequest(
                scope=scope,
                artifact_id=ArtifactId(UUID("d0000000-0000-0000-0000-000000000002")),
                source_reference=WorkspaceTransferReference("runtime-route"),
                created_at=_NOW,
            ),
            SecurityContext(),
        )

    await runtime.stop()


@pytest.mark.asyncio
async def test_workspace_stack_owns_backing_but_not_shared_state_store() -> None:
    state = MemoryStateStore()
    backing = InMemoryWorkspaceBackingAdapter()
    stack = create_agent_workspace_runtime_stack(
        configuration=_workspace_configuration(),
        policy=PolicyEngine(),
        state_store=state,
        backing=backing,
        cleanup_configuration=AgentWorkspaceCleanupRuntimeConfiguration(
            interval=timedelta(hours=1)
        ),
    )
    context = RuntimeContext(services={})

    for spec in stack.components:
        await spec.component.start(context)
    for spec in reversed(stack.components):
        await spec.component.stop(context)

    assert stack.service.closed is True
    assert stack.owner.closed is True
    assert backing.closed is True
    assert state.closed is False
    await state.close()


@pytest.mark.asyncio
async def test_workspace_runtime_options_are_explicit_and_fail_closed() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="workspace configuration"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_workspace_backing=InMemoryWorkspaceBackingAdapter(),
        )

    with pytest.raises(ValueError, match="agent_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_workspace_configuration=_workspace_configuration(),
        )

    with pytest.raises(ValueError, match="transfer adapter"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_workspace_configuration=_workspace_configuration(),
            agent_workspace_transfer_configuration=(AgentWorkspaceTransferRuntimeConfiguration()),
        )
