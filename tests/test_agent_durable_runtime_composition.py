from __future__ import annotations

import pytest

import phoenix_os.configuration.dependencies as dependencies_module
from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    PhoenixRuntime,
    Router,
    RuntimeAssembler,
    RuntimePhase,
    RuntimeStartError,
)
from phoenix_os.agent import (
    AgentId,
    AgentService,
    AgentServiceConfiguration,
    AgentServiceState,
    BoundedDurableRecoveryWorker,
    DeterministicCheckpointProtector,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DurableAgentRuntimeStack,
    DurableLeaseManager,
    DurableRecoveryWorkerState,
    InMemoryDurableLeaseManager,
    InMemoryDurableRunStore,
    StaticDurableCompatibilityValidator,
    create_durable_agent_runtime_stack,
)
from phoenix_os.configuration import Configuration
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine


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
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
    )


def _model_adapter() -> DeterministicModelTurnAdapter:
    return DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))


def _compatibility() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(())


async def _durable_runtime(
    *,
    store: InMemoryDurableRunStore | None = None,
    lease_manager: InMemoryDurableLeaseManager | None = None,
    protector: DeterministicCheckpointProtector | None = None,
) -> tuple[PhoenixRuntime, InMemoryDurableRunStore, DurableLeaseManager]:
    configuration, events, kernel, capabilities = await _base()
    selected_store = InMemoryDurableRunStore() if store is None else store
    selected_leases = selected_store.lease_manager if lease_manager is None else lease_manager
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=selected_store,
        agent_durable_lease_manager=selected_leases,
        agent_durable_compatibility_validator=_compatibility(),
        agent_checkpoint_protector=protector,
    ).assemble()
    return runtime, selected_store, selected_leases


def test_durable_stack_rejects_mismatched_store_lease_manager() -> None:
    store = InMemoryDurableRunStore()
    other = InMemoryDurableLeaseManager()

    with pytest.raises(ValueError, match="must match"):
        create_durable_agent_runtime_stack(
            store=store,
            lease_manager=other,
            compatibility_validator=_compatibility(),
        )


@pytest.mark.asyncio
async def test_durable_stack_rejects_closed_store_before_composition() -> None:
    store = InMemoryDurableRunStore()
    lease_manager = store.lease_manager
    await store.close()

    with pytest.raises(ValueError, match="durable store must be open"):
        create_durable_agent_runtime_stack(
            store=store,
            lease_manager=lease_manager,
            compatibility_validator=_compatibility(),
        )


@pytest.mark.asyncio
async def test_durable_stack_rejects_closed_lease_manager_before_composition() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await lease_manager.close()

    with pytest.raises(ValueError, match="durable lease manager must be open"):
        create_durable_agent_runtime_stack(
            store=store,
            lease_manager=lease_manager,
            compatibility_validator=_compatibility(),
        )

    await store.close()


@pytest.mark.asyncio
async def test_runtime_assembler_preserves_compatibility_when_durability_is_omitted() -> None:
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

    assert all(not name.startswith("agent.durable") for name in runtime.services)
    assert all(
        not name.startswith("agent.durable") for name in (await runtime.snapshot()).components
    )

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_durable_options_require_explicit_enablement() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()

    with pytest.raises(ValueError, match="require agent_durable_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_store=store,
        )

    await store.close()


@pytest.mark.asyncio
async def test_enabled_durability_requires_agent_and_core_dependencies() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="requires agent_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_durable_enabled=True,
        )

    with pytest.raises(ValueError, match="requires a DurableRunStore"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_enabled=True,
        )


@pytest.mark.asyncio
async def test_runtime_assembler_composes_and_owns_durable_services() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    runtime, selected_store, selected_leases = await _durable_runtime(
        store=store,
        lease_manager=lease_manager,
    )

    stack = runtime.service("agent.durable")
    agent = runtime.service("agent")
    assert isinstance(stack, DurableAgentRuntimeStack)
    assert isinstance(agent, AgentService)
    assert runtime.service("agent.durable.storage") is selected_store
    assert runtime.service("agent.durable.leases") is selected_leases
    assert runtime.service("agent.durable.compatibility") is stack.compatibility_validator
    assert runtime.service("agent.durable.recovery") is stack.recovery_coordinator
    assert runtime.service("agent.durable.recovery-worker") is stack.recovery_worker

    components = (await runtime.snapshot()).components
    assert components.index("agent.durable.storage") < components.index("agent")
    assert components.index("agent") < components.index("agent.durable.recovery")

    await runtime.start()
    assert (await stack.recovery_worker.snapshot()).state is DurableRecoveryWorkerState.RUNNING
    assert (await agent.snapshot()).state is AgentServiceState.RUNNING

    await runtime.stop()

    assert (await stack.recovery_worker.snapshot()).state is DurableRecoveryWorkerState.CLOSED
    assert stack.recovery_coordinator.closed
    assert selected_store.closed
    assert selected_leases.closed
    assert (await agent.snapshot()).state is AgentServiceState.STOPPED


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_optional_checkpoint_protector() -> None:
    protector = DeterministicCheckpointProtector(b"x" * 32)
    runtime, store, _leases = await _durable_runtime(protector=protector)

    assert runtime.service("agent.durable.protector") is protector
    stack = runtime.service("agent.durable")
    assert isinstance(stack, DurableAgentRuntimeStack)
    assert stack.protector is protector

    await runtime.start()
    await runtime.stop()
    assert store.closed


@pytest.mark.asyncio
async def test_durable_recovery_start_failure_rolls_back_agent_and_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_start(self: BoundedDurableRecoveryWorker) -> None:
        del self
        raise RuntimeError("private recovery startup detail")

    monkeypatch.setattr(BoundedDurableRecoveryWorker, "start", fail_start)

    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    runtime, _, _ = await _durable_runtime(
        store=store,
        lease_manager=lease_manager,
    )
    agent = runtime.service("agent")
    assert isinstance(agent, AgentService)

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.recovery"
    assert captured.value.failure.phase is RuntimePhase.START
    assert captured.value.rollback_failures == ()
    assert (await agent.snapshot()).state is AgentServiceState.STOPPED
    assert store.closed
    assert lease_manager.closed

    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_failure_rolls_back_composed_durable_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)

    def fail_runtime(*args: object, **kwargs: object) -> PhoenixRuntime:
        del args, kwargs
        raise RuntimeError("private runtime construction detail")

    monkeypatch.setattr(dependencies_module, "PhoenixRuntime", fail_runtime)

    with pytest.raises(RuntimeError, match="private runtime construction detail"):
        await RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_enabled=True,
            agent_durable_store=store,
            agent_durable_lease_manager=lease_manager,
            agent_durable_compatibility_validator=_compatibility(),
        ).assemble()

    assert store.closed
    assert lease_manager.closed


@pytest.mark.asyncio
async def test_closed_durable_storage_fails_before_agent_start() -> None:
    store = InMemoryDurableRunStore()
    leases = store.lease_manager
    runtime, _, _ = await _durable_runtime(store=store)
    agent = runtime.service("agent")
    assert isinstance(agent, AgentService)

    await store.close()

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.storage"
    assert captured.value.failure.phase is RuntimePhase.START
    assert (await agent.snapshot()).state is AgentServiceState.CREATED
    assert leases.closed

    await runtime.stop()
