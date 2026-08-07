from __future__ import annotations

from datetime import datetime

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
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    DurableAgentRunId,
    DurableLease,
    DurableRunStore,
    DurableRunVersion,
    RetentionPolicy,
)
from phoenix_os.agent.durable_retention import DurableRetentionStore
from phoenix_os.agent.durable_retention_worker import (
    BoundedDurableRetentionWorker,
    DurableRetentionWorkerConfiguration,
    DurableRetentionWorkerState,
)
from phoenix_os.configuration import Configuration
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine
from phoenix_os.runtime import RuntimeContext


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


class _LegacyDurableRunStore:
    def __init__(
        self,
        delegate: InMemoryDurableRunStore,
    ) -> None:
        self._delegate = delegate

    @property
    def closed(self) -> bool:
        return self._delegate.closed

    async def create(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> None:
        await self._delegate.create(checkpoint)

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        return await self._delegate.get_current(run_id)

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        return await self._delegate.list_history(
            run_id,
            limit=limit,
        )

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        return await self._delegate.list_recovery_candidates(
            limit=limit,
            after=after,
        )

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        return await self._delegate.append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
        )

    async def close(self) -> None:
        await self._delegate.close()


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
    assert "agent.durable.retention" not in runtime.services
    assert "agent.durable.retention-worker" not in runtime.services
    assert stack.retention_policy is None
    assert stack.retention_worker is None
    assert stack.retention_lifecycle is None

    components = (await runtime.snapshot()).components
    assert "agent.durable.retention" not in components
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


@pytest.mark.asyncio
async def test_durable_stack_retention_is_disabled_when_policy_is_omitted() -> None:
    store = InMemoryDurableRunStore()

    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility(),
    )

    try:
        assert stack.retention_policy is None
        assert stack.retention_worker is None
        assert stack.retention_lifecycle is None
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_durable_stack_retention_is_explicit_opt_in() -> None:
    store = InMemoryDurableRunStore()
    policy = RetentionPolicy()
    stack: DurableAgentRuntimeStack | None = None

    try:
        stack = create_durable_agent_runtime_stack(
            store=store,
            lease_manager=store.lease_manager,
            compatibility_validator=_compatibility(),
            retention_policy=policy,
        )

        assert stack.retention_policy == policy
        assert stack.retention_worker is not None
        assert stack.retention_lifecycle is not None
        assert stack.retention_worker.state is DurableRetentionWorkerState.CREATED
    finally:
        if stack is None:
            await store.close()
        else:
            await stack.close()


@pytest.mark.asyncio
async def test_durable_stack_rejects_retention_configuration_without_policy() -> None:
    store = InMemoryDurableRunStore()
    configuration = DurableRetentionWorkerConfiguration()

    try:
        with pytest.raises(
            ValueError,
            match="retention_configuration requires retention_policy",
        ):
            create_durable_agent_runtime_stack(
                store=store,
                lease_manager=store.lease_manager,
                compatibility_validator=_compatibility(),
                retention_configuration=configuration,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_durable_stack_applies_explicit_retention_configuration() -> None:
    store = InMemoryDurableRunStore()
    policy = RetentionPolicy()
    configuration = DurableRetentionWorkerConfiguration(
        owner_id="runtime-retention",
        page_size=7,
        max_candidates=19,
    )
    stack: DurableAgentRuntimeStack | None = None

    try:
        stack = create_durable_agent_runtime_stack(
            store=store,
            lease_manager=store.lease_manager,
            compatibility_validator=_compatibility(),
            retention_policy=policy,
            retention_configuration=configuration,
        )

        worker = stack.retention_worker
        assert isinstance(
            worker,
            BoundedDurableRetentionWorker,
        )
        assert worker.configuration is configuration
        assert worker.policy is policy
    finally:
        if stack is None:
            await store.close()
        else:
            await stack.close()


@pytest.mark.asyncio
async def test_durable_stack_preserves_legacy_store_without_retention() -> None:
    delegate = InMemoryDurableRunStore()
    store = _LegacyDurableRunStore(delegate)

    assert isinstance(store, DurableRunStore)
    assert not isinstance(store, DurableRetentionStore)

    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=delegate.lease_manager,
        compatibility_validator=_compatibility(),
    )

    assert stack.store is store
    assert stack.retention_policy is None
    assert stack.retention_worker is None
    assert stack.retention_lifecycle is None

    await stack.close()
    assert delegate.closed


@pytest.mark.asyncio
async def test_durable_stack_rejects_legacy_store_when_retention_is_enabled() -> None:
    delegate = InMemoryDurableRunStore()
    store = _LegacyDurableRunStore(delegate)

    try:
        with pytest.raises(
            TypeError,
            match="DurableRetentionStore",
        ):
            create_durable_agent_runtime_stack(
                store=store,
                lease_manager=delegate.lease_manager,
                compatibility_validator=_compatibility(),
                retention_policy=RetentionPolicy(),
            )
    finally:
        await delegate.close()


@pytest.mark.asyncio
async def test_durable_retention_lifecycle_start_is_manual_only() -> None:
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility(),
        retention_policy=RetentionPolicy(),
    )

    try:
        worker = stack.retention_worker
        lifecycle = stack.retention_lifecycle

        assert worker is not None
        assert lifecycle is not None
        initial_snapshot = await worker.snapshot()
        assert initial_snapshot.state is DurableRetentionWorkerState.CREATED

        await lifecycle.start(RuntimeContext(services={}))

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.RUNNING
        assert snapshot.passes_started == 0
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 0
        assert snapshot.passes_stopped == 0
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_durable_stack_close_preserves_retention_recovery_storage_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility(),
        retention_policy=RetentionPolicy(),
    )

    retention_lifecycle = stack.retention_lifecycle
    assert retention_lifecycle is not None

    calls: list[str] = []

    original_retention_close = retention_lifecycle.close
    original_recovery_close = stack.recovery_lifecycle.close
    original_storage_close = stack.storage_lifecycle.close

    async def close_retention(self: object) -> None:
        del self
        calls.append("retention")
        await original_retention_close()
        raise RuntimeError("retention close failure")

    async def close_recovery(self: object) -> None:
        del self
        calls.append("recovery")
        await original_recovery_close()
        raise RuntimeError("recovery close failure")

    async def close_storage(self: object) -> None:
        del self
        calls.append("storage")
        await original_storage_close()

    monkeypatch.setattr(
        type(retention_lifecycle),
        "close",
        close_retention,
    )
    monkeypatch.setattr(
        type(stack.recovery_lifecycle),
        "close",
        close_recovery,
    )
    monkeypatch.setattr(
        type(stack.storage_lifecycle),
        "close",
        close_storage,
    )

    with pytest.raises(
        RuntimeError,
        match="retention close failure",
    ):
        await stack.close()

    assert calls == [
        "retention",
        "recovery",
        "storage",
    ]
    assert store.closed
    assert store.lease_manager.closed


@pytest.mark.asyncio
async def test_runtime_assembler_composes_opt_in_durable_retention() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    policy = RetentionPolicy()
    retention_configuration = DurableRetentionWorkerConfiguration(
        owner_id="runtime-assembler-retention",
        page_size=5,
        max_candidates=17,
    )

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
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_retention_policy=policy,
        agent_durable_retention_configuration=retention_configuration,
    ).assemble()

    stack = runtime.service("agent.durable")
    assert isinstance(stack, DurableAgentRuntimeStack)

    worker = stack.retention_worker
    assert isinstance(
        worker,
        BoundedDurableRetentionWorker,
    )

    assert stack.retention_policy is policy
    assert worker.policy is policy
    assert worker.configuration is retention_configuration

    assert runtime.service("agent.durable.retention") is policy
    assert runtime.service("agent.durable.retention-worker") is worker

    components = (await runtime.snapshot()).components

    storage_index = components.index("agent.durable.storage")
    agent_index = components.index("agent")
    recovery_index = components.index("agent.durable.recovery")
    retention_index = components.index("agent.durable.retention")

    assert storage_index < agent_index
    assert agent_index < recovery_index
    assert recovery_index < retention_index

    initial_snapshot = await worker.snapshot()
    assert initial_snapshot.state is DurableRetentionWorkerState.CREATED

    await runtime.start()

    retention_snapshot = await worker.snapshot()
    assert retention_snapshot.state is DurableRetentionWorkerState.RUNNING
    assert retention_snapshot.passes_started == 0
    assert retention_snapshot.passes_completed == 0

    await runtime.stop()

    stopped_snapshot = await worker.snapshot()
    assert stopped_snapshot.state is DurableRetentionWorkerState.CLOSED
    assert store.closed
    assert store.lease_manager.closed


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_retention_configuration_without_policy() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()

    try:
        with pytest.raises(
            ValueError,
            match="retention_configuration requires retention_policy",
        ):
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
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_retention_configuration=(DurableRetentionWorkerConfiguration()),
            ).assemble()
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_legacy_store_for_retention() -> None:
    configuration, events, kernel, capabilities = await _base()
    delegate = InMemoryDurableRunStore()
    store = _LegacyDurableRunStore(delegate)

    try:
        with pytest.raises(
            TypeError,
            match="DurableRetentionStore",
        ):
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
                agent_durable_lease_manager=delegate.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_retention_policy=RetentionPolicy(),
            ).assemble()
    finally:
        await delegate.close()


@pytest.mark.asyncio
async def test_durable_retention_start_failure_rolls_back_recovery_agent_and_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_start(
        self: BoundedDurableRetentionWorker,
    ) -> None:
        del self
        raise RuntimeError("private retention startup detail")

    monkeypatch.setattr(
        BoundedDurableRetentionWorker,
        "start",
        fail_start,
    )

    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)

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
        agent_durable_store=store,
        agent_durable_lease_manager=lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_retention_policy=RetentionPolicy(),
    ).assemble()

    stack = runtime.service("agent.durable")
    agent = runtime.service("agent")
    retention_worker = runtime.service("agent.durable.retention-worker")

    assert isinstance(
        stack,
        DurableAgentRuntimeStack,
    )
    assert isinstance(
        agent,
        AgentService,
    )
    assert isinstance(
        retention_worker,
        BoundedDurableRetentionWorker,
    )

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.retention"
    assert captured.value.failure.phase is RuntimePhase.START
    assert captured.value.rollback_failures == ()

    assert retention_worker.state is DurableRetentionWorkerState.CREATED

    retention_snapshot = await retention_worker.snapshot()
    assert retention_snapshot.passes_started == 0
    assert retention_snapshot.passes_completed == 0
    assert retention_snapshot.passes_timed_out == 0
    assert retention_snapshot.passes_failed == 0
    assert retention_snapshot.passes_stopped == 0

    assert (await stack.recovery_worker.snapshot()).state is DurableRecoveryWorkerState.CLOSED
    assert stack.recovery_coordinator.closed

    assert (await agent.snapshot()).state is AgentServiceState.STOPPED

    assert store.closed
    assert lease_manager.closed

    await runtime.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("retention_policy", "retention_configuration"),
    (
        (RetentionPolicy(), None),
        (None, DurableRetentionWorkerConfiguration()),
    ),
)
async def test_runtime_assembler_retention_options_require_explicit_durable_enablement(
    retention_policy: RetentionPolicy | None,
    retention_configuration: DurableRetentionWorkerConfiguration | None,
) -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(
        ValueError,
        match="durable agent options require agent_durable_enabled",
    ):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_retention_policy=retention_policy,
            agent_durable_retention_configuration=retention_configuration,
        )
