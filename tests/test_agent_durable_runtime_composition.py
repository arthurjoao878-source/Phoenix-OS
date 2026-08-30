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
    AgentAdministrationAccessDeniedError,
    AgentId,
    AgentService,
    AgentServiceConfiguration,
    AgentServiceState,
    BoundedDurableRecoveryWorker,
    ContentFreeDurableRunObserver,
    DeterministicCheckpointProtector,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DurableAdministrationConfiguration,
    DurableAgentRuntimeStack,
    DurableCleanupAdministration,
    DurableLeaseManager,
    DurableReconciliationAdministration,
    DurableRecoveryWorkerState,
    DurableRunAdministration,
    InMemoryDurableLeaseManager,
    InMemoryDurableRunStore,
    NullDurableRunObserver,
    StaticDurableCompatibilityValidator,
    create_durable_agent_runtime_stack,
)
from phoenix_os.agent.durable_authorization import PolicyEngineDurableResumeAuthorizer
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    DurableAgentRunId,
    DurableLease,
    DurableRunStore,
    DurableRunVersion,
    RetentionPolicy,
)
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.durable_retention import DurableRetentionStore
from phoenix_os.agent.durable_retention_worker import (
    BoundedDurableRetentionWorker,
    DurableRetentionWorkerConfiguration,
    DurableRetentionWorkerState,
)
from phoenix_os.audit import AuditLedger
from phoenix_os.configuration import Configuration
from phoenix_os.control_plane import (
    ControlPlaneDurableCleanupAdministration,
    ControlPlaneDurableReconciliationAdministration,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.durable_cleanup_http import (
    ControlPlaneDurableCleanupHttpAdapter,
)
from phoenix_os.control_plane.durable_reconciliation_http import (
    ControlPlaneDurableReconciliationHttpAdapter,
)
from phoenix_os.control_plane.http import ControlPlaneHttpServer
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext
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


def _maintainer_context(*permissions: str) -> SecurityContext:
    return SecurityContext(
        principal="operator:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
        correlation_id="durable-runtime-composition-test",
    )


def _service_context(*scopes: str) -> SecurityContext:
    return SecurityContext(
        principal="service:durable-administration",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        scopes=frozenset(scopes),
        correlation_id="durable-runtime-machine-test",
    )


class _AllowMachineAdministrationGuard:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def authorize(
        self,
        context: SecurityContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        del context
        self.calls.append((action, resource))


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
    coordinator = stack.recovery_coordinator
    assert isinstance(coordinator, StartupDurableRecoveryCoordinator)
    assert isinstance(coordinator._resume_authorizer, PolicyEngineDurableResumeAuthorizer)
    assert coordinator._resume_context is not None
    assert coordinator._resume_context.principal == "phoenix-recovery"
    assert coordinator._resume_context.principal_type is PrincipalType.SERVICE
    assert coordinator._resume_context.authenticated
    assert runtime.service("agent.durable.storage") is selected_store
    assert runtime.service("agent.durable.leases") is selected_leases
    assert runtime.service("agent.durable.compatibility") is stack.compatibility_validator
    assert runtime.service("agent.durable.observer") is stack.observer
    assert runtime.service("agent.durable.administration") is stack.administration
    assert isinstance(stack.observer, ContentFreeDurableRunObserver)
    assert isinstance(stack.administration, DurableRunAdministration)
    assert runtime.service("agent.durable.recovery") is stack.recovery_coordinator
    assert runtime.service("agent.durable.recovery-worker") is stack.recovery_worker
    assert "agent.durable.retention" not in runtime.services
    assert "agent.durable.retention-worker" not in runtime.services
    assert stack.retention_policy is None
    assert stack.retention_worker is None
    assert stack.retention_lifecycle is None

    components = (await runtime.snapshot()).components
    assert "agent.durable.retention" not in components
    assert "agent.durable.observer" not in components
    assert "agent.durable.administration" not in components
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
async def test_durable_stack_defaults_to_null_observer_and_read_administration() -> None:
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility(),
    )

    try:
        assert isinstance(stack.observer, NullDurableRunObserver)
        assert isinstance(stack.administration, DurableRunAdministration)
        snapshot = await stack.administration.snapshot(
            _maintainer_context("agent.durable.health.read")
        )
        assert snapshot.store_open
        assert snapshot.lease_manager_open
        assert snapshot.recovery is not None
        assert snapshot.observer is not None
        assert snapshot.observer.observations == 0
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_runtime_assembler_machine_administration_is_disabled_by_default() -> None:
    runtime, _store, _leases = await _durable_runtime()
    administration = runtime.service("agent.durable.administration")
    assert isinstance(administration, DurableRunAdministration)

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.snapshot(_service_context("agent.durable.health.read"))

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_wires_explicit_machine_administration_guard() -> None:
    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    guard = _AllowMachineAdministrationGuard()
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
        agent_durable_administration_configuration=DurableAdministrationConfiguration(
            machine_administration_enabled=True
        ),
        agent_durable_machine_administration_guard=guard,
    ).assemble()

    administration = runtime.service("agent.durable.administration")
    assert isinstance(administration, DurableRunAdministration)
    snapshot = await administration.snapshot(_service_context("agent.durable.health.read"))
    assert snapshot.store_open
    assert guard.calls == [("agent.durable.health.read", "durable-agent-runs:health")]

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_enabled_machine_administration_requires_guard() -> None:
    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)

    with pytest.raises(ValueError, match="requires a machine guard"):
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
            agent_durable_store=store,
            agent_durable_lease_manager=lease_manager,
            agent_durable_compatibility_validator=_compatibility(),
            agent_durable_administration_configuration=DurableAdministrationConfiguration(
                machine_administration_enabled=True
            ),
        )

    assert not store.closed
    assert not lease_manager.closed
    await store.close()


@pytest.mark.asyncio
async def test_runtime_assembler_administration_options_require_explicit_durable_enablement() -> (
    None
):
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="require agent_durable_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_durable_administration_configuration=(DurableAdministrationConfiguration()),
        )

    with pytest.raises(ValueError, match="require agent_durable_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_durable_machine_administration_guard=_AllowMachineAdministrationGuard(),
        )


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
    assert stack.cleanup_administration is None
    assert "agent.durable.cleanup-administration" not in runtime.services

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


@pytest.mark.asyncio
async def test_durable_stack_cleanup_administration_requires_retention_policy() -> None:
    store = InMemoryDurableRunStore()
    audit = AuditLedger()

    try:
        with pytest.raises(
            ValueError,
            match="cleanup_audit requires retention_policy",
        ):
            create_durable_agent_runtime_stack(
                store=store,
                lease_manager=store.lease_manager,
                compatibility_validator=_compatibility(),
                cleanup_audit=audit,
            )
    finally:
        await audit.close()
        await store.close()


@pytest.mark.asyncio
async def test_durable_stack_composes_cleanup_above_exact_retention_worker() -> None:
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    policy = RetentionPolicy()
    retention_configuration = DurableRetentionWorkerConfiguration(
        owner_id="runtime-cleanup-composition",
        page_size=32,
        max_candidates=16,
    )
    stack: DurableAgentRuntimeStack | None = None

    try:
        stack = create_durable_agent_runtime_stack(
            store=store,
            lease_manager=store.lease_manager,
            compatibility_validator=_compatibility(),
            retention_policy=policy,
            retention_configuration=retention_configuration,
            cleanup_audit=audit,
        )

        cleanup = stack.cleanup_administration
        worker = stack.retention_worker
        assert isinstance(cleanup, DurableCleanupAdministration)
        assert isinstance(worker, BoundedDurableRetentionWorker)
        assert worker.policy is policy
        assert worker.configuration is retention_configuration
        assert not cleanup.closed

        bounds = cleanup.bounds(_maintainer_context("agent.durable.cleanup"))
        assert bounds.page_size == retention_configuration.page_size
        assert bounds.max_candidates == retention_configuration.max_candidates
    finally:
        if stack is None:
            await store.close()
        else:
            cleanup = stack.cleanup_administration
            await stack.close()
            assert cleanup is not None
            assert cleanup.closed
        await audit.close()


@pytest.mark.asyncio
async def test_runtime_assembler_cleanup_requires_audit_retention_and_operator_mode() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    operator_token = ControlPlaneOperatorToken("r" * 32)

    try:
        with pytest.raises(
            ValueError,
            match="cleanup administration requires AuditLedger",
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
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_retention_policy=RetentionPolicy(),
                agent_durable_cleanup_administration_enabled=True,
                control_plane_operator_token=operator_token,
            )

        with pytest.raises(
            ValueError,
            match="cleanup administration requires retention policy",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=PolicyEngine(),
                audit=audit,
                agent_enabled=True,
                agent_configuration=_agent_configuration(),
                agent_model_adapter=_model_adapter(),
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_cleanup_administration_enabled=True,
                control_plane_operator_token=operator_token,
            )

        with pytest.raises(
            ValueError,
            match="cleanup administration requires durable operator mode",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=PolicyEngine(),
                audit=audit,
                agent_enabled=True,
                agent_configuration=_agent_configuration(),
                agent_model_adapter=_model_adapter(),
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_retention_policy=RetentionPolicy(),
                agent_durable_cleanup_administration_enabled=True,
            )
    finally:
        await audit.close()
        await store.close()


@pytest.mark.asyncio
async def test_runtime_assembler_composes_opt_in_durable_cleanup_administration() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    policy = RetentionPolicy()
    retention_configuration = DurableRetentionWorkerConfiguration(
        owner_id="runtime-cleanup-admin",
        page_size=11,
        max_candidates=7,
    )

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_retention_policy=policy,
        agent_durable_retention_configuration=retention_configuration,
        agent_durable_cleanup_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()

    stack = runtime.service("agent.durable")
    cleanup = runtime.service("agent.durable.cleanup-administration")
    control_plane_cleanup = runtime.service("control_plane.durable-cleanup")
    cleanup_http = runtime.service("control_plane.durable-cleanup-http")
    worker = runtime.service("agent.durable.retention-worker")
    http = runtime.service("control_plane.http")

    assert isinstance(stack, DurableAgentRuntimeStack)
    assert isinstance(cleanup, DurableCleanupAdministration)
    assert isinstance(control_plane_cleanup, ControlPlaneDurableCleanupAdministration)
    assert isinstance(cleanup_http, ControlPlaneDurableCleanupHttpAdapter)
    assert isinstance(worker, BoundedDurableRetentionWorker)
    assert isinstance(http, ControlPlaneHttpServer)
    assert cleanup is stack.cleanup_administration
    assert worker is stack.retention_worker
    assert http.durable_cleanup_http is cleanup_http
    assert http.durable_reconciliation_http is None
    assert cleanup_http.administration is control_plane_cleanup
    assert not cleanup.closed

    components = (await runtime.snapshot()).components
    assert "agent.durable.cleanup-administration" not in components
    assert "agent.durable.retention" in components
    assert "control_plane.durable-cleanup" in components
    assert components.index("agent.durable.retention") < components.index(
        "control_plane.durable-cleanup"
    )
    assert components.index("control_plane.durable-cleanup") < components.index(
        "control_plane.http"
    )

    await runtime.start()
    assert worker.state is DurableRetentionWorkerState.RUNNING
    assert not cleanup.closed

    await runtime.stop()
    assert cleanup_http.closed
    assert cleanup.closed
    assert worker.state is DurableRetentionWorkerState.CLOSED
    assert store.closed
    assert store.lease_manager.closed


@pytest.mark.asyncio
async def test_cleanup_http_bind_failure_rolls_back_confirmation_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.control_plane.durable_administration_protection import (
        ControlPlaneDurableAdministrationProtection,
    )

    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    close_calls = 0
    original_close = ControlPlaneDurableAdministrationProtection.close

    async def tracked_close(
        self: ControlPlaneDurableAdministrationProtection,
    ) -> None:
        nonlocal close_calls
        close_calls += 1
        await original_close(self)

    def fail_bind(
        self: ControlPlaneHttpServer,
        administration: ControlPlaneDurableCleanupAdministration,
    ) -> ControlPlaneDurableCleanupHttpAdapter:
        del self, administration
        raise RuntimeError("private durable cleanup HTTP binding detail")

    monkeypatch.setattr(
        ControlPlaneDurableAdministrationProtection,
        "close",
        tracked_close,
    )
    monkeypatch.setattr(
        ControlPlaneHttpServer,
        "bind_durable_cleanup_http",
        fail_bind,
    )

    with pytest.raises(
        RuntimeError,
        match="private durable cleanup HTTP binding detail",
    ):
        await RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            audit=audit,
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_enabled=True,
            agent_durable_store=store,
            agent_durable_lease_manager=store.lease_manager,
            agent_durable_compatibility_validator=_compatibility(),
            agent_durable_retention_policy=RetentionPolicy(),
            agent_durable_cleanup_administration_enabled=True,
            control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
        ).assemble()

    assert close_calls == 1
    assert store.closed
    assert store.lease_manager.closed


@pytest.mark.asyncio
async def test_cleanup_storage_start_failure_rolls_back_control_plane_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.control_plane.durable_administration_protection import (
        ControlPlaneDurableAdministrationProtection,
    )

    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    close_calls = 0
    original_close = ControlPlaneDurableAdministrationProtection.close

    async def tracked_close(
        self: ControlPlaneDurableAdministrationProtection,
    ) -> None:
        nonlocal close_calls
        close_calls += 1
        await original_close(self)

    monkeypatch.setattr(
        ControlPlaneDurableAdministrationProtection,
        "close",
        tracked_close,
    )

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_retention_policy=RetentionPolicy(),
        agent_durable_cleanup_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()
    cleanup = runtime.service("agent.durable.cleanup-administration")
    cleanup_http = runtime.service("control_plane.durable-cleanup-http")
    assert isinstance(cleanup, DurableCleanupAdministration)
    assert isinstance(cleanup_http, ControlPlaneDurableCleanupHttpAdapter)

    await store.close()

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.storage"
    assert captured.value.failure.phase is RuntimePhase.START
    assert close_calls >= 1
    assert cleanup_http.closed
    assert cleanup.closed
    assert store.closed
    assert store.lease_manager.closed

    await runtime.stop()


@pytest.mark.asyncio
async def test_durable_stack_cleanup_closes_before_retention_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility(),
        retention_policy=RetentionPolicy(),
        cleanup_audit=audit,
    )
    cleanup = stack.cleanup_administration
    worker = stack.retention_worker
    assert isinstance(cleanup, DurableCleanupAdministration)
    assert isinstance(worker, BoundedDurableRetentionWorker)

    calls: list[str] = []
    original_cleanup_close = DurableCleanupAdministration.close
    original_worker_close = BoundedDurableRetentionWorker.close

    async def close_cleanup(self: DurableCleanupAdministration) -> None:
        calls.append("cleanup")
        await original_cleanup_close(self)

    async def close_retention(self: BoundedDurableRetentionWorker) -> None:
        calls.append("retention")
        await original_worker_close(self)

    monkeypatch.setattr(DurableCleanupAdministration, "close", close_cleanup)
    monkeypatch.setattr(BoundedDurableRetentionWorker, "close", close_retention)

    try:
        await stack.close()

        assert calls[:2] == ["cleanup", "retention"]
        assert cleanup.closed
        assert worker.state is DurableRetentionWorkerState.CLOSED
        assert store.closed
        assert store.lease_manager.closed
    finally:
        await audit.close()


@pytest.mark.asyncio
async def test_retention_start_failure_closes_cleanup_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_start(self: BoundedDurableRetentionWorker) -> None:
        del self
        raise RuntimeError("private retention startup detail")

    monkeypatch.setattr(BoundedDurableRetentionWorker, "start", fail_start)

    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_retention_policy=RetentionPolicy(),
        agent_durable_cleanup_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()

    stack = runtime.service("agent.durable")
    cleanup = runtime.service("agent.durable.cleanup-administration")
    worker = runtime.service("agent.durable.retention-worker")
    assert isinstance(stack, DurableAgentRuntimeStack)
    assert isinstance(cleanup, DurableCleanupAdministration)
    assert isinstance(worker, BoundedDurableRetentionWorker)

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.retention"
    assert captured.value.failure.phase is RuntimePhase.START
    assert cleanup.closed
    assert worker.state is DurableRetentionWorkerState.CREATED
    assert store.closed
    assert store.lease_manager.closed

    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_durable_reconciliation_is_explicit_opt_in() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()

    stack = runtime.service("agent.durable")
    assert isinstance(stack, DurableAgentRuntimeStack)
    assert stack.reconciliation_administration is None
    assert "agent.durable.reconciliation-administration" not in runtime.services
    assert "control_plane.durable-reconciliation" not in runtime.services
    assert "control_plane.durable-reconciliation-http" not in runtime.services
    http = runtime.service("control_plane.http")
    assert isinstance(http, ControlPlaneHttpServer)
    assert http.durable_reconciliation_http is None
    assert "control_plane.durable-reconciliation" not in (await runtime.snapshot()).components

    await runtime.start()
    await runtime.stop()
    assert store.closed
    assert audit.closed


@pytest.mark.asyncio
async def test_runtime_assembler_reconciliation_requires_audit_and_operator_mode() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit_without_runtime = AuditLedger()
    try:
        with pytest.raises(
            ValueError,
            match="requires durable operator mode",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=PolicyEngine(),
                audit=audit_without_runtime,
                agent_enabled=True,
                agent_configuration=_agent_configuration(),
                agent_model_adapter=_model_adapter(),
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_reconciliation_administration_enabled=True,
            )

        with pytest.raises(
            ValueError,
            match="requires AuditLedger",
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
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=_compatibility(),
                agent_durable_reconciliation_administration_enabled=True,
                control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
            )
    finally:
        await audit_without_runtime.close()
        await store.close()


@pytest.mark.asyncio
async def test_runtime_assembler_composes_and_orders_durable_reconciliation() -> None:
    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    audit = AuditLedger()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_reconciliation_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()

    stack = runtime.service("agent.durable")
    assert isinstance(stack, DurableAgentRuntimeStack)
    coordinator = runtime.service("agent.durable.reconciliation-administration")
    administration = runtime.service("control_plane.durable-reconciliation")
    reconciliation_http = runtime.service("control_plane.durable-reconciliation-http")
    http = runtime.service("control_plane.http")
    assert isinstance(http, ControlPlaneHttpServer)
    assert isinstance(coordinator, DurableReconciliationAdministration)
    assert coordinator is stack.reconciliation_administration
    assert isinstance(
        administration,
        ControlPlaneDurableReconciliationAdministration,
    )
    assert isinstance(
        reconciliation_http,
        ControlPlaneDurableReconciliationHttpAdapter,
    )
    assert http.durable_reconciliation_http is reconciliation_http
    assert http.durable_cleanup_http is None
    assert reconciliation_http.administration is administration

    components = (await runtime.snapshot()).components
    assert "control_plane.durable-reconciliation" in components
    assert components.index("control_plane.durable-reconciliation") < components.index(
        "control_plane.http"
    )
    assert components.index("agent.durable.storage") < components.index(
        "control_plane.durable-reconciliation"
    )

    await runtime.start()
    await runtime.stop()

    assert reconciliation_http.closed
    assert coordinator.closed
    assert store.closed
    assert lease_manager.closed
    assert audit.closed


@pytest.mark.asyncio
async def test_runtime_assembler_composes_cleanup_and_reconciliation_http_together() -> None:
    configuration, events, kernel, capabilities = await _base()
    store = InMemoryDurableRunStore()
    audit = AuditLedger()

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_reconciliation_administration_enabled=True,
        agent_durable_retention_policy=RetentionPolicy(),
        agent_durable_cleanup_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()

    http = runtime.service("control_plane.http")
    cleanup_http = runtime.service("control_plane.durable-cleanup-http")
    reconciliation_http = runtime.service("control_plane.durable-reconciliation-http")

    assert isinstance(http, ControlPlaneHttpServer)
    assert isinstance(cleanup_http, ControlPlaneDurableCleanupHttpAdapter)
    assert isinstance(reconciliation_http, ControlPlaneDurableReconciliationHttpAdapter)
    assert http.durable_cleanup_http is cleanup_http
    assert http.durable_reconciliation_http is reconciliation_http

    components = (await runtime.snapshot()).components
    assert components.index("control_plane.durable-reconciliation") < components.index(
        "control_plane.durable-cleanup"
    )
    assert components.index("control_plane.durable-cleanup") < components.index(
        "control_plane.http"
    )

    await runtime.start()
    await runtime.stop()

    assert cleanup_http.closed
    assert reconciliation_http.closed
    assert store.closed
    assert store.lease_manager.closed
    assert audit.closed


@pytest.mark.asyncio
async def test_runtime_assembler_reconciliation_rollback_closes_confirmation_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.control_plane.durable_administration_protection import (
        ControlPlaneDurableAdministrationProtection,
    )

    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    audit = AuditLedger()
    close_calls = 0
    original_close = ControlPlaneDurableAdministrationProtection.close

    async def tracked_close(
        self: ControlPlaneDurableAdministrationProtection,
    ) -> None:
        nonlocal close_calls
        close_calls += 1
        await original_close(self)

    def fail_runtime(*args: object, **kwargs: object) -> PhoenixRuntime:
        del args, kwargs
        raise RuntimeError("private reconciliation runtime construction detail")

    monkeypatch.setattr(
        ControlPlaneDurableAdministrationProtection,
        "close",
        tracked_close,
    )
    monkeypatch.setattr(dependencies_module, "PhoenixRuntime", fail_runtime)

    with pytest.raises(
        RuntimeError,
        match="private reconciliation runtime construction detail",
    ):
        await RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            audit=audit,
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_enabled=True,
            agent_durable_store=store,
            agent_durable_lease_manager=lease_manager,
            agent_durable_compatibility_validator=_compatibility(),
            agent_durable_reconciliation_administration_enabled=True,
            control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
        ).assemble()

    assert close_calls == 1
    assert store.closed
    assert lease_manager.closed


@pytest.mark.asyncio
async def test_reconciliation_http_bind_failure_rolls_back_confirmation_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.control_plane.durable_administration_protection import (
        ControlPlaneDurableAdministrationProtection,
    )

    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    audit = AuditLedger()
    close_calls = 0
    original_close = ControlPlaneDurableAdministrationProtection.close

    async def tracked_close(
        self: ControlPlaneDurableAdministrationProtection,
    ) -> None:
        nonlocal close_calls
        close_calls += 1
        await original_close(self)

    def fail_bind(
        self: ControlPlaneHttpServer,
        administration: ControlPlaneDurableReconciliationAdministration,
    ) -> ControlPlaneDurableReconciliationHttpAdapter:
        del self, administration
        raise RuntimeError("private durable reconciliation HTTP binding detail")

    monkeypatch.setattr(
        ControlPlaneDurableAdministrationProtection,
        "close",
        tracked_close,
    )
    monkeypatch.setattr(
        ControlPlaneHttpServer,
        "bind_durable_reconciliation_http",
        fail_bind,
    )

    with pytest.raises(
        RuntimeError,
        match="private durable reconciliation HTTP binding detail",
    ):
        await RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            audit=audit,
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_durable_enabled=True,
            agent_durable_store=store,
            agent_durable_lease_manager=lease_manager,
            agent_durable_compatibility_validator=_compatibility(),
            agent_durable_reconciliation_administration_enabled=True,
            control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
        ).assemble()

    assert close_calls == 1
    assert store.closed
    assert lease_manager.closed


@pytest.mark.asyncio
async def test_reconciliation_storage_start_failure_closes_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.control_plane.durable_administration_protection import (
        ControlPlaneDurableAdministrationProtection,
    )

    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    audit = AuditLedger()
    close_calls = 0
    original_close = ControlPlaneDurableAdministrationProtection.close

    async def tracked_close(
        self: ControlPlaneDurableAdministrationProtection,
    ) -> None:
        nonlocal close_calls
        close_calls += 1
        await original_close(self)

    monkeypatch.setattr(
        ControlPlaneDurableAdministrationProtection,
        "close",
        tracked_close,
    )

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_reconciliation_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()
    coordinator = runtime.service("agent.durable.reconciliation-administration")
    assert isinstance(coordinator, DurableReconciliationAdministration)

    await store.close()

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.storage"
    assert captured.value.failure.phase is RuntimePhase.START
    assert close_calls == 1
    assert coordinator.closed
    assert store.closed
    assert lease_manager.closed
    assert audit.closed

    await runtime.stop()


@pytest.mark.asyncio
async def test_reconciliation_recovery_start_failure_rolls_back_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.control_plane.durable_administration_protection import (
        ControlPlaneDurableAdministrationProtection,
    )

    async def fail_start(self: BoundedDurableRecoveryWorker) -> None:
        del self
        raise RuntimeError("private reconciliation recovery startup detail")

    configuration, events, kernel, capabilities = await _base()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    audit = AuditLedger()
    close_calls = 0
    original_close = ControlPlaneDurableAdministrationProtection.close

    async def tracked_close(
        self: ControlPlaneDurableAdministrationProtection,
    ) -> None:
        nonlocal close_calls
        close_calls += 1
        await original_close(self)

    monkeypatch.setattr(BoundedDurableRecoveryWorker, "start", fail_start)
    monkeypatch.setattr(
        ControlPlaneDurableAdministrationProtection,
        "close",
        tracked_close,
    )

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        audit=audit,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=lease_manager,
        agent_durable_compatibility_validator=_compatibility(),
        agent_durable_reconciliation_administration_enabled=True,
        control_plane_operator_token=ControlPlaneOperatorToken("r" * 32),
    ).assemble()
    coordinator = runtime.service("agent.durable.reconciliation-administration")
    assert isinstance(coordinator, DurableReconciliationAdministration)

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert captured.value.failure.component == "agent.durable.recovery"
    assert captured.value.failure.phase is RuntimePhase.START
    assert close_calls == 1
    assert coordinator.closed
    assert store.closed
    assert lease_manager.closed
    assert audit.closed

    await runtime.stop()
