from datetime import timedelta
from pathlib import Path

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
    AgentAdministration,
    AgentAdmissionController,
    AgentId,
    AgentLoop,
    AgentService,
    AgentServiceConfiguration,
    AgentServiceState,
    AgentToolConfiguration,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    StaticToolResourceResolver,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolOutputSchema,
    ToolRegistry,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
from phoenix_os.agent.durable_runtime import DurableAgentRuntimeStack
from phoenix_os.agent.durable_sqlite import SQLiteDurableRunStore
from phoenix_os.agent.model_turn import InferenceBackedAgentModelTurnAdapter
from phoenix_os.configuration import Configuration
from phoenix_os.events import Event
from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProviderId,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
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


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"value"}),
    )


def _descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId("workspace.read"),
        name="Workspace read",
        description="One reviewed deterministic Runtime integration tool.",
        input_schema=ToolInputSchema(_schema()),
        output_schema=ToolOutputSchema(_schema()),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=8_192,
        timeout=timedelta(seconds=10),
        resolver_id="workspace.read.resolver",
        adapter_id="workspace.read.adapter",
    )


def _agent_configuration(descriptor: ToolDescriptor) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(descriptor),),
    )


def _model_adapter() -> DeterministicModelTurnAdapter:
    return DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))


class _NoopExecutionInterceptor:
    async def before_model_turn(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def before_tool_authorization(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def before_tool_invocation(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def final_tool_admission(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def after_tool_result(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def before_final_output(self, *_args: object, **_kwargs: object) -> None:
        return None


def _inference_configuration() -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(InferenceProviderConfiguration(ModelProviderId("deterministic")),),
        models=(
            ModelDescriptor(
                provider_id=ModelProviderId("deterministic"),
                model_id=ModelId("chat"),
                provider_model_name="chat",
                capabilities=ModelCapabilities(complete=True, streaming=True),
            ),
        ),
    )


@pytest.mark.asyncio
async def test_runtime_assembler_preserves_compatibility_when_agent_is_omitted() -> None:
    configuration, events, kernel, capabilities = await _base()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent."):
            captured.append(event)

    await events.subscribe("*", capture)
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
    ).assemble()

    assert "agent" not in runtime.services
    assert "agent.health" not in runtime.services
    assert "agent.administration" not in runtime.services
    assert "agent.runtime" not in runtime.services
    assert "agent.registry" not in runtime.services
    assert "agent.admission" not in runtime.services
    assert "agent.executor" not in runtime.services
    await runtime.start()
    await runtime.stop()
    assert captured == []


@pytest.mark.asyncio
async def test_runtime_assembler_composes_and_owns_enabled_agent() -> None:
    configuration, events, kernel, capabilities = await _base()
    descriptor = _descriptor()
    policy = PolicyEngine()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=policy,
        agent_enabled=True,
        agent_configuration=_agent_configuration(descriptor),
        agent_model_adapter=_model_adapter(),
        agent_tool_resolvers=(
            StaticToolResourceResolver(
                resolver_id=descriptor.resolver_id,
                resource="workspace/read",
            ),
        ),
        agent_tool_adapters=(
            DeterministicReadOnlyTool(
                descriptor.tool_id,
                {"value": "ok"},
                adapter_id=descriptor.adapter_id,
            ),
        ),
    ).assemble()

    agent = runtime.service("agent")
    registry = runtime.service("agent.registry")
    admission = runtime.service("agent.admission")

    assert isinstance(agent, AgentService)
    assert runtime.service("agent.health") is agent
    assert isinstance(runtime.service("agent.runtime"), AgentLoop)
    assert isinstance(runtime.service("agent.administration"), AgentAdministration)
    assert isinstance(registry, ToolRegistry)
    assert isinstance(admission, AgentAdmissionController)
    assert isinstance(runtime.service("agent.executor"), BoundedAgentExecutor)
    assert (await runtime.snapshot()).components[-1] == "agent"

    await runtime.start()
    assert (await agent.snapshot()).state is AgentServiceState.RUNNING
    await runtime.stop()

    assert (await agent.snapshot()).state is AgentServiceState.STOPPED
    assert registry.closed
    assert admission.closed
    assert policy.closed


@pytest.mark.asyncio
async def test_agent_options_require_explicit_enablement() -> None:
    configuration, events, kernel, capabilities = await _base()
    descriptor = _descriptor()

    with pytest.raises(ValueError, match="require agent_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_configuration=_agent_configuration(descriptor),
        )


@pytest.mark.asyncio
async def test_enabled_agent_requires_policy_configuration_and_model_adapter() -> None:
    configuration, events, kernel, capabilities = await _base()
    descriptor = _descriptor()

    with pytest.raises(ValueError, match="PolicyEngine"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_enabled=True,
            agent_configuration=_agent_configuration(descriptor),
            agent_model_adapter=_model_adapter(),
        )

    with pytest.raises(ValueError, match="configuration"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_model_adapter=_model_adapter(),
        )

    with pytest.raises(ValueError, match="model adapter"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(descriptor),
        )


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_execution_interceptor_without_agent_enablement() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="agent options require agent_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_execution_interceptor=_NoopExecutionInterceptor(),
        )


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_invalid_execution_interceptor() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(TypeError, match="agent execution interceptor"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=AgentServiceConfiguration(
                agent_id=AgentId("nova"),
                provider_id=ModelProviderId("deterministic"),
                model_id=ModelId("chat"),
            ),
            agent_model_adapter=_model_adapter(),
            agent_execution_interceptor=object(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_runtime_assembler_forwards_exact_execution_interceptor() -> None:
    configuration, events, kernel, capabilities = await _base()
    interceptor = _NoopExecutionInterceptor()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=AgentServiceConfiguration(
            agent_id=AgentId("nova"),
            provider_id=ModelProviderId("deterministic"),
            model_id=ModelId("chat"),
        ),
        agent_model_adapter=_model_adapter(),
        agent_execution_interceptor=interceptor,
    ).assemble()

    agent_loop = runtime.service("agent.runtime")
    assert isinstance(agent_loop, AgentLoop)
    assert agent_loop.execution_interceptor is interceptor

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_auto_binds_inference_backed_agent_model_adapter() -> None:
    configuration, events, kernel, capabilities = await _base()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        inference_enabled=True,
        inference_configuration=_inference_configuration(),
        inference_providers=(
            DeterministicModelProvider(
                {"chat": "inference"},
                provider_id="deterministic",
            ),
        ),
        agent_enabled=True,
        agent_configuration=AgentServiceConfiguration(
            agent_id=AgentId("nova"),
            provider_id=ModelProviderId("deterministic"),
            model_id=ModelId("chat"),
        ),
    ).assemble()

    inference = runtime.service("inference")
    agent_loop = runtime.service("agent.runtime")

    assert isinstance(agent_loop, AgentLoop)
    assert isinstance(
        agent_loop._model_adapter,
        InferenceBackedAgentModelTurnAdapter,
    )
    assert agent_loop._model_adapter._inference_service is inference

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_preserves_explicit_model_adapter_with_inference() -> None:
    configuration, events, kernel, capabilities = await _base()
    explicit_adapter = _model_adapter()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        inference_enabled=True,
        inference_configuration=_inference_configuration(),
        inference_providers=(
            DeterministicModelProvider(
                {"chat": "inference"},
                provider_id="deterministic",
            ),
        ),
        agent_enabled=True,
        agent_configuration=AgentServiceConfiguration(
            agent_id=AgentId("nova"),
            provider_id=ModelProviderId("deterministic"),
            model_id=ModelId("chat"),
        ),
        agent_model_adapter=explicit_adapter,
    ).assemble()

    agent_loop = runtime.service("agent.runtime")
    assert isinstance(agent_loop, AgentLoop)
    assert agent_loop._model_adapter is explicit_adapter

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_shutdown_stops_agent_before_inference() -> None:
    configuration, events, kernel, capabilities = await _base()
    descriptor = _descriptor()
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
        inference_enabled=True,
        inference_configuration=_inference_configuration(),
        inference_providers=(
            DeterministicModelProvider(
                {"chat": "inference"},
                provider_id="deterministic",
            ),
        ),
        agent_enabled=True,
        agent_configuration=_agent_configuration(descriptor),
        agent_model_adapter=_model_adapter(),
        agent_tool_resolvers=(
            StaticToolResourceResolver(
                resolver_id=descriptor.resolver_id,
                resource="workspace/read",
            ),
        ),
        agent_tool_adapters=(
            DeterministicReadOnlyTool(
                descriptor.tool_id,
                {"value": "ok"},
                adapter_id=descriptor.adapter_id,
            ),
        ),
    ).assemble()

    await runtime.start()
    await runtime.stop()

    assert "agent" in stopped
    assert "inference" in stopped
    assert stopped.index("agent") < stopped.index("inference")


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_metadata_projector_without_durable_enablement() -> None:
    configuration, events, kernel, capabilities = await _base()
    projector = IntegratedDurableCheckpointMetadataProjector()

    with pytest.raises(ValueError, match="durable agent options require agent_durable_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_durable_metadata_projector=projector,
        )


@pytest.mark.asyncio
async def test_runtime_assembler_composes_explicit_sqlite_durable_state(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    durable_state = tmp_path / "state" / "agent-durable.sqlite3"
    projector = IntegratedDurableCheckpointMetadataProjector()
    history_validator = IntegratedDurableRecoveryHistoryValidator()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=AgentServiceConfiguration(
            agent_id=AgentId("nova"),
            provider_id=ModelProviderId("deterministic"),
            model_id=ModelId("chat"),
        ),
        agent_model_adapter=_model_adapter(),
        agent_durable_enabled=True,
        agent_durable_sqlite_path=durable_state,
        agent_durable_compatibility_validator=StaticDurableCompatibilityValidator(()),
        agent_durable_metadata_projector=projector,
        agent_durable_history_validator=history_validator,
    ).assemble()

    stack = runtime.service("agent.durable")
    store = runtime.service("agent.durable.storage")
    leases = runtime.service("agent.durable.leases")

    assert isinstance(stack, DurableAgentRuntimeStack)
    assert stack.metadata_projector is projector
    assert stack.history_validator is history_validator
    assert isinstance(store, SQLiteDurableRunStore)
    assert store.path == durable_state.resolve(strict=False)
    assert leases is store.lease_manager
    assert store.freshness_witness_path == durable_state.with_name(
        f"{durable_state.name}.freshness"
    ).resolve(strict=False)

    await runtime.start()
    try:
        await store.get_store_freshness()
        assert durable_state.exists()
        assert store.freshness_witness_path.exists()
    finally:
        await runtime.stop()

    assert store.closed
    assert store.lease_manager.closed


@pytest.mark.asyncio
async def test_agent_durable_sqlite_coexists_with_generic_state_on_same_file(
    tmp_path: Path,
) -> None:
    from phoenix_os.state import SQLiteStateStore, StateKey

    path = tmp_path / "shared-durable.sqlite3"
    durable = SQLiteDurableRunStore(path)
    state = SQLiteStateStore(path)
    try:
        identity = await durable.resolve_checkout_registration_identity(
            registration_key="a" * 64,
            registration_digest="b" * 64,
        )
        stored = await state.put(StateKey("agent", "coexistence"), {"ready": True})
        assert identity.generation == 1
        assert stored.value == {"ready": True}
    finally:
        await state.close()
        await durable.close()
