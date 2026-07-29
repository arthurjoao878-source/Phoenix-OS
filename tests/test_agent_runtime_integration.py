from datetime import timedelta

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
