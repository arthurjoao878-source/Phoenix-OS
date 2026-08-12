from __future__ import annotations

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
    AgentId,
    AgentMemoryRuntimeConfiguration,
    AgentMemoryRuntimeOwner,
    AgentServiceConfiguration,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    InMemoryDerivedMemoryIndex,
    MemoryEmbeddingProvider,
    MemoryNamespace,
)
from phoenix_os.configuration import Configuration
from phoenix_os.events import Event
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
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
    )


def _model_adapter() -> DeterministicModelTurnAdapter:
    return DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))


class _EmbeddingProvider:
    provider_id = "runtime-test"
    dimension = 3

    async def embed(self, text: str) -> tuple[float, float, float]:
        if "blue" in text.casefold():
            return (1.0, 0.0, 0.0)
        return (0.0, 1.0, 0.0)


@pytest.mark.asyncio
async def test_runtime_memory_is_absent_when_configuration_is_omitted() -> None:
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
        "agent.memory",
        "agent.memory.store",
        "agent.memory.retrieval",
        "agent.memory.index",
        "agent.memory.administration",
    ):
        assert name not in runtime.services
    assert "agent.memory" not in (await runtime.snapshot()).components

    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_owns_opt_in_memory_before_agent_and_stops_agent_first() -> None:
    configuration, events, kernel, capabilities = await _base()
    stopped: list[str] = []

    async def capture(event: Event) -> None:
        if event.name == "runtime.component.stopped":
            component = event.payload.get("component")
            if isinstance(component, str):
                stopped.append(component)

    await events.subscribe("*", capture)
    policy = PolicyEngine()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=policy,
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_memory_configuration=AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("assistant-memory"),
            maintenance_interval=timedelta(hours=1),
        ),
    ).assemble()

    owner = runtime.service("agent.memory")
    assert isinstance(owner, object)
    assert isinstance(runtime.service("agent.memory.owner"), AgentMemoryRuntimeOwner)
    assert runtime.service("agent.memory.store") is not None
    assert runtime.service("agent.memory.retrieval") is not None
    assert runtime.service("agent.memory.administration") is not None
    assert "agent.memory.index" not in runtime.services

    components = (await runtime.snapshot()).components
    assert components.index("agent.memory") < components.index("agent")

    await runtime.start()
    await runtime.stop()

    memory_owner = runtime.service("agent.memory.owner")
    assert isinstance(memory_owner, AgentMemoryRuntimeOwner)
    assert memory_owner.closed
    assert stopped.index("agent") < stopped.index("agent.memory")
    assert policy.closed


@pytest.mark.asyncio
async def test_runtime_semantic_memory_is_explicit_and_exposes_derived_index() -> None:
    configuration, events, kernel, capabilities = await _base()
    provider = _EmbeddingProvider()
    assert isinstance(provider, MemoryEmbeddingProvider)
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=PolicyEngine(),
        agent_enabled=True,
        agent_configuration=_agent_configuration(),
        agent_model_adapter=_model_adapter(),
        agent_memory_configuration=AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("assistant-memory"),
            semantic_enabled=True,
            maintenance_interval=timedelta(hours=1),
        ),
        agent_memory_embedding_provider=provider,
    ).assemble()

    assert isinstance(runtime.service("agent.memory.index"), InMemoryDerivedMemoryIndex)
    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_memory_configuration_requires_agent_and_semantic_provider() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="agent_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_memory_configuration=AgentMemoryRuntimeConfiguration(
                namespace=MemoryNamespace("assistant-memory")
            ),
        )

    with pytest.raises(ValueError, match="embedding provider"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=PolicyEngine(),
            agent_enabled=True,
            agent_configuration=_agent_configuration(),
            agent_model_adapter=_model_adapter(),
            agent_memory_configuration=AgentMemoryRuntimeConfiguration(
                namespace=MemoryNamespace("assistant-memory"),
                semantic_enabled=True,
            ),
        )
