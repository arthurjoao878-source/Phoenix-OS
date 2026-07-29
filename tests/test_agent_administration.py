from datetime import timedelta

import pytest

from phoenix_os.agent import (
    AGENT_HEALTH_READ_PERMISSION,
    AGENT_TOOLS_DISABLE_PERMISSION,
    AGENT_TOOLS_ENABLE_PERMISSION,
    AGENT_TOOLS_READ_PERMISSION,
    AgentAdministrationAccessDeniedError,
    AgentId,
    AgentRuntimeStack,
    AgentServiceConfiguration,
    AgentToolConfiguration,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    StaticToolResourceResolver,
    ToolAvailability,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
    agent_health_resource,
    agent_tool_resource,
    create_agent_runtime_stack,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext


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
        description="Read one reviewed workspace value.",
        input_schema=ToolInputSchema(_schema()),
        output_schema=ToolOutputSchema(_schema()),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=8_192,
        timeout=timedelta(seconds=10),
        resolver_id="workspace.read.resolver",
        adapter_id="workspace.read.adapter",
        metadata={"private": "PRIVATE-TOOL-METADATA-MUST-NOT-LEAK"},
    )


def _configuration(descriptor: ToolDescriptor) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(descriptor),),
    )


def _admin_context() -> SecurityContext:
    return SecurityContext(
        principal="operator:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(
            {
                AGENT_TOOLS_READ_PERMISSION,
                AGENT_TOOLS_DISABLE_PERMISSION,
                AGENT_TOOLS_ENABLE_PERMISSION,
                AGENT_HEALTH_READ_PERMISSION,
            }
        ),
        correlation_id="agent-admin-correlation",
    )


def _service_context(resource: str, permission: str) -> SecurityContext:
    return SecurityContext(
        principal="service:agent-admin",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({permission}),
        attributes={"resource": resource},
    )


def _stack(events: EventBus | None = None) -> AgentRuntimeStack:
    descriptor = _descriptor()
    configuration = _configuration(descriptor)
    return create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(
            StaticToolResourceResolver(
                descriptor.resolver_id,
                "workspace/read",
            ),
        ),
        tool_adapters=(
            DeterministicReadOnlyTool(
                descriptor.tool_id,
                {"value": "SECRET-TOOL-RESULT-MUST-NOT-LEAK"},
                adapter_id=descriptor.adapter_id,
            ),
        ),
        policy=PolicyEngine(),
        events=EventBus() if events is None else events,
    )


@pytest.mark.asyncio
async def test_administration_exposes_safe_tool_inventory_and_health() -> None:
    stack = _stack()
    tools = await stack.administration.list_tools(_admin_context())
    snapshot = await stack.administration.snapshot(_admin_context())

    assert len(tools) == 1
    tool = tools[0]
    assert str(tool.tool_id) == "workspace.read"
    assert tool.effect is ToolEffect.READ_ONLY
    assert tool.availability is ToolAvailability.ACTIVE
    assert tool.enabled is True
    assert tool.revision == 1
    assert snapshot.tools == 1
    assert snapshot.enabled_tools == 1
    serialized = repr((tools, snapshot))
    assert "PRIVATE-TOOL-METADATA-MUST-NOT-LEAK" not in serialized
    assert "SECRET-TOOL-RESULT-MUST-NOT-LEAK" not in serialized
    assert "workspace.read.adapter" not in serialized
    assert "workspace.read.resolver" not in serialized


@pytest.mark.asyncio
async def test_administration_disables_and_reenables_one_tool_optimistically() -> None:
    stack = _stack()
    context = _admin_context()
    initial = await stack.administration.tool("workspace.read", context)

    disabled = await stack.administration.set_tool_enabled(
        "workspace.read",
        context,
        enabled=False,
        expected_revision=initial.revision,
    )
    assert disabled.availability is ToolAvailability.DISABLED
    assert disabled.revision == 2
    assert stack.registry.list_descriptors() == ()

    enabled = await stack.administration.set_tool_enabled(
        "workspace.read",
        context,
        enabled=True,
        expected_revision=disabled.revision,
    )
    assert enabled.availability is ToolAvailability.ACTIVE
    assert enabled.revision == 3
    assert len(stack.registry.list_descriptors()) == 1


@pytest.mark.asyncio
async def test_service_account_administration_is_bound_to_exact_resource() -> None:
    stack = _stack()
    configuration = stack.configuration
    exact = agent_tool_resource(configuration.agent_id, "workspace.read")

    tool = await stack.administration.tool(
        "workspace.read",
        _service_context(exact, AGENT_TOOLS_READ_PERMISSION),
    )
    assert str(tool.tool_id) == "workspace.read"

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await stack.administration.snapshot(_service_context(exact, AGENT_HEALTH_READ_PERMISSION))

    health = agent_health_resource(configuration.agent_id)
    snapshot = await stack.administration.snapshot(
        _service_context(health, AGENT_HEALTH_READ_PERMISSION)
    )
    assert snapshot.tools == 1


@pytest.mark.asyncio
async def test_tool_lifecycle_events_have_empty_payload_and_safe_metadata() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.tool."):
            captured.append(event)

    await events.subscribe("*", capture)
    stack = _stack(events)
    initial = await stack.administration.tool("workspace.read", _admin_context())

    await stack.administration.set_tool_enabled(
        "workspace.read",
        _admin_context(),
        enabled=False,
        expected_revision=initial.revision,
    )

    assert len(captured) == 1
    assert captured[0].payload == {}
    assert captured[0].metadata["tool_id"] == "workspace.read"
    assert captured[0].metadata["availability"] == "disabled"
    assert "PRIVATE-TOOL-METADATA-MUST-NOT-LEAK" not in repr(captured[0])
