from datetime import timedelta

import pytest

from phoenix_os.agent import (
    AgentAdministration,
    AgentAdmissionController,
    AgentId,
    AgentRuntimeLifecycle,
    AgentService,
    AgentServiceConfiguration,
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
    create_agent_runtime_stack,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine


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


def _descriptor(
    tool_id: str = "workspace.read",
    *,
    effect: ToolEffect = ToolEffect.READ_ONLY,
    adapter_id: str | None = None,
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=f"Tool {tool_id}",
        description="One reviewed deterministic composition test tool.",
        input_schema=ToolInputSchema(_schema()),
        output_schema=ToolOutputSchema(_schema()),
        effect=effect,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=8_192,
        timeout=timedelta(seconds=10),
        resolver_id=f"{tool_id}.resolver",
        adapter_id=adapter_id or f"{tool_id}.adapter",
    )


def _configuration(*descriptors: ToolDescriptor) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=tuple(AgentToolConfiguration(descriptor) for descriptor in descriptors),
    )


def _model_adapter() -> DeterministicModelTurnAdapter:
    return DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))


def _resolver(descriptor: ToolDescriptor) -> StaticToolResourceResolver:
    return StaticToolResourceResolver(
        resolver_id=descriptor.resolver_id,
        resource=f"workspace/{descriptor.tool_id}",
    )


def _adapter(descriptor: ToolDescriptor) -> DeterministicReadOnlyTool:
    return DeterministicReadOnlyTool(
        descriptor.tool_id,
        {"value": "ok"},
        adapter_id=descriptor.adapter_id,
    )


def test_agent_composition_builds_one_closed_world_runtime_stack() -> None:
    descriptor = _descriptor()
    configuration = _configuration(descriptor)

    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=_model_adapter(),
        tool_resolvers=(_resolver(descriptor),),
        tool_adapters=(_adapter(descriptor),),
        policy=PolicyEngine(),
    )

    assert stack.configuration is configuration
    assert stack.registry.list_descriptors() == (descriptor,)
    assert stack.admission.limits is configuration.limits
    assert isinstance(stack.admission, AgentAdmissionController)
    assert isinstance(stack.executor, BoundedAgentExecutor)
    assert isinstance(stack.service, AgentService)
    assert isinstance(stack.administration, AgentAdministration)
    assert isinstance(stack.lifecycle, AgentRuntimeLifecycle)
    assert stack.lifecycle is stack.service
    assert stack.approval_service is None


def test_agent_composition_requires_exact_resolver_and_adapter_installations() -> None:
    descriptor = _descriptor()
    configuration = _configuration(descriptor)

    with pytest.raises(ValueError, match="resolvers must exactly match"):
        create_agent_runtime_stack(
            configuration=configuration,
            model_adapter=_model_adapter(),
            tool_resolvers=(),
            tool_adapters=(_adapter(descriptor),),
            policy=PolicyEngine(),
        )

    with pytest.raises(ValueError, match="adapters must exactly match"):
        create_agent_runtime_stack(
            configuration=configuration,
            model_adapter=_model_adapter(),
            tool_resolvers=(_resolver(descriptor),),
            tool_adapters=(),
            policy=PolicyEngine(),
        )


def test_agent_composition_closes_registry_after_partial_registration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _descriptor("workspace.read")
    second = _descriptor("workspace.write")
    configuration = _configuration(first, second)
    closed: list[ToolRegistry] = []
    original_close = ToolRegistry.close

    def track_close(registry: ToolRegistry) -> None:
        closed.append(registry)
        original_close(registry)

    monkeypatch.setattr(ToolRegistry, "close", track_close)

    with pytest.raises(ValueError, match="adapter identity"):
        create_agent_runtime_stack(
            configuration=configuration,
            model_adapter=_model_adapter(),
            tool_resolvers=(_resolver(first), _resolver(second)),
            tool_adapters=(
                _adapter(first),
                DeterministicReadOnlyTool(
                    second.tool_id,
                    {"value": "ok"},
                    adapter_id="wrong.adapter",
                ),
            ),
            policy=PolicyEngine(),
        )

    assert len(closed) == 1
    assert closed[0].closed


def test_agent_composition_rejects_approval_required_tools_without_approval_services() -> None:
    descriptor = _descriptor(
        "mail.send",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )

    with pytest.raises(ValueError, match="approval-required"):
        create_agent_runtime_stack(
            configuration=_configuration(descriptor),
            model_adapter=_model_adapter(),
            tool_resolvers=(_resolver(descriptor),),
            tool_adapters=(_adapter(descriptor),),
            policy=PolicyEngine(),
        )
