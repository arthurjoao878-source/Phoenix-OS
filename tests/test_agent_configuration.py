from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest

from phoenix_os.agent import (
    MAX_AGENT_CONFIG_METADATA_ITEMS,
    MAX_AGENT_CONFIG_TOOLS,
    AgentId,
    AgentLimits,
    AgentObservabilityConfiguration,
    AgentServiceConfiguration,
    AgentToolConfiguration,
    ToolAvailability,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.inference import ModelId, ModelProviderId


def _object_schema() -> ToolSchema:
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
    availability: ToolAvailability = ToolAvailability.ACTIVE,
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=f"Tool {tool_id}",
        description="One reviewed bounded deterministic test tool.",
        input_schema=ToolInputSchema(_object_schema()),
        output_schema=ToolOutputSchema(_object_schema()),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=8_192,
        timeout=timedelta(seconds=10),
        resolver_id=f"{tool_id}.resolver",
        adapter_id=f"{tool_id}.adapter",
        availability=availability,
    )


def _configuration(**overrides: object) -> AgentServiceConfiguration:
    values: dict[str, object] = {
        "agent_id": AgentId("nova"),
        "provider_id": ModelProviderId("deterministic"),
        "model_id": ModelId("chat"),
        "tools": (AgentToolConfiguration(_descriptor()),),
        "limits": AgentLimits(),
        "observability": AgentObservabilityConfiguration(),
        "source": "phoenix.agent",
        "metadata": {"environment": "test"},
    }
    values.update(overrides)
    return AgentServiceConfiguration(**values)  # type: ignore[arg-type]


def test_tool_configuration_is_typed_and_immutable() -> None:
    descriptor = _descriptor()
    configured = AgentToolConfiguration(descriptor)

    assert configured.tool_id == ToolId("workspace.read")
    assert configured.descriptor is descriptor
    with pytest.raises(FrozenInstanceError):
        configured.descriptor = _descriptor("other.read")  # type: ignore[misc]
    with pytest.raises(TypeError, match="ToolDescriptor"):
        AgentToolConfiguration(object())  # type: ignore[arg-type]


def test_service_configuration_is_finite_immutable_and_ordered() -> None:
    first = AgentToolConfiguration(_descriptor("workspace.read"))
    second = AgentToolConfiguration(
        _descriptor("mail.send", availability=ToolAvailability.DISABLED)
    )
    source_tools = [first, second]
    metadata = {" Environment ": " Test "}

    configured = _configuration(tools=source_tools, metadata=metadata, source=" PHOENIX.Agent ")
    source_tools.reverse()
    metadata["Environment"] = "changed"

    assert configured.source == "phoenix.agent"
    assert configured.metadata == {"environment": "Test"}
    assert configured.tool_ids == (ToolId("workspace.read"), ToolId("mail.send"))
    assert configured.descriptors == (first.descriptor, second.descriptor)
    assert configured.tools == (first, second)
    with pytest.raises(TypeError):
        configured.metadata["new"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        configured.source = "changed"  # type: ignore[misc]


def test_configuration_allows_a_model_only_agent() -> None:
    configured = _configuration(tools=())

    assert configured.tools == ()
    assert configured.tool_ids == ()
    assert configured.descriptors == ()


def test_configuration_rejects_duplicate_or_untyped_tools() -> None:
    tool = AgentToolConfiguration(_descriptor())

    with pytest.raises(ValueError, match="duplicate tools"):
        _configuration(tools=(tool, tool))
    with pytest.raises(TypeError, match="AgentToolConfiguration"):
        _configuration(tools=(_descriptor(),))


def test_configuration_rejects_tool_count_above_supported_bound() -> None:
    tools = tuple(
        AgentToolConfiguration(_descriptor(f"test.tool-{index}"))
        for index in range(MAX_AGENT_CONFIG_TOOLS + 1)
    )

    with pytest.raises(ValueError, match="supported count"):
        _configuration(tools=tools)


def test_configuration_requires_exact_agent_model_and_limit_types() -> None:
    with pytest.raises(TypeError, match="agent_id"):
        _configuration(agent_id="nova")
    with pytest.raises(TypeError, match="provider_id"):
        _configuration(provider_id="deterministic")
    with pytest.raises(TypeError, match="model_id"):
        _configuration(model_id="chat")
    with pytest.raises(TypeError, match="limits"):
        _configuration(limits=object())
    with pytest.raises(TypeError, match="observability"):
        _configuration(observability=object())


def test_observability_configuration_is_strict_and_content_free() -> None:
    disabled = AgentObservabilityConfiguration(
        audit_enabled=False,
        metrics_enabled=False,
        logs_enabled=False,
        events_enabled=False,
    )

    assert disabled.any_enabled is False
    assert AgentObservabilityConfiguration().any_enabled is True
    with pytest.raises(TypeError, match="booleans"):
        AgentObservabilityConfiguration(audit_enabled=1)  # type: ignore[arg-type]


def test_configuration_metadata_is_bounded_normalized_and_non_secret() -> None:
    with pytest.raises(ValueError, match="duplicate normalized"):
        _configuration(metadata={"Environment": "one", " environment ": "two"})
    with pytest.raises(ValueError, match="blank"):
        _configuration(metadata={"environment": " "})
    with pytest.raises(TypeError, match="strings"):
        _configuration(metadata={"environment": 1})
    with pytest.raises(ValueError, match="item count"):
        _configuration(
            metadata={
                f"key-{index}": "value" for index in range(MAX_AGENT_CONFIG_METADATA_ITEMS + 1)
            }
        )


def test_configuration_rejects_invalid_source_identifier() -> None:
    with pytest.raises(ValueError, match="lowercase Phoenix identifier"):
        _configuration(source="unsafe source")
    with pytest.raises(TypeError, match="source"):
        _configuration(source=1)
