import json
from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest

from phoenix_os.agent import (
    AgentCodecError,
    AgentSchemaError,
    StaticToolResourceResolver,
    ToolAvailability,
    ToolDescriptor,
    ToolEffect,
    ToolExecutionError,
    ToolId,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
    canonical_tool_descriptor_bytes,
    decode_tool_descriptor,
    encode_tool_descriptor,
    resolve_server_resource,
    validate_tool_input,
)


def _object_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "path": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"path"}),
    )


def _descriptor(**overrides: object) -> ToolDescriptor:
    values: dict[str, object] = {
        "tool_id": ToolId("files.read"),
        "name": "Read reviewed file",
        "description": "Read one bounded file from an admitted workspace.",
        "input_schema": ToolInputSchema(_object_schema()),
        "output_schema": ToolOutputSchema(
            ToolSchema(
                kind=ToolSchemaType.OBJECT,
                properties={
                    "content": ToolSchema(
                        kind=ToolSchemaType.STRING,
                        max_length=1_024,
                    )
                },
                required=frozenset({"content"}),
            )
        ),
        "effect": ToolEffect.READ_ONLY,
        "approval_may_be_required": False,
        "max_input_bytes": 4_096,
        "max_output_bytes": 8_192,
        "timeout": timedelta(seconds=10),
        "resolver_id": "workspace-file",
        "adapter_id": "deterministic-file-reader",
        "metadata": {"category": "test"},
    }
    values.update(overrides)
    return ToolDescriptor(**values)  # type: ignore[arg-type]


def test_descriptor_is_immutable_bounded_and_canonical() -> None:
    metadata = {"category": "test"}
    descriptor = _descriptor(metadata=metadata)
    metadata["category"] = "changed"

    assert descriptor.name == "Read reviewed file"
    assert descriptor.metadata == {"category": "test"}
    assert canonical_tool_descriptor_bytes(descriptor) == encode_tool_descriptor(descriptor)
    assert decode_tool_descriptor(encode_tool_descriptor(descriptor)) == descriptor
    with pytest.raises(TypeError):
        descriptor.metadata["new"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        descriptor.name = "changed"  # type: ignore[misc]


def test_descriptor_rejects_invalid_limits_and_implementation_ids() -> None:
    with pytest.raises(ValueError, match="max_input_bytes"):
        _descriptor(max_input_bytes=0)
    with pytest.raises(ValueError, match="timeout"):
        _descriptor(timeout=timedelta(0))
    with pytest.raises(ValueError, match="resolver_id"):
        _descriptor(resolver_id="unsafe resolver")
    with pytest.raises(TypeError, match="approval"):
        _descriptor(approval_may_be_required=1)


def test_descriptor_decoder_rejects_noncanonical_and_duplicate_json() -> None:
    descriptor = _descriptor()
    record = json.loads(encode_tool_descriptor(descriptor))
    noncanonical = json.dumps(record, indent=2).encode()

    with pytest.raises(AgentCodecError, match="canonical"):
        decode_tool_descriptor(noncanonical)
    with pytest.raises(AgentCodecError, match="duplicate"):
        decode_tool_descriptor(b'{"tool_id":"one","tool_id":"two"}')


def test_static_resource_resolver_is_server_owned_and_normalized() -> None:
    resolver = StaticToolResourceResolver(
        resolver_id="workspace-file",
        resource=" workspace:docs/readme.md ",
    )

    assert resolver.resource == "workspace:docs/readme.md"
    assert resolve_server_resource(resolver, {"path": "model-value"}) == (
        "workspace:docs/readme.md"
    )
    with pytest.raises(ToolExecutionError):
        StaticToolResourceResolver("workspace-file", "../../unsafe path")


def test_schema_contract_still_rejects_unknown_properties() -> None:
    descriptor = _descriptor(availability=ToolAvailability.DISABLED)

    with pytest.raises(AgentSchemaError, match="unknown"):
        validate_tool_input(
            descriptor.input_schema,
            {"path": "docs/readme.md", "unexpected": True},
        )
