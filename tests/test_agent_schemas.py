from types import MappingProxyType

import pytest

from phoenix_os.agent import (
    AgentSchemaError,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
    canonical_tool_schema_bytes,
    validate_tool_input,
    validate_tool_output,
)


def _input_schema() -> ToolInputSchema:
    return ToolInputSchema(
        ToolSchema(
            ToolSchemaType.OBJECT,
            properties={
                "path": ToolSchema(
                    ToolSchemaType.STRING,
                    min_length=1,
                    max_length=128,
                ),
                "lines": ToolSchema(
                    ToolSchemaType.ARRAY,
                    items=ToolSchema(
                        ToolSchemaType.INTEGER,
                        minimum=1,
                        maximum=10_000,
                    ),
                    min_items=1,
                    max_items=10,
                ),
                "strict": ToolSchema(ToolSchemaType.BOOLEAN),
                "mode": ToolSchema(
                    ToolSchemaType.STRING,
                    enum=("text", "metadata"),
                ),
            },
            required=frozenset({"path", "lines"}),
        )
    )


def test_schema_validates_and_deeply_freezes_tool_input() -> None:
    source: dict[str, object] = {
        "path": "docs/readme.md",
        "lines": [1, 2],
        "strict": True,
        "mode": "text",
    }
    validated = validate_tool_input(_input_schema(), source)  # type: ignore[arg-type]
    source["path"] = "changed"
    source["lines"] = [99]

    assert isinstance(validated, MappingProxyType)
    assert validated == {
        "path": "docs/readme.md",
        "lines": (1, 2),
        "strict": True,
        "mode": "text",
    }
    with pytest.raises(TypeError):
        validated["path"] = "changed"  # type: ignore[index]


def test_schema_rejects_unknown_missing_and_wrong_typed_values() -> None:
    schema = _input_schema()

    with pytest.raises(AgentSchemaError, match="unknown"):
        validate_tool_input(
            schema,
            {"path": "a", "lines": [1], "extra": True},
        )
    with pytest.raises(AgentSchemaError, match="missing"):
        validate_tool_input(schema, {"path": "a"})
    with pytest.raises(AgentSchemaError, match="required type"):
        validate_tool_input(schema, {"path": "a", "lines": [True]})


def test_schema_enforces_string_array_numeric_and_enum_bounds() -> None:
    schema = _input_schema()

    with pytest.raises(AgentSchemaError, match="too few characters"):
        validate_tool_input(schema, {"path": "", "lines": [1]})
    with pytest.raises(AgentSchemaError, match="too many items"):
        validate_tool_input(schema, {"path": "a", "lines": list(range(11))})
    with pytest.raises(AgentSchemaError, match="below the minimum"):
        validate_tool_input(schema, {"path": "a", "lines": [0]})
    with pytest.raises(AgentSchemaError, match="enum"):
        validate_tool_input(
            schema,
            {"path": "a", "lines": [1], "mode": "unsupported"},
        )


def test_schema_contract_rejects_invalid_constraints() -> None:
    with pytest.raises(AgentSchemaError, match="object schema"):
        ToolInputSchema(ToolSchema(ToolSchemaType.STRING))
    with pytest.raises(AgentSchemaError, match="required properties"):
        ToolSchema(
            ToolSchemaType.OBJECT,
            properties={"known": ToolSchema(ToolSchemaType.STRING)},
            required=frozenset({"missing"}),
        )
    with pytest.raises(AgentSchemaError, match="item schema"):
        ToolSchema(ToolSchemaType.ARRAY)
    with pytest.raises(AgentSchemaError, match="minimum"):
        ToolSchema(ToolSchemaType.INTEGER, minimum=2, maximum=1)
    with pytest.raises(AgentSchemaError, match="finite"):
        ToolSchema(ToolSchemaType.NUMBER, maximum=float("inf"))
    with pytest.raises(AgentSchemaError, match="non-object"):
        ToolSchema(
            ToolSchemaType.STRING,
            properties={"unsafe": ToolSchema(ToolSchemaType.STRING)},
        )


def test_output_schema_and_canonical_schema_bytes_are_deterministic() -> None:
    first = ToolOutputSchema(
        ToolSchema(
            ToolSchemaType.OBJECT,
            properties={
                "count": ToolSchema(ToolSchemaType.INTEGER, minimum=0),
                "ok": ToolSchema(ToolSchemaType.BOOLEAN),
            },
            required=frozenset({"ok", "count"}),
        )
    )
    second = ToolOutputSchema(
        ToolSchema(
            ToolSchemaType.OBJECT,
            properties={
                "ok": ToolSchema(ToolSchemaType.BOOLEAN),
                "count": ToolSchema(ToolSchemaType.INTEGER, minimum=0),
            },
            required=frozenset({"count", "ok"}),
        )
    )

    assert canonical_tool_schema_bytes(first) == canonical_tool_schema_bytes(second)
    assert validate_tool_output(first, {"ok": True, "count": 2}) == {
        "ok": True,
        "count": 2,
    }
