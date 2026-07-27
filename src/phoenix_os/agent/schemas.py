"""Strict bounded schemas for untrusted tool arguments and results."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from phoenix_os.agent.contracts import (
    AgentJsonInput,
    AgentJsonScalar,
    AgentJsonValue,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import AgentSchemaError

MAX_TOOL_SCHEMA_DEPTH = 16
MAX_TOOL_SCHEMA_NODES = 4_096
MAX_TOOL_SCHEMA_PROPERTIES = 256
MAX_TOOL_SCHEMA_REQUIRED_PROPERTIES = 256
MAX_TOOL_SCHEMA_ENUM_ITEMS = 256
MAX_TOOL_SCHEMA_NAME_LENGTH = 256
MAX_TOOL_SCHEMA_STRING_LENGTH = 262_144
MAX_TOOL_SCHEMA_ARRAY_ITEMS = 16_384
MAX_TOOL_SCHEMA_CANONICAL_BYTES = 262_144


class ToolSchemaType(StrEnum):
    OBJECT = "object"
    ARRAY = "array"
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    NULL = "null"


@dataclass(frozen=True, slots=True)
class ToolSchema:
    """One immutable node in the Phoenix strict schema subset."""

    kind: ToolSchemaType
    properties: Mapping[str, ToolSchema] = field(default_factory=dict)
    required: frozenset[str] = field(default_factory=frozenset)
    items: ToolSchema | None = None
    enum: tuple[AgentJsonScalar, ...] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    min_length: int | None = None
    max_length: int | None = None
    min_items: int | None = None
    max_items: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ToolSchemaType):
            raise TypeError("kind must be ToolSchemaType")
        properties = _freeze_properties(self.properties)
        required = _freeze_required(self.required)
        enum = tuple(self.enum)
        if len(enum) > MAX_TOOL_SCHEMA_ENUM_ITEMS:
            raise AgentSchemaError("tool schema enum exceeds the maximum item count")
        for value in enum:
            _validate_enum_scalar(value, self.kind)
        object.__setattr__(self, "properties", properties)
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "enum", enum)
        self._validate_kind_constraints()

    def _validate_kind_constraints(self) -> None:
        if self.kind is ToolSchemaType.OBJECT:
            if self.items is not None:
                raise AgentSchemaError("object schemas cannot define items")
            if not self.required.issubset(self.properties):
                raise AgentSchemaError("required properties must exist in properties")
            _reject_numeric_constraints(self)
            _reject_length_constraints(self)
            _reject_array_constraints(self)
            return

        if self.kind is ToolSchemaType.ARRAY:
            if not isinstance(self.items, ToolSchema):
                raise AgentSchemaError("array schemas require one item schema")
            _require_empty_object_constraints(self)
            _reject_numeric_constraints(self)
            _reject_length_constraints(self)
            _validate_optional_bound(
                self.min_items,
                label="min_items",
                maximum=MAX_TOOL_SCHEMA_ARRAY_ITEMS,
            )
            _validate_optional_bound(
                self.max_items,
                label="max_items",
                maximum=MAX_TOOL_SCHEMA_ARRAY_ITEMS,
            )
            _require_ordered_bounds(self.min_items, self.max_items, label="array item")
            return

        _require_empty_object_constraints(self)
        if self.items is not None:
            raise AgentSchemaError("primitive schemas cannot define items")
        _reject_array_constraints(self)

        if self.kind is ToolSchemaType.STRING:
            _reject_numeric_constraints(self)
            _validate_optional_bound(
                self.min_length,
                label="min_length",
                maximum=MAX_TOOL_SCHEMA_STRING_LENGTH,
            )
            _validate_optional_bound(
                self.max_length,
                label="max_length",
                maximum=MAX_TOOL_SCHEMA_STRING_LENGTH,
            )
            _require_ordered_bounds(self.min_length, self.max_length, label="string length")
            return

        _reject_length_constraints(self)
        if self.kind in {ToolSchemaType.INTEGER, ToolSchemaType.NUMBER}:
            minimum = _validate_optional_number(self.minimum, label="minimum")
            maximum = _validate_optional_number(self.maximum, label="maximum")
            if minimum is not None and maximum is not None and minimum > maximum:
                raise AgentSchemaError("minimum cannot exceed maximum")
            if self.kind is ToolSchemaType.INTEGER:
                for label, value in (("minimum", minimum), ("maximum", maximum)):
                    if value is not None and not isinstance(value, int):
                        raise AgentSchemaError(f"integer schema {label} must be an integer")
            return

        _reject_numeric_constraints(self)


@dataclass(frozen=True, slots=True)
class ToolInputSchema:
    root: ToolSchema

    def __post_init__(self) -> None:
        _validate_root_schema(self.root, label="tool input schema")


@dataclass(frozen=True, slots=True)
class ToolOutputSchema:
    root: ToolSchema

    def __post_init__(self) -> None:
        _validate_root_schema(self.root, label="tool output schema")


def validate_tool_input(
    schema: ToolInputSchema,
    value: Mapping[str, AgentJsonInput],
) -> Mapping[str, AgentJsonValue]:
    if not isinstance(schema, ToolInputSchema):
        raise TypeError("schema must be ToolInputSchema")
    return _validate_root_value(schema.root, value, label="tool input")


def validate_tool_output(
    schema: ToolOutputSchema,
    value: Mapping[str, AgentJsonInput],
) -> Mapping[str, AgentJsonValue]:
    if not isinstance(schema, ToolOutputSchema):
        raise TypeError("schema must be ToolOutputSchema")
    return _validate_root_value(schema.root, value, label="tool output")


def canonical_tool_schema_bytes(
    schema: ToolInputSchema | ToolOutputSchema,
) -> bytes:
    if not isinstance(schema, (ToolInputSchema, ToolOutputSchema)):
        raise TypeError("schema must be ToolInputSchema or ToolOutputSchema")
    try:
        encoded = json.dumps(
            tool_schema_to_record(schema.root),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise AgentSchemaError() from exception
    if len(encoded) > MAX_TOOL_SCHEMA_CANONICAL_BYTES:
        raise AgentSchemaError("tool schema exceeds the maximum encoded size")
    return encoded


def tool_schema_to_record(schema: ToolSchema) -> dict[str, object]:
    if not isinstance(schema, ToolSchema):
        raise TypeError("schema must be ToolSchema")
    return {
        "type": schema.kind.value,
        "properties": {
            key: tool_schema_to_record(value) for key, value in schema.properties.items()
        },
        "required": sorted(schema.required),
        "items": None if schema.items is None else tool_schema_to_record(schema.items),
        "enum": list(schema.enum),
        "minimum": schema.minimum,
        "maximum": schema.maximum,
        "min_length": schema.min_length,
        "max_length": schema.max_length,
        "min_items": schema.min_items,
        "max_items": schema.max_items,
        "additional_properties": False,
    }


def tool_schema_from_record(record: Mapping[str, object]) -> ToolSchema:
    expected = frozenset(
        {
            "type",
            "properties",
            "required",
            "items",
            "enum",
            "minimum",
            "maximum",
            "min_length",
            "max_length",
            "min_items",
            "max_items",
            "additional_properties",
        }
    )
    if frozenset(record) != expected:
        raise AgentSchemaError("tool schema fields are invalid")
    additional = record.get("additional_properties")
    if additional is not False:
        raise AgentSchemaError("tool schemas must reject unknown properties")
    properties_value = record.get("properties")
    if not isinstance(properties_value, Mapping):
        raise AgentSchemaError("tool schema properties must be an object")
    properties_mapping = cast(Mapping[object, object], properties_value)
    properties: dict[str, ToolSchema] = {}
    for key, value in properties_mapping.items():
        if not isinstance(key, str) or not isinstance(value, Mapping):
            raise AgentSchemaError("tool schema properties are invalid")
        properties[key] = tool_schema_from_record(cast(Mapping[str, object], value))
    required_value = record.get("required")
    if not isinstance(required_value, list):
        raise AgentSchemaError("tool schema required must be a string array")
    required_items: list[str] = []
    for item in cast(list[object], required_value):
        if not isinstance(item, str):
            raise AgentSchemaError("tool schema required must be a string array")
        required_items.append(item)
    enum_value = record.get("enum")
    if not isinstance(enum_value, list):
        raise AgentSchemaError("tool schema enum must be an array")
    enum: list[AgentJsonScalar] = []
    for item in cast(list[object], enum_value):
        if item is None or isinstance(item, (str, bool, int, float)):
            enum.append(item)
        else:
            raise AgentSchemaError("tool schema enum values must be scalar")
    items_value = record.get("items")
    if items_value is not None and not isinstance(items_value, Mapping):
        raise AgentSchemaError("tool schema items must be an object or null")
    return ToolSchema(
        kind=ToolSchemaType(_require_string(record.get("type"), label="type")),
        properties=properties,
        required=frozenset(required_items),
        items=(
            None
            if items_value is None
            else tool_schema_from_record(cast(Mapping[str, object], items_value))
        ),
        enum=tuple(enum),
        minimum=_optional_number_from_record(record.get("minimum"), label="minimum"),
        maximum=_optional_number_from_record(record.get("maximum"), label="maximum"),
        min_length=_optional_integer_from_record(record.get("min_length"), label="min_length"),
        max_length=_optional_integer_from_record(record.get("max_length"), label="max_length"),
        min_items=_optional_integer_from_record(record.get("min_items"), label="min_items"),
        max_items=_optional_integer_from_record(record.get("max_items"), label="max_items"),
    )


def _freeze_properties(value: Mapping[str, ToolSchema]) -> Mapping[str, ToolSchema]:
    if not isinstance(value, Mapping):
        raise TypeError("properties must be a mapping")
    if len(value) > MAX_TOOL_SCHEMA_PROPERTIES:
        raise AgentSchemaError("tool schema exceeds the maximum property count")
    frozen: dict[str, ToolSchema] = {}
    for key, schema in value.items():
        normalized = _normalize_property_name(key)
        if normalized in frozen:
            raise AgentSchemaError("tool schema contains duplicate normalized properties")
        if not isinstance(schema, ToolSchema):
            raise TypeError("properties must contain ToolSchema values")
        frozen[normalized] = schema
    return MappingProxyType(frozen)


def _freeze_required(value: frozenset[str]) -> frozenset[str]:
    if not isinstance(value, frozenset):
        raise TypeError("required must be a frozenset")
    if len(value) > MAX_TOOL_SCHEMA_REQUIRED_PROPERTIES:
        raise AgentSchemaError("required exceeds the maximum property count")
    normalized: set[str] = set()
    for item in value:
        name = _normalize_property_name(item)
        if name in normalized:
            raise AgentSchemaError("required contains duplicate normalized property names")
        normalized.add(name)
    return frozenset(normalized)


def _normalize_property_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("tool schema property names must be strings")
    normalized = value.strip()
    if not normalized:
        raise AgentSchemaError("tool schema property names must not be blank")
    if len(normalized) > MAX_TOOL_SCHEMA_NAME_LENGTH:
        raise AgentSchemaError("tool schema property name exceeds the maximum length")
    return normalized


def _validate_enum_scalar(value: AgentJsonScalar, kind: ToolSchemaType) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise AgentSchemaError("tool schema enum numbers must be finite")
    if not _value_matches_kind(value, kind):
        raise AgentSchemaError("tool schema enum value does not match its type")


def _value_matches_kind(value: object, kind: ToolSchemaType) -> bool:
    if kind is ToolSchemaType.STRING:
        return isinstance(value, str)
    if kind is ToolSchemaType.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind is ToolSchemaType.NUMBER:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )
    if kind is ToolSchemaType.BOOLEAN:
        return isinstance(value, bool)
    if kind is ToolSchemaType.NULL:
        return value is None
    return False


def _validate_optional_number(value: int | float | None, *, label: str) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AgentSchemaError(f"{label} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise AgentSchemaError(f"{label} must be finite")
    return value


def _validate_optional_bound(value: int | None, *, label: str, maximum: int) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentSchemaError(f"{label} must be an integer")
    if value < 0:
        raise AgentSchemaError(f"{label} must not be negative")
    if value > maximum:
        raise AgentSchemaError(f"{label} exceeds the global maximum")


def _require_ordered_bounds(
    minimum: int | None,
    maximum: int | None,
    *,
    label: str,
) -> None:
    if minimum is not None and maximum is not None and minimum > maximum:
        raise AgentSchemaError(f"minimum {label} cannot exceed maximum {label}")


def _require_empty_object_constraints(schema: ToolSchema) -> None:
    if schema.properties or schema.required:
        raise AgentSchemaError("non-object schemas cannot define properties")


def _reject_numeric_constraints(schema: ToolSchema) -> None:
    if schema.minimum is not None or schema.maximum is not None:
        raise AgentSchemaError("this schema type cannot define numeric bounds")


def _reject_length_constraints(schema: ToolSchema) -> None:
    if schema.min_length is not None or schema.max_length is not None:
        raise AgentSchemaError("this schema type cannot define string length bounds")


def _reject_array_constraints(schema: ToolSchema) -> None:
    if schema.min_items is not None or schema.max_items is not None:
        raise AgentSchemaError("this schema type cannot define array bounds")


def _validate_root_schema(schema: ToolSchema, *, label: str) -> None:
    if not isinstance(schema, ToolSchema):
        raise TypeError(f"{label} root must be ToolSchema")
    if schema.kind is not ToolSchemaType.OBJECT:
        raise AgentSchemaError(f"{label} root must be an object schema")
    visited: set[int] = set()
    active: set[int] = set()
    count = [0]
    _walk_schema(schema, depth=0, visited=visited, active=active, count=count)
    try:
        encoded = json.dumps(
            tool_schema_to_record(schema),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise AgentSchemaError() from exception
    if len(encoded) > MAX_TOOL_SCHEMA_CANONICAL_BYTES:
        raise AgentSchemaError("tool schema exceeds the maximum encoded size")


def _walk_schema(
    schema: ToolSchema,
    *,
    depth: int,
    visited: set[int],
    active: set[int],
    count: list[int],
) -> None:
    if depth > MAX_TOOL_SCHEMA_DEPTH:
        raise AgentSchemaError("tool schema exceeds the maximum depth")
    identity = id(schema)
    if identity in active:
        raise AgentSchemaError("recursive tool schemas are not supported")
    if identity in visited:
        return
    active.add(identity)
    count[0] += 1
    if count[0] > MAX_TOOL_SCHEMA_NODES:
        raise AgentSchemaError("tool schema exceeds the maximum node count")
    for child in schema.properties.values():
        _walk_schema(
            child,
            depth=depth + 1,
            visited=visited,
            active=active,
            count=count,
        )
    if schema.items is not None:
        _walk_schema(
            schema.items,
            depth=depth + 1,
            visited=visited,
            active=active,
            count=count,
        )
    active.remove(identity)
    visited.add(identity)


def _validate_root_value(
    schema: ToolSchema,
    value: Mapping[str, AgentJsonInput],
    *,
    label: str,
) -> Mapping[str, AgentJsonValue]:
    try:
        frozen = freeze_agent_json_object(value)
        validated = _validate_value(schema, frozen, path="$", depth=0, count=[0])
    except AgentSchemaError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentSchemaError(f"{label} is invalid") from exception
    if not isinstance(validated, Mapping):
        raise AgentSchemaError(f"{label} must be an object")
    return validated


def _validate_value(
    schema: ToolSchema,
    value: AgentJsonValue,
    *,
    path: str,
    depth: int,
    count: list[int],
) -> AgentJsonValue:
    if depth > MAX_TOOL_SCHEMA_DEPTH:
        raise AgentSchemaError("tool value exceeds the maximum depth")
    count[0] += 1
    if count[0] > MAX_TOOL_SCHEMA_NODES:
        raise AgentSchemaError("tool value exceeds the maximum item count")

    if schema.kind is ToolSchemaType.OBJECT:
        if not isinstance(value, Mapping):
            raise AgentSchemaError(f"{path} must be an object")
        unknown = frozenset(value) - frozenset(schema.properties)
        if unknown:
            raise AgentSchemaError(f"{path} contains unknown properties")
        missing = schema.required - frozenset(value)
        if missing:
            raise AgentSchemaError(f"{path} is missing required properties")
        return MappingProxyType(
            {
                key: _validate_value(
                    schema.properties[key],
                    item,
                    path=f"{path}.{key}",
                    depth=depth + 1,
                    count=count,
                )
                for key, item in value.items()
            }
        )

    if schema.kind is ToolSchemaType.ARRAY:
        if not isinstance(value, tuple):
            raise AgentSchemaError(f"{path} must be an array")
        _check_size_bounds(
            len(value),
            schema.min_items,
            schema.max_items,
            path=path,
            label="items",
        )
        assert schema.items is not None
        return tuple(
            _validate_value(
                schema.items,
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                count=count,
            )
            for index, item in enumerate(value)
        )

    if not _value_matches_kind(value, schema.kind):
        raise AgentSchemaError(f"{path} does not match the required type")
    if schema.enum and value not in schema.enum:
        raise AgentSchemaError(f"{path} is not an allowed enum value")
    if schema.kind is ToolSchemaType.STRING:
        assert isinstance(value, str)
        _check_size_bounds(
            len(value),
            schema.min_length,
            schema.max_length,
            path=path,
            label="characters",
        )
    elif schema.kind in {ToolSchemaType.INTEGER, ToolSchemaType.NUMBER}:
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
        if schema.minimum is not None and value < schema.minimum:
            raise AgentSchemaError(f"{path} is below the minimum")
        if schema.maximum is not None and value > schema.maximum:
            raise AgentSchemaError(f"{path} is above the maximum")
    return value


def _check_size_bounds(
    value: int,
    minimum: int | None,
    maximum: int | None,
    *,
    path: str,
    label: str,
) -> None:
    if minimum is not None and value < minimum:
        raise AgentSchemaError(f"{path} has too few {label}")
    if maximum is not None and value > maximum:
        raise AgentSchemaError(f"{path} has too many {label}")


def _require_string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise AgentSchemaError(f"{label} must be a string")
    return value


def _optional_integer_from_record(value: object, *, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentSchemaError(f"{label} must be an integer or null")
    return value


def _optional_number_from_record(value: object, *, label: str) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AgentSchemaError(f"{label} must be a number or null")
    if isinstance(value, float) and not math.isfinite(value):
        raise AgentSchemaError(f"{label} must be finite")
    return value
