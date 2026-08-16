"""Reviewed tool descriptors, adapters, and server-side resource resolvers."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from phoenix_os.agent.contracts import (
    MAX_AGENT_ARGUMENT_BYTES,
    MAX_AGENT_RESOURCE_LENGTH,
    MAX_AGENT_RESULT_BYTES,
    MAX_AGENT_TOOL_CALL_TIMEOUT,
    AgentJsonValue,
    AgentMetadata,
    ToolAvailability,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import AgentCodecError, ToolExecutionError
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    tool_schema_from_record,
    tool_schema_to_record,
)

if TYPE_CHECKING:
    from phoenix_os.policy import SecurityContext

MAX_TOOL_DESCRIPTOR_NAME_LENGTH = 128
MAX_TOOL_DESCRIPTOR_DESCRIPTION_LENGTH = 2_048
MAX_TOOL_IMPLEMENTATION_ID_LENGTH = 128
MAX_TOOL_DESCRIPTOR_METADATA_ITEMS = 64
MAX_TOOL_DESCRIPTOR_METADATA_KEY_LENGTH = 128
MAX_TOOL_DESCRIPTOR_METADATA_VALUE_LENGTH = 1_024
MAX_TOOL_DESCRIPTOR_DOCUMENT_BYTES = 1_048_576
MAX_TOOL_DESCRIPTOR_JSON_DEPTH = 32
MAX_TOOL_DESCRIPTOR_JSON_ITEMS = 65_536

_SCHEMA_VERSION = 1
_TOOL_DESCRIPTOR_KIND = "phoenix.agent.tool-descriptor"
_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record"})

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_RESOURCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._:/-]{0,1023})$")
_DESCRIPTOR_FIELDS = frozenset(
    {
        "tool_id",
        "name",
        "description",
        "input_schema",
        "output_schema",
        "effect",
        "approval_may_be_required",
        "max_input_bytes",
        "max_output_bytes",
        "timeout_seconds",
        "resolver_id",
        "adapter_id",
        "availability",
        "metadata",
    }
)


def _normalize_text(value: str, *, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be blank")
    if len(normalized) > maximum:
        raise ValueError(f"{label} exceeds the maximum length")
    return normalized


def _normalize_implementation_id(value: str, *, label: str) -> str:
    normalized = _normalize_text(
        value,
        label=label,
        maximum=MAX_TOOL_IMPLEMENTATION_ID_LENGTH,
    )
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _normalize_resource(value: str) -> str:
    if not isinstance(value, str):
        raise ToolExecutionError()
    normalized = value.strip()
    if len(normalized) > MAX_AGENT_RESOURCE_LENGTH or not _RESOURCE_PATTERN.fullmatch(normalized):
        raise ToolExecutionError()
    return normalized


def _freeze_metadata(value: Mapping[str, str]) -> AgentMetadata:
    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")
    if len(value) > MAX_TOOL_DESCRIPTOR_METADATA_ITEMS:
        raise ValueError("metadata exceeds the maximum item count")
    frozen: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _normalize_text(
            key,
            label="metadata key",
            maximum=MAX_TOOL_DESCRIPTOR_METADATA_KEY_LENGTH,
        )
        if normalized_key in frozen:
            raise ValueError("metadata contains duplicate normalized keys")
        if not isinstance(item, str):
            raise TypeError("metadata values must be strings")
        if len(item) > MAX_TOOL_DESCRIPTOR_METADATA_VALUE_LENGTH:
            raise ValueError("metadata value exceeds the maximum length")
        frozen[normalized_key] = item
    return MappingProxyType(frozen)


def _require_positive_integer(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """Immutable model-facing description of one reviewed server-owned tool."""

    tool_id: ToolId
    name: str
    description: str
    input_schema: ToolInputSchema
    output_schema: ToolOutputSchema
    effect: ToolEffect
    approval_may_be_required: bool
    max_input_bytes: int
    max_output_bytes: int
    timeout: timedelta
    resolver_id: str
    adapter_id: str
    availability: ToolAvailability = ToolAvailability.ACTIVE
    metadata: AgentMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.input_schema, ToolInputSchema):
            raise TypeError("input_schema must be ToolInputSchema")
        if not isinstance(self.output_schema, ToolOutputSchema):
            raise TypeError("output_schema must be ToolOutputSchema")
        if not isinstance(self.effect, ToolEffect):
            raise TypeError("effect must be ToolEffect")
        if not isinstance(self.approval_may_be_required, bool):
            raise TypeError("approval_may_be_required must be a boolean")
        if not isinstance(self.timeout, timedelta):
            raise TypeError("timeout must be a timedelta")
        if self.timeout <= timedelta(0):
            raise ValueError("timeout must be greater than zero")
        if self.timeout > MAX_AGENT_TOOL_CALL_TIMEOUT:
            raise ValueError("timeout exceeds the global maximum")
        if not isinstance(self.availability, ToolAvailability):
            raise TypeError("availability must be ToolAvailability")
        _require_positive_integer(
            self.max_input_bytes,
            label="max_input_bytes",
            maximum=MAX_AGENT_ARGUMENT_BYTES,
        )
        _require_positive_integer(
            self.max_output_bytes,
            label="max_output_bytes",
            maximum=MAX_AGENT_RESULT_BYTES,
        )
        object.__setattr__(
            self,
            "name",
            _normalize_text(
                self.name,
                label="tool name",
                maximum=MAX_TOOL_DESCRIPTOR_NAME_LENGTH,
            ),
        )
        object.__setattr__(
            self,
            "description",
            _normalize_text(
                self.description,
                label="tool description",
                maximum=MAX_TOOL_DESCRIPTOR_DESCRIPTION_LENGTH,
            ),
        )
        object.__setattr__(
            self,
            "resolver_id",
            _normalize_implementation_id(self.resolver_id, label="resolver_id"),
        )
        object.__setattr__(
            self,
            "adapter_id",
            _normalize_implementation_id(self.adapter_id, label="adapter_id"),
        )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))
        canonical_tool_descriptor_bytes(self)


@dataclass(frozen=True, slots=True)
class ToolResolution:
    """Validated arguments and one trusted server-resolved policy resource."""

    descriptor: ToolDescriptor
    arguments: Mapping[str, AgentJsonValue]
    resolved_resource: str

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        object.__setattr__(
            self,
            "arguments",
            freeze_agent_json_object(self.arguments),
        )
        object.__setattr__(
            self,
            "resolved_resource",
            _normalize_resource(self.resolved_resource),
        )


@runtime_checkable
class ToolResourceResolver(Protocol):
    """Trusted resolver that derives policy resources after schema validation."""

    @property
    def resolver_id(self) -> str: ...

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str: ...


@runtime_checkable
class ToolAdapter(Protocol):
    """Trusted installed adapter for one exact registered tool."""

    @property
    def adapter_id(self) -> str: ...

    @property
    def tool_id(self) -> ToolId: ...

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult: ...


@runtime_checkable
class ContextualToolAdapter(ToolAdapter, Protocol):
    """Trusted adapter that requires the current explicit security context."""

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult: ...


@dataclass(frozen=True, slots=True)
class StaticToolResourceResolver:
    """Resolve every admitted invocation to one reviewed static resource."""

    resolver_id: str
    resource: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "resolver_id",
            _normalize_implementation_id(self.resolver_id, label="resolver_id"),
        )
        object.__setattr__(self, "resource", _normalize_resource(self.resource))

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        return self.resource


def resolve_server_resource(
    resolver: ToolResourceResolver,
    arguments: Mapping[str, AgentJsonValue],
) -> str:
    """Resolve and normalize one resource without leaking resolver failures."""

    if not isinstance(resolver, ToolResourceResolver):
        raise TypeError("resolver must implement ToolResourceResolver")
    try:
        return _normalize_resource(resolver.resolve_resource(arguments))
    except ToolExecutionError:
        raise
    except Exception as exception:
        raise ToolExecutionError() from exception


def tool_descriptor_to_record(descriptor: ToolDescriptor) -> dict[str, object]:
    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    return {
        "tool_id": str(descriptor.tool_id),
        "name": descriptor.name,
        "description": descriptor.description,
        "input_schema": tool_schema_to_record(descriptor.input_schema.root),
        "output_schema": tool_schema_to_record(descriptor.output_schema.root),
        "effect": descriptor.effect.value,
        "approval_may_be_required": descriptor.approval_may_be_required,
        "max_input_bytes": descriptor.max_input_bytes,
        "max_output_bytes": descriptor.max_output_bytes,
        "timeout_seconds": descriptor.timeout.total_seconds(),
        "resolver_id": descriptor.resolver_id,
        "adapter_id": descriptor.adapter_id,
        "availability": descriptor.availability.value,
        "metadata": dict(descriptor.metadata),
    }


def tool_descriptor_from_record(record: Mapping[str, object]) -> ToolDescriptor:
    if frozenset(record) != _DESCRIPTOR_FIELDS:
        raise AgentCodecError("tool descriptor fields are invalid")
    try:
        input_record = _mapping(record.get("input_schema"), label="input_schema")
        output_record = _mapping(record.get("output_schema"), label="output_schema")
        timeout_seconds = _number(record.get("timeout_seconds"), label="timeout_seconds")
        descriptor = ToolDescriptor(
            tool_id=ToolId(_string(record.get("tool_id"), label="tool_id")),
            name=_string(record.get("name"), label="name"),
            description=_string(record.get("description"), label="description"),
            input_schema=ToolInputSchema(tool_schema_from_record(input_record)),
            output_schema=ToolOutputSchema(tool_schema_from_record(output_record)),
            effect=ToolEffect(_string(record.get("effect"), label="effect")),
            approval_may_be_required=_boolean(
                record.get("approval_may_be_required"),
                label="approval_may_be_required",
            ),
            max_input_bytes=_integer(record.get("max_input_bytes"), label="max_input_bytes"),
            max_output_bytes=_integer(record.get("max_output_bytes"), label="max_output_bytes"),
            timeout=timedelta(seconds=timeout_seconds),
            resolver_id=_string(record.get("resolver_id"), label="resolver_id"),
            adapter_id=_string(record.get("adapter_id"), label="adapter_id"),
            availability=ToolAvailability(
                _string(record.get("availability"), label="availability")
            ),
            metadata=_string_mapping(record.get("metadata"), label="metadata"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    return descriptor


def canonical_tool_descriptor_bytes(descriptor: ToolDescriptor) -> bytes:
    return encode_tool_descriptor(descriptor)


def encode_tool_descriptor(descriptor: ToolDescriptor) -> bytes:
    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    document = {
        "schema_version": _SCHEMA_VERSION,
        "kind": _TOOL_DESCRIPTOR_KIND,
        "record": tool_descriptor_to_record(descriptor),
    }
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise AgentCodecError() from exception
    if len(encoded) > MAX_TOOL_DESCRIPTOR_DOCUMENT_BYTES:
        raise AgentCodecError("tool descriptor exceeds the maximum encoded size")
    return encoded


def decode_tool_descriptor(encoded: bytes) -> ToolDescriptor:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded tool descriptor must be bytes")
    if not encoded or len(encoded) > MAX_TOOL_DESCRIPTOR_DOCUMENT_BYTES:
        raise AgentCodecError()
    try:
        decoded: object = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
        _validate_json_shape(decoded, depth=0, counter=[0])
        envelope = _mapping(decoded, label="tool descriptor envelope")
        if frozenset(envelope) != _ENVELOPE_FIELDS:
            raise AgentCodecError("tool descriptor envelope fields are invalid")
        if _integer(envelope.get("schema_version"), label="schema_version") != _SCHEMA_VERSION:
            raise AgentCodecError("unsupported tool descriptor schema version")
        if _string(envelope.get("kind"), label="kind") != _TOOL_DESCRIPTOR_KIND:
            raise AgentCodecError("unexpected tool descriptor kind")
        record = _mapping(envelope.get("record"), label="tool descriptor record")
        descriptor = tool_descriptor_from_record(record)
    except AgentCodecError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exception:
        raise AgentCodecError() from exception
    if encode_tool_descriptor(descriptor) != encoded:
        raise AgentCodecError("tool descriptor is not canonical")
    return descriptor


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AgentCodecError("tool descriptor contains duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise AgentCodecError("tool descriptor contains a non-finite number")


def _validate_json_shape(value: object, *, depth: int, counter: list[int]) -> None:
    if depth > MAX_TOOL_DESCRIPTOR_JSON_DEPTH:
        raise AgentCodecError("tool descriptor exceeds the maximum JSON depth")
    counter[0] += 1
    if counter[0] > MAX_TOOL_DESCRIPTOR_JSON_ITEMS:
        raise AgentCodecError("tool descriptor exceeds the maximum JSON item count")
    if isinstance(value, Mapping):
        for item in value.values():
            _validate_json_shape(item, depth=depth + 1, counter=counter)
    elif isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth=depth + 1, counter=counter)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AgentCodecError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise AgentCodecError(f"{label} keys must be strings")
    return cast(Mapping[str, object], raw)


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise AgentCodecError(f"{label} must be a string")
    return value


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentCodecError(f"{label} must be an integer")
    return value


def _number(value: object, *, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AgentCodecError(f"{label} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise AgentCodecError(f"{label} must be finite")
    return value


def _boolean(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise AgentCodecError(f"{label} must be a boolean")
    return value


def _string_mapping(value: object, *, label: str) -> Mapping[str, str]:
    mapping = _mapping(value, label=label)
    result: dict[str, str] = {}
    for key, item in mapping.items():
        if not isinstance(item, str):
            raise AgentCodecError(f"{label} values must be strings")
        result[key] = item
    return result
