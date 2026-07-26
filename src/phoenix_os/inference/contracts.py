"""Immutable public contracts for secure model inference."""

from __future__ import annotations

import math
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

MAX_INFERENCE_IDENTIFIER_LENGTH = 128
MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH = 256
MAX_INFERENCE_MESSAGE_COUNT = 128
MAX_INFERENCE_MESSAGE_CHARS = 65_536
MAX_INFERENCE_TOTAL_INPUT_CHARS = 262_144
MAX_INFERENCE_OUTPUT_TOKENS = 32_768
MAX_INFERENCE_RESPONSE_CHARS = 1_048_576
MAX_INFERENCE_CHUNKS = 16_384
MAX_INFERENCE_CHUNK_CHARS = 65_536
MAX_INFERENCE_METADATA_ITEMS = 64
MAX_INFERENCE_METADATA_KEY_LENGTH = 128
MAX_INFERENCE_METADATA_VALUE_LENGTH = 1_024
MAX_INFERENCE_PARAMETER_ITEMS = 64
MAX_INFERENCE_PARAMETER_KEY_LENGTH = 128
MAX_INFERENCE_PARAMETER_STRING_LENGTH = 4_096
MAX_INFERENCE_CORRELATION_ID_LENGTH = 256
MAX_INFERENCE_DEADLINE = timedelta(hours=1)

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")

type InferenceParameter = str | int | float | bool | None
type InferenceParameters = Mapping[str, InferenceParameter]
type InferenceMetadata = Mapping[str, str]


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _normalize_text(value: str, *, label: str, maximum: int, allow_blank: bool) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip() if not allow_blank else value
    if not allow_blank and not normalized:
        raise ValueError(f"{label} must not be blank")
    if len(normalized) > maximum:
        raise ValueError(f"{label} exceeds the maximum length")
    return normalized


def _freeze_metadata(value: Mapping[str, str]) -> InferenceMetadata:
    if len(value) > MAX_INFERENCE_METADATA_ITEMS:
        raise ValueError("metadata exceeds the maximum item count")
    frozen: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _normalize_text(
            key,
            label="metadata key",
            maximum=MAX_INFERENCE_METADATA_KEY_LENGTH,
            allow_blank=False,
        )
        normalized_value = _normalize_text(
            item,
            label="metadata value",
            maximum=MAX_INFERENCE_METADATA_VALUE_LENGTH,
            allow_blank=True,
        )
        if normalized_key in frozen:
            raise ValueError("metadata contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


def _freeze_parameters(value: Mapping[str, InferenceParameter]) -> InferenceParameters:
    if len(value) > MAX_INFERENCE_PARAMETER_ITEMS:
        raise ValueError("parameters exceed the maximum item count")
    frozen: dict[str, InferenceParameter] = {}
    for key, item in value.items():
        normalized_key = _normalize_text(
            key,
            label="parameter key",
            maximum=MAX_INFERENCE_PARAMETER_KEY_LENGTH,
            allow_blank=False,
        )
        if normalized_key in frozen:
            raise ValueError("parameters contain duplicate normalized keys")
        if isinstance(item, str):
            normalized_item: InferenceParameter = _normalize_text(
                item,
                label="parameter string",
                maximum=MAX_INFERENCE_PARAMETER_STRING_LENGTH,
                allow_blank=True,
            )
        elif isinstance(item, bool) or item is None or isinstance(item, int):
            normalized_item = item
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("parameter floats must be finite")
            normalized_item = item
        else:
            raise TypeError("parameter values must be scalar JSON values")
        frozen[normalized_key] = normalized_item
    return MappingProxyType(frozen)


def _require_positive_integer(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True, order=True)
class ModelProviderId:
    """Stable trusted identifier for one provider registration."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="provider id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class ModelId:
    """Stable trusted identifier for one model under a provider."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="model id"),
        )

    def __str__(self) -> str:
        return self.value


class InferenceRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class InferenceFinishReason(StrEnum):
    STOP = "stop"
    LENGTH = "length"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    """Provider or model support for complete and streamed inference."""

    complete: bool = True
    streaming: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.complete, bool) or not isinstance(self.streaming, bool):
            raise TypeError("model capabilities must be booleans")
        if not self.complete and not self.streaming:
            raise ValueError("at least one inference mode must be supported")

    def supports(self, requested: ModelCapabilities) -> bool:
        return (not requested.complete or self.complete) and (
            not requested.streaming or self.streaming
        )


@dataclass(frozen=True, slots=True)
class InferenceLimits:
    """Finite model limits; callers may only request values inside these bounds."""

    max_messages: int = 64
    max_message_chars: int = 32_768
    max_total_input_chars: int = 131_072
    max_output_tokens: int = 4_096
    max_response_chars: int = 262_144
    max_chunks: int = 4_096
    max_chunk_chars: int = 8_192

    def __post_init__(self) -> None:
        _require_positive_integer(
            self.max_messages,
            label="max_messages",
            maximum=MAX_INFERENCE_MESSAGE_COUNT,
        )
        _require_positive_integer(
            self.max_message_chars,
            label="max_message_chars",
            maximum=MAX_INFERENCE_MESSAGE_CHARS,
        )
        _require_positive_integer(
            self.max_total_input_chars,
            label="max_total_input_chars",
            maximum=MAX_INFERENCE_TOTAL_INPUT_CHARS,
        )
        _require_positive_integer(
            self.max_output_tokens,
            label="max_output_tokens",
            maximum=MAX_INFERENCE_OUTPUT_TOKENS,
        )
        _require_positive_integer(
            self.max_response_chars,
            label="max_response_chars",
            maximum=MAX_INFERENCE_RESPONSE_CHARS,
        )
        _require_positive_integer(
            self.max_chunks,
            label="max_chunks",
            maximum=MAX_INFERENCE_CHUNKS,
        )
        _require_positive_integer(
            self.max_chunk_chars,
            label="max_chunk_chars",
            maximum=MAX_INFERENCE_CHUNK_CHARS,
        )
        if self.max_message_chars > self.max_total_input_chars:
            raise ValueError("max_message_chars cannot exceed max_total_input_chars")
        if self.max_chunk_chars > self.max_response_chars:
            raise ValueError("max_chunk_chars cannot exceed max_response_chars")

    def contains(self, other: InferenceLimits) -> bool:
        return (
            other.max_messages <= self.max_messages
            and other.max_message_chars <= self.max_message_chars
            and other.max_total_input_chars <= self.max_total_input_chars
            and other.max_output_tokens <= self.max_output_tokens
            and other.max_response_chars <= self.max_response_chars
            and other.max_chunks <= self.max_chunks
            and other.max_chunk_chars <= self.max_chunk_chars
        )


@dataclass(frozen=True, slots=True)
class InferenceMessage:
    role: InferenceRole
    content: str
    metadata: InferenceMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.role, InferenceRole):
            raise TypeError("role must be InferenceRole")
        object.__setattr__(
            self,
            "content",
            _normalize_text(
                self.content,
                label="message content",
                maximum=MAX_INFERENCE_MESSAGE_CHARS,
                allow_blank=False,
            ),
        )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class ModelDescriptor:
    provider_id: ModelProviderId
    model_id: ModelId
    provider_model_name: str
    capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)
    limits: InferenceLimits = field(default_factory=InferenceLimits)
    metadata: InferenceMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        if not isinstance(self.capabilities, ModelCapabilities):
            raise TypeError("capabilities must be ModelCapabilities")
        if not isinstance(self.limits, InferenceLimits):
            raise TypeError("limits must be InferenceLimits")
        object.__setattr__(
            self,
            "provider_model_name",
            _normalize_text(
                self.provider_model_name,
                label="provider model name",
                maximum=MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH,
                allow_blank=False,
            ),
        )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class InferenceRequest:
    provider_id: ModelProviderId
    model_id: ModelId
    messages: tuple[InferenceMessage, ...]
    max_output_tokens: int = 512
    parameters: InferenceParameters = field(default_factory=dict)
    metadata: InferenceMetadata = field(default_factory=dict)
    correlation_id: str | None = None
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(seconds=60))

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        messages = tuple(self.messages)
        if not messages:
            raise ValueError("messages must not be empty")
        if len(messages) > MAX_INFERENCE_MESSAGE_COUNT:
            raise ValueError("messages exceed the maximum count")
        if any(not isinstance(message, InferenceMessage) for message in messages):
            raise TypeError("messages must contain InferenceMessage values")
        if sum(len(message.content) for message in messages) > MAX_INFERENCE_TOTAL_INPUT_CHARS:
            raise ValueError("messages exceed the total input limit")
        _require_positive_integer(
            self.max_output_tokens,
            label="max_output_tokens",
            maximum=MAX_INFERENCE_OUTPUT_TOKENS,
        )
        _require_timezone_aware(self.created_at, label="created_at")
        _require_timezone_aware(self.deadline, label="deadline")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must be after created_at")
        if self.deadline - self.created_at > MAX_INFERENCE_DEADLINE:
            raise ValueError("deadline exceeds the global maximum")
        correlation_id = self.correlation_id
        if correlation_id is not None:
            correlation_id = _normalize_text(
                correlation_id,
                label="correlation_id",
                maximum=MAX_INFERENCE_CORRELATION_ID_LENGTH,
                allow_blank=False,
            )
        object.__setattr__(self, "messages", messages)
        object.__setattr__(self, "parameters", _freeze_parameters(self.parameters))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))
        object.__setattr__(self, "correlation_id", correlation_id)


@dataclass(frozen=True, slots=True)
class InferenceUsage:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int = 0

    def __post_init__(self) -> None:
        for label, value in (
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("cached_input_tokens", self.cached_input_tokens),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0:
                raise ValueError(f"{label} must not be negative")
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached_input_tokens cannot exceed input_tokens")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class InferenceResponse:
    request_id: UUID
    provider_id: ModelProviderId
    model_id: ModelId
    text: str
    finish_reason: InferenceFinishReason
    usage: InferenceUsage
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: InferenceMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        if not isinstance(self.finish_reason, InferenceFinishReason):
            raise TypeError("finish_reason must be InferenceFinishReason")
        if not isinstance(self.usage, InferenceUsage):
            raise TypeError("usage must be InferenceUsage")
        _require_timezone_aware(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "text",
            _normalize_text(
                self.text,
                label="response text",
                maximum=MAX_INFERENCE_RESPONSE_CHARS,
                allow_blank=True,
            ),
        )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class InferenceChunk:
    request_id: UUID
    provider_id: ModelProviderId
    model_id: ModelId
    index: int
    text: str = ""
    terminal: bool = False
    finish_reason: InferenceFinishReason | None = None
    usage: InferenceUsage | None = None
    metadata: InferenceMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise TypeError("index must be an integer")
        if self.index < 0:
            raise ValueError("index must not be negative")
        if not isinstance(self.terminal, bool):
            raise TypeError("terminal must be a boolean")
        object.__setattr__(
            self,
            "text",
            _normalize_text(
                self.text,
                label="chunk text",
                maximum=MAX_INFERENCE_CHUNK_CHARS,
                allow_blank=True,
            ),
        )
        if self.terminal:
            if self.finish_reason is None:
                raise ValueError("terminal chunks require a finish_reason")
            if self.usage is None:
                raise ValueError("terminal chunks require usage")
        elif self.finish_reason is not None or self.usage is not None:
            raise ValueError("non-terminal chunks cannot contain finish metadata")
        if self.finish_reason is not None and not isinstance(
            self.finish_reason, InferenceFinishReason
        ):
            raise TypeError("finish_reason must be InferenceFinishReason")
        if self.usage is not None and not isinstance(self.usage, InferenceUsage):
            raise TypeError("usage must be InferenceUsage")
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@runtime_checkable
class ModelProvider(Protocol):
    """Trusted installed adapter behind the provider-neutral boundary."""

    @property
    def provider_id(self) -> ModelProviderId: ...

    @property
    def capabilities(self) -> ModelCapabilities: ...

    async def infer(self, request: InferenceRequest) -> InferenceResponse: ...

    def stream(self, request: InferenceRequest) -> AsyncIterator[InferenceChunk]: ...


def ensure_request_within_limits(
    request: InferenceRequest,
    limits: InferenceLimits,
) -> None:
    """Validate one immutable request against one registered model limit set."""

    if len(request.messages) > limits.max_messages:
        raise ValueError("request exceeds the model message count")
    if any(len(message.content) > limits.max_message_chars for message in request.messages):
        raise ValueError("request exceeds the model message size")
    if sum(len(message.content) for message in request.messages) > limits.max_total_input_chars:
        raise ValueError("request exceeds the model total input size")
    if request.max_output_tokens > limits.max_output_tokens:
        raise ValueError("request exceeds the model output token limit")


def normalize_provider_id(value: ModelProviderId | str) -> ModelProviderId:
    return value if isinstance(value, ModelProviderId) else ModelProviderId(value)


def normalize_model_id(value: ModelId | str) -> ModelId:
    return value if isinstance(value, ModelId) else ModelId(value)


def normalize_messages(
    values: Sequence[InferenceMessage],
) -> tuple[InferenceMessage, ...]:
    return tuple(values)
