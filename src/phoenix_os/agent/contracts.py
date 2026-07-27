"""Immutable public contracts for bounded agent and tool-calling orchestration."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from phoenix_os.inference.contracts import ModelId, ModelProviderId

MAX_AGENT_IDENTIFIER_LENGTH = 128
MAX_AGENT_RESOURCE_LENGTH = 1_024
MAX_AGENT_MESSAGE_COUNT = 256
MAX_AGENT_MESSAGE_CHARS = 65_536
MAX_AGENT_TOTAL_MESSAGE_CHARS = 524_288
MAX_AGENT_FINAL_OUTPUT_CHARS = 1_048_576
MAX_AGENT_METADATA_ITEMS = 64
MAX_AGENT_METADATA_KEY_LENGTH = 128
MAX_AGENT_METADATA_VALUE_LENGTH = 1_024
MAX_AGENT_JSON_DEPTH = 32
MAX_AGENT_JSON_ITEMS = 16_384
MAX_AGENT_JSON_KEY_LENGTH = 256
MAX_AGENT_JSON_STRING_CHARS = 262_144
MAX_AGENT_ARGUMENT_BYTES = 1_048_576
MAX_AGENT_RESULT_BYTES = 4_194_304
MAX_AGENT_STEPS = 256
MAX_AGENT_MODEL_TURNS = 128
MAX_AGENT_TOOL_CALLS = 128
MAX_AGENT_PROMPT_BYTES = 4_194_304
MAX_AGENT_MODEL_OUTPUT_BYTES = 4_194_304
MAX_AGENT_TOOL_RESULT_BYTES = 4_194_304
MAX_AGENT_INPUT_TOKENS = 1_048_576
MAX_AGENT_OUTPUT_TOKENS = 262_144
MAX_AGENT_QUEUE_DEPTH = 4_096
MAX_AGENT_CONCURRENT_RUNS = 1_024
MAX_AGENT_CONCURRENT_MODEL_CALLS = 1_024
MAX_AGENT_CONCURRENT_TOOL_CALLS = 1_024
MAX_AGENT_MODEL_TURN_TIMEOUT = timedelta(minutes=30)
MAX_AGENT_TOOL_CALL_TIMEOUT = timedelta(minutes=30)
MAX_AGENT_APPROVAL_WAIT_TIMEOUT = timedelta(hours=1)
MAX_AGENT_TOTAL_DURATION = timedelta(hours=2)
MAX_AGENT_CANCELLATION_GRACE = timedelta(minutes=2)
MAX_AGENT_SHUTDOWN_GRACE = timedelta(minutes=5)

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_RESOURCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._:/-]{0,1023})$")


type AgentJsonScalar = str | int | float | bool | None
type AgentJsonInput = AgentJsonScalar | Sequence[AgentJsonInput] | Mapping[str, AgentJsonInput]
type AgentJsonValue = AgentJsonScalar | tuple[AgentJsonValue, ...] | Mapping[str, AgentJsonValue]
type AgentMetadata = Mapping[str, str]


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _normalize_resource(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("resolved_resource must be a string")
    normalized = value.strip()
    if not _RESOURCE_PATTERN.fullmatch(normalized):
        raise ValueError("resolved_resource is invalid")
    return normalized


def _normalize_text(value: str, *, label: str, maximum: int, allow_blank: bool) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value if allow_blank else value.strip()
    if not allow_blank and not normalized:
        raise ValueError(f"{label} must not be blank")
    if len(normalized) > maximum:
        raise ValueError(f"{label} exceeds the maximum length")
    return normalized


def _freeze_metadata(value: Mapping[str, str]) -> AgentMetadata:
    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")
    if len(value) > MAX_AGENT_METADATA_ITEMS:
        raise ValueError("metadata exceeds the maximum item count")
    frozen: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _normalize_text(
            key,
            label="metadata key",
            maximum=MAX_AGENT_METADATA_KEY_LENGTH,
            allow_blank=False,
        )
        normalized_value = _normalize_text(
            item,
            label="metadata value",
            maximum=MAX_AGENT_METADATA_VALUE_LENGTH,
            allow_blank=True,
        )
        if normalized_key in frozen:
            raise ValueError("metadata contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


def _freeze_json(value: object, *, depth: int, counter: list[int]) -> AgentJsonValue:
    if depth > MAX_AGENT_JSON_DEPTH:
        raise ValueError("structured value exceeds the maximum depth")
    counter[0] += 1
    if counter[0] > MAX_AGENT_JSON_ITEMS:
        raise ValueError("structured value exceeds the maximum item count")

    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("structured floats must be finite")
        return value
    if isinstance(value, str):
        if len(value) > MAX_AGENT_JSON_STRING_CHARS:
            raise ValueError("structured string exceeds the maximum length")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, AgentJsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("structured object keys must be strings")
            normalized_key = _normalize_text(
                key,
                label="structured object key",
                maximum=MAX_AGENT_JSON_KEY_LENGTH,
                allow_blank=False,
            )
            if normalized_key in frozen:
                raise ValueError("structured object contains duplicate normalized keys")
            frozen[normalized_key] = _freeze_json(
                item,
                depth=depth + 1,
                counter=counter,
            )
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze_json(item, depth=depth + 1, counter=counter) for item in value)
    raise TypeError("structured values must contain only JSON-compatible values")


def freeze_agent_json_object(
    value: Mapping[str, AgentJsonInput],
) -> Mapping[str, AgentJsonValue]:
    """Freeze one caller-owned JSON object into immutable Phoenix-owned values."""

    if not isinstance(value, Mapping):
        raise TypeError("structured object must be a mapping")
    frozen = _freeze_json(value, depth=0, counter=[0])
    if not isinstance(frozen, Mapping):
        raise TypeError("structured object must be a mapping")
    return frozen


def _json_to_builtin(value: AgentJsonValue) -> object:
    if isinstance(value, Mapping):
        return {key: _json_to_builtin(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_to_builtin(item) for item in value]
    return value


def canonical_agent_json_bytes(value: Mapping[str, AgentJsonValue]) -> bytes:
    """Return deterministic UTF-8 JSON for an already frozen structured object."""

    try:
        return json.dumps(
            _json_to_builtin(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exception:
        raise ValueError("structured object is not canonically encodable") from exception


def _require_positive_integer(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_non_negative_integer(value: int, *, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")


def _require_positive_duration(
    value: timedelta,
    *,
    label: str,
    maximum: timedelta,
) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be a timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True, order=True)
class AgentId:
    """Stable trusted identifier for one configured agent."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _normalize_identifier(self.value, label="agent id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class ToolId:
    """Stable trusted identifier for one registered tool."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _normalize_identifier(self.value, label="tool id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class AgentRunId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("agent run id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class AgentStepId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("agent step id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class ToolCallId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("tool call id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class ToolApprovalId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("tool approval id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


class AgentMessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolEffect(StrEnum):
    READ_ONLY = "read_only"
    REVERSIBLE_WRITE = "reversible_write"
    IRREVERSIBLE_WRITE = "irreversible_write"
    EXTERNAL_COMMUNICATION = "external_communication"


class ToolAvailability(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class ToolResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"
    CANCELLED = "cancelled"


class AgentRunStatus(StrEnum):
    CREATED = "created"
    INFERENCING = "inferencing"
    VALIDATING_PROPOSAL = "validating_proposal"
    AUTHORIZING_TOOL = "authorizing_tool"
    AWAITING_APPROVAL = "awaiting_approval"
    INVOKING_TOOL = "invoking_tool"
    VALIDATING_RESULT = "validating_result"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.CANCELLED}


@dataclass(frozen=True, slots=True)
class AgentMessage:
    role: AgentMessageRole
    content: str
    tool_call_id: ToolCallId | None = None
    metadata: AgentMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.role, AgentMessageRole):
            raise TypeError("role must be AgentMessageRole")
        object.__setattr__(
            self,
            "content",
            _normalize_text(
                self.content,
                label="agent message content",
                maximum=MAX_AGENT_MESSAGE_CHARS,
                allow_blank=False,
            ),
        )
        if self.role is AgentMessageRole.TOOL:
            if not isinstance(self.tool_call_id, ToolCallId):
                raise ValueError("tool messages require a tool_call_id")
        elif self.tool_call_id is not None:
            raise ValueError("only tool messages may contain a tool_call_id")
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class AgentLimits:
    """Finite orchestration limits; the most restrictive applicable set wins."""

    max_steps: int = 16
    max_model_turns: int = 8
    max_tool_calls: int = 8
    max_prompt_bytes: int = 262_144
    max_model_output_bytes: int = 1_048_576
    max_tool_result_bytes: int = 1_048_576
    max_input_tokens: int = 65_536
    max_output_tokens: int = 32_768
    max_argument_bytes: int = 262_144
    max_result_bytes: int = 1_048_576
    max_structured_depth: int = 16
    max_structured_items: int = 4_096
    max_queue_depth: int = 128
    max_concurrent_runs: int = 32
    max_concurrent_model_calls: int = 16
    max_concurrent_tool_calls: int = 16
    model_turn_timeout: timedelta = timedelta(minutes=2)
    tool_call_timeout: timedelta = timedelta(minutes=2)
    approval_wait_timeout: timedelta = timedelta(minutes=10)
    total_duration: timedelta = timedelta(minutes=20)
    cancellation_grace: timedelta = timedelta(seconds=10)
    shutdown_grace: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        integer_limits = (
            ("max_steps", self.max_steps, MAX_AGENT_STEPS),
            ("max_model_turns", self.max_model_turns, MAX_AGENT_MODEL_TURNS),
            ("max_tool_calls", self.max_tool_calls, MAX_AGENT_TOOL_CALLS),
            ("max_prompt_bytes", self.max_prompt_bytes, MAX_AGENT_PROMPT_BYTES),
            (
                "max_model_output_bytes",
                self.max_model_output_bytes,
                MAX_AGENT_MODEL_OUTPUT_BYTES,
            ),
            (
                "max_tool_result_bytes",
                self.max_tool_result_bytes,
                MAX_AGENT_TOOL_RESULT_BYTES,
            ),
            ("max_input_tokens", self.max_input_tokens, MAX_AGENT_INPUT_TOKENS),
            ("max_output_tokens", self.max_output_tokens, MAX_AGENT_OUTPUT_TOKENS),
            ("max_argument_bytes", self.max_argument_bytes, MAX_AGENT_ARGUMENT_BYTES),
            ("max_result_bytes", self.max_result_bytes, MAX_AGENT_RESULT_BYTES),
            ("max_structured_depth", self.max_structured_depth, MAX_AGENT_JSON_DEPTH),
            ("max_structured_items", self.max_structured_items, MAX_AGENT_JSON_ITEMS),
            ("max_queue_depth", self.max_queue_depth, MAX_AGENT_QUEUE_DEPTH),
            ("max_concurrent_runs", self.max_concurrent_runs, MAX_AGENT_CONCURRENT_RUNS),
            (
                "max_concurrent_model_calls",
                self.max_concurrent_model_calls,
                MAX_AGENT_CONCURRENT_MODEL_CALLS,
            ),
            (
                "max_concurrent_tool_calls",
                self.max_concurrent_tool_calls,
                MAX_AGENT_CONCURRENT_TOOL_CALLS,
            ),
        )
        for label, integer_value, integer_maximum in integer_limits:
            _require_positive_integer(
                integer_value,
                label=label,
                maximum=integer_maximum,
            )

        duration_limits = (
            (
                "model_turn_timeout",
                self.model_turn_timeout,
                MAX_AGENT_MODEL_TURN_TIMEOUT,
            ),
            (
                "tool_call_timeout",
                self.tool_call_timeout,
                MAX_AGENT_TOOL_CALL_TIMEOUT,
            ),
            (
                "approval_wait_timeout",
                self.approval_wait_timeout,
                MAX_AGENT_APPROVAL_WAIT_TIMEOUT,
            ),
            ("total_duration", self.total_duration, MAX_AGENT_TOTAL_DURATION),
            (
                "cancellation_grace",
                self.cancellation_grace,
                MAX_AGENT_CANCELLATION_GRACE,
            ),
            ("shutdown_grace", self.shutdown_grace, MAX_AGENT_SHUTDOWN_GRACE),
        )
        for label, duration_value, duration_maximum in duration_limits:
            _require_positive_duration(
                duration_value,
                label=label,
                maximum=duration_maximum,
            )

        if self.max_tool_calls > self.max_model_turns:
            raise ValueError("max_tool_calls cannot exceed max_model_turns")
        if self.max_concurrent_model_calls > self.max_concurrent_runs:
            raise ValueError("max_concurrent_model_calls cannot exceed max_concurrent_runs")
        if self.max_concurrent_tool_calls > self.max_concurrent_runs:
            raise ValueError("max_concurrent_tool_calls cannot exceed max_concurrent_runs")
        if self.model_turn_timeout > self.total_duration:
            raise ValueError("model_turn_timeout cannot exceed total_duration")
        if self.tool_call_timeout > self.total_duration:
            raise ValueError("tool_call_timeout cannot exceed total_duration")
        if self.approval_wait_timeout > self.total_duration:
            raise ValueError("approval_wait_timeout cannot exceed total_duration")

    def contains(self, other: AgentLimits) -> bool:
        if not isinstance(other, AgentLimits):
            raise TypeError("other must be AgentLimits")
        return (
            other.max_steps <= self.max_steps
            and other.max_model_turns <= self.max_model_turns
            and other.max_tool_calls <= self.max_tool_calls
            and other.max_prompt_bytes <= self.max_prompt_bytes
            and other.max_model_output_bytes <= self.max_model_output_bytes
            and other.max_tool_result_bytes <= self.max_tool_result_bytes
            and other.max_input_tokens <= self.max_input_tokens
            and other.max_output_tokens <= self.max_output_tokens
            and other.max_argument_bytes <= self.max_argument_bytes
            and other.max_result_bytes <= self.max_result_bytes
            and other.max_structured_depth <= self.max_structured_depth
            and other.max_structured_items <= self.max_structured_items
            and other.max_queue_depth <= self.max_queue_depth
            and other.max_concurrent_runs <= self.max_concurrent_runs
            and other.max_concurrent_model_calls <= self.max_concurrent_model_calls
            and other.max_concurrent_tool_calls <= self.max_concurrent_tool_calls
            and other.model_turn_timeout <= self.model_turn_timeout
            and other.tool_call_timeout <= self.tool_call_timeout
            and other.approval_wait_timeout <= self.approval_wait_timeout
            and other.total_duration <= self.total_duration
            and other.cancellation_grace <= self.cancellation_grace
            and other.shutdown_grace <= self.shutdown_grace
        )


@dataclass(frozen=True, slots=True)
class ToolCallProposal:
    """Untrusted structured model proposal with no execution authority."""

    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    arguments: Mapping[str, AgentJsonInput]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=2))

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        _require_timezone_aware(self.created_at, label="created_at")
        _require_timezone_aware(self.deadline, label="deadline")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must be after created_at")
        if self.deadline - self.created_at > MAX_AGENT_TOTAL_DURATION:
            raise ValueError("deadline exceeds the global maximum")
        frozen_arguments = freeze_agent_json_object(self.arguments)
        if len(canonical_agent_json_bytes(frozen_arguments)) > MAX_AGENT_ARGUMENT_BYTES:
            raise ValueError("tool arguments exceed the maximum encoded size")
        object.__setattr__(self, "arguments", frozen_arguments)


@dataclass(frozen=True, slots=True)
class ToolInvocationRequest:
    """Trusted request created only after validation and resource resolution."""

    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    arguments: Mapping[str, AgentJsonInput]
    resolved_resource: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=2))

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        _require_timezone_aware(self.created_at, label="created_at")
        _require_timezone_aware(self.deadline, label="deadline")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must be after created_at")
        if self.deadline - self.created_at > MAX_AGENT_TOOL_CALL_TIMEOUT:
            raise ValueError("tool deadline exceeds the global maximum")
        frozen_arguments = freeze_agent_json_object(self.arguments)
        if len(canonical_agent_json_bytes(frozen_arguments)) > MAX_AGENT_ARGUMENT_BYTES:
            raise ValueError("tool arguments exceed the maximum encoded size")
        object.__setattr__(self, "arguments", frozen_arguments)
        object.__setattr__(self, "resolved_resource", _normalize_resource(self.resolved_resource))


@dataclass(frozen=True, slots=True)
class ToolInvocationResult:
    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    status: ToolResultStatus
    output: Mapping[str, AgentJsonInput] | None = None
    error_code: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.status, ToolResultStatus):
            raise TypeError("status must be ToolResultStatus")
        _require_timezone_aware(self.started_at, label="started_at")
        _require_timezone_aware(self.completed_at, label="completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be before started_at")

        if self.status is ToolResultStatus.SUCCEEDED:
            if self.output is None:
                raise ValueError("successful tool results require output")
            if self.error_code is not None:
                raise ValueError("successful tool results cannot contain error_code")
            frozen_output = freeze_agent_json_object(self.output)
            if len(canonical_agent_json_bytes(frozen_output)) > MAX_AGENT_RESULT_BYTES:
                raise ValueError("tool result exceeds the maximum encoded size")
            object.__setattr__(self, "output", frozen_output)
        else:
            if self.output is not None:
                raise ValueError("failed tool results cannot contain output")
            if self.error_code is None:
                raise ValueError("failed tool results require error_code")
            object.__setattr__(
                self,
                "error_code",
                _normalize_identifier(self.error_code, label="tool error code"),
            )


@dataclass(frozen=True, slots=True)
class AgentRunRequest:
    agent_id: AgentId
    provider_id: ModelProviderId
    model_id: ModelId
    messages: Sequence[AgentMessage]
    limits: AgentLimits = field(default_factory=AgentLimits)
    metadata: AgentMetadata = field(default_factory=dict)
    run_id: AgentRunId = field(default_factory=AgentRunId)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=20))

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.limits, AgentLimits):
            raise TypeError("limits must be AgentLimits")
        messages = tuple(self.messages)
        if not messages:
            raise ValueError("messages must not be empty")
        if len(messages) > MAX_AGENT_MESSAGE_COUNT:
            raise ValueError("messages exceed the maximum count")
        if any(not isinstance(message, AgentMessage) for message in messages):
            raise TypeError("messages must contain AgentMessage values")
        total_chars = sum(len(message.content) for message in messages)
        if total_chars > MAX_AGENT_TOTAL_MESSAGE_CHARS:
            raise ValueError("messages exceed the total character limit")
        total_bytes = sum(len(message.content.encode("utf-8")) for message in messages)
        if total_bytes > self.limits.max_prompt_bytes:
            raise ValueError("messages exceed the configured prompt byte limit")
        _require_timezone_aware(self.created_at, label="created_at")
        _require_timezone_aware(self.deadline, label="deadline")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must be after created_at")
        if self.deadline - self.created_at > self.limits.total_duration:
            raise ValueError("deadline exceeds the configured total duration")
        object.__setattr__(self, "messages", messages)
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    run_id: AgentRunId
    status: AgentRunStatus
    model_turns: int
    tool_calls: int
    final_output: str | None = None
    error_code: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: AgentMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.status, AgentRunStatus):
            raise TypeError("status must be AgentRunStatus")
        if not self.status.terminal:
            raise ValueError("agent run results require a terminal status")
        _require_non_negative_integer(self.model_turns, label="model_turns")
        _require_non_negative_integer(self.tool_calls, label="tool_calls")
        if self.tool_calls > self.model_turns:
            raise ValueError("tool_calls cannot exceed model_turns")
        _require_timezone_aware(self.started_at, label="started_at")
        _require_timezone_aware(self.completed_at, label="completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be before started_at")

        if self.status is AgentRunStatus.COMPLETED:
            if self.final_output is None:
                raise ValueError("completed agent runs require final_output")
            if self.error_code is not None:
                raise ValueError("completed agent runs cannot contain error_code")
            object.__setattr__(
                self,
                "final_output",
                _normalize_text(
                    self.final_output,
                    label="final_output",
                    maximum=MAX_AGENT_FINAL_OUTPUT_CHARS,
                    allow_blank=True,
                ),
            )
        else:
            if self.final_output is not None:
                raise ValueError("failed agent runs cannot contain final_output")
            if self.error_code is None:
                raise ValueError("failed agent runs require error_code")
            object.__setattr__(
                self,
                "error_code",
                _normalize_identifier(self.error_code, label="agent error code"),
            )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class AgentSnapshot:
    """Content-free progress snapshot for one in-memory agent run."""

    run_id: AgentRunId
    status: AgentRunStatus
    model_turns: int
    tool_calls: int
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.status, AgentRunStatus):
            raise TypeError("status must be AgentRunStatus")
        _require_non_negative_integer(self.model_turns, label="model_turns")
        _require_non_negative_integer(self.tool_calls, label="tool_calls")
        if self.tool_calls > self.model_turns:
            raise ValueError("tool_calls cannot exceed model_turns")
        _require_timezone_aware(self.created_at, label="created_at")
        _require_timezone_aware(self.updated_at, label="updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be before created_at")
