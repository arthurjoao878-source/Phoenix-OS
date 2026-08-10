"""Immutable bounded contracts for secure Phoenix agent delegation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import (
    MAX_AGENT_INPUT_TOKENS,
    MAX_AGENT_JSON_DEPTH,
    MAX_AGENT_MODEL_TURNS,
    MAX_AGENT_OUTPUT_TOKENS,
    MAX_AGENT_PROMPT_BYTES,
    MAX_AGENT_RESULT_BYTES,
    MAX_AGENT_TOOL_CALLS,
    MAX_AGENT_TOTAL_DURATION,
    AgentId,
    AgentJsonInput,
    AgentRunId,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)

MAX_COORDINATION_NAMESPACE_LENGTH = 128
MAX_DELEGATION_DEPTH = 32
MAX_DELEGATION_FAN_OUT = 256
MAX_DELEGATION_TOTAL_CHILDREN = 1_024
MAX_DELEGATION_CONCURRENT_CHILDREN = 256
MAX_DELEGATION_QUEUE_DEPTH = 4_096
MAX_DELEGATION_INPUT_BYTES = MAX_AGENT_PROMPT_BYTES
MAX_DELEGATION_RESULT_BYTES = MAX_AGENT_RESULT_BYTES
MAX_DELEGATION_RESULT_DEPTH = MAX_AGENT_JSON_DEPTH
MAX_DELEGATION_DURATION = MAX_AGENT_TOTAL_DURATION
MAX_DELEGATION_LINEAGE_ENTRIES = MAX_DELEGATION_DEPTH + 1

_COORDINATION_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _positive_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _non_negative_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _positive_duration(value: timedelta, *, label: str, maximum: timedelta) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be a timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True, order=True)
class CoordinationNamespace:
    """Stable server-owned namespace for one delegation policy domain."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("coordination namespace must be a string")
        normalized = self.value.strip().lower()
        if _COORDINATION_NAMESPACE_PATTERN.fullmatch(normalized) is None:
            raise ValueError("coordination namespace is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class DelegationId:
    """Stable Phoenix-owned identity for one delegation."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("delegation id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class DelegationDepth:
    """Bounded number of delegation edges from the root run."""

    value: int = 0

    def __post_init__(self) -> None:
        _non_negative_int(
            self.value,
            label="delegation depth",
            maximum=MAX_DELEGATION_DEPTH,
        )

    def __int__(self) -> int:
        return self.value


class DelegationStatus(StrEnum):
    REQUESTED = "requested"
    AUTHORIZED = "authorized"
    ADMITTED = "admitted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

    @property
    def terminal(self) -> bool:
        return self in {
            self.COMPLETED,
            self.FAILED,
            self.CANCELLED,
            self.EXPIRED,
        }


@dataclass(frozen=True, slots=True)
class DelegationLimits:
    """Finite coordination limits; every child remains inside these bounds."""

    max_depth: int = 4
    max_fan_out: int = 8
    max_total_children: int = 32
    max_concurrent_children: int = 4
    max_queue_depth: int = 64
    max_input_bytes: int = 262_144
    max_result_bytes: int = 1_048_576
    max_result_depth: int = 16
    child_timeout: timedelta = timedelta(minutes=10)

    def __post_init__(self) -> None:
        limits = (
            ("max_depth", self.max_depth, MAX_DELEGATION_DEPTH),
            ("max_fan_out", self.max_fan_out, MAX_DELEGATION_FAN_OUT),
            ("max_total_children", self.max_total_children, MAX_DELEGATION_TOTAL_CHILDREN),
            (
                "max_concurrent_children",
                self.max_concurrent_children,
                MAX_DELEGATION_CONCURRENT_CHILDREN,
            ),
            ("max_queue_depth", self.max_queue_depth, MAX_DELEGATION_QUEUE_DEPTH),
            ("max_input_bytes", self.max_input_bytes, MAX_DELEGATION_INPUT_BYTES),
            ("max_result_bytes", self.max_result_bytes, MAX_DELEGATION_RESULT_BYTES),
            ("max_result_depth", self.max_result_depth, MAX_DELEGATION_RESULT_DEPTH),
        )
        for label, value, maximum in limits:
            _positive_int(value, label=label, maximum=maximum)
        _positive_duration(
            self.child_timeout,
            label="child_timeout",
            maximum=MAX_DELEGATION_DURATION,
        )
        if self.max_fan_out > self.max_total_children:
            raise ValueError("max_fan_out cannot exceed max_total_children")
        if self.max_concurrent_children > self.max_total_children:
            raise ValueError("max_concurrent_children cannot exceed max_total_children")
        if self.max_concurrent_children > self.max_fan_out:
            raise ValueError("max_concurrent_children cannot exceed max_fan_out")

    def contains(self, other: DelegationLimits) -> bool:
        if not isinstance(other, DelegationLimits):
            raise TypeError("other must be DelegationLimits")
        return (
            other.max_depth <= self.max_depth
            and other.max_fan_out <= self.max_fan_out
            and other.max_total_children <= self.max_total_children
            and other.max_concurrent_children <= self.max_concurrent_children
            and other.max_queue_depth <= self.max_queue_depth
            and other.max_input_bytes <= self.max_input_bytes
            and other.max_result_bytes <= self.max_result_bytes
            and other.max_result_depth <= self.max_result_depth
            and other.child_timeout <= self.child_timeout
        )


@dataclass(frozen=True, slots=True)
class DelegationBudget:
    """Finite child allowance carved out of the already-bounded root run."""

    max_model_turns: int = 4
    max_tool_calls: int = 4
    max_input_tokens: int = 32_768
    max_output_tokens: int = 16_384
    max_prompt_bytes: int = 131_072
    max_result_bytes: int = 524_288
    duration: timedelta = timedelta(minutes=10)

    def __post_init__(self) -> None:
        limits = (
            ("max_model_turns", self.max_model_turns, MAX_AGENT_MODEL_TURNS),
            ("max_tool_calls", self.max_tool_calls, MAX_AGENT_TOOL_CALLS),
            ("max_input_tokens", self.max_input_tokens, MAX_AGENT_INPUT_TOKENS),
            ("max_output_tokens", self.max_output_tokens, MAX_AGENT_OUTPUT_TOKENS),
            ("max_prompt_bytes", self.max_prompt_bytes, MAX_AGENT_PROMPT_BYTES),
            ("max_result_bytes", self.max_result_bytes, MAX_AGENT_RESULT_BYTES),
        )
        for label, value, maximum in limits:
            _positive_int(value, label=label, maximum=maximum)
        _positive_duration(
            self.duration,
            label="duration",
            maximum=MAX_DELEGATION_DURATION,
        )
        if self.max_tool_calls > self.max_model_turns:
            raise ValueError("max_tool_calls cannot exceed max_model_turns")

    def contains(self, other: DelegationBudget) -> bool:
        if not isinstance(other, DelegationBudget):
            raise TypeError("other must be DelegationBudget")
        return (
            other.max_model_turns <= self.max_model_turns
            and other.max_tool_calls <= self.max_tool_calls
            and other.max_input_tokens <= self.max_input_tokens
            and other.max_output_tokens <= self.max_output_tokens
            and other.max_prompt_bytes <= self.max_prompt_bytes
            and other.max_result_bytes <= self.max_result_bytes
            and other.duration <= self.duration
        )


@dataclass(frozen=True, slots=True)
class DelegationLineageEntry:
    """One Phoenix-owned content-free ancestor entry."""

    agent_id: AgentId
    run_id: AgentRunId
    via_delegation_id: DelegationId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if self.via_delegation_id is not None and not isinstance(
            self.via_delegation_id,
            DelegationId,
        ):
            raise TypeError("via_delegation_id must be DelegationId or None")


@dataclass(frozen=True, slots=True)
class DelegationLineage:
    """Bounded immutable root-to-parent lineage used for cycle prevention."""

    entries: Sequence[DelegationLineageEntry]

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        if not entries:
            raise ValueError("delegation lineage must not be empty")
        if len(entries) > MAX_DELEGATION_LINEAGE_ENTRIES:
            raise ValueError("delegation lineage exceeds the global maximum")
        if any(not isinstance(entry, DelegationLineageEntry) for entry in entries):
            raise TypeError("lineage entries must be DelegationLineageEntry values")
        if entries[0].via_delegation_id is not None:
            raise ValueError("root lineage entry cannot have via_delegation_id")
        if any(entry.via_delegation_id is None for entry in entries[1:]):
            raise ValueError("non-root lineage entries require via_delegation_id")

        agent_ids = tuple(entry.agent_id for entry in entries)
        run_ids = tuple(entry.run_id for entry in entries)
        delegation_ids = tuple(entry.via_delegation_id for entry in entries[1:])
        if len(agent_ids) != len(set(agent_ids)):
            raise ValueError("delegation lineage contains an agent cycle")
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("delegation lineage contains duplicate run ids")
        if len(delegation_ids) != len(set(delegation_ids)):
            raise ValueError("delegation lineage contains duplicate delegation ids")

        object.__setattr__(self, "entries", entries)

    @property
    def depth(self) -> DelegationDepth:
        return DelegationDepth(len(self.entries) - 1)

    @property
    def root_run_id(self) -> AgentRunId:
        return self.entries[0].run_id

    @property
    def parent_agent_id(self) -> AgentId:
        return self.entries[-1].agent_id

    @property
    def parent_run_id(self) -> AgentRunId:
        return self.entries[-1].run_id

    def contains_agent(self, agent_id: AgentId) -> bool:
        if not isinstance(agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        return any(entry.agent_id == agent_id for entry in self.entries)


@dataclass(frozen=True, slots=True)
class DelegationRequest:
    """Trusted bounded request created before exact delegation authorization."""

    parent_agent_id: AgentId
    parent_run_id: AgentRunId
    child_agent_id: AgentId
    namespace: CoordinationNamespace
    lineage: DelegationLineage
    input: Mapping[str, AgentJsonInput]
    budget: DelegationBudget = field(default_factory=DelegationBudget)
    limits: DelegationLimits = field(default_factory=DelegationLimits)
    delegation_id: DelegationId = field(default_factory=DelegationId)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=5))

    def __post_init__(self) -> None:
        if not isinstance(self.parent_agent_id, AgentId):
            raise TypeError("parent_agent_id must be AgentId")
        if not isinstance(self.parent_run_id, AgentRunId):
            raise TypeError("parent_run_id must be AgentRunId")
        if not isinstance(self.child_agent_id, AgentId):
            raise TypeError("child_agent_id must be AgentId")
        if not isinstance(self.namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
        if not isinstance(self.lineage, DelegationLineage):
            raise TypeError("lineage must be DelegationLineage")
        if not isinstance(self.budget, DelegationBudget):
            raise TypeError("budget must be DelegationBudget")
        if not isinstance(self.limits, DelegationLimits):
            raise TypeError("limits must be DelegationLimits")
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        if (
            self.lineage.parent_agent_id != self.parent_agent_id
            or self.lineage.parent_run_id != self.parent_run_id
        ):
            raise ValueError("delegation lineage does not match the parent run")
        if self.lineage.contains_agent(self.child_agent_id):
            raise ValueError("delegation child would create a lineage cycle")

        child_depth = self.child_depth
        if child_depth.value > self.limits.max_depth:
            raise ValueError("delegation child exceeds the configured maximum depth")

        frozen_input = freeze_agent_json_object(self.input)
        if len(canonical_agent_json_bytes(frozen_input)) > self.limits.max_input_bytes:
            raise ValueError("delegation input exceeds the configured byte limit")

        _aware(self.created_at, label="created_at")
        _aware(self.deadline, label="deadline")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must be after created_at")
        duration = self.deadline - self.created_at
        if duration > self.limits.child_timeout:
            raise ValueError("deadline exceeds the configured child timeout")
        if duration > self.budget.duration:
            raise ValueError("deadline exceeds the delegated duration budget")

        object.__setattr__(self, "input", frozen_input)

    @property
    def child_depth(self) -> DelegationDepth:
        return DelegationDepth(self.lineage.depth.value + 1)


def delegation_budget_fits_agent_limits(
    budget: DelegationBudget,
    *,
    max_model_turns: int,
    max_tool_calls: int,
    max_input_tokens: int,
    max_output_tokens: int,
    max_prompt_bytes: int,
    max_result_bytes: int,
    total_duration: timedelta,
) -> bool:
    """Return whether one delegated allowance fits trusted child execution limits."""

    if not isinstance(budget, DelegationBudget):
        raise TypeError("budget must be DelegationBudget")
    return (
        budget.max_model_turns <= max_model_turns
        and budget.max_tool_calls <= max_tool_calls
        and budget.max_input_tokens <= max_input_tokens
        and budget.max_output_tokens <= max_output_tokens
        and budget.max_prompt_bytes <= max_prompt_bytes
        and budget.max_result_bytes <= max_result_bytes
        and budget.duration <= total_duration
    )
