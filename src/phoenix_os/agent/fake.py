"""Deterministic model-turn and tool adapters for network-free tests."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import (
    MAX_AGENT_FINAL_OUTPUT_CHARS,
    MAX_AGENT_INPUT_TOKENS,
    MAX_AGENT_MESSAGE_COUNT,
    MAX_AGENT_MODEL_TURN_TIMEOUT,
    MAX_AGENT_OUTPUT_TOKENS,
    AgentJsonInput,
    AgentJsonValue,
    AgentMessage,
    AgentRunId,
    AgentStepId,
    ToolAvailability,
    ToolCallId,
    ToolCallProposal,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import AgentMalformedProposalError, ToolExecutionError
from phoenix_os.agent.tools import ToolDescriptor

_ADAPTER_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _normalize_adapter_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("adapter_id must be a string")
    normalized = value.strip()
    if not _ADAPTER_ID_PATTERN.fullmatch(normalized):
        raise ValueError("adapter_id is invalid")
    return normalized


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


class AgentModelTurnKind(StrEnum):
    FINAL_OUTPUT = "final_output"
    TOOL_PROPOSAL = "tool_proposal"


@dataclass(frozen=True, slots=True)
class AgentModelTurnRequest:
    """One bounded provider-neutral model turn over admitted tools only."""

    run_id: AgentRunId
    step_id: AgentStepId
    messages: Sequence[AgentMessage]
    tools: Sequence[ToolDescriptor] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=2))

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        messages = tuple(self.messages)
        if not messages:
            raise ValueError("messages must not be empty")
        if len(messages) > MAX_AGENT_MESSAGE_COUNT:
            raise ValueError("messages exceed the maximum count")
        if any(not isinstance(message, AgentMessage) for message in messages):
            raise TypeError("messages must contain AgentMessage values")
        tools = tuple(self.tools)
        if any(not isinstance(tool, ToolDescriptor) for tool in tools):
            raise TypeError("tools must contain ToolDescriptor values")
        admitted_ids: set[ToolId] = set()
        for tool in tools:
            if tool.availability is not ToolAvailability.ACTIVE:
                raise ValueError("model turn tools must be active")
            if tool.tool_id in admitted_ids:
                raise ValueError("model turn tools contain duplicate identifiers")
            admitted_ids.add(tool.tool_id)
        _require_timezone_aware(self.created_at, label="created_at")
        _require_timezone_aware(self.deadline, label="deadline")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must be after created_at")
        if self.deadline - self.created_at > MAX_AGENT_MODEL_TURN_TIMEOUT:
            raise ValueError("model turn deadline exceeds the global maximum")
        object.__setattr__(self, "messages", messages)
        object.__setattr__(self, "tools", tools)


@dataclass(frozen=True, slots=True)
class AgentModelTurnResult:
    """Exactly one final output or one untrusted tool-call proposal."""

    run_id: AgentRunId
    step_id: AgentStepId
    kind: AgentModelTurnKind
    final_output: str | None = None
    proposal: ToolCallProposal | None = None
    input_tokens: int = 0
    output_tokens: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.kind, AgentModelTurnKind):
            raise TypeError("kind must be AgentModelTurnKind")
        for label, value, maximum in (
            ("input_tokens", self.input_tokens, MAX_AGENT_INPUT_TOKENS),
            ("output_tokens", self.output_tokens, MAX_AGENT_OUTPUT_TOKENS),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0 or value > maximum:
                raise ValueError(f"{label} is outside the supported range")
        if self.kind is AgentModelTurnKind.FINAL_OUTPUT:
            if not isinstance(self.final_output, str):
                raise ValueError("final model turns require final_output")
            if self.proposal is not None:
                raise ValueError("final model turns cannot contain a proposal")
            if len(self.final_output) > MAX_AGENT_FINAL_OUTPUT_CHARS:
                raise ValueError("final_output exceeds the maximum length")
            return
        if self.final_output is not None:
            raise ValueError("tool model turns cannot contain final_output")
        if not isinstance(self.proposal, ToolCallProposal):
            raise ValueError("tool model turns require one proposal")
        if self.proposal.run_id != self.run_id or self.proposal.step_id != self.step_id:
            raise ValueError("tool proposal identifiers do not match the model turn")


@runtime_checkable
class AgentModelTurnAdapter(Protocol):
    @property
    def adapter_id(self) -> str: ...

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult: ...


@dataclass(frozen=True, slots=True)
class DeterministicFinalTurn:
    final_output: str

    def __post_init__(self) -> None:
        if not isinstance(self.final_output, str):
            raise TypeError("final_output must be a string")
        if len(self.final_output) > MAX_AGENT_FINAL_OUTPUT_CHARS:
            raise ValueError("final_output exceeds the maximum length")


@dataclass(frozen=True, slots=True)
class DeterministicToolTurn:
    tool_id: ToolId
    arguments: Mapping[str, AgentJsonInput]
    call_id: ToolCallId = field(default_factory=ToolCallId)

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        object.__setattr__(self, "arguments", freeze_agent_json_object(self.arguments))


type DeterministicModelTurn = DeterministicFinalTurn | DeterministicToolTurn


class DeterministicModelTurnAdapter:
    """Replay one reviewed finite sequence without network or provider SDK state."""

    def __init__(
        self,
        turns: Sequence[DeterministicModelTurn],
        *,
        adapter_id: str = "deterministic-model-turn",
    ) -> None:
        self._adapter_id = _normalize_adapter_id(adapter_id)
        normalized = tuple(turns)
        if not normalized:
            raise ValueError("deterministic model adapter requires at least one turn")
        if any(
            not isinstance(turn, (DeterministicFinalTurn, DeterministicToolTurn))
            for turn in normalized
        ):
            raise TypeError("turns contain an unsupported deterministic turn")
        self._turns = normalized
        self._index = 0
        self._requests: list[AgentModelTurnRequest] = []

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def requests(self) -> tuple[AgentModelTurnRequest, ...]:
        return tuple(self._requests)

    @property
    def remaining_turns(self) -> int:
        return len(self._turns) - self._index

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        if not isinstance(request, AgentModelTurnRequest):
            raise TypeError("request must be AgentModelTurnRequest")
        if self._index >= len(self._turns):
            raise AgentMalformedProposalError()
        turn = self._turns[self._index]
        self._index += 1
        self._requests.append(request)
        if isinstance(turn, DeterministicFinalTurn):
            return AgentModelTurnResult(
                run_id=request.run_id,
                step_id=request.step_id,
                kind=AgentModelTurnKind.FINAL_OUTPUT,
                final_output=turn.final_output,
            )
        admitted = {descriptor.tool_id for descriptor in request.tools}
        if turn.tool_id not in admitted:
            raise AgentMalformedProposalError()
        proposal = ToolCallProposal(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=turn.call_id,
            tool_id=turn.tool_id,
            arguments=turn.arguments,
            created_at=request.created_at,
            deadline=request.deadline,
        )
        return AgentModelTurnResult(
            run_id=request.run_id,
            step_id=request.step_id,
            kind=AgentModelTurnKind.TOOL_PROPOSAL,
            proposal=proposal,
        )


class DeterministicReadOnlyTool:
    """Return one fixed immutable result and perform no external side effect."""

    def __init__(
        self,
        tool_id: ToolId | str,
        output: Mapping[str, AgentJsonInput],
        *,
        adapter_id: str = "deterministic-read-only",
    ) -> None:
        self._tool_id = tool_id if isinstance(tool_id, ToolId) else ToolId(tool_id)
        self._adapter_id = _normalize_adapter_id(adapter_id)
        self._output = freeze_agent_json_object(output)
        self._requests: list[ToolInvocationRequest] = []

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def tool_id(self) -> ToolId:
        return self._tool_id

    @property
    def output(self) -> Mapping[str, AgentJsonValue]:
        return self._output

    @property
    def requests(self) -> tuple[ToolInvocationRequest, ...]:
        return tuple(self._requests)

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        _validate_fake_tool_request(request, self._tool_id)
        self._requests.append(request)
        return _successful_result(request, self._output)


class DeterministicSideEffectTool:
    """Record one in-memory effect for each explicit invocation, without retry."""

    def __init__(
        self,
        tool_id: ToolId | str,
        output: Mapping[str, AgentJsonInput],
        *,
        adapter_id: str = "deterministic-side-effect",
    ) -> None:
        self._tool_id = tool_id if isinstance(tool_id, ToolId) else ToolId(tool_id)
        self._adapter_id = _normalize_adapter_id(adapter_id)
        self._output = freeze_agent_json_object(output)
        self._requests: list[ToolInvocationRequest] = []
        self._effects: list[ToolCallId] = []

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def tool_id(self) -> ToolId:
        return self._tool_id

    @property
    def requests(self) -> tuple[ToolInvocationRequest, ...]:
        return tuple(self._requests)

    @property
    def effects(self) -> tuple[ToolCallId, ...]:
        return tuple(self._effects)

    @property
    def effect_count(self) -> int:
        return len(self._effects)

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        _validate_fake_tool_request(request, self._tool_id)
        self._requests.append(request)
        self._effects.append(request.call_id)
        return _successful_result(request, self._output)


def _validate_fake_tool_request(request: ToolInvocationRequest, tool_id: ToolId) -> None:
    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    if request.tool_id != tool_id:
        raise ToolExecutionError()


def _successful_result(
    request: ToolInvocationRequest,
    output: Mapping[str, AgentJsonValue],
) -> ToolInvocationResult:
    return ToolInvocationResult(
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        status=ToolResultStatus.SUCCEEDED,
        output=output,
        started_at=request.created_at,
        completed_at=request.created_at,
    )
