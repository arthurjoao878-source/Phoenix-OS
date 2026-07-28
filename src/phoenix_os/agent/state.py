"""Deterministic state, budgets, and cancellation for bounded agent runs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta

from phoenix_os.agent.contracts import (
    AgentLimits,
    AgentRunId,
    AgentRunStatus,
    AgentSnapshot,
)
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentLimitExceededError,
    AgentStateConflictError,
    AgentTimeoutError,
)


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_non_negative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")


@dataclass(frozen=True, slots=True)
class AgentBudgetSnapshot:
    """Content-free point-in-time counters for one bounded run."""

    steps: int
    model_turns: int
    tool_calls: int
    model_output_bytes: int
    tool_result_bytes: int
    input_tokens: int
    output_tokens: int
    started_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        counters = (
            ("steps", self.steps),
            ("model_turns", self.model_turns),
            ("tool_calls", self.tool_calls),
            ("model_output_bytes", self.model_output_bytes),
            ("tool_result_bytes", self.tool_result_bytes),
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
        )
        for label, value in counters:
            _require_non_negative_integer(value, label)
        _require_aware(self.started_at, "started_at")
        _require_aware(self.deadline, "deadline")
        if self.deadline <= self.started_at:
            raise ValueError("deadline must follow started_at")
        if self.tool_calls > self.model_turns:
            raise ValueError("tool_calls cannot exceed model_turns")


class AgentRunBudget:
    """Apply finite counters and deadlines before additional run work begins."""

    def __init__(
        self,
        limits: AgentLimits,
        *,
        started_at: datetime,
        deadline: datetime,
    ) -> None:
        if not isinstance(limits, AgentLimits):
            raise TypeError("limits must be AgentLimits")
        _require_aware(started_at, "started_at")
        _require_aware(deadline, "deadline")
        if deadline <= started_at:
            raise ValueError("deadline must follow started_at")
        if deadline - started_at > limits.total_duration:
            raise ValueError("deadline exceeds the configured total duration")
        self._limits = limits
        self._started_at = started_at
        self._deadline = deadline
        self._steps = 0
        self._model_turns = 0
        self._tool_calls = 0
        self._model_output_bytes = 0
        self._tool_result_bytes = 0
        self._input_tokens = 0
        self._output_tokens = 0

    @property
    def limits(self) -> AgentLimits:
        return self._limits

    @property
    def deadline(self) -> datetime:
        return self._deadline

    @property
    def steps(self) -> int:
        return self._steps

    @property
    def model_turns(self) -> int:
        return self._model_turns

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    def begin_model_turn(self, *, now: datetime) -> None:
        """Reserve one model turn and one run step before inference starts."""

        self._require_time(now)
        if self._steps >= self._limits.max_steps:
            raise AgentLimitExceededError()
        if self._model_turns >= self._limits.max_model_turns:
            raise AgentLimitExceededError()
        self._steps += 1
        self._model_turns += 1

    def begin_tool_call(self, *, now: datetime) -> None:
        """Reserve one serial tool call and one run step before invocation."""

        self._require_time(now)
        if self._steps >= self._limits.max_steps:
            raise AgentLimitExceededError()
        if self._tool_calls >= self._limits.max_tool_calls:
            raise AgentLimitExceededError()
        if self._tool_calls >= self._model_turns:
            raise AgentStateConflictError()
        self._steps += 1
        self._tool_calls += 1

    def record_model_usage(
        self,
        encoded_bytes: int,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Account bounded model bytes and tokens without retaining model content."""

        _require_non_negative_integer(encoded_bytes, "encoded_bytes")
        _require_non_negative_integer(input_tokens, "input_tokens")
        _require_non_negative_integer(output_tokens, "output_tokens")
        next_bytes = self._model_output_bytes + encoded_bytes
        next_input_tokens = self._input_tokens + input_tokens
        next_output_tokens = self._output_tokens + output_tokens
        if next_bytes > self._limits.max_model_output_bytes:
            raise AgentLimitExceededError()
        if next_input_tokens > self._limits.max_input_tokens:
            raise AgentLimitExceededError()
        if next_output_tokens > self._limits.max_output_tokens:
            raise AgentLimitExceededError()
        self._model_output_bytes = next_bytes
        self._input_tokens = next_input_tokens
        self._output_tokens = next_output_tokens

    def record_tool_result(self, encoded_bytes: int) -> None:
        """Account bounded accumulated tool-result bytes without retaining output."""

        _require_non_negative_integer(encoded_bytes, "encoded_bytes")
        next_bytes = self._tool_result_bytes + encoded_bytes
        if next_bytes > self._limits.max_tool_result_bytes:
            raise AgentLimitExceededError()
        self._tool_result_bytes = next_bytes

    def require_argument_bytes(self, encoded_bytes: int) -> None:
        _require_non_negative_integer(encoded_bytes, "encoded_bytes")
        if encoded_bytes > self._limits.max_argument_bytes:
            raise AgentLimitExceededError()

    def require_result_bytes(self, encoded_bytes: int) -> None:
        _require_non_negative_integer(encoded_bytes, "encoded_bytes")
        if encoded_bytes > self._limits.max_result_bytes:
            raise AgentLimitExceededError()

    def model_timeout_seconds(self, *, now: datetime) -> float:
        return self._operation_timeout(now, self._limits.model_turn_timeout)

    def tool_timeout_seconds(self, *, now: datetime) -> float:
        return self._operation_timeout(now, self._limits.tool_call_timeout)

    def approval_timeout_seconds(self, *, now: datetime) -> float:
        return self._operation_timeout(now, self._limits.approval_wait_timeout)

    def snapshot(self) -> AgentBudgetSnapshot:
        return AgentBudgetSnapshot(
            steps=self._steps,
            model_turns=self._model_turns,
            tool_calls=self._tool_calls,
            model_output_bytes=self._model_output_bytes,
            tool_result_bytes=self._tool_result_bytes,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            started_at=self._started_at,
            deadline=self._deadline,
        )

    def _operation_timeout(self, now: datetime, configured: timedelta) -> float:
        self._require_time(now)
        remaining = (self._deadline - now).total_seconds()
        return min(remaining, configured.total_seconds())

    def _require_time(self, now: datetime) -> None:
        _require_aware(now, "now")
        if now < self._started_at:
            raise ValueError("now cannot precede started_at")
        if now >= self._deadline:
            raise AgentTimeoutError()


class AgentRunStateMachine:
    """Permit only reviewed agent-loop transitions and terminal outcomes."""

    def __init__(
        self,
        run_id: AgentRunId,
        limits: AgentLimits,
        *,
        created_at: datetime,
        deadline: datetime,
    ) -> None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        self._run_id = run_id
        self._status = AgentRunStatus.CREATED
        self._created_at = created_at
        self._updated_at = created_at
        self._budget = AgentRunBudget(
            limits,
            started_at=created_at,
            deadline=deadline,
        )

    @property
    def status(self) -> AgentRunStatus:
        return self._status

    @property
    def terminal(self) -> bool:
        return self._status.terminal

    @property
    def budget(self) -> AgentRunBudget:
        return self._budget

    def start_inference(self, *, now: datetime) -> None:
        self._require_status(AgentRunStatus.CREATED, AgentRunStatus.VALIDATING_RESULT)
        self._require_monotonic(now)
        self._budget.begin_model_turn(now=now)
        self._set_status(AgentRunStatus.INFERENCING, now)

    def start_proposal_validation(self, *, now: datetime) -> None:
        self._transition(
            AgentRunStatus.VALIDATING_PROPOSAL,
            now,
            AgentRunStatus.INFERENCING,
        )

    def start_tool_authorization(self, *, now: datetime) -> None:
        self._transition(
            AgentRunStatus.AUTHORIZING_TOOL,
            now,
            AgentRunStatus.VALIDATING_PROPOSAL,
        )

    def start_approval(self, *, now: datetime) -> None:
        self._transition(
            AgentRunStatus.AWAITING_APPROVAL,
            now,
            AgentRunStatus.AUTHORIZING_TOOL,
        )

    def start_tool_invocation(self, *, now: datetime) -> None:
        self._require_status(
            AgentRunStatus.AUTHORIZING_TOOL,
            AgentRunStatus.AWAITING_APPROVAL,
        )
        self._require_monotonic(now)
        self._budget.begin_tool_call(now=now)
        self._set_status(AgentRunStatus.INVOKING_TOOL, now)

    def start_result_validation(self, *, now: datetime) -> None:
        self._transition(
            AgentRunStatus.VALIDATING_RESULT,
            now,
            AgentRunStatus.INVOKING_TOOL,
        )

    def complete(self, *, now: datetime) -> None:
        self._transition(AgentRunStatus.COMPLETED, now, AgentRunStatus.INFERENCING)

    def fail(self, *, now: datetime) -> None:
        self._set_terminal(AgentRunStatus.FAILED, now)

    def cancel(self, *, now: datetime) -> None:
        self._set_terminal(AgentRunStatus.CANCELLED, now)

    def snapshot(self) -> AgentSnapshot:
        return AgentSnapshot(
            run_id=self._run_id,
            status=self._status,
            model_turns=self._budget.model_turns,
            tool_calls=self._budget.tool_calls,
            created_at=self._created_at,
            updated_at=self._updated_at,
        )

    def _transition(
        self,
        target: AgentRunStatus,
        now: datetime,
        *sources: AgentRunStatus,
    ) -> None:
        self._require_status(*sources)
        self._set_status(target, now)

    def _set_terminal(self, target: AgentRunStatus, now: datetime) -> None:
        if target not in {AgentRunStatus.FAILED, AgentRunStatus.CANCELLED}:
            raise ValueError("target must be a failure terminal state")
        if self._status.terminal:
            raise AgentStateConflictError()
        self._set_status(target, now)

    def _require_status(self, *allowed: AgentRunStatus) -> None:
        if self._status not in allowed or self._status.terminal:
            raise AgentStateConflictError()

    def _set_status(self, status: AgentRunStatus, now: datetime) -> None:
        if not isinstance(status, AgentRunStatus):
            raise TypeError("status must be AgentRunStatus")
        self._require_monotonic(now)
        self._status = status
        self._updated_at = now

    def _require_monotonic(self, now: datetime) -> None:
        _require_aware(now, "now")
        if now < self._updated_at:
            raise AgentStateConflictError()


class AgentCancellationToken:
    """Idempotent cooperative cancellation signal for one in-memory run."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise AgentCancelledError()
