"""Deterministic lifecycle and root-budget accounting for agent delegation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.coordination_contracts import (
    DelegationBudget,
    DelegationId,
    DelegationStatus,
)
from phoenix_os.agent.errors import AgentLimitExceededError, AgentStateConflictError


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DelegationLifecycleSnapshot:
    """Content-free immutable lifecycle state for one delegation."""

    delegation_id: DelegationId
    child_run_id: AgentRunId
    status: DelegationStatus
    created_at: datetime
    updated_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        if not isinstance(self.child_run_id, AgentRunId):
            raise TypeError("child_run_id must be AgentRunId")
        if not isinstance(self.status, DelegationStatus):
            raise TypeError("status must be DelegationStatus")
        _require_aware(self.created_at, label="created_at")
        _require_aware(self.updated_at, label="updated_at")
        _require_aware(self.deadline, label="deadline")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must follow created_at")


class DelegationStateMachine:
    """Permit only reviewed delegation transitions and immutable terminals."""

    def __init__(
        self,
        delegation_id: DelegationId,
        child_run_id: AgentRunId,
        *,
        created_at: datetime,
        deadline: datetime,
    ) -> None:
        if not isinstance(delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        if not isinstance(child_run_id, AgentRunId):
            raise TypeError("child_run_id must be AgentRunId")
        _require_aware(created_at, label="created_at")
        _require_aware(deadline, label="deadline")
        if deadline <= created_at:
            raise ValueError("deadline must follow created_at")
        self._delegation_id = delegation_id
        self._child_run_id = child_run_id
        self._status = DelegationStatus.REQUESTED
        self._created_at = created_at
        self._updated_at = created_at
        self._deadline = deadline

    @property
    def status(self) -> DelegationStatus:
        return self._status

    @property
    def terminal(self) -> bool:
        return self._status.terminal

    @property
    def child_run_id(self) -> AgentRunId:
        return self._child_run_id

    @property
    def deadline(self) -> datetime:
        return self._deadline

    def authorize(self, *, now: datetime) -> None:
        self._transition(DelegationStatus.AUTHORIZED, now, DelegationStatus.REQUESTED)

    def admit(self, *, now: datetime) -> None:
        self._transition(DelegationStatus.ADMITTED, now, DelegationStatus.AUTHORIZED)

    def start(self, *, now: datetime) -> None:
        self._transition(DelegationStatus.RUNNING, now, DelegationStatus.ADMITTED)

    def complete(self, *, now: datetime) -> None:
        self._transition(DelegationStatus.COMPLETED, now, DelegationStatus.RUNNING)

    def fail(self, *, now: datetime) -> None:
        self._set_terminal(DelegationStatus.FAILED, now)

    def cancel(self, *, now: datetime) -> None:
        self._set_terminal(DelegationStatus.CANCELLED, now)

    def expire(self, *, now: datetime) -> None:
        self._set_terminal(DelegationStatus.EXPIRED, now)

    def snapshot(self) -> DelegationLifecycleSnapshot:
        return DelegationLifecycleSnapshot(
            delegation_id=self._delegation_id,
            child_run_id=self._child_run_id,
            status=self._status,
            created_at=self._created_at,
            updated_at=self._updated_at,
            deadline=self._deadline,
        )

    def _transition(
        self,
        target: DelegationStatus,
        now: datetime,
        *sources: DelegationStatus,
    ) -> None:
        if self._status not in sources or self._status.terminal:
            raise AgentStateConflictError()
        self._set_status(target, now)

    def _set_terminal(self, target: DelegationStatus, now: datetime) -> None:
        if target not in {
            DelegationStatus.FAILED,
            DelegationStatus.CANCELLED,
            DelegationStatus.EXPIRED,
        }:
            raise ValueError("target must be a failure terminal state")
        if self._status.terminal:
            raise AgentStateConflictError()
        self._set_status(target, now)

    def _set_status(self, target: DelegationStatus, now: datetime) -> None:
        if not isinstance(target, DelegationStatus):
            raise TypeError("target must be DelegationStatus")
        _require_aware(now, label="now")
        if now < self._updated_at:
            raise AgentStateConflictError()
        if (
            target
            not in {
                DelegationStatus.COMPLETED,
                DelegationStatus.FAILED,
                DelegationStatus.CANCELLED,
                DelegationStatus.EXPIRED,
            }
            and now >= self._deadline
        ):
            raise AgentStateConflictError()
        self._status = target
        self._updated_at = now


@dataclass(frozen=True, slots=True)
class DelegationRootBudgetSnapshot:
    """Content-free aggregate reservations for one root run."""

    root_run_id: AgentRunId
    children: int
    model_turns: int
    tool_calls: int
    input_tokens: int
    output_tokens: int
    prompt_bytes: int
    result_bytes: int
    duration: timedelta

    def __post_init__(self) -> None:
        if not isinstance(self.root_run_id, AgentRunId):
            raise TypeError("root_run_id must be AgentRunId")
        counters = (
            self.children,
            self.model_turns,
            self.tool_calls,
            self.input_tokens,
            self.output_tokens,
            self.prompt_bytes,
            self.result_bytes,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in counters):
            raise TypeError("budget counters must be integers")
        if min(counters) < 0:
            raise ValueError("budget counters must not be negative")
        if not isinstance(self.duration, timedelta) or self.duration < timedelta(0):
            raise ValueError("duration must be a non-negative timedelta")


@dataclass(slots=True)
class _RootReservation:
    children: int = 0
    model_turns: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    prompt_bytes: int = 0
    result_bytes: int = 0
    duration: timedelta = timedelta(0)


class DelegationBudgetLedger:
    """Reserve finite child allowances without multiplying one root budget."""

    def __init__(self, limit: DelegationBudget, *, max_children: int) -> None:
        if not isinstance(limit, DelegationBudget):
            raise TypeError("limit must be DelegationBudget")
        if isinstance(max_children, bool) or not isinstance(max_children, int):
            raise TypeError("max_children must be an integer")
        if max_children <= 0:
            raise ValueError("max_children must be greater than zero")
        self._limit = limit
        self._max_children = max_children
        self._roots: dict[AgentRunId, _RootReservation] = {}

    @property
    def limit(self) -> DelegationBudget:
        return self._limit

    def can_reserve(self, root_run_id: AgentRunId, budget: DelegationBudget) -> bool:
        if not isinstance(root_run_id, AgentRunId):
            raise TypeError("root_run_id must be AgentRunId")
        if not isinstance(budget, DelegationBudget):
            raise TypeError("budget must be DelegationBudget")
        current = self._roots.get(root_run_id, _RootReservation())
        return (
            current.children + 1 <= self._max_children
            and current.model_turns + budget.max_model_turns <= self._limit.max_model_turns
            and current.tool_calls + budget.max_tool_calls <= self._limit.max_tool_calls
            and current.input_tokens + budget.max_input_tokens <= self._limit.max_input_tokens
            and current.output_tokens + budget.max_output_tokens <= self._limit.max_output_tokens
            and current.prompt_bytes + budget.max_prompt_bytes <= self._limit.max_prompt_bytes
            and current.result_bytes + budget.max_result_bytes <= self._limit.max_result_bytes
            and current.duration + budget.duration <= self._limit.duration
        )

    def reserve(self, root_run_id: AgentRunId, budget: DelegationBudget) -> None:
        if not self.can_reserve(root_run_id, budget):
            raise AgentLimitExceededError()
        current = self._roots.setdefault(root_run_id, _RootReservation())
        current.children += 1
        current.model_turns += budget.max_model_turns
        current.tool_calls += budget.max_tool_calls
        current.input_tokens += budget.max_input_tokens
        current.output_tokens += budget.max_output_tokens
        current.prompt_bytes += budget.max_prompt_bytes
        current.result_bytes += budget.max_result_bytes
        current.duration += budget.duration

    def snapshot(self, root_run_id: AgentRunId) -> DelegationRootBudgetSnapshot:
        if not isinstance(root_run_id, AgentRunId):
            raise TypeError("root_run_id must be AgentRunId")
        current = self._roots.get(root_run_id, _RootReservation())
        return DelegationRootBudgetSnapshot(
            root_run_id=root_run_id,
            children=current.children,
            model_turns=current.model_turns,
            tool_calls=current.tool_calls,
            input_tokens=current.input_tokens,
            output_tokens=current.output_tokens,
            prompt_bytes=current.prompt_bytes,
            result_bytes=current.result_bytes,
            duration=current.duration,
        )
