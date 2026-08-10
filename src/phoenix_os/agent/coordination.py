"""Bounded in-memory coordinator for secure Phoenix agent delegation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.coordination_authorization import DelegationAuthorizer
from phoenix_os.agent.coordination_contracts import (
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationRequest,
    DelegationStatus,
)
from phoenix_os.agent.coordination_registry import (
    AgentDelegationRegistry,
    DelegableAgentDescriptor,
)
from phoenix_os.agent.coordination_state import (
    DelegationBudgetLedger,
    DelegationRootBudgetSnapshot,
    DelegationStateMachine,
)
from phoenix_os.agent.errors import (
    AgentLimitExceededError,
    AgentStateConflictError,
    AgentTimeoutError,
    DelegationAlreadyExistsError,
    DelegationNotFoundError,
)
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DelegatedChildRun:
    """Content-free immutable view of one coordinated child run."""

    delegation_id: DelegationId
    parent_agent_id: AgentId
    parent_run_id: AgentRunId
    root_run_id: AgentRunId
    child_agent_id: AgentId
    child_run_id: AgentRunId
    depth: DelegationDepth
    status: DelegationStatus
    budget: DelegationBudget
    created_at: datetime
    updated_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        for label, agent_id in (
            ("parent_agent_id", self.parent_agent_id),
            ("child_agent_id", self.child_agent_id),
        ):
            if not isinstance(agent_id, AgentId):
                raise TypeError(f"{label} must be AgentId")
        for label, run_id in (
            ("parent_run_id", self.parent_run_id),
            ("root_run_id", self.root_run_id),
            ("child_run_id", self.child_run_id),
        ):
            if not isinstance(run_id, AgentRunId):
                raise TypeError(f"{label} must be AgentRunId")
        if not isinstance(self.depth, DelegationDepth):
            raise TypeError("depth must be DelegationDepth")
        if not isinstance(self.status, DelegationStatus):
            raise TypeError("status must be DelegationStatus")
        if not isinstance(self.budget, DelegationBudget):
            raise TypeError("budget must be DelegationBudget")
        _require_aware(self.created_at, label="created_at")
        _require_aware(self.updated_at, label="updated_at")
        _require_aware(self.deadline, label="deadline")


@dataclass(frozen=True, slots=True)
class AgentDelegationCoordinatorSnapshot:
    """Content-free bounded counters for one in-memory coordinator."""

    delegations: int
    active: int
    queued: int
    completed: int
    failed: int
    expired: int
    max_concurrent_children: int
    max_queue_depth: int
    max_total_children: int

    def __post_init__(self) -> None:
        values = (
            self.delegations,
            self.active,
            self.queued,
            self.completed,
            self.failed,
            self.expired,
            self.max_concurrent_children,
            self.max_queue_depth,
            self.max_total_children,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TypeError("coordinator counters and limits must be integers")
        if min(values) < 0:
            raise ValueError("coordinator counters and limits cannot be negative")
        if self.active > self.max_concurrent_children:
            raise ValueError("active children exceed coordinator capacity")
        if self.queued > self.max_queue_depth:
            raise ValueError("queued children exceed coordinator capacity")


@dataclass(slots=True)
class _CoordinatorRecord:
    request: DelegationRequest
    descriptor: DelegableAgentDescriptor
    lifecycle: DelegationStateMachine
    active: bool = False
    queued: bool = False


class AgentDelegationCoordinator:
    """Authorize, admit, bound, and track child delegation without executing it."""

    def __init__(
        self,
        registry: AgentDelegationRegistry,
        authorizer: DelegationAuthorizer,
        *,
        limits: DelegationLimits,
        root_budget_limit: DelegationBudget,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(registry, AgentDelegationRegistry):
            raise TypeError("registry must be AgentDelegationRegistry")
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("authorizer must provide authorize")
        if not isinstance(limits, DelegationLimits):
            raise TypeError("limits must be DelegationLimits")
        if not isinstance(root_budget_limit, DelegationBudget):
            raise TypeError("root_budget_limit must be DelegationBudget")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._registry = registry
        self._authorizer = authorizer
        self._limits = limits
        self._budget = DelegationBudgetLedger(
            root_budget_limit,
            max_children=limits.max_total_children,
        )
        self._clock = clock
        self._records: dict[DelegationId, _CoordinatorRecord] = {}
        self._parent_children: dict[AgentRunId, int] = {}
        self._active = 0
        self._queued = 0
        self._lock = asyncio.Lock()
        self._changed = asyncio.Event()

    @property
    def limits(self) -> DelegationLimits:
        return self._limits

    @property
    def root_budget_limit(self) -> DelegationBudget:
        return self._budget.limit

    async def delegate(
        self,
        request: DelegationRequest,
        context: SecurityContext,
    ) -> DelegatedChildRun:
        """Authorize and admit one child, waiting only inside finite queue/deadline bounds."""

        if not isinstance(request, DelegationRequest):
            raise TypeError("request must be DelegationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not self._limits.contains(request.limits):
            raise AgentLimitExceededError()

        descriptor = self._registry.resolve_request(request)
        await self._authorizer.authorize(request, descriptor, context)

        child_run_id = AgentRunId()
        lifecycle = DelegationStateMachine(
            request.delegation_id,
            child_run_id,
            created_at=request.created_at,
            deadline=request.deadline,
        )
        now = self._clock()
        _require_aware(now, label="clock result")
        if now >= request.deadline:
            raise AgentTimeoutError()
        lifecycle.authorize(now=now)

        record = _CoordinatorRecord(
            request=request,
            descriptor=descriptor,
            lifecycle=lifecycle,
        )

        async with self._lock:
            if request.delegation_id in self._records:
                raise DelegationAlreadyExistsError()
            self._records[request.delegation_id] = record
            try:
                self._require_lifetime_capacity_locked(record)
            except AgentLimitExceededError:
                record.lifecycle.fail(now=self._clock())
                self._signal_locked()
                raise
            if self._has_execution_capacity_locked(record):
                self._admit_locked(record, now=self._clock())
                return self._view(record)

            queue_limit = min(self._limits.max_queue_depth, request.limits.max_queue_depth)
            if self._queued >= queue_limit:
                record.lifecycle.fail(now=self._clock())
                self._signal_locked()
                raise AgentLimitExceededError()

            record.queued = True
            self._queued += 1

        try:
            while True:
                now = self._clock()
                _require_aware(now, label="clock result")
                remaining = (request.deadline - now).total_seconds()
                if remaining <= 0:
                    await self._expire_queued(record)
                    raise AgentTimeoutError()

                async with self._lock:
                    try:
                        self._require_lifetime_capacity_locked(record)
                    except AgentLimitExceededError:
                        record.queued = False
                        self._queued -= 1
                        record.lifecycle.fail(now=self._clock())
                        self._signal_locked()
                        raise
                    if self._has_execution_capacity_locked(record):
                        record.queued = False
                        self._queued -= 1
                        self._admit_locked(record, now=self._clock())
                        return self._view(record)
                    changed = self._changed

                try:
                    await asyncio.wait_for(changed.wait(), timeout=remaining)
                except TimeoutError:
                    await self._expire_queued(record)
                    raise AgentTimeoutError() from None
        except asyncio.CancelledError:
            await self._fail_queued(record)
            raise

    async def start(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        async with self._lock:
            record = self._require_record_locked(delegation_id)
            record.lifecycle.start(now=self._resolve_now(now))
            return self._view(record)

    async def complete(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        async with self._lock:
            record = self._require_record_locked(delegation_id)
            record.lifecycle.complete(now=self._resolve_now(now))
            self._release_active_locked(record)
            return self._view(record)

    async def fail(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        async with self._lock:
            record = self._require_record_locked(delegation_id)
            record.lifecycle.fail(now=self._resolve_now(now))
            self._release_active_locked(record)
            return self._view(record)

    async def get(self, delegation_id: DelegationId) -> DelegatedChildRun:
        async with self._lock:
            return self._view(self._require_record_locked(delegation_id))

    async def snapshot(self) -> AgentDelegationCoordinatorSnapshot:
        async with self._lock:
            statuses = tuple(record.lifecycle.status for record in self._records.values())
            return AgentDelegationCoordinatorSnapshot(
                delegations=len(self._records),
                active=self._active,
                queued=self._queued,
                completed=sum(status is DelegationStatus.COMPLETED for status in statuses),
                failed=sum(status is DelegationStatus.FAILED for status in statuses),
                expired=sum(status is DelegationStatus.EXPIRED for status in statuses),
                max_concurrent_children=self._limits.max_concurrent_children,
                max_queue_depth=self._limits.max_queue_depth,
                max_total_children=self._limits.max_total_children,
            )

    def root_budget_snapshot(
        self,
        root_run_id: AgentRunId,
    ) -> DelegationRootBudgetSnapshot:
        return self._budget.snapshot(root_run_id)

    def _has_execution_capacity_locked(self, record: _CoordinatorRecord) -> bool:
        request = record.request
        capacity = min(
            self._limits.max_concurrent_children,
            request.limits.max_concurrent_children,
        )
        return self._active < capacity

    def _require_lifetime_capacity_locked(self, record: _CoordinatorRecord) -> None:
        request = record.request
        parent_count = self._parent_children.get(request.parent_run_id, 0)
        fan_out_limit = min(self._limits.max_fan_out, request.limits.max_fan_out)
        if parent_count >= fan_out_limit:
            raise AgentLimitExceededError()
        if not self._budget.can_reserve(request.lineage.root_run_id, request.budget):
            raise AgentLimitExceededError()

    def _admit_locked(self, record: _CoordinatorRecord, *, now: datetime) -> None:
        request = record.request
        _require_aware(now, label="now")
        if now >= request.deadline:
            record.lifecycle.expire(now=now)
            raise AgentTimeoutError()

        parent_count = self._parent_children.get(request.parent_run_id, 0)
        fan_out_limit = min(self._limits.max_fan_out, request.limits.max_fan_out)
        if parent_count >= fan_out_limit:
            record.lifecycle.fail(now=now)
            raise AgentLimitExceededError()

        if not self._budget.can_reserve(request.lineage.root_run_id, request.budget):
            record.lifecycle.fail(now=now)
            raise AgentLimitExceededError()

        self._budget.reserve(request.lineage.root_run_id, request.budget)
        self._parent_children[request.parent_run_id] = parent_count + 1
        self._active += 1
        record.active = True
        record.lifecycle.admit(now=now)
        self._signal_locked()

    async def _expire_queued(self, record: _CoordinatorRecord) -> None:
        async with self._lock:
            if record.queued:
                record.queued = False
                self._queued -= 1
                if not record.lifecycle.terminal:
                    record.lifecycle.expire(now=self._clock())
                self._signal_locked()

    async def _fail_queued(self, record: _CoordinatorRecord) -> None:
        async with self._lock:
            if record.queued:
                record.queued = False
                self._queued -= 1
                if not record.lifecycle.terminal:
                    record.lifecycle.fail(now=self._clock())
                self._signal_locked()

    def _release_active_locked(self, record: _CoordinatorRecord) -> None:
        if not record.active:
            raise AgentStateConflictError()
        if self._active <= 0:
            raise AgentStateConflictError()
        record.active = False
        self._active -= 1
        self._signal_locked()

    def _require_record_locked(self, delegation_id: DelegationId) -> _CoordinatorRecord:
        if not isinstance(delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        record = self._records.get(delegation_id)
        if record is None:
            raise DelegationNotFoundError()
        return record

    def _resolve_now(self, now: datetime | None) -> datetime:
        resolved = self._clock() if now is None else now
        _require_aware(resolved, label="now")
        return resolved

    @staticmethod
    def _view(record: _CoordinatorRecord) -> DelegatedChildRun:
        snapshot = record.lifecycle.snapshot()
        request = record.request
        return DelegatedChildRun(
            delegation_id=request.delegation_id,
            parent_agent_id=request.parent_agent_id,
            parent_run_id=request.parent_run_id,
            root_run_id=request.lineage.root_run_id,
            child_agent_id=request.child_agent_id,
            child_run_id=snapshot.child_run_id,
            depth=request.child_depth,
            status=snapshot.status,
            budget=request.budget,
            created_at=snapshot.created_at,
            updated_at=snapshot.updated_at,
            deadline=snapshot.deadline,
        )

    def _signal_locked(self) -> None:
        changed = self._changed
        self._changed = asyncio.Event()
        changed.set()
