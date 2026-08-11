"""Deterministic in-memory durable delegation store."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.coordination_contracts import (
    DelegationBudget,
    DelegationId,
    DelegationLimits,
)
from phoenix_os.agent.coordination_durable_contracts import (
    DurableDelegationRecord,
    DurableDelegationStore,
    DurableDelegationVersion,
    require_recovery_page_limit,
)
from phoenix_os.agent.errors import AgentStateConflictError


class InMemoryDurableDelegationStore(DurableDelegationStore):
    """Atomic content-free delegation records with optimistic versioning."""

    def __init__(self) -> None:
        self._records: dict[DelegationId, DurableDelegationRecord] = {}
        self._child_runs: set[AgentRunId] = set()
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def record_count(self) -> int:
        return len(self._records)

    async def create(
        self,
        record: DurableDelegationRecord,
        *,
        limits: DelegationLimits,
        root_budget_limit: DelegationBudget,
    ) -> None:
        if not isinstance(record, DurableDelegationRecord):
            raise TypeError("record must be DurableDelegationRecord")
        if not isinstance(limits, DelegationLimits):
            raise TypeError("limits must be DelegationLimits")
        if not isinstance(root_budget_limit, DelegationBudget):
            raise TypeError("root_budget_limit must be DelegationBudget")
        if record.version.value != 1:
            raise AgentStateConflictError()

        async with self._lock:
            self._ensure_open()
            if record.delegation_id in self._records:
                raise AgentStateConflictError()
            if record.child_run_id in self._child_runs:
                raise AgentStateConflictError()
            root_records = tuple(
                item for item in self._records.values() if item.root_run_id == record.root_run_id
            )
            _require_durable_capacity(
                root_records,
                record,
                limits=limits,
                root_budget_limit=root_budget_limit,
            )
            self._records[record.delegation_id] = record
            self._child_runs.add(record.child_run_id)

    async def get(
        self,
        delegation_id: DelegationId,
    ) -> DurableDelegationRecord | None:
        if not isinstance(delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        async with self._lock:
            self._ensure_open()
            return self._records.get(delegation_id)

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DelegationId | None = None,
    ) -> tuple[DelegationId, ...]:
        require_recovery_page_limit(limit)
        if after is not None and not isinstance(after, DelegationId):
            raise TypeError("after must be DelegationId or None")

        async with self._lock:
            self._ensure_open()
            candidates: list[DelegationId] = []
            for delegation_id in sorted(self._records):
                if after is not None and delegation_id <= after:
                    continue
                if self._records[delegation_id].terminal:
                    continue
                candidates.append(delegation_id)
                if len(candidates) == limit:
                    break
            return tuple(candidates)

    async def list_root_records(
        self,
        root_run_id: AgentRunId,
        *,
        limit: int = 1_024,
    ) -> tuple[DurableDelegationRecord, ...]:
        if not isinstance(root_run_id, AgentRunId):
            raise TypeError("root_run_id must be AgentRunId")
        require_recovery_page_limit(limit)
        async with self._lock:
            self._ensure_open()
            records = sorted(
                (record for record in self._records.values() if record.root_run_id == root_run_id),
                key=lambda record: record.delegation_id,
            )
            return tuple(records[:limit])

    async def compare_and_swap(
        self,
        record: DurableDelegationRecord,
        *,
        expected_version: DurableDelegationVersion,
    ) -> DurableDelegationRecord:
        if not isinstance(record, DurableDelegationRecord):
            raise TypeError("record must be DurableDelegationRecord")
        if not isinstance(expected_version, DurableDelegationVersion):
            raise TypeError("expected_version must be DurableDelegationVersion")
        if record.version != expected_version.next():
            raise AgentStateConflictError()

        async with self._lock:
            self._ensure_open()
            current = self._records.get(record.delegation_id)
            if current is None or current.version != expected_version:
                raise AgentStateConflictError()
            _require_same_identity(current, record)
            self._records[record.delegation_id] = record
            return record

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("durable delegation store is closed")


def _require_same_identity(
    current: DurableDelegationRecord,
    candidate: DurableDelegationRecord,
) -> None:
    immutable = (
        "delegation_id",
        "namespace",
        "parent_agent_id",
        "parent_run_id",
        "root_run_id",
        "child_agent_id",
        "child_run_id",
        "depth",
        "budget",
        "request_digest",
        "compatibility_digest",
        "created_at",
        "deadline",
    )
    for field_name in immutable:
        if getattr(current, field_name) != getattr(candidate, field_name):
            raise AgentStateConflictError()
    if candidate.updated_at < current.updated_at:
        raise AgentStateConflictError()


def _require_durable_capacity(
    existing: tuple[DurableDelegationRecord, ...],
    candidate: DurableDelegationRecord,
    *,
    limits: DelegationLimits,
    root_budget_limit: DelegationBudget,
) -> None:
    if len(existing) + 1 > limits.max_total_children:
        raise AgentStateConflictError()
    parent_children = sum(record.parent_run_id == candidate.parent_run_id for record in existing)
    if parent_children + 1 > limits.max_fan_out:
        raise AgentStateConflictError()

    budgets = (*existing, candidate)
    if sum(item.budget.max_model_turns for item in budgets) > root_budget_limit.max_model_turns:
        raise AgentStateConflictError()
    if sum(item.budget.max_tool_calls for item in budgets) > root_budget_limit.max_tool_calls:
        raise AgentStateConflictError()
    if sum(item.budget.max_input_tokens for item in budgets) > root_budget_limit.max_input_tokens:
        raise AgentStateConflictError()
    if sum(item.budget.max_output_tokens for item in budgets) > root_budget_limit.max_output_tokens:
        raise AgentStateConflictError()
    if sum(item.budget.max_prompt_bytes for item in budgets) > root_budget_limit.max_prompt_bytes:
        raise AgentStateConflictError()
    if sum(item.budget.max_result_bytes for item in budgets) > root_budget_limit.max_result_bytes:
        raise AgentStateConflictError()
    if (
        sum((item.budget.duration for item in budgets), start=timedelta())
        > root_budget_limit.duration
    ):
        raise AgentStateConflictError()
