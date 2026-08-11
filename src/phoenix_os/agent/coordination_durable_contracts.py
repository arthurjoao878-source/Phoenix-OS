"""Content-free durable contracts for secure agent delegation recovery."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.coordination_authorization import canonical_delegation_input_digest
from phoenix_os.agent.coordination_contracts import (
    CoordinationNamespace,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationRequest,
    DelegationStatus,
)

MAX_DURABLE_DELEGATION_RECOVERY_PAGE = 1_024
MAX_DURABLE_DELEGATION_VERSION = 2_147_483_647

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class DurableDelegationRecoveryState(StrEnum):
    """Recovery classification independent from the live delegation lifecycle."""

    CLEAN = "clean"
    RECOVERABLE = "recoverable"
    INDETERMINATE = "indeterminate"


class DurableDelegationReconciliationDecision(StrEnum):
    """Evidence-backed resolution for one indeterminate child."""

    CONFIRM_NOT_STARTED = "confirm_not_started"
    CONFIRM_COMPLETED = "confirm_completed"
    CONFIRM_FAILED = "confirm_failed"
    CONFIRM_CANCELLED = "confirm_cancelled"
    REMAIN_INDETERMINATE = "remain_indeterminate"


@dataclass(frozen=True, slots=True, order=True)
class DurableDelegationVersion:
    value: int = 1

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("durable delegation version must be an integer")
        if self.value <= 0 or self.value > MAX_DURABLE_DELEGATION_VERSION:
            raise ValueError("durable delegation version is out of bounds")

    def next(self) -> DurableDelegationVersion:
        return DurableDelegationVersion(self.value + 1)


@dataclass(frozen=True, slots=True)
class DurableDelegationRecord:
    """Content-free persisted binding from a delegation to exactly one child run."""

    delegation_id: DelegationId
    namespace: CoordinationNamespace
    parent_agent_id: AgentId
    parent_run_id: AgentRunId
    root_run_id: AgentRunId
    child_agent_id: AgentId
    child_run_id: AgentRunId
    depth: DelegationDepth
    budget: DelegationBudget
    status: DelegationStatus
    request_digest: str
    compatibility_digest: str
    version: DurableDelegationVersion
    recovery_state: DurableDelegationRecoveryState
    created_at: datetime
    updated_at: datetime
    deadline: datetime
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        if not isinstance(self.namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
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
        if not isinstance(self.budget, DelegationBudget):
            raise TypeError("budget must be DelegationBudget")
        if not isinstance(self.status, DelegationStatus):
            raise TypeError("status must be DelegationStatus")
        if not isinstance(self.version, DurableDelegationVersion):
            raise TypeError("version must be DurableDelegationVersion")
        if not isinstance(self.recovery_state, DurableDelegationRecoveryState):
            raise TypeError("recovery_state must be DurableDelegationRecoveryState")
        _require_digest(self.request_digest, label="request_digest")
        _require_digest(self.compatibility_digest, label="compatibility_digest")
        _require_aware(self.created_at, label="created_at")
        _require_aware(self.updated_at, label="updated_at")
        _require_aware(self.deadline, label="deadline")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.deadline <= self.created_at:
            raise ValueError("deadline must follow created_at")
        if self.status.terminal and self.recovery_state is not DurableDelegationRecoveryState.CLEAN:
            raise ValueError("terminal delegation records must have clean recovery state")
        if (
            self.recovery_state is DurableDelegationRecoveryState.INDETERMINATE
            and self.status is not DelegationStatus.RUNNING
        ):
            raise ValueError("only running delegation records may be indeterminate")
        if self.error_code is not None:
            normalized = self.error_code.strip().lower()
            if _SAFE_CODE_PATTERN.fullmatch(normalized) is None:
                raise ValueError("error_code must be a safe bounded identifier")
            object.__setattr__(self, "error_code", normalized)

    @property
    def terminal(self) -> bool:
        return self.status.terminal


@dataclass(frozen=True, slots=True)
class DurableDelegationReconciliationEvidence:
    evidence_type: str
    evidence_digest: str
    observed_at: datetime

    def __post_init__(self) -> None:
        normalized = self.evidence_type.strip().lower()
        if _SAFE_CODE_PATTERN.fullmatch(normalized) is None:
            raise ValueError("evidence_type must be a safe bounded identifier")
        object.__setattr__(self, "evidence_type", normalized)
        _require_digest(self.evidence_digest, label="evidence_digest")
        _require_aware(self.observed_at, label="observed_at")


@dataclass(frozen=True, slots=True)
class DurableDelegationReconciliationRequest:
    delegation_id: DelegationId
    expected_version: DurableDelegationVersion
    decision: DurableDelegationReconciliationDecision
    evidence: DurableDelegationReconciliationEvidence | None = None
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        if not isinstance(self.expected_version, DurableDelegationVersion):
            raise TypeError("expected_version must be DurableDelegationVersion")
        if not isinstance(self.decision, DurableDelegationReconciliationDecision):
            raise TypeError("decision must be DurableDelegationReconciliationDecision")
        if self.evidence is not None and not isinstance(
            self.evidence,
            DurableDelegationReconciliationEvidence,
        ):
            raise TypeError("evidence must be DurableDelegationReconciliationEvidence or None")
        if (
            self.decision is not DurableDelegationReconciliationDecision.REMAIN_INDETERMINATE
            and self.evidence is None
        ):
            raise ValueError("the selected reconciliation decision requires evidence")
        _require_aware(self.requested_at, label="requested_at")


@runtime_checkable
class DurableDelegationStore(Protocol):
    """Atomic content-free persistence boundary for delegation identity and state."""

    @property
    def closed(self) -> bool: ...

    async def create(
        self,
        record: DurableDelegationRecord,
        *,
        limits: DelegationLimits,
        root_budget_limit: DelegationBudget,
    ) -> None: ...

    async def get(
        self,
        delegation_id: DelegationId,
    ) -> DurableDelegationRecord | None: ...

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DelegationId | None = None,
    ) -> tuple[DelegationId, ...]: ...

    async def list_root_records(
        self,
        root_run_id: AgentRunId,
        *,
        limit: int = MAX_DURABLE_DELEGATION_RECOVERY_PAGE,
    ) -> tuple[DurableDelegationRecord, ...]: ...

    async def compare_and_swap(
        self,
        record: DurableDelegationRecord,
        *,
        expected_version: DurableDelegationVersion,
    ) -> DurableDelegationRecord: ...

    async def close(self) -> None: ...


def durable_delegation_request_digest(request: DelegationRequest) -> str:
    """Hash all replay-relevant request identity without persisting child input."""

    if not isinstance(request, DelegationRequest):
        raise TypeError("request must be DelegationRequest")
    document = {
        "delegation_id": str(request.delegation_id),
        "namespace": str(request.namespace),
        "parent_agent_id": str(request.parent_agent_id),
        "parent_run_id": str(request.parent_run_id),
        "root_run_id": str(request.lineage.root_run_id),
        "child_agent_id": str(request.child_agent_id),
        "depth": request.child_depth.value,
        "deadline": request.deadline.isoformat(),
        "input_digest": canonical_delegation_input_digest(request),
        "lineage": [
            {
                "agent_id": str(entry.agent_id),
                "run_id": str(entry.run_id),
                "via_delegation_id": (
                    None if entry.via_delegation_id is None else str(entry.via_delegation_id)
                ),
            }
            for entry in request.lineage.entries
        ],
        "budget": {
            "max_model_turns": request.budget.max_model_turns,
            "max_tool_calls": request.budget.max_tool_calls,
            "max_input_tokens": request.budget.max_input_tokens,
            "max_output_tokens": request.budget.max_output_tokens,
            "max_prompt_bytes": request.budget.max_prompt_bytes,
            "max_result_bytes": request.budget.max_result_bytes,
            "duration_us": _timedelta_microseconds(request.budget.duration),
        },
        "limits": {
            "max_depth": request.limits.max_depth,
            "max_fan_out": request.limits.max_fan_out,
            "max_total_children": request.limits.max_total_children,
            "max_concurrent_children": request.limits.max_concurrent_children,
            "max_queue_depth": request.limits.max_queue_depth,
            "max_input_bytes": request.limits.max_input_bytes,
            "max_result_bytes": request.limits.max_result_bytes,
            "max_result_depth": request.limits.max_result_depth,
            "child_timeout_us": _timedelta_microseconds(request.limits.child_timeout),
        },
    }
    payload = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _timedelta_microseconds(value: timedelta) -> int:
    return ((value.days * 86_400 + value.seconds) * 1_000_000) + value.microseconds


def _require_digest(value: str, *, label: str) -> None:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical sha256 digest")


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def require_recovery_page_limit(limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if limit <= 0 or limit > MAX_DURABLE_DELEGATION_RECOVERY_PAGE:
        raise ValueError("limit is outside the durable delegation recovery bounds")
