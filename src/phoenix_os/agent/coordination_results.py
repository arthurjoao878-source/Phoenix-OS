"""Bounded untrusted child results and deterministic aggregation for coordination."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from phoenix_os.agent.contracts import (
    MAX_AGENT_RESULT_BYTES,
    AgentId,
    AgentJsonInput,
    AgentJsonValue,
    AgentRunId,
    AgentRunResult,
    AgentRunStatus,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.coordination import DelegatedChildRun
from phoenix_os.agent.coordination_contracts import DelegationId, DelegationLimits

_ERROR_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class ChildResultStatus(StrEnum):
    """Safe bounded terminal status of one delegated child."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class DelegatedChildResult:
    """Bounded child output. Its content is data, never authorization or executable authority."""

    delegation_id: DelegationId
    child_agent_id: AgentId
    child_run_id: AgentRunId
    status: ChildResultStatus
    output: Mapping[str, AgentJsonInput] | None = None
    error_code: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        if not isinstance(self.child_agent_id, AgentId):
            raise TypeError("child_agent_id must be AgentId")
        if not isinstance(self.child_run_id, AgentRunId):
            raise TypeError("child_run_id must be AgentRunId")
        if not isinstance(self.status, ChildResultStatus):
            raise TypeError("status must be ChildResultStatus")
        _require_aware(self.started_at, label="started_at")
        _require_aware(self.completed_at, label="completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")

        if self.status is ChildResultStatus.SUCCEEDED:
            if self.output is None:
                raise ValueError("successful child results require output")
            if self.error_code is not None:
                raise ValueError("successful child results cannot contain error_code")
            frozen = freeze_agent_json_object(self.output)
            if len(canonical_agent_json_bytes(frozen)) > MAX_AGENT_RESULT_BYTES:
                raise ValueError("child result exceeds the global byte limit")
            object.__setattr__(self, "output", frozen)
        else:
            if self.output is not None:
                raise ValueError("unsuccessful child results cannot contain output")
            if self.error_code is None:
                raise ValueError("unsuccessful child results require error_code")
            normalized = self.error_code.strip().lower()
            if _ERROR_CODE_PATTERN.fullmatch(normalized) is None:
                raise ValueError("child error_code is invalid")
            object.__setattr__(self, "error_code", normalized)


@dataclass(frozen=True, slots=True)
class DelegatedChildAggregate:
    """Deterministically ordered bounded collection of child results."""

    results: Sequence[DelegatedChildResult]
    encoded_bytes: int

    def __post_init__(self) -> None:
        normalized = tuple(self.results)
        if any(not isinstance(result, DelegatedChildResult) for result in normalized):
            raise TypeError("aggregate results must be DelegatedChildResult values")
        if isinstance(self.encoded_bytes, bool) or not isinstance(self.encoded_bytes, int):
            raise TypeError("encoded_bytes must be an integer")
        if self.encoded_bytes < 0:
            raise ValueError("encoded_bytes must not be negative")
        object.__setattr__(self, "results", normalized)


def delegated_child_result_from_agent_result(
    child: DelegatedChildRun,
    result: AgentRunResult,
    *,
    limits: DelegationLimits,
    max_result_bytes: int,
) -> DelegatedChildResult:
    """Validate one untrusted child run result against exact delegation bounds."""

    if not isinstance(child, DelegatedChildRun):
        raise TypeError("child must be DelegatedChildRun")
    if not isinstance(result, AgentRunResult):
        raise TypeError("result must be AgentRunResult")
    if not isinstance(limits, DelegationLimits):
        raise TypeError("limits must be DelegationLimits")
    _require_positive_int(max_result_bytes, label="max_result_bytes")
    if result.run_id != child.child_run_id:
        raise ValueError("child run result identity mismatch")

    if result.status is AgentRunStatus.COMPLETED:
        if result.final_output is None:  # pragma: no cover - AgentRunResult invariant
            raise ValueError("completed child run is missing final output")
        output: Mapping[str, AgentJsonInput] = {"final_output": result.final_output}
        frozen = freeze_agent_json_object(output)
        encoded = canonical_agent_json_bytes(frozen)
        effective_bytes = min(limits.max_result_bytes, max_result_bytes)
        if len(encoded) > effective_bytes:
            raise ValueError("child result exceeds the delegated byte limit")
        if _structured_depth(frozen) > limits.max_result_depth:
            raise ValueError("child result exceeds the delegated depth limit")
        return DelegatedChildResult(
            delegation_id=child.delegation_id,
            child_agent_id=child.child_agent_id,
            child_run_id=child.child_run_id,
            status=ChildResultStatus.SUCCEEDED,
            output=output,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )

    error_code = result.error_code or "child_failed"
    if result.status is AgentRunStatus.CANCELLED:
        status = ChildResultStatus.CANCELLED
    elif error_code in {"timeout", "timed_out"}:
        status = ChildResultStatus.TIMED_OUT
    else:
        status = ChildResultStatus.FAILED
    return DelegatedChildResult(
        delegation_id=child.delegation_id,
        child_agent_id=child.child_agent_id,
        child_run_id=child.child_run_id,
        status=status,
        error_code=error_code,
        started_at=result.started_at,
        completed_at=result.completed_at,
    )


def aggregate_delegated_child_results(
    results: Sequence[DelegatedChildResult],
    *,
    max_results: int,
    max_encoded_bytes: int,
) -> DelegatedChildAggregate:
    """Sort by stable delegation identity and reject duplicate or oversized aggregates."""

    _require_positive_int(max_results, label="max_results")
    _require_positive_int(max_encoded_bytes, label="max_encoded_bytes")
    normalized = tuple(results)
    if len(normalized) > max_results:
        raise ValueError("child result aggregate exceeds the result-count limit")
    if any(not isinstance(result, DelegatedChildResult) for result in normalized):
        raise TypeError("results must contain DelegatedChildResult values")

    delegation_ids = tuple(result.delegation_id for result in normalized)
    child_run_ids = tuple(result.child_run_id for result in normalized)
    if len(delegation_ids) != len(set(delegation_ids)):
        raise ValueError("child result aggregate contains duplicate delegation ids")
    if len(child_run_ids) != len(set(child_run_ids)):
        raise ValueError("child result aggregate contains duplicate child run ids")

    ordered = tuple(sorted(normalized, key=lambda result: str(result.delegation_id)))
    encoded = _canonical_aggregate_bytes(ordered)
    if len(encoded) > max_encoded_bytes:
        raise ValueError("child result aggregate exceeds the encoded byte limit")
    return DelegatedChildAggregate(results=ordered, encoded_bytes=len(encoded))


def _canonical_aggregate_bytes(results: Sequence[DelegatedChildResult]) -> bytes:
    document = []
    for result in results:
        document.append(
            {
                "delegation_id": str(result.delegation_id),
                "child_agent_id": str(result.child_agent_id),
                "child_run_id": str(result.child_run_id),
                "status": result.status.value,
                "output": None
                if result.output is None
                else _json_builtin(freeze_agent_json_object(result.output)),
                "error_code": result.error_code,
            }
        )
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _json_builtin(value: Mapping[str, AgentJsonValue]) -> dict[str, object]:
    return {key: _json_value_builtin(item) for key, item in value.items()}


def _json_value_builtin(value: AgentJsonValue) -> object:
    if isinstance(value, Mapping):
        return {key: _json_value_builtin(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_value_builtin(item) for item in value]
    return value


def _structured_depth(value: AgentJsonValue | Mapping[str, AgentJsonValue]) -> int:
    if isinstance(value, Mapping):
        if not value:
            return 1
        return 1 + max(_structured_depth(item) for item in value.values())
    if isinstance(value, tuple):
        if not value:
            return 1
        return 1 + max(_structured_depth(item) for item in value)
    return 0


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_positive_int(value: int, *, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
