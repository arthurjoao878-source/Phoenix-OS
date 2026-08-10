from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentRunId,
    CoordinationNamespace,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationRequest,
    DelegationStatus,
)

_NOW = datetime(2026, 8, 10, 17, tzinfo=UTC)


def _lineage() -> DelegationLineage:
    return DelegationLineage(
        (
            DelegationLineageEntry(
                agent_id=AgentId("root"),
                run_id=AgentRunId(),
            ),
        )
    )


def _request(**overrides: object) -> DelegationRequest:
    lineage = overrides.pop("lineage", _lineage())
    assert isinstance(lineage, DelegationLineage)
    values: dict[str, object] = {
        "parent_agent_id": lineage.parent_agent_id,
        "parent_run_id": lineage.parent_run_id,
        "child_agent_id": AgentId("researcher"),
        "namespace": CoordinationNamespace("default"),
        "lineage": lineage,
        "input": {"task": "summarize"},
        "created_at": _NOW,
        "deadline": _NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    return DelegationRequest(**values)  # type: ignore[arg-type]


def test_coordination_identifiers_are_strict_and_immutable() -> None:
    namespace = CoordinationNamespace(" Research.Team ")
    delegation_id = DelegationId()
    depth = DelegationDepth(2)

    assert str(namespace) == "research.team"
    assert str(delegation_id)
    assert int(depth) == 2
    with pytest.raises(FrozenInstanceError):
        namespace.value = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError):
        CoordinationNamespace("unsafe/namespace")
    with pytest.raises(ValueError):
        DelegationDepth(33)


def test_delegation_status_terminal_semantics_are_explicit() -> None:
    assert not DelegationStatus.REQUESTED.terminal
    assert not DelegationStatus.RUNNING.terminal
    assert DelegationStatus.COMPLETED.terminal
    assert DelegationStatus.FAILED.terminal
    assert DelegationStatus.CANCELLED.terminal
    assert DelegationStatus.EXPIRED.terminal


def test_limits_and_budgets_are_finite_and_monotonic() -> None:
    outer_limits = DelegationLimits()
    inner_limits = DelegationLimits(
        max_depth=2,
        max_fan_out=2,
        max_total_children=8,
        max_concurrent_children=2,
        max_queue_depth=16,
        max_input_bytes=65_536,
        max_result_bytes=262_144,
        max_result_depth=8,
        child_timeout=timedelta(minutes=5),
    )
    assert outer_limits.contains(inner_limits)
    assert not inner_limits.contains(outer_limits)

    outer_budget = DelegationBudget()
    inner_budget = DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=8_192,
        max_output_tokens=4_096,
        max_prompt_bytes=32_768,
        max_result_bytes=131_072,
        duration=timedelta(minutes=5),
    )
    assert outer_budget.contains(inner_budget)
    assert not inner_budget.contains(outer_budget)

    with pytest.raises(ValueError, match="fan_out"):
        DelegationLimits(max_fan_out=9, max_total_children=8)
    with pytest.raises(ValueError, match="tool_calls"):
        DelegationBudget(max_model_turns=2, max_tool_calls=3)


def test_lineage_is_bounded_server_owned_and_cycle_rejecting() -> None:
    root_run = AgentRunId()
    child_run = AgentRunId()
    first = DelegationId()
    lineage = DelegationLineage(
        (
            DelegationLineageEntry(AgentId("root"), root_run),
            DelegationLineageEntry(AgentId("planner"), child_run, first),
        )
    )

    assert lineage.depth == DelegationDepth(1)
    assert lineage.root_run_id == root_run
    assert lineage.parent_agent_id == AgentId("planner")
    assert lineage.parent_run_id == child_run
    assert lineage.contains_agent(AgentId("root"))

    with pytest.raises(ValueError, match="cycle"):
        DelegationLineage(
            (
                DelegationLineageEntry(AgentId("root"), root_run),
                DelegationLineageEntry(AgentId("root"), child_run, first),
            )
        )


def test_request_freezes_input_and_rejects_parent_or_child_lineage_mismatch() -> None:
    caller_owned: dict[str, object] = {"task": "summarize", "options": {"brief": True}}
    request = _request(input=caller_owned)
    caller_owned["task"] = "changed"

    assert request.input["task"] == "summarize"
    with pytest.raises(TypeError):
        request.input["task"] = "changed"  # type: ignore[index]

    with pytest.raises(ValueError, match="parent"):
        _request(parent_agent_id=AgentId("other"))
    with pytest.raises(ValueError, match="cycle"):
        _request(child_agent_id=AgentId("root"))


def test_request_enforces_depth_input_and_deadline_bounds() -> None:
    tiny = DelegationLimits(
        max_depth=1,
        max_fan_out=1,
        max_total_children=1,
        max_concurrent_children=1,
        max_queue_depth=1,
        max_input_bytes=16,
        max_result_bytes=64,
        max_result_depth=2,
        child_timeout=timedelta(seconds=5),
    )
    with pytest.raises(ValueError, match="byte"):
        _request(limits=tiny, input={"task": "this input is too long"})
    with pytest.raises(ValueError, match="timeout"):
        _request(
            limits=tiny,
            input={"x": "y"},
            deadline=_NOW + timedelta(seconds=6),
        )
