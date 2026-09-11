from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentLimits, AgentRunId, AgentRunStatus
from phoenix_os.agent.errors import AgentLimitExceededError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentRunBudget, AgentRunStateMachine

_START = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)
_DEADLINE = _START + timedelta(minutes=10)
_RUN_ID = AgentRunId(UUID("71000000-0000-4000-8000-000000000001"))


def _snapshot(
    *,
    steps: int = 4,
    model_turns: int = 2,
    tool_calls: int = 2,
) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=steps,
        model_turns=model_turns,
        tool_calls=tool_calls,
        model_output_bytes=17,
        tool_result_bytes=19,
        input_tokens=23,
        output_tokens=29,
        started_at=_START,
        deadline=_DEADLINE,
    )


def test_agent_run_budget_restore_preserves_exact_snapshot_and_continues() -> None:
    limits = AgentLimits()
    snapshot = _snapshot()

    budget = AgentRunBudget.restore(limits, snapshot)

    assert budget.snapshot() == snapshot
    budget.begin_model_turn(now=_START + timedelta(minutes=5))
    continued = budget.snapshot()
    assert continued.steps == snapshot.steps + 1
    assert continued.model_turns == snapshot.model_turns + 1
    assert continued.tool_calls == snapshot.tool_calls
    assert continued.model_output_bytes == snapshot.model_output_bytes
    assert continued.tool_result_bytes == snapshot.tool_result_bytes
    assert continued.input_tokens == snapshot.input_tokens
    assert continued.output_tokens == snapshot.output_tokens


def test_agent_run_budget_restore_rejects_impossible_or_exhausted_usage() -> None:
    with pytest.raises(AgentStateConflictError):
        AgentRunBudget.restore(
            AgentLimits(),
            _snapshot(steps=5),
        )

    limits = AgentLimits(
        max_steps=3,
        max_model_turns=2,
        max_tool_calls=2,
    )
    with pytest.raises(AgentLimitExceededError):
        AgentRunBudget.restore(limits, _snapshot())


def test_model_turn_boundary_restore_preserves_identity_budget_and_position() -> None:
    snapshot = _snapshot()
    restored_at = _START + timedelta(minutes=5)

    machine = AgentRunStateMachine.restore_model_turn_boundary(
        _RUN_ID,
        AgentLimits(),
        budget=snapshot,
        restored_at=restored_at,
    )

    assert machine.status is AgentRunStatus.VALIDATING_RESULT
    assert machine.budget.snapshot() == snapshot
    assert machine.snapshot().run_id == _RUN_ID
    assert machine.snapshot().created_at == snapshot.started_at
    assert machine.snapshot().updated_at == restored_at

    machine.start_inference(now=restored_at)
    assert machine.snapshot().status is AgentRunStatus.INFERENCING
    assert machine.budget.model_turns == snapshot.model_turns + 1


def test_initial_model_turn_boundary_restores_created_without_consuming_budget() -> None:
    snapshot = AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=_START,
        deadline=_DEADLINE,
    )

    machine = AgentRunStateMachine.restore_model_turn_boundary(
        _RUN_ID,
        AgentLimits(),
        budget=snapshot,
        restored_at=_START + timedelta(seconds=1),
    )

    assert machine.status is AgentRunStatus.CREATED
    assert machine.budget.snapshot() == snapshot


def test_model_turn_boundary_restore_rejects_non_boundary_budget_shape() -> None:
    snapshot = _snapshot(
        steps=3,
        model_turns=2,
        tool_calls=1,
    )

    with pytest.raises(AgentStateConflictError):
        AgentRunStateMachine.restore_model_turn_boundary(
            _RUN_ID,
            AgentLimits(),
            budget=snapshot,
            restored_at=_START + timedelta(minutes=5),
        )


def test_normal_state_machine_constructor_still_starts_with_zero_usage() -> None:
    machine = AgentRunStateMachine(
        _RUN_ID,
        AgentLimits(),
        created_at=_START,
        deadline=_DEADLINE,
    )

    snapshot = machine.budget.snapshot()
    assert machine.status is AgentRunStatus.CREATED
    assert snapshot.steps == 0
    assert snapshot.model_turns == 0
    assert snapshot.tool_calls == 0
