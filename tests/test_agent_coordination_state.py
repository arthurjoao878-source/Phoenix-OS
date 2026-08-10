from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentLimitExceededError,
    AgentRunId,
    AgentStateConflictError,
    DelegationBudget,
    DelegationBudgetLedger,
    DelegationId,
    DelegationStateMachine,
    DelegationStatus,
)

_NOW = datetime(2026, 8, 10, 18, tzinfo=UTC)


def test_delegation_state_machine_allows_only_reviewed_lifecycle() -> None:
    machine = DelegationStateMachine(
        DelegationId(),
        AgentRunId(),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )

    assert machine.snapshot().status is DelegationStatus.REQUESTED
    machine.authorize(now=_NOW)
    assert machine.snapshot().status is DelegationStatus.AUTHORIZED
    machine.admit(now=_NOW)
    assert machine.snapshot().status is DelegationStatus.ADMITTED
    machine.start(now=_NOW)
    assert machine.snapshot().status is DelegationStatus.RUNNING
    machine.complete(now=_NOW)
    assert machine.snapshot().status is DelegationStatus.COMPLETED
    assert machine.terminal

    with pytest.raises(AgentStateConflictError):
        machine.fail(now=_NOW)


def test_invalid_transition_and_non_monotonic_time_fail_closed() -> None:
    machine = DelegationStateMachine(
        DelegationId(),
        AgentRunId(),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )

    with pytest.raises(AgentStateConflictError):
        machine.start(now=_NOW)

    machine.authorize(now=_NOW + timedelta(seconds=2))
    with pytest.raises(AgentStateConflictError):
        machine.admit(now=_NOW + timedelta(seconds=1))


def test_root_budget_ledger_prevents_budget_multiplication() -> None:
    limit = DelegationBudget(
        max_model_turns=6,
        max_tool_calls=4,
        max_input_tokens=24_000,
        max_output_tokens=12_000,
        max_prompt_bytes=96_000,
        max_result_bytes=384_000,
        duration=timedelta(minutes=12),
    )
    child = DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=8_000,
        max_output_tokens=4_000,
        max_prompt_bytes=32_000,
        max_result_bytes=128_000,
        duration=timedelta(minutes=4),
    )
    root = AgentRunId()
    ledger = DelegationBudgetLedger(limit, max_children=3)

    ledger.reserve(root, child)
    ledger.reserve(root, child)
    ledger.reserve(root, child)

    snapshot = ledger.snapshot(root)
    assert snapshot.children == 3
    assert snapshot.model_turns == 6
    assert snapshot.tool_calls == 3
    assert snapshot.duration == timedelta(minutes=12)

    with pytest.raises(AgentLimitExceededError):
        ledger.reserve(root, child)


def test_root_budget_isolated_per_root_run() -> None:
    limit = DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=8_000,
        max_output_tokens=4_000,
        max_prompt_bytes=32_000,
        max_result_bytes=128_000,
        duration=timedelta(minutes=4),
    )
    ledger = DelegationBudgetLedger(limit, max_children=1)
    first = AgentRunId()
    second = AgentRunId()

    ledger.reserve(first, limit)
    ledger.reserve(second, limit)

    assert ledger.snapshot(first).children == 1
    assert ledger.snapshot(second).children == 1
