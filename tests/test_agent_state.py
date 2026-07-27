from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentBudgetSnapshot,
    AgentCancellationToken,
    AgentCancelledError,
    AgentLimitExceededError,
    AgentLimits,
    AgentRunId,
    AgentRunStateMachine,
    AgentRunStatus,
    AgentStateConflictError,
    AgentTimeoutError,
)

_START = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _machine(*, limits: AgentLimits | None = None) -> AgentRunStateMachine:
    configured = limits or AgentLimits()
    return AgentRunStateMachine(
        AgentRunId(),
        configured,
        created_at=_START,
        deadline=_START + configured.total_duration,
    )


def test_state_machine_allows_reviewed_serial_tool_cycle() -> None:
    machine = _machine()

    machine.start_inference(now=_START)
    machine.start_proposal_validation(now=_START + timedelta(seconds=1))
    machine.start_tool_authorization(now=_START + timedelta(seconds=2))
    machine.start_tool_invocation(now=_START + timedelta(seconds=3))
    machine.start_result_validation(now=_START + timedelta(seconds=4))
    machine.start_inference(now=_START + timedelta(seconds=5))
    machine.complete(now=_START + timedelta(seconds=6))

    snapshot = machine.snapshot()
    assert snapshot.status is AgentRunStatus.COMPLETED
    assert snapshot.model_turns == 2
    assert snapshot.tool_calls == 1
    assert machine.terminal is True


def test_state_machine_allows_explicit_approval_path() -> None:
    machine = _machine()

    machine.start_inference(now=_START)
    machine.start_proposal_validation(now=_START)
    machine.start_tool_authorization(now=_START)
    machine.start_approval(now=_START)
    machine.start_tool_invocation(now=_START)

    assert machine.status is AgentRunStatus.INVOKING_TOOL
    assert machine.snapshot().tool_calls == 1


def test_state_machine_rejects_invalid_and_post_terminal_work() -> None:
    machine = _machine()

    with pytest.raises(AgentStateConflictError):
        machine.start_tool_authorization(now=_START)

    machine.start_inference(now=_START)
    machine.complete(now=_START)
    with pytest.raises(AgentStateConflictError):
        machine.complete(now=_START)
    with pytest.raises(AgentStateConflictError):
        machine.start_inference(now=_START)


def test_state_machine_rejects_time_regression_without_mutation() -> None:
    machine = _machine()
    machine.start_inference(now=_START + timedelta(seconds=2))

    with pytest.raises(AgentStateConflictError):
        machine.start_proposal_validation(now=_START + timedelta(seconds=1))

    assert machine.status is AgentRunStatus.INFERENCING


def test_budget_enforces_step_model_and_tool_limits_before_work() -> None:
    limits = AgentLimits(
        max_steps=2,
        max_model_turns=1,
        max_tool_calls=1,
    )
    machine = _machine(limits=limits)

    machine.start_inference(now=_START)
    machine.start_proposal_validation(now=_START)
    machine.start_tool_authorization(now=_START)
    machine.start_tool_invocation(now=_START)
    machine.start_result_validation(now=_START)

    with pytest.raises(AgentLimitExceededError):
        machine.start_inference(now=_START)

    assert machine.status is AgentRunStatus.VALIDATING_RESULT
    assert machine.budget.steps == 2


def test_budget_accounts_bytes_and_tokens_without_content() -> None:
    limits = AgentLimits(
        max_model_output_bytes=10,
        max_tool_result_bytes=10,
        max_input_tokens=10,
        max_output_tokens=10,
    )
    budget = _machine(limits=limits).budget

    budget.record_model_usage(6, input_tokens=4, output_tokens=5)
    budget.record_tool_result(7)
    budget.require_argument_bytes(limits.max_argument_bytes)
    budget.require_result_bytes(limits.max_result_bytes)

    snapshot = budget.snapshot()
    assert snapshot == AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=6,
        tool_result_bytes=7,
        input_tokens=4,
        output_tokens=5,
        started_at=_START,
        deadline=_START + limits.total_duration,
    )
    with pytest.raises(AgentLimitExceededError):
        budget.record_model_usage(5)
    with pytest.raises(AgentLimitExceededError):
        budget.record_tool_result(4)
    with pytest.raises(AgentLimitExceededError):
        budget.record_model_usage(0, input_tokens=7)


def test_budget_uses_most_restrictive_operation_and_total_deadline() -> None:
    limits = AgentLimits(
        model_turn_timeout=timedelta(seconds=20),
        tool_call_timeout=timedelta(seconds=20),
        approval_wait_timeout=timedelta(seconds=10),
        total_duration=timedelta(seconds=25),
        cancellation_grace=timedelta(seconds=1),
        shutdown_grace=timedelta(seconds=1),
    )
    budget = _machine(limits=limits).budget
    now = _START + timedelta(seconds=20)

    assert budget.model_timeout_seconds(now=now) == 5
    assert budget.tool_timeout_seconds(now=now) == 5
    assert budget.approval_timeout_seconds(now=now) == 5
    with pytest.raises(AgentTimeoutError):
        budget.model_timeout_seconds(now=_START + timedelta(seconds=25))


def test_budget_rejects_tool_call_without_prior_model_proposal() -> None:
    budget = _machine().budget

    with pytest.raises(AgentStateConflictError):
        budget.begin_tool_call(now=_START)

    assert budget.snapshot().tool_calls == 0


@pytest.mark.asyncio
async def test_cancellation_token_is_idempotent_and_cooperative() -> None:
    token = AgentCancellationToken()
    assert token.cancelled is False

    token.cancel()
    token.cancel()
    await token.wait()

    assert token.cancelled is True
    with pytest.raises(AgentCancelledError):
        token.raise_if_cancelled()
