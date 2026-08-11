from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentRunId,
    AgentRunResult,
    AgentRunStatus,
    ChildResultStatus,
    DelegatedChildResult,
    DelegatedChildRun,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationStatus,
    aggregate_delegated_child_results,
    delegated_child_result_from_agent_result,
)

_NOW = datetime(2026, 8, 10, 18, 30, tzinfo=UTC)


def _limits(*, result_bytes: int = 1024, result_depth: int = 4) -> DelegationLimits:
    return DelegationLimits(
        max_depth=2,
        max_fan_out=2,
        max_total_children=4,
        max_concurrent_children=2,
        max_queue_depth=4,
        max_input_bytes=4096,
        max_result_bytes=result_bytes,
        max_result_depth=result_depth,
        child_timeout=timedelta(minutes=5),
    )


def _child(*, delegation_id: DelegationId | None = None) -> DelegatedChildRun:
    return DelegatedChildRun(
        delegation_id=delegation_id or DelegationId(),
        parent_agent_id=AgentId("parent"),
        parent_run_id=AgentRunId(),
        root_run_id=AgentRunId(),
        child_agent_id=AgentId("child"),
        child_run_id=AgentRunId(),
        depth=DelegationDepth(1),
        status=DelegationStatus.RUNNING,
        budget=DelegationBudget(
            max_model_turns=2,
            max_tool_calls=1,
            max_input_tokens=4096,
            max_output_tokens=2048,
            max_prompt_bytes=4096,
            max_result_bytes=1024,
            duration=timedelta(minutes=2),
        ),
        created_at=_NOW,
        updated_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


def test_successful_agent_result_becomes_bounded_untrusted_child_result() -> None:
    child = _child()
    result = AgentRunResult(
        run_id=child.child_run_id,
        status=AgentRunStatus.COMPLETED,
        model_turns=1,
        tool_calls=0,
        final_output="bounded answer",
        started_at=_NOW,
        completed_at=_NOW,
    )

    delegated = delegated_child_result_from_agent_result(
        child,
        result,
        limits=_limits(),
        max_result_bytes=1024,
    )

    assert delegated.status is ChildResultStatus.SUCCEEDED
    assert delegated.output == {"final_output": "bounded answer"}
    assert delegated.error_code is None


def test_child_result_identity_and_byte_limits_fail_closed() -> None:
    child = _child()
    wrong = AgentRunResult(
        run_id=AgentRunId(),
        status=AgentRunStatus.COMPLETED,
        model_turns=1,
        tool_calls=0,
        final_output="answer",
        started_at=_NOW,
        completed_at=_NOW,
    )
    with pytest.raises(ValueError, match="identity"):
        delegated_child_result_from_agent_result(
            child,
            wrong,
            limits=_limits(),
            max_result_bytes=1024,
        )

    oversized = AgentRunResult(
        run_id=child.child_run_id,
        status=AgentRunStatus.COMPLETED,
        model_turns=1,
        tool_calls=0,
        final_output="x" * 128,
        started_at=_NOW,
        completed_at=_NOW,
    )
    with pytest.raises(ValueError, match="byte"):
        delegated_child_result_from_agent_result(
            child,
            oversized,
            limits=_limits(result_bytes=32),
            max_result_bytes=32,
        )


def test_failed_and_cancelled_results_never_carry_output() -> None:
    child = _child()

    failed = delegated_child_result_from_agent_result(
        child,
        AgentRunResult(
            run_id=child.child_run_id,
            status=AgentRunStatus.FAILED,
            model_turns=1,
            tool_calls=0,
            error_code="child_failed",
            started_at=_NOW,
            completed_at=_NOW,
        ),
        limits=_limits(),
        max_result_bytes=1024,
    )
    cancelled = delegated_child_result_from_agent_result(
        child,
        AgentRunResult(
            run_id=child.child_run_id,
            status=AgentRunStatus.CANCELLED,
            model_turns=0,
            tool_calls=0,
            error_code="cancelled",
            started_at=_NOW,
            completed_at=_NOW,
        ),
        limits=_limits(),
        max_result_bytes=1024,
    )

    assert failed.status is ChildResultStatus.FAILED
    assert failed.output is None
    assert cancelled.status is ChildResultStatus.CANCELLED
    assert cancelled.output is None


def test_aggregate_is_sorted_by_stable_delegation_id_and_duplicate_rejecting() -> None:
    first_id = DelegationId()
    second_id = DelegationId()
    first, second = sorted((first_id, second_id), key=str)

    def result(identity: DelegationId, run_id: AgentRunId) -> DelegatedChildResult:
        return DelegatedChildResult(
            delegation_id=identity,
            child_agent_id=AgentId("child"),
            child_run_id=run_id,
            status=ChildResultStatus.SUCCEEDED,
            output={"final_output": str(identity)},
            started_at=_NOW,
            completed_at=_NOW,
        )

    first_result = result(first, AgentRunId())
    second_result = result(second, AgentRunId())
    aggregate = aggregate_delegated_child_results(
        (second_result, first_result),
        max_results=4,
        max_encoded_bytes=4096,
    )

    assert aggregate.results == (first_result, second_result)
    assert aggregate.encoded_bytes > 0

    with pytest.raises(ValueError, match="duplicate delegation"):
        aggregate_delegated_child_results(
            (first_result, first_result),
            max_results=4,
            max_encoded_bytes=4096,
        )
