from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentAuthorizationRejectedError,
    AgentServiceUnavailableError,
    ToolExecutionError,
)
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedAgentBudgetExhaustedError,
    IntegratedAgentCancelledError,
    IntegratedAgentDeadlineExceededError,
    IntegratedAgentIndeterminateEffectError,
    IntegratedBudgetExtension,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedEffectDisposition,
    IntegratedEffectLedger,
    IntegratedFailureClass,
    IntegratedLocalTransformBinding,
    IntegratedRunBudget,
    classify_integrated_failure,
    integrated_effect_disposition,
)

_NOW = datetime(2026, 8, 27, 20, 0, tzinfo=UTC)


def _descriptor(
    tool_id: str,
    *,
    effect: ToolEffect,
) -> ToolDescriptor:
    empty_object = ToolSchema(kind=ToolSchemaType.OBJECT)
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=tool_id,
        description="test tool",
        input_schema=ToolInputSchema(empty_object),
        output_schema=ToolOutputSchema(empty_object),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=1024,
        max_output_bytes=1024,
        timeout=timedelta(seconds=10),
        resolver_id=f"resolver.{tool_id}",
        adapter_id=f"adapter.{tool_id}",
    )


def _result(
    descriptor: ToolDescriptor,
    status: ToolResultStatus,
    *,
    call_id: ToolCallId | None = None,
) -> ToolInvocationResult:
    resolved_call_id = call_id or ToolCallId()
    if status is ToolResultStatus.SUCCEEDED:
        return ToolInvocationResult(
            run_id=AgentRunId(),
            step_id=AgentStepId(),
            call_id=resolved_call_id,
            tool_id=descriptor.tool_id,
            status=status,
            output={},
            started_at=_NOW,
            completed_at=_NOW,
        )
    return ToolInvocationResult(
        run_id=AgentRunId(),
        step_id=AgentStepId(),
        call_id=resolved_call_id,
        tool_id=descriptor.tool_id,
        status=status,
        error_code="test_failure",
        started_at=_NOW,
        completed_at=_NOW,
    )


def _network_binding() -> IntegratedDownstreamBridgeBinding:
    return IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("network.request"),
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id="network:profile/research",
        action_family="network.request",
        generation=3,
    )


def test_integrated_budget_uses_the_most_restrictive_parent_deadline() -> None:
    budget = IntegratedRunBudget(
        IntegratedBudgetExtension(total_duration=timedelta(minutes=5)),
        started_at=_NOW,
        parent_deadline=_NOW + timedelta(minutes=2),
    )

    assert budget.deadline == _NOW + timedelta(minutes=2)
    assert budget.remaining_seconds(now=_NOW + timedelta(seconds=30)) == 90.0

    with pytest.raises(IntegratedAgentDeadlineExceededError):
        budget.require_active(now=_NOW + timedelta(minutes=2))


def test_integrated_budget_counts_exact_boundaries_and_fails_before_extra_work() -> None:
    budget = IntegratedRunBudget(
        IntegratedBudgetExtension(
            max_integrated_steps=2,
            max_network_operations=1,
        ),
        started_at=_NOW,
        parent_deadline=_NOW + timedelta(minutes=10),
    )
    binding = _network_binding()

    usage = budget.consume_step(
        ToolCallId(UUID(int=1)),
        binding,
        {},
        now=_NOW,
    )

    assert usage.integrated_steps == 1
    assert usage.network_operations == 1

    with pytest.raises(IntegratedAgentBudgetExhaustedError):
        budget.require_step(
            binding,
            {},
            now=_NOW + timedelta(seconds=1),
        )
    assert budget.usage == usage


def test_plan_revision_and_workspace_mutation_budgets_are_separate_dimensions() -> None:
    budget = IntegratedRunBudget(
        IntegratedBudgetExtension(
            max_plan_revisions=1,
            max_integrated_steps=3,
            max_workspace_operations=2,
            max_workspace_mutation_bytes=8,
        ),
        started_at=_NOW,
        parent_deadline=_NOW + timedelta(minutes=10),
    )
    plan = IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
        advisory_state_keys=("plan",),
    )
    workspace = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("workspace.write"),
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id="agent-workspace:reports/scope:agent",
        action_family="workspace.write",
    )

    budget.consume_step(ToolCallId(UUID(int=2)), plan, {}, now=_NOW)
    usage = budget.consume_step(
        ToolCallId(UUID(int=3)),
        workspace,
        {},
        now=_NOW,
        workspace_mutation_bytes=8,
    )

    assert usage.plan_revisions == 1
    assert usage.workspace_operations == 1
    assert usage.workspace_mutation_bytes == 8

    with pytest.raises(IntegratedAgentBudgetExhaustedError):
        budget.require_step(
            workspace,
            {},
            now=_NOW,
            workspace_mutation_bytes=1,
        )


def test_cancellation_prevents_new_integrated_budget_admission() -> None:
    token = AgentCancellationToken()
    budget = IntegratedRunBudget(
        IntegratedBudgetExtension(),
        started_at=_NOW,
        parent_deadline=_NOW + timedelta(minutes=10),
    )
    token.cancel()

    with pytest.raises(IntegratedAgentCancelledError):
        budget.require_step(
            _network_binding(),
            {},
            now=_NOW,
            cancellation=token,
        )


def test_effect_disposition_uses_existing_rfc0027_indeterminate_result() -> None:
    read_only = _descriptor("read", effect=ToolEffect.READ_ONLY)
    effectful = _descriptor("write", effect=ToolEffect.REVERSIBLE_WRITE)

    assert (
        integrated_effect_disposition(read_only, _result(read_only, ToolResultStatus.INDETERMINATE))
        is IntegratedEffectDisposition.NO_EFFECT
    )
    assert (
        integrated_effect_disposition(effectful, _result(effectful, ToolResultStatus.SUCCEEDED))
        is IntegratedEffectDisposition.CONFIRMED_EFFECT
    )
    assert (
        integrated_effect_disposition(effectful, _result(effectful, ToolResultStatus.FAILED))
        is IntegratedEffectDisposition.NO_EFFECT
    )
    assert (
        integrated_effect_disposition(
            effectful,
            _result(effectful, ToolResultStatus.INDETERMINATE),
        )
        is IntegratedEffectDisposition.INDETERMINATE
    )


def test_indeterminate_effect_blocks_later_effectful_admission_but_not_read_only() -> None:
    ledger = IntegratedEffectLedger()
    effectful = _descriptor("write", effect=ToolEffect.EXTERNAL_COMMUNICATION)
    read_only = _descriptor("read", effect=ToolEffect.READ_ONLY)
    result = _result(effectful, ToolResultStatus.INDETERMINATE)

    assert ledger.record(effectful, result) is IntegratedEffectDisposition.INDETERMINATE
    assert ledger.indeterminate is True
    ledger.require_admission(read_only)
    with pytest.raises(IntegratedAgentIndeterminateEffectError):
        ledger.require_admission(effectful)


def test_failure_classification_is_sanitized_and_finite() -> None:
    assert (
        classify_integrated_failure(AgentAuthorizationRejectedError())
        is IntegratedFailureClass.AUTHORITY_DENIED
    )
    assert (
        classify_integrated_failure(AgentApprovalRejectedError())
        is IntegratedFailureClass.APPROVAL_REQUIRED
    )
    assert (
        classify_integrated_failure(AgentServiceUnavailableError())
        is IntegratedFailureClass.DEPENDENCY_UNAVAILABLE
    )
    assert (
        classify_integrated_failure(ToolExecutionError())
        is IntegratedFailureClass.DEFINITIVE_OPERATION_FAILURE
    )


def test_workspace_mutation_bytes_are_consumed_after_exact_step_admission() -> None:
    budget = IntegratedRunBudget(
        IntegratedBudgetExtension(
            max_integrated_steps=1,
            max_workspace_operations=1,
            max_workspace_mutation_bytes=8,
        ),
        started_at=_NOW,
        parent_deadline=_NOW + timedelta(minutes=10),
    )
    binding = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("workspace.write"),
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id="agent-workspace:reports/scope:agent",
        action_family="workspace.write",
    )
    call_id = ToolCallId(UUID(int=201))

    step_usage = budget.consume_step(
        call_id,
        binding,
        {},
        now=_NOW,
    )
    mutation_usage = budget.consume_workspace_mutation(
        call_id,
        8,
        now=_NOW,
    )

    assert step_usage.workspace_operations == 1
    assert step_usage.workspace_mutation_bytes == 0
    assert mutation_usage.workspace_operations == 1
    assert mutation_usage.workspace_mutation_bytes == 8


def test_plan_revision_preflight_is_non_consuming_and_exact_attempt_counts_once() -> None:
    from phoenix_os.integrated_agent.errors import IntegratedAgentStaleError

    budget = IntegratedRunBudget(
        IntegratedBudgetExtension(
            max_plan_revisions=1,
            max_integrated_steps=2,
        ),
        started_at=_NOW,
        parent_deadline=_NOW + timedelta(minutes=10),
    )
    plan = IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
        advisory_state_keys=("plan",),
    )

    prospective = budget.require_step(plan, {}, now=_NOW)
    assert prospective.plan_revisions == 1
    assert prospective.integrated_steps == 1
    assert budget.usage.plan_revisions == 0
    assert budget.usage.integrated_steps == 0

    call_id = ToolCallId(UUID(int=901))
    consumed = budget.consume_step(
        call_id,
        plan,
        {},
        now=_NOW,
    )
    assert consumed.plan_revisions == 1
    assert consumed.integrated_steps == 1

    with pytest.raises(IntegratedAgentStaleError):
        budget.consume_step(
            call_id,
            plan,
            {},
            now=_NOW,
        )
    with pytest.raises(IntegratedAgentBudgetExhaustedError):
        budget.require_step(
            plan,
            {},
            now=_NOW,
        )
    assert budget.usage == consumed


def test_effect_ledger_allows_fresh_attempt_only_after_definitive_no_effect() -> None:
    effectful = _descriptor(
        "network.write",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )
    ledger = IntegratedEffectLedger()

    failed = _result(
        effectful,
        ToolResultStatus.FAILED,
        call_id=ToolCallId(UUID(int=902)),
    )
    assert ledger.record(effectful, failed) is IntegratedEffectDisposition.NO_EFFECT
    ledger.require_admission(effectful)

    indeterminate = _result(
        effectful,
        ToolResultStatus.INDETERMINATE,
        call_id=ToolCallId(UUID(int=903)),
    )
    assert ledger.record(effectful, indeterminate) is IntegratedEffectDisposition.INDETERMINATE
    with pytest.raises(IntegratedAgentIndeterminateEffectError):
        ledger.require_admission(effectful)


def test_effect_ledger_never_re_records_the_same_effect_attempt() -> None:
    from phoenix_os.integrated_agent.errors import IntegratedAgentStaleError

    effectful = _descriptor(
        "workspace.export",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
    )
    ledger = IntegratedEffectLedger()
    result = _result(
        effectful,
        ToolResultStatus.SUCCEEDED,
        call_id=ToolCallId(UUID(int=904)),
    )

    assert ledger.record(effectful, result) is IntegratedEffectDisposition.CONFIRMED_EFFECT
    with pytest.raises(IntegratedAgentStaleError):
        ledger.record(effectful, result)
