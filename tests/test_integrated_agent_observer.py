from __future__ import annotations

import inspect
from dataclasses import fields
from uuid import UUID

import pytest

from phoenix_os.agent import AgentRunId
from phoenix_os.integrated_agent import (
    ContentFreeIntegratedAgentObserver,
    IntegratedAgentObservabilityConfiguration,
    IntegratedAgentObservation,
    IntegratedBudgetUsage,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedFailureClass,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
    IntegratedWaitingReason,
    PlanRevision,
)


def _observation(
    *,
    phase: IntegratedOrchestrationPhase = IntegratedOrchestrationPhase.EXECUTING,
    waiting_reason: IntegratedWaitingReason | None = None,
) -> IntegratedAgentObservation:
    return IntegratedAgentObservation(
        task_id=IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222")),
        run_id=AgentRunId(UUID("11111111-1111-1111-1111-111111111111")),
        phase=phase,
        profile_id=IntegratedExecutionProfileId("integrated-research"),
        profile_generation=IntegratedExecutionProfileGeneration(7),
        plan_revision=PlanRevision(3),
        capability_id="workspace",
        action_category="workspace.write",
        failure_class=IntegratedFailureClass.STALE_STATE,
        budget_usage=IntegratedBudgetUsage(
            plan_revisions=3,
            integrated_steps=4,
            workspace_operations=2,
            workspace_mutation_bytes=128,
        ),
        duration_ms=9,
        waiting_reason=waiting_reason,
    )


def test_integrated_observation_shape_is_closed_and_content_free() -> None:
    assert {item.name for item in fields(IntegratedAgentObservation)} == {
        "task_id",
        "run_id",
        "phase",
        "profile_id",
        "profile_generation",
        "step_id",
        "plan_revision",
        "capability_id",
        "tool_id",
        "action_category",
        "effect_disposition",
        "failure_class",
        "budget_usage",
        "duration_ms",
        "waiting_reason",
        "schema_version",
    }

    observation = _observation()
    metadata = observation.metadata()
    assert set(metadata) == {
        "task_id",
        "run_id",
        "profile_id",
        "profile_generation",
        "orchestration_phase",
        "plan_revision",
        "capability_id",
        "action_category",
        "failure_class",
        "duration_ms",
        "budget_plan_revisions",
        "budget_integrated_steps",
        "budget_browser_operations",
        "budget_network_operations",
        "budget_memory_operations",
        "budget_workspace_operations",
        "budget_workspace_mutation_bytes",
        "budget_host_operations",
    }
    assert metadata["profile_generation"] == 7
    assert metadata["budget_workspace_mutation_bytes"] == 128

    serialized = repr(observation).lower()
    for forbidden in (
        "task_text",
        "objective=",
        "prompt",
        "model_response",
        "tool_argument",
        "tool_result",
        "browser_page_text",
        "network_body",
        "memory_content",
        "workspace_content",
        "clipboard_content",
        "cookie",
        "credential",
        "secret_value",
        "approval_evidence",
        "policy_internals",
        "raw_exception",
    ):
        assert forbidden not in serialized


def test_integrated_observability_configuration_is_explicit_and_bounded() -> None:
    configuration = IntegratedAgentObservabilityConfiguration()
    assert configuration.audit_enabled is True
    assert configuration.metrics_enabled is True
    assert configuration.logs_enabled is True
    assert configuration.events_enabled is True
    assert configuration.source == "phoenix.integrated_agent"
    assert configuration.any_enabled is True

    with pytest.raises(ValueError):
        IntegratedAgentObservabilityConfiguration(source="https://collector.invalid")


def test_waiting_reason_is_bound_to_waiting_phase() -> None:
    waiting = _observation(
        phase=IntegratedOrchestrationPhase.WAITING,
        waiting_reason=IntegratedWaitingReason.CONTEXT_RESUPPLY,
    )
    assert waiting.metadata()["waiting_reason"] == "context_resupply"

    with pytest.raises(ValueError):
        _observation(phase=IntegratedOrchestrationPhase.WAITING)

    with pytest.raises(ValueError):
        _observation(
            phase=IntegratedOrchestrationPhase.EXECUTING,
            waiting_reason=IntegratedWaitingReason.RECONCILIATION,
        )


def test_content_free_integrated_observer_uses_empty_payload_and_fixed_metadata() -> None:
    source = inspect.getsource(ContentFreeIntegratedAgentObserver.record)
    compact = "".join(source.split())

    assert "payload={}" in compact
    assert 'message="integratedagentorchestrationchangedstate"' in compact
    for forbidden in (
        ".objective",
        ".messages",
        ".prompt",
        ".final_output",
        ".arguments",
        ".result",
        ".body",
        ".headers",
        ".cookies",
        "AuthorityIntent",
        "Approval",
        "SecretRef",
    ):
        assert forbidden not in source
