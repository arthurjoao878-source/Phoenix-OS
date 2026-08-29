from __future__ import annotations

import inspect
from dataclasses import fields
from uuid import UUID

import pytest

from phoenix_os.agent import AgentRunId
from phoenix_os.integrated_agent import (
    INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
    INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
    IntegratedAgentAdministration,
    IntegratedAgentAdministrationSnapshot,
    IntegratedAgentRedactedRunInspection,
    integrated_agent_inspection_resource,
)


def test_administration_contracts_have_no_content_or_generic_escape_hatches() -> None:
    assert {item.name for item in fields(IntegratedAgentAdministrationSnapshot)} == {
        "runtime_state",
        "profile_id",
        "profile_generation",
        "admission_closed",
        "planner_configured",
        "planner_closed",
        "execution_guard_configured",
        "execution_guard_closed",
        "composition_configured",
        "schema_version",
    }
    assert {item.name for item in fields(IntegratedAgentRedactedRunInspection)} == {
        "task_id",
        "run_id",
        "profile_id",
        "profile_generation",
        "plan_revision",
        "budget_usage",
        "failure_class",
        "provenance_source_kinds",
        "schema_version",
    }

    forbidden_fields = {
        "metadata",
        "attributes",
        "details",
        "payload",
        "content",
        "message",
        "exception",
        "objective",
        "prompt",
        "response",
        "arguments",
        "result",
        "task_digest",
        "plan_digest",
        "source_binding",
        "freshness_bindings",
        "authority",
        "approval",
        "credential",
        "secret",
    }
    for contract in (
        IntegratedAgentAdministrationSnapshot,
        IntegratedAgentRedactedRunInspection,
    ):
        assert not ({item.name for item in fields(contract)} & forbidden_fields)


def test_inspection_implementation_never_reads_content_or_raw_provenance_bindings() -> None:
    source = inspect.getsource(IntegratedAgentAdministration.inspect_run)
    for forbidden in (
        "request_for_run",
        "current_plan",
        ".task_digest",
        ".authority",
        ".effective_limits",
        ".objective",
        ".messages",
        ".final_output",
        ".statements",
        ".source_binding",
        ".freshness_bindings",
        "Approval",
        "Secret",
        "Exception",
        "__dict__",
        "asdict",
    ):
        assert forbidden not in source


def test_health_and_inspection_permissions_are_distinct() -> None:
    assert INTEGRATED_AGENT_HEALTH_READ_PERMISSION != INTEGRATED_AGENT_INSPECTION_READ_PERMISSION


def test_inspection_resource_is_exactly_run_scoped() -> None:
    run_id = AgentRunId(UUID("11111111-1111-1111-1111-111111111111"))
    assert (
        integrated_agent_inspection_resource(run_id)
        == "integrated-agent:run/11111111-1111-1111-1111-111111111111/inspection"
    )
    with pytest.raises(TypeError):
        integrated_agent_inspection_resource("not-a-run-id")  # type: ignore[arg-type]
