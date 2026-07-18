from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from phoenix_os.workflows import (
    WorkflowDefinition,
    WorkflowPlanner,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepStatus,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
WORKFLOW_ID = UUID("00000000-0000-0000-0000-000000000016")


def definition() -> WorkflowDefinition:
    return WorkflowDefinition(
        "release",
        (
            WorkflowStep("prepare", "release.prepare"),
            WorkflowStep(
                "tests",
                "release.test",
                dependencies=frozenset({"prepare"}),
            ),
            WorkflowStep(
                "package",
                "release.package",
                dependencies=frozenset({"prepare"}),
            ),
            WorkflowStep(
                "publish",
                "release.publish",
                dependencies=frozenset({"tests", "package"}),
            ),
        ),
    )


def test_planner_builds_deterministic_fan_out_and_fan_in_levels() -> None:
    plan = WorkflowPlanner().plan(definition())

    assert plan.levels == (("prepare",), ("tests", "package"), ("publish",))
    assert plan.ordered_steps == ("prepare", "tests", "package", "publish")


def test_planner_instantiates_root_steps_as_ready() -> None:
    record = WorkflowPlanner().instantiate(
        definition(),
        now=NOW,
        workflow_id=WORKFLOW_ID,
    )

    assert record.id == WORKFLOW_ID
    assert record.status is WorkflowStatus.PENDING
    assert record.revision == 0
    assert record.steps["prepare"].status is WorkflowStepStatus.READY
    assert record.steps["tests"].status is WorkflowStepStatus.BLOCKED
    assert record.steps["package"].status is WorkflowStepStatus.BLOCKED
    assert record.steps["publish"].status is WorkflowStepStatus.BLOCKED


def test_planner_returns_ready_steps_in_declaration_order() -> None:
    planner = WorkflowPlanner()
    record = planner.instantiate(definition(), now=NOW)

    assert tuple(step.id for step in planner.ready_steps(record)) == ("prepare",)
