from __future__ import annotations

from datetime import UTC, datetime

import pytest

from phoenix_os.workflows import (
    WorkflowCycleError,
    WorkflowDefinition,
    WorkflowDependencyError,
    WorkflowDuplicateStepError,
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepRecord,
    WorkflowStepStatus,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_workflow_step_normalizes_and_freezes_values() -> None:
    arguments = {"value": 1}
    metadata = {" owner ": "phoenix"}
    step = WorkflowStep(
        " prepare ",
        " test.echo ",
        arguments=arguments,
        metadata=metadata,
    )

    arguments["value"] = 2
    metadata[" owner "] = "changed"

    assert step.id == "prepare"
    assert step.capability == "test.echo"
    assert step.arguments == {"value": 1}
    assert step.metadata == {"owner": "phoenix"}
    with pytest.raises(TypeError):
        step.arguments["other"] = 2  # type: ignore[index]


def test_workflow_step_rejects_self_dependency() -> None:
    with pytest.raises(WorkflowDependencyError):
        WorkflowStep("prepare", "test.echo", dependencies=frozenset({"prepare"}))


def test_workflow_definition_rejects_duplicate_steps() -> None:
    with pytest.raises(WorkflowDuplicateStepError):
        WorkflowDefinition(
            "duplicate",
            (
                WorkflowStep("same", "test.echo"),
                WorkflowStep("same", "test.echo"),
            ),
        )


def test_workflow_definition_rejects_missing_dependency() -> None:
    with pytest.raises(WorkflowDependencyError, match="missing"):
        WorkflowDefinition(
            "missing",
            (WorkflowStep("publish", "test.echo", dependencies=frozenset({"build"})),),
        )


def test_workflow_definition_rejects_cycle() -> None:
    with pytest.raises(WorkflowCycleError):
        WorkflowDefinition(
            "cycle",
            (
                WorkflowStep("first", "test.echo", dependencies=frozenset({"second"})),
                WorkflowStep("second", "test.echo", dependencies=frozenset({"first"})),
            ),
        )


def test_workflow_definition_resolves_step() -> None:
    step = WorkflowStep("prepare", "test.echo")
    definition = WorkflowDefinition("release", (step,))

    assert definition.step(" prepare ") is step
    with pytest.raises(WorkflowDependencyError):
        definition.step("missing")


def test_running_step_record_requires_job_and_start_time() -> None:
    with pytest.raises(ValueError, match="requires job_id"):
        WorkflowStepRecord("prepare", WorkflowStepStatus.RUNNING)


def test_terminal_workflow_requires_finished_time() -> None:
    definition = WorkflowDefinition("release", (WorkflowStep("prepare", "test.echo"),))
    records = {
        "prepare": WorkflowStepRecord(
            "prepare",
            WorkflowStepStatus.SUCCEEDED,
            finished_at=NOW,
        )
    }

    with pytest.raises(ValueError, match="requires finished_at"):
        WorkflowRecord(
            definition=definition,
            status=WorkflowStatus.SUCCEEDED,
            created_at=NOW,
            updated_at=NOW,
            steps=records,
        )
