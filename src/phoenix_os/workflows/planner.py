"""Deterministic validation and topological planning for workflow graphs."""

from __future__ import annotations

from datetime import UTC, datetime

from phoenix_os.workflows.contracts import (
    WorkflowDefinition,
    WorkflowId,
    WorkflowPlan,
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepRecord,
    WorkflowStepStatus,
)


class WorkflowPlanner:
    """Build deterministic DAG levels and initial workflow instance state."""

    def plan(self, definition: WorkflowDefinition) -> WorkflowPlan:
        remaining = {step.id: set(step.dependencies) for step in definition.steps}
        resolved: set[str] = set()
        levels: list[tuple[str, ...]] = []

        while len(resolved) < len(definition.steps):
            level = tuple(
                step.id
                for step in definition.steps
                if step.id not in resolved and not remaining[step.id]
            )
            # WorkflowDefinition already guarantees acyclicity.
            assert level
            levels.append(level)
            resolved.update(level)
            for dependencies in remaining.values():
                dependencies.difference_update(level)

        ordered = tuple(step_id for level in levels for step_id in level)
        return WorkflowPlan(ordered_steps=ordered, levels=tuple(levels))

    def instantiate(
        self,
        definition: WorkflowDefinition,
        *,
        now: datetime | None = None,
        workflow_id: WorkflowId | None = None,
    ) -> WorkflowRecord:
        created_at = datetime.now(UTC) if now is None else now
        if created_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        records = {
            step.id: WorkflowStepRecord(
                step_id=step.id,
                status=(
                    WorkflowStepStatus.READY
                    if not step.dependencies
                    else WorkflowStepStatus.BLOCKED
                ),
            )
            for step in definition.steps
        }
        if workflow_id is None:
            return WorkflowRecord(
                definition=definition,
                status=WorkflowStatus.PENDING,
                created_at=created_at,
                updated_at=created_at,
                steps=records,
            )
        return WorkflowRecord(
            id=workflow_id,
            definition=definition,
            status=WorkflowStatus.PENDING,
            created_at=created_at,
            updated_at=created_at,
            steps=records,
        )

    def ready_steps(self, record: WorkflowRecord) -> tuple[WorkflowStep, ...]:
        """Return ready steps in original declaration order."""

        return tuple(
            step
            for step in record.definition.steps
            if record.steps[step.id].status is WorkflowStepStatus.READY
        )
