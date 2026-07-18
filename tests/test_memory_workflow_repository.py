from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.workflows import (
    InMemoryWorkflowRepository,
    WorkflowAlreadyExistsError,
    WorkflowConflictError,
    WorkflowDefinition,
    WorkflowPlanner,
    WorkflowRecord,
    WorkflowRepositoryClosedError,
    WorkflowStep,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def record() -> WorkflowRecord:
    definition = WorkflowDefinition("release", (WorkflowStep("prepare", "test.echo"),))
    return WorkflowPlanner().instantiate(definition, now=NOW)


@pytest.mark.asyncio
async def test_repository_add_get_and_list() -> None:
    repository = InMemoryWorkflowRepository()
    workflow = record()

    await repository.add(workflow)

    assert await repository.get(workflow.id) == workflow
    assert await repository.list_all() == (workflow,)


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_id() -> None:
    repository = InMemoryWorkflowRepository()
    workflow = record()
    await repository.add(workflow)

    with pytest.raises(WorkflowAlreadyExistsError):
        await repository.add(workflow)


@pytest.mark.asyncio
async def test_repository_replaces_exact_revision() -> None:
    repository = InMemoryWorkflowRepository()
    workflow = record()
    await repository.add(workflow)
    updated = replace(
        workflow,
        revision=1,
        updated_at=NOW + timedelta(seconds=1),
    )

    saved = await repository.replace(updated, expected_revision=0)

    assert saved.revision == 1
    assert await repository.get(workflow.id) == updated


@pytest.mark.asyncio
async def test_repository_rejects_stale_revision() -> None:
    repository = InMemoryWorkflowRepository()
    workflow = record()
    await repository.add(workflow)
    updated = replace(
        workflow,
        revision=1,
        updated_at=NOW + timedelta(seconds=1),
    )
    await repository.replace(updated, expected_revision=0)

    stale = replace(
        workflow,
        revision=1,
        updated_at=NOW + timedelta(seconds=2),
    )
    with pytest.raises(WorkflowConflictError):
        await repository.replace(stale, expected_revision=0)


@pytest.mark.asyncio
async def test_closed_repository_rejects_access() -> None:
    repository = InMemoryWorkflowRepository()
    await repository.close()

    with pytest.raises(WorkflowRepositoryClosedError):
        await repository.list_all()
