from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.capabilities import CapabilityContext
from phoenix_os.jobs import RetryPolicy
from phoenix_os.state import MemoryStateStore, StateKey
from phoenix_os.workflows import (
    StateWorkflowRepository,
    WorkflowAlreadyExistsError,
    WorkflowConflictError,
    WorkflowDefinition,
    WorkflowPersistenceError,
    WorkflowPlanner,
    WorkflowRecord,
    WorkflowRepositoryClosedError,
    WorkflowStep,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def definition() -> WorkflowDefinition:
    return WorkflowDefinition(
        "release",
        (
            WorkflowStep(
                "prepare",
                "release.prepare",
                arguments={"target": "production"},
                context=CapabilityContext(
                    principal="release-bot",
                    correlation_id="release-42",
                    confirmed=True,
                    permissions=frozenset({"release.prepare"}),
                    metadata={"source": "workflow"},
                ),
                retry=RetryPolicy(
                    max_attempts=3,
                    initial_delay=timedelta(seconds=2),
                    multiplier=2,
                    max_delay=timedelta(seconds=10),
                ),
                deadline=30,
                metadata={"owner": "platform"},
            ),
            WorkflowStep(
                "publish",
                "release.publish",
                dependencies=frozenset({"prepare"}),
            ),
        ),
        version="2",
        metadata={"environment": "production"},
    )


def record() -> WorkflowRecord:
    return WorkflowPlanner().instantiate(definition(), now=NOW)


@pytest.mark.asyncio
async def test_state_repository_round_trips_complete_record() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    workflow = record()

    await repository.add(workflow)
    restored = await repository.get(workflow.id)

    assert restored == workflow
    assert restored is not None
    assert restored.definition.steps[0].context.principal == "release-bot"
    assert restored.definition.steps[0].retry.max_attempts == 3
    assert await repository.list_all() == (workflow,)


@pytest.mark.asyncio
async def test_state_repository_survives_repository_restart() -> None:
    store = MemoryStateStore()
    first = StateWorkflowRepository(store)
    workflow = record()
    await first.add(workflow)
    await first.close()

    second = StateWorkflowRepository(store)

    assert await second.get(workflow.id) == workflow
    assert not store.closed


@pytest.mark.asyncio
async def test_state_repository_rejects_duplicate_id() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    workflow = record()
    await repository.add(workflow)

    with pytest.raises(WorkflowAlreadyExistsError):
        await repository.add(workflow)


@pytest.mark.asyncio
async def test_state_repository_replaces_exact_revision() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    workflow = record()
    await repository.add(workflow)
    updated = replace(
        workflow,
        revision=1,
        updated_at=NOW + timedelta(seconds=1),
    )

    saved = await repository.replace(updated, expected_revision=0)

    assert saved == updated
    assert await repository.get(workflow.id) == updated


@pytest.mark.asyncio
async def test_state_repository_rejects_stale_revision() -> None:
    store = MemoryStateStore()
    first = StateWorkflowRepository(store)
    second = StateWorkflowRepository(store)
    workflow = record()
    await first.add(workflow)
    updated = replace(
        workflow,
        revision=1,
        updated_at=NOW + timedelta(seconds=1),
    )
    await first.replace(updated, expected_revision=0)

    stale = replace(
        workflow,
        revision=1,
        updated_at=NOW + timedelta(seconds=2),
    )
    with pytest.raises(WorkflowConflictError):
        await second.replace(stale, expected_revision=0)


@pytest.mark.asyncio
async def test_state_repository_rejects_definition_replacement() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    workflow = record()
    await repository.add(workflow)
    changed_definition = WorkflowDefinition(
        "changed",
        (WorkflowStep("prepare", "release.prepare"),),
    )
    invalid = replace(
        workflow,
        definition=changed_definition,
        steps=WorkflowPlanner().instantiate(changed_definition, now=NOW).steps,
        revision=1,
        updated_at=NOW + timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="definition is immutable"):
        await repository.replace(invalid, expected_revision=0)


@pytest.mark.asyncio
async def test_state_repository_detects_corrupt_schema_version() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    workflow = record()
    await repository.add(workflow)
    key = StateKey("workflows", f"w_{workflow.id.hex}", dict)
    stored = await store.get(key)
    assert stored is not None
    corrupt = dict(stored.value)
    corrupt["schema_version"] = 99
    await store.put(key, corrupt, expected_version=stored.version)

    with pytest.raises(WorkflowPersistenceError):
        await repository.get(workflow.id)


@pytest.mark.asyncio
async def test_state_repository_detects_invalid_step_records() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    workflow = record()
    await repository.add(workflow)
    key = StateKey("workflows", f"w_{workflow.id.hex}", dict)
    stored = await store.get(key)
    assert stored is not None
    corrupt = dict(stored.value)
    corrupt["steps"] = []
    await store.put(key, corrupt, expected_version=stored.version)

    with pytest.raises(WorkflowPersistenceError):
        await repository.get(workflow.id)


@pytest.mark.asyncio
async def test_state_repository_close_borrows_store() -> None:
    store = MemoryStateStore()
    repository = StateWorkflowRepository(store)
    await repository.close()

    assert repository.closed
    assert not store.closed
    with pytest.raises(WorkflowRepositoryClosedError):
        await repository.list_all()
