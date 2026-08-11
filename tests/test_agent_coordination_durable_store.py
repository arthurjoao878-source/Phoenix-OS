from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentRunId,
    CoordinationNamespace,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationStatus,
    DurableDelegationRecord,
    DurableDelegationRecoveryState,
    DurableDelegationVersion,
    InMemoryDurableDelegationStore,
    SQLiteDurableDelegationStore,
)
from phoenix_os.agent.errors import AgentStateConflictError

_NOW = datetime(2026, 8, 11, 1, tzinfo=UTC)


def _budget() -> DelegationBudget:
    return DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=4096,
        max_output_tokens=2048,
        max_prompt_bytes=8192,
        max_result_bytes=16_384,
        duration=timedelta(minutes=2),
    )


def _limits(
    *,
    max_fan_out: int = 4,
    max_total_children: int = 8,
) -> DelegationLimits:
    return DelegationLimits(
        max_depth=3,
        max_fan_out=min(max_fan_out, max_total_children),
        max_total_children=max_total_children,
        max_concurrent_children=min(4, max_fan_out, max_total_children),
        max_queue_depth=8,
        max_input_bytes=16_384,
        max_result_bytes=65_536,
        max_result_depth=8,
        child_timeout=timedelta(minutes=5),
    )


def _root_budget(children: int = 4) -> DelegationBudget:
    child = _budget()
    return DelegationBudget(
        max_model_turns=child.max_model_turns * children,
        max_tool_calls=child.max_tool_calls * children,
        max_input_tokens=child.max_input_tokens * children,
        max_output_tokens=child.max_output_tokens * children,
        max_prompt_bytes=child.max_prompt_bytes * children,
        max_result_bytes=child.max_result_bytes * children,
        duration=child.duration * children,
    )


def _record(
    *,
    delegation_id: DelegationId | None = None,
    child_run_id: AgentRunId | None = None,
    parent_run_id: AgentRunId | None = None,
    root_run_id: AgentRunId | None = None,
    budget: DelegationBudget | None = None,
    status: DelegationStatus = DelegationStatus.ADMITTED,
    recovery_state: DurableDelegationRecoveryState = DurableDelegationRecoveryState.CLEAN,
) -> DurableDelegationRecord:
    return DurableDelegationRecord(
        delegation_id=delegation_id or DelegationId(),
        namespace=CoordinationNamespace("default"),
        parent_agent_id=AgentId("parent"),
        parent_run_id=parent_run_id or AgentRunId(),
        root_run_id=root_run_id or AgentRunId(),
        child_agent_id=AgentId("child"),
        child_run_id=child_run_id or AgentRunId(),
        depth=DelegationDepth(1),
        budget=budget or _budget(),
        status=status,
        request_digest="sha256:" + "1" * 64,
        compatibility_digest="sha256:" + "2" * 64,
        version=DurableDelegationVersion(),
        recovery_state=recovery_state,
        created_at=_NOW,
        updated_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


async def _create(
    store: InMemoryDurableDelegationStore | SQLiteDurableDelegationStore,
    record: DurableDelegationRecord,
    *,
    limits: DelegationLimits | None = None,
    root_budget_limit: DelegationBudget | None = None,
) -> None:
    await store.create(
        record,
        limits=limits or _limits(),
        root_budget_limit=root_budget_limit or _root_budget(),
    )


@pytest.mark.asyncio
async def test_in_memory_store_rejects_duplicate_delegation_and_child_identity() -> None:
    store = InMemoryDurableDelegationStore()
    first = _record()
    await _create(store, first)

    with pytest.raises(AgentStateConflictError):
        await _create(store, first)

    with pytest.raises(AgentStateConflictError):
        await _create(store, _record(child_run_id=first.child_run_id))


@pytest.mark.asyncio
async def test_in_memory_store_compare_and_swap_is_versioned_and_identity_immutable() -> None:
    store = InMemoryDurableDelegationStore()
    first = _record()
    await _create(store, first)

    second = replace(
        first,
        status=DelegationStatus.RUNNING,
        version=first.version.next(),
        updated_at=_NOW + timedelta(seconds=1),
    )
    assert await store.compare_and_swap(second, expected_version=first.version) == second

    with pytest.raises(AgentStateConflictError):
        await store.compare_and_swap(
            replace(
                second,
                version=second.version.next(),
                updated_at=_NOW + timedelta(seconds=2),
            ),
            expected_version=first.version,
        )

    current = await store.get(first.delegation_id)
    assert current == second


@pytest.mark.asyncio
async def test_in_memory_recovery_candidates_are_bounded_sorted_and_nonterminal() -> None:
    store = InMemoryDurableDelegationStore()
    identities = sorted((DelegationId(), DelegationId(), DelegationId()))
    await _create(store, _record(delegation_id=identities[2]))
    await _create(store, _record(delegation_id=identities[0]))
    terminal = _record(
        delegation_id=identities[1],
        status=DelegationStatus.COMPLETED,
    )
    await _create(store, terminal)

    assert await store.list_recovery_candidates(limit=10) == (
        identities[0],
        identities[2],
    )


@pytest.mark.asyncio
async def test_sqlite_store_survives_close_and_reopen(tmp_path: Path) -> None:
    path = tmp_path / "coordination.sqlite3"
    first_store = SQLiteDurableDelegationStore(path)
    record = _record()
    await _create(first_store, record)
    await first_store.close()

    second_store = SQLiteDurableDelegationStore(path)
    recovered = await second_store.get(record.delegation_id)

    assert recovered == record
    assert await second_store.list_recovery_candidates(limit=10) == (record.delegation_id,)
    await second_store.close()


@pytest.mark.asyncio
async def test_sqlite_compare_and_swap_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "coordination.sqlite3"
    store = SQLiteDurableDelegationStore(path)
    first = _record()
    await _create(store, first)
    running = replace(
        first,
        status=DelegationStatus.RUNNING,
        version=first.version.next(),
        updated_at=_NOW + timedelta(seconds=1),
    )
    await store.compare_and_swap(running, expected_version=first.version)
    await store.close()

    reopened = SQLiteDurableDelegationStore(path)
    assert await reopened.get(first.delegation_id) == running
    await reopened.close()


@pytest.mark.asyncio
async def test_lifetime_total_children_counts_terminal_records() -> None:
    store = InMemoryDurableDelegationStore()
    root = AgentRunId()
    first = _record(
        root_run_id=root,
        parent_run_id=AgentRunId(),
        status=DelegationStatus.COMPLETED,
    )
    limits = _limits(max_total_children=1)
    await _create(store, first, limits=limits)

    with pytest.raises(AgentStateConflictError):
        await _create(
            store,
            _record(root_run_id=root, parent_run_id=AgentRunId()),
            limits=limits,
        )


@pytest.mark.asyncio
async def test_sqlite_restart_preserves_lifetime_root_budget(tmp_path: Path) -> None:
    path = tmp_path / "coordination.sqlite3"
    root = AgentRunId()
    first_store = SQLiteDurableDelegationStore(path)
    first = _record(
        root_run_id=root,
        parent_run_id=AgentRunId(),
        status=DelegationStatus.COMPLETED,
    )
    await _create(
        first_store,
        first,
        root_budget_limit=_root_budget(children=1),
    )
    await first_store.close()

    second_store = SQLiteDurableDelegationStore(path)
    with pytest.raises(AgentStateConflictError):
        await _create(
            second_store,
            _record(root_run_id=root, parent_run_id=AgentRunId()),
            root_budget_limit=_root_budget(children=1),
        )
    await second_store.close()


@pytest.mark.asyncio
async def test_sqlite_restart_preserves_lifetime_parent_fanout(tmp_path: Path) -> None:
    path = tmp_path / "coordination.sqlite3"
    root = AgentRunId()
    parent = AgentRunId()
    limits = _limits(max_fan_out=1)
    first_store = SQLiteDurableDelegationStore(path)
    await _create(
        first_store,
        _record(
            root_run_id=root,
            parent_run_id=parent,
            status=DelegationStatus.COMPLETED,
        ),
        limits=limits,
    )
    await first_store.close()

    second_store = SQLiteDurableDelegationStore(path)
    with pytest.raises(AgentStateConflictError):
        await _create(
            second_store,
            _record(root_run_id=root, parent_run_id=parent),
            limits=limits,
        )
    await second_store.close()
