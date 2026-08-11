import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phoenix_os.agent import (
    AgentDelegationRegistry,
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentServiceConfiguration,
    CoordinationNamespace,
    DelegableAgentDescriptor,
    DelegatedChildRun,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationRequest,
    DelegationStatus,
    DurableAgentDelegationCoordinator,
    DurableDelegationReconciliationDecision,
    DurableDelegationReconciliationEvidence,
    DurableDelegationReconciliationRequest,
    DurableDelegationRecoveryCoordinator,
    DurableDelegationRecoveryState,
    DurableDelegationStore,
    InMemoryDurableDelegationStore,
    SQLiteDurableDelegationStore,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 11, 1, tzinfo=UTC)


class _AllowAuthorizer:
    async def authorize(
        self,
        request: DelegationRequest,
        descriptor: DelegableAgentDescriptor,
        context: SecurityContext,
    ) -> None:
        assert descriptor.agent_id == request.child_agent_id
        assert context.authenticated


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:parent",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _limits() -> DelegationLimits:
    return DelegationLimits(
        max_depth=3,
        max_fan_out=4,
        max_total_children=8,
        max_concurrent_children=4,
        max_queue_depth=8,
        max_input_bytes=16_384,
        max_result_bytes=65_536,
        max_result_depth=8,
        child_timeout=timedelta(minutes=5),
    )


def _budget() -> DelegationBudget:
    return DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=8192,
        max_output_tokens=4096,
        max_prompt_bytes=16_384,
        max_result_bytes=65_536,
        duration=timedelta(minutes=2),
    )


def _root_budget() -> DelegationBudget:
    child = _budget()
    return DelegationBudget(
        max_model_turns=8,
        max_tool_calls=4,
        max_input_tokens=32_768,
        max_output_tokens=16_384,
        max_prompt_bytes=65_536,
        max_result_bytes=262_144,
        duration=child.duration * 4,
    )


def _descriptor() -> DelegableAgentDescriptor:
    return DelegableAgentDescriptor(
        configuration=AgentServiceConfiguration(
            agent_id=AgentId("child"),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
            limits=AgentLimits(
                max_model_turns=4,
                max_tool_calls=2,
                max_input_tokens=16_384,
                max_output_tokens=8192,
                max_prompt_bytes=65_536,
                max_result_bytes=262_144,
                approval_wait_timeout=timedelta(minutes=5),
                total_duration=timedelta(minutes=5),
            ),
        ),
        namespace=CoordinationNamespace("default"),
        allowed_parent_agents=(AgentId("parent"),),
        compatibility_digest="sha256:" + "a" * 64,
        allow_nested_delegation=True,
        max_accepted_depth=DelegationDepth(3),
    )


def _registry() -> AgentDelegationRegistry:
    registry = AgentDelegationRegistry()
    registry.register_agent(_descriptor())
    return registry


def _request(
    *,
    delegation_id: DelegationId | None = None,
    input_value: str = "work",
    parent_run_id: AgentRunId | None = None,
    root_run_id: AgentRunId | None = None,
    deadline: datetime | None = None,
) -> DelegationRequest:
    parent_run = parent_run_id or root_run_id or AgentRunId()
    root_run = root_run_id or parent_run
    return DelegationRequest(
        parent_agent_id=AgentId("parent"),
        parent_run_id=parent_run,
        child_agent_id=AgentId("child"),
        namespace=CoordinationNamespace("default"),
        lineage=DelegationLineage((DelegationLineageEntry(AgentId("parent"), root_run),)),
        input={"task": input_value},
        budget=_budget(),
        limits=_limits(),
        delegation_id=delegation_id or DelegationId(),
        created_at=_NOW,
        deadline=deadline or (_NOW + timedelta(minutes=2)),
    )


def _replay(request: DelegationRequest, *, input_value: str) -> DelegationRequest:
    return DelegationRequest(
        parent_agent_id=request.parent_agent_id,
        parent_run_id=request.parent_run_id,
        child_agent_id=request.child_agent_id,
        namespace=request.namespace,
        lineage=request.lineage,
        input={"task": input_value},
        budget=request.budget,
        limits=request.limits,
        delegation_id=request.delegation_id,
        created_at=request.created_at,
        deadline=request.deadline,
    )


def _coordinator(store: DurableDelegationStore) -> DurableAgentDelegationCoordinator:
    return DurableAgentDelegationCoordinator(
        _registry(),
        _AllowAuthorizer(),
        store=store,
        limits=_limits(),
        root_budget_limit=_root_budget(),
        clock=lambda: _NOW,
    )


@pytest.mark.asyncio
async def test_restart_reuses_exact_persisted_child_identity_for_recoverable_work() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()

    first = _coordinator(store)
    admitted = await first.delegate(request, _context())
    record = await first.durable_record(request.delegation_id)
    assert record.status is DelegationStatus.ADMITTED
    assert record.child_run_id == admitted.child_run_id

    recovery = DurableDelegationRecoveryCoordinator(store, clock=lambda: _NOW)
    report = await recovery.recover()
    assert report.recoverable == 1

    second = _coordinator(store)
    resumed = await second.delegate(request, _context())
    assert resumed.child_run_id == admitted.child_run_id
    assert (await second.durable_record(request.delegation_id)).recovery_state is (
        DurableDelegationRecoveryState.CLEAN
    )


@pytest.mark.asyncio
async def test_running_process_loss_becomes_indeterminate_and_never_replays() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()

    first = _coordinator(store)
    admitted = await first.delegate(request, _context())
    await first.start(request.delegation_id, now=_NOW)

    recovery = DurableDelegationRecoveryCoordinator(store, clock=lambda: _NOW)
    report = await recovery.recover()
    assert report.indeterminate == 1

    record = await store.get(request.delegation_id)
    assert record is not None
    assert record.child_run_id == admitted.child_run_id
    assert record.status is DelegationStatus.RUNNING
    assert record.recovery_state is DurableDelegationRecoveryState.INDETERMINATE

    second = _coordinator(store)
    with pytest.raises(AgentStateConflictError):
        await second.delegate(request, _context())

    unchanged = await store.get(request.delegation_id)
    assert unchanged is not None
    assert unchanged.child_run_id == admitted.child_run_id


@pytest.mark.asyncio
async def test_reconciliation_confirm_not_started_allows_same_identity_resume() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()

    first = _coordinator(store)
    admitted = await first.delegate(request, _context())
    await first.start(request.delegation_id, now=_NOW)

    recovery = DurableDelegationRecoveryCoordinator(store, clock=lambda: _NOW)
    await recovery.recover()
    current = await store.get(request.delegation_id)
    assert current is not None

    reconciled = await recovery.reconcile(
        DurableDelegationReconciliationRequest(
            delegation_id=request.delegation_id,
            expected_version=current.version,
            decision=DurableDelegationReconciliationDecision.CONFIRM_NOT_STARTED,
            evidence=DurableDelegationReconciliationEvidence(
                evidence_type="child_status",
                evidence_digest="sha256:" + "b" * 64,
                observed_at=_NOW,
            ),
            requested_at=_NOW,
        )
    )
    assert reconciled.status is DelegationStatus.ADMITTED
    assert reconciled.recovery_state is DurableDelegationRecoveryState.RECOVERABLE

    second = _coordinator(store)
    resumed = await second.delegate(request, _context())
    assert resumed.child_run_id == admitted.child_run_id


@pytest.mark.asyncio
async def test_replayed_request_substitution_fails_closed() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()
    first = _coordinator(store)
    admitted = await first.delegate(request, _context())

    await DurableDelegationRecoveryCoordinator(
        store,
        clock=lambda: _NOW,
    ).recover()

    second = _coordinator(store)
    with pytest.raises(AgentStateConflictError):
        await second.delegate(
            _replay(request, input_value="different-work"),
            _context(),
        )

    record = await store.get(request.delegation_id)
    assert record is not None
    assert record.child_run_id == admitted.child_run_id


@pytest.mark.asyncio
async def test_reconciliation_can_confirm_terminal_without_child_reexecution() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()
    first = _coordinator(store)
    await first.delegate(request, _context())
    await first.start(request.delegation_id, now=_NOW)

    recovery = DurableDelegationRecoveryCoordinator(store, clock=lambda: _NOW)
    await recovery.recover()
    current = await store.get(request.delegation_id)
    assert current is not None

    terminal = await recovery.reconcile(
        DurableDelegationReconciliationRequest(
            delegation_id=request.delegation_id,
            expected_version=current.version,
            decision=DurableDelegationReconciliationDecision.CONFIRM_COMPLETED,
            evidence=DurableDelegationReconciliationEvidence(
                evidence_type="child_status",
                evidence_digest="sha256:" + "c" * 64,
                observed_at=_NOW,
            ),
            requested_at=_NOW,
        )
    )

    assert terminal.status is DelegationStatus.COMPLETED
    assert terminal.terminal
    assert terminal.recovery_state is DurableDelegationRecoveryState.CLEAN


@pytest.mark.asyncio
async def test_sqlite_process_restart_never_duplicates_unknown_running_child(
    tmp_path: Path,
) -> None:
    path = tmp_path / "coordination.sqlite3"
    request = _request()

    first_store = SQLiteDurableDelegationStore(path)
    first = _coordinator(first_store)
    admitted = await first.delegate(request, _context())
    await first.start(request.delegation_id, now=_NOW)
    await first_store.close()

    second_store = SQLiteDurableDelegationStore(path)
    recovery = DurableDelegationRecoveryCoordinator(second_store, clock=lambda: _NOW)
    report = await recovery.recover()
    assert report.indeterminate == 1

    persisted = await second_store.get(request.delegation_id)
    assert persisted is not None
    assert persisted.child_run_id == admitted.child_run_id
    assert persisted.recovery_state is DurableDelegationRecoveryState.INDETERMINATE

    second = _coordinator(second_store)
    with pytest.raises(AgentStateConflictError):
        await second.delegate(request, _context())

    after = await second_store.get(request.delegation_id)
    assert after is not None
    assert after.child_run_id == admitted.child_run_id
    await second_store.close()


@pytest.mark.asyncio
async def test_recovery_expires_persisted_work_past_deadline() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()
    coordinator = _coordinator(store)
    await coordinator.delegate(request, _context())

    recovery = DurableDelegationRecoveryCoordinator(
        store,
        clock=lambda: _NOW + timedelta(minutes=3),
    )
    report = await recovery.recover()

    assert report.expired == 1
    current = await store.get(request.delegation_id)
    assert current is not None
    assert current.status is DelegationStatus.EXPIRED
    assert current.recovery_state is DurableDelegationRecoveryState.CLEAN


@pytest.mark.asyncio
async def test_indeterminate_sibling_blocks_new_work_for_same_root() -> None:
    store = InMemoryDurableDelegationStore()
    root = AgentRunId()
    first_request = _request(root_run_id=root)

    first = _coordinator(store)
    await first.delegate(first_request, _context())
    await first.start(first_request.delegation_id, now=_NOW)

    recovery = DurableDelegationRecoveryCoordinator(store, clock=lambda: _NOW)
    await recovery.recover()

    second = _coordinator(store)
    with pytest.raises(AgentStateConflictError):
        await second.delegate(
            _request(root_run_id=root),
            _context(),
        )


@pytest.mark.asyncio
async def test_recoverable_replay_claim_allows_only_one_concurrent_owner() -> None:
    store = InMemoryDurableDelegationStore()
    request = _request()
    original = _coordinator(store)
    admitted = await original.delegate(request, _context())
    await DurableDelegationRecoveryCoordinator(
        store,
        clock=lambda: _NOW,
    ).recover()

    first = _coordinator(store)
    second = _coordinator(store)
    outcomes = await asyncio.gather(
        first.delegate(request, _context()),
        second.delegate(request, _context()),
        return_exceptions=True,
    )

    failures = [item for item in outcomes if isinstance(item, AgentStateConflictError)]
    successes = [item for item in outcomes if isinstance(item, DelegatedChildRun)]
    assert len(failures) == 1
    assert len(successes) == 1
    assert successes[0].child_run_id == admitted.child_run_id
