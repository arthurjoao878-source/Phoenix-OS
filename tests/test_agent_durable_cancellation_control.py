from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId, ToolCallId, ToolEffect
from phoenix_os.agent.durable_authorization import (
    AGENT_CANCEL_ACTION,
    DurableCancellationAuthorizer,
    PolicyEngineDurableCancellationAuthorizer,
    durable_agent_run_resource,
)
from phoenix_os.agent.durable_cancellation import (
    StoreBackedDurableCancellationCoordinator,
    durable_cancellation_requested,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableCancellationRequest,
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    FencingGeneration,
    IndeterminateReason,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.errors import AgentAuthorizationRejectedError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

NOW = datetime(2026, 9, 4, 22, tzinfo=UTC)
REQUESTED_AT = NOW + timedelta(seconds=10)
RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000005"))


class _AllowCancellation:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(
        self,
        request: DurableCancellationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del request, checkpoint, lease, context
        self.calls += 1


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind,
    *,
    status: ExecutionAttemptStatus,
) -> ExecutionAttempt:
    prepared_at = NOW + timedelta(seconds=1)
    started_at = (
        NOW + timedelta(seconds=2) if status is not ExecutionAttemptStatus.PREPARED else None
    )
    completed_at = (
        NOW + timedelta(seconds=3)
        if status not in {ExecutionAttemptStatus.PREPARED, ExecutionAttemptStatus.STARTED}
        else None
    )
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=prepared_at,
        tool_call_id=TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None,
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=started_at,
        completed_at=completed_at,
        external_request_digest=_digest("e"),
        indeterminate_reason=(
            IndeterminateReason.PROCESS_LOSS
            if status is ExecutionAttemptStatus.INDETERMINATE
            else None
        ),
    )


def _checkpoint(
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    attempt: ExecutionAttempt | None = None,
) -> CheckpointEnvelope:
    next_operation = (
        CheckpointNextOperation.OPERATOR_REVIEW
        if status.indeterminate
        else (
            CheckpointNextOperation.TOOL_INVOCATION
            if attempt is not None and attempt.kind is ExecutionAttemptKind.TOOL_INVOCATION
            else CheckpointNextOperation.MODEL_TURN
        )
    )
    if status.terminal:
        next_operation = CheckpointNextOperation.NONE
        attempt = None
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=RUN_ID,
            checkpoint_id=CheckpointId(UUID("60000000-0000-0000-0000-000000000006")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("nova"),
                actor_id="operator-1",
                next_operation=next_operation,
                budget=_budget(),
                compatibility=CompatibilityDigests(
                    configuration=_digest("a"),
                    tool_registry=_digest("b"),
                    model_provider=_digest("c"),
                    checkpoint_codec=_digest("d"),
                ),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(hours=2),
                active_attempt=attempt,
            ),
            created_at=NOW + timedelta(seconds=4),
            digest=_digest("0"),
        )
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="durable-cancel-test",
        attributes={"durable_actor_id": "operator-1"},
    )


async def _services(
    checkpoint: CheckpointEnvelope,
) -> tuple[
    InMemoryDurableRunStore,
    InMemoryDurableLeaseManager,
    DurableLease,
    _AllowCancellation,
    StoreBackedDurableCancellationCoordinator,
]:
    manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    await store.create(checkpoint)
    lease = await manager.acquire(RUN_ID, owner_id="cancel-worker", now=REQUESTED_AT)
    authorizer = _AllowCancellation()
    coordinator = StoreBackedDurableCancellationCoordinator(
        store=store,
        lease_manager=manager,
        authorizer=authorizer,
    )
    return store, manager, lease, authorizer, coordinator


def _request(checkpoint: CheckpointEnvelope, lease: DurableLease) -> DurableCancellationRequest:
    return DurableCancellationRequest(
        run_id=RUN_ID,
        actor_id="operator-1",
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        requested_at=REQUESTED_AT,
    )


def test_cancellation_contracts_and_action_are_exact() -> None:
    checkpoint = _checkpoint()
    request = DurableCancellationRequest(
        run_id=RUN_ID,
        actor_id="operator-1",
        expected_version=checkpoint.run_version,
        generation=FencingGeneration(1),
        requested_at=REQUESTED_AT,
    )
    assert AGENT_CANCEL_ACTION == "agent.cancel"
    assert durable_agent_run_resource(RUN_ID) == f"durable-agent-run:{RUN_ID}"
    assert isinstance(_AllowCancellation(), DurableCancellationAuthorizer)
    assert request.run_id == RUN_ID


@pytest.mark.asyncio
async def test_safe_cancellation_is_confirmed_terminal_checkpoint() -> None:
    checkpoint = _checkpoint()
    store, manager, lease, authorizer, coordinator = await _services(checkpoint)
    result = await coordinator.cancel(
        _request(checkpoint, lease),
        lease=lease,
        context=_context(),
        now=REQUESTED_AT,
    )
    assert authorizer.calls == 1
    assert result.status is DurableRunStatus.CANCELLED
    assert result.metadata.next_operation is CheckpointNextOperation.NONE
    assert result.metadata.active_attempt is None
    assert durable_cancellation_requested(result)
    assert await store.get_current(RUN_ID) == result
    assert len(await store.list_history(RUN_ID, limit=2)) == 2
    await manager.release(lease, now=REQUESTED_AT)
    await store.close()


@pytest.mark.asyncio
async def test_prepared_attempt_is_safe_to_terminally_cancel() -> None:
    checkpoint = _checkpoint(
        attempt=_attempt(ExecutionAttemptKind.MODEL_TURN, status=ExecutionAttemptStatus.PREPARED)
    )
    store, manager, lease, _, coordinator = await _services(checkpoint)
    result = await coordinator.cancel(
        _request(checkpoint, lease),
        lease=lease,
        context=_context(),
        now=REQUESTED_AT,
    )
    assert result.status is DurableRunStatus.CANCELLED
    assert result.metadata.active_attempt is None
    assert durable_cancellation_requested(result)
    await manager.release(lease, now=REQUESTED_AT)
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "expected_status", "expected_reason"),
    (
        (
            ExecutionAttemptKind.MODEL_TURN,
            DurableRunStatus.INDETERMINATE_MODEL,
            IndeterminateReason.PROVIDER_STATUS_UNKNOWN,
        ),
        (
            ExecutionAttemptKind.TOOL_INVOCATION,
            DurableRunStatus.INDETERMINATE_TOOL,
            IndeterminateReason.TOOL_STATUS_UNKNOWN,
        ),
    ),
)
async def test_started_external_attempt_becomes_indeterminate_not_false_cancelled(
    kind: ExecutionAttemptKind,
    expected_status: DurableRunStatus,
    expected_reason: IndeterminateReason,
) -> None:
    checkpoint = _checkpoint(attempt=_attempt(kind, status=ExecutionAttemptStatus.STARTED))
    store, manager, lease, _, coordinator = await _services(checkpoint)
    result = await coordinator.cancel(
        _request(checkpoint, lease),
        lease=lease,
        context=_context(),
        now=REQUESTED_AT,
    )
    assert result.status is expected_status
    assert result.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    attempt = result.metadata.active_attempt
    assert attempt is not None
    assert attempt.status is ExecutionAttemptStatus.INDETERMINATE
    assert attempt.indeterminate_reason is expected_reason
    assert durable_cancellation_requested(result)
    await manager.release(lease, now=REQUESTED_AT)
    await store.close()


@pytest.mark.asyncio
async def test_existing_indeterminate_state_is_preserved_for_reconciliation() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        attempt=_attempt(
            ExecutionAttemptKind.MODEL_TURN,
            status=ExecutionAttemptStatus.INDETERMINATE,
        ),
    )
    store, manager, lease, _, coordinator = await _services(checkpoint)
    result = await coordinator.cancel(
        _request(checkpoint, lease),
        lease=lease,
        context=_context(),
        now=REQUESTED_AT,
    )
    assert result.status is DurableRunStatus.INDETERMINATE_MODEL
    assert result.metadata.active_attempt == checkpoint.metadata.active_attempt
    assert durable_cancellation_requested(result)
    assert len(await store.list_history(RUN_ID, limit=2)) == 2
    await manager.release(lease, now=REQUESTED_AT)
    await store.close()


@pytest.mark.asyncio
async def test_repeat_cancel_of_marked_indeterminate_run_is_idempotent() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        attempt=_attempt(
            ExecutionAttemptKind.MODEL_TURN,
            status=ExecutionAttemptStatus.INDETERMINATE,
        ),
    )
    store, manager, lease, _, coordinator = await _services(checkpoint)
    first = await coordinator.cancel(
        _request(checkpoint, lease),
        lease=lease,
        context=_context(),
        now=REQUESTED_AT,
    )
    second_request = replace(
        _request(first, lease),
        requested_at=REQUESTED_AT + timedelta(seconds=1),
    )
    second = await coordinator.cancel(
        second_request,
        lease=lease,
        context=_context(),
        now=REQUESTED_AT + timedelta(seconds=1),
    )
    assert second == first
    assert len(await store.list_history(RUN_ID, limit=3)) == 2
    await manager.release(lease, now=REQUESTED_AT + timedelta(seconds=1))
    await store.close()


@pytest.mark.asyncio
async def test_stale_fencing_generation_cannot_cancel() -> None:
    checkpoint = _checkpoint()
    store, manager, stale, _, coordinator = await _services(checkpoint)
    replacement_time = stale.expires_at
    current = await manager.acquire(RUN_ID, owner_id="replacement-worker", now=replacement_time)
    with pytest.raises(AgentStateConflictError):
        await coordinator.cancel(
            _request(checkpoint, stale),
            lease=stale,
            context=_context(),
            now=replacement_time,
        )
    assert await store.get_current(RUN_ID) == checkpoint
    await manager.release(current, now=replacement_time)
    await store.close()


@pytest.mark.asyncio
async def test_policy_cancellation_authorization_is_default_deny() -> None:
    checkpoint = _checkpoint()
    manager = InMemoryDurableLeaseManager()
    lease = await manager.acquire(RUN_ID, owner_id="cancel-worker", now=REQUESTED_AT)
    authorizer = PolicyEngineDurableCancellationAuthorizer(
        PolicyEngine(),
        manager,
        clock=lambda: REQUESTED_AT,
    )
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _request(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )
    await manager.release(lease, now=REQUESTED_AT)
    await manager.close()
