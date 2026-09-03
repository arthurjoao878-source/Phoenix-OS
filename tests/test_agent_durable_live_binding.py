from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
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
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_live_binding import (
    StoreBackedDurableModelTurnBindingProvider,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentStateConflictError,
)
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.model_turn import agent_model_turn_inference_messages
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId

NOW = datetime(2026, 8, 1, 12, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
TURN_TIME = NOW + timedelta(seconds=2)
BIND_TIME = NOW + timedelta(seconds=3)

DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
OTHER_STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000004"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(hours=1),
    )


def _checkpoint(
    *,
    step_id: AgentStepId | None = None,
    active_attempt: ExecutionAttempt | None = None,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("40000000-0000-0000-0000-000000000001")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=step_id,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=active_attempt,
                metadata={"tenant": "demo"},
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


def _turn(step_id: AgentStepId = STEP_ID) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=AGENT_RUN_ID,
        step_id=step_id,
        messages=(
            AgentMessage(
                role=AgentMessageRole.USER,
                content="bounded durable test",
            ),
        ),
        created_at=TURN_TIME,
        deadline=TURN_TIME + timedelta(minutes=10),
    )


def _inference(turn: AgentModelTurnRequest) -> InferenceRequest:
    return InferenceRequest(
        provider_id=ModelProviderId("local-test"),
        model_id=ModelId("model-test"),
        messages=agent_model_turn_inference_messages(turn),
        max_output_tokens=32,
        metadata={
            "agent_run_id": str(turn.run_id),
            "agent_step_id": str(turn.step_id),
        },
        correlation_id=str(turn.run_id),
        created_at=turn.created_at,
        deadline=turn.deadline,
    )


async def _created(
    checkpoint: CheckpointEnvelope,
) -> Any:
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id="live-worker",
        now=LEASE_TIME,
    )
    return store, lease


def _terminal_previous_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000001")),
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.SUCCEEDED,
        agent_run_id=AGENT_RUN_ID,
        step_id=OTHER_STEP_ID,
        prepared_at=NOW - timedelta(seconds=3),
        tool_call_id=ToolCallId(UUID("60000000-0000-0000-0000-000000000001")),
        tool_effect=ToolEffect.READ_ONLY,
        started_at=NOW - timedelta(seconds=2),
        completed_at=NOW - timedelta(seconds=1),
        external_request_digest=_digest("e"),
    )


def _nonterminal_previous_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000002")),
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.PREPARED,
        agent_run_id=AGENT_RUN_ID,
        step_id=OTHER_STEP_ID,
        prepared_at=NOW - timedelta(seconds=1),
        external_request_digest=_digest("f"),
    )


@pytest.mark.asyncio
async def test_initial_unbound_step_is_published_before_model_attempt() -> None:
    current = _checkpoint()
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()
    inference = _inference(turn)

    binding = await provider.bind(turn, inference, now=BIND_TIME)
    bound = binding.checkpoint

    assert bound.step_id == STEP_ID
    assert bound.sequence == CheckpointSequence(2)
    assert bound.run_version == DurableRunVersion(2)
    assert bound.previous_digest == current.digest
    assert bound.status is DurableRunStatus.ACTIVE
    assert bound.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
    assert bound.metadata.active_attempt is None
    assert bound.metadata.budget == current.metadata.budget
    assert bound.metadata.compatibility == current.metadata.compatibility
    assert bound.metadata.retention_deadline == current.metadata.retention_deadline
    assert binding.turn is turn
    assert binding.inference_request is inference
    assert await store.get_current(DURABLE_RUN_ID) == bound


@pytest.mark.asyncio
async def test_exact_prebound_step_is_read_only() -> None:
    current = _checkpoint(step_id=STEP_ID)
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()

    binding = await provider.bind(turn, _inference(turn), now=BIND_TIME)

    assert binding.checkpoint == current
    assert await store.get_current(DURABLE_RUN_ID) == current


@pytest.mark.asyncio
async def test_inference_substitution_is_rejected_without_mutation() -> None:
    current = _checkpoint()
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()
    inference = _inference(turn)
    substituted = replace(
        inference,
        metadata={
            "agent_run_id": str(turn.run_id),
            "agent_step_id": str(OTHER_STEP_ID),
        },
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await provider.bind(turn, substituted, now=BIND_TIME)

    assert await store.get_current(DURABLE_RUN_ID) == current


@pytest.mark.asyncio
async def test_different_step_without_terminal_evidence_fails_closed() -> None:
    current = _checkpoint(step_id=OTHER_STEP_ID)
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()

    with pytest.raises(AgentStateConflictError):
        await provider.bind(turn, _inference(turn), now=BIND_TIME)

    assert await store.get_current(DURABLE_RUN_ID) == current


@pytest.mark.asyncio
async def test_terminal_previous_step_can_advance_and_is_cleared() -> None:
    current = _checkpoint(
        step_id=OTHER_STEP_ID,
        active_attempt=_terminal_previous_attempt(),
    )
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()

    binding = await provider.bind(turn, _inference(turn), now=BIND_TIME)
    bound = binding.checkpoint

    assert bound.step_id == STEP_ID
    assert bound.sequence == CheckpointSequence(2)
    assert bound.run_version == DurableRunVersion(2)
    assert bound.metadata.active_attempt is None
    assert await store.get_current(DURABLE_RUN_ID) == bound


@pytest.mark.asyncio
async def test_nonterminal_previous_attempt_blocks_new_step() -> None:
    current = _checkpoint(
        step_id=OTHER_STEP_ID,
        active_attempt=_nonterminal_previous_attempt(),
    )
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()

    with pytest.raises(AgentStateConflictError):
        await provider.bind(turn, _inference(turn), now=BIND_TIME)

    assert await store.get_current(DURABLE_RUN_ID) == current


@pytest.mark.asyncio
async def test_expired_lease_blocks_step_binding_without_mutation() -> None:
    current = _checkpoint()
    store, lease = await _created(current)
    provider = StoreBackedDurableModelTurnBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    turn = _turn()

    with pytest.raises(AgentStateConflictError):
        await provider.bind(
            turn,
            _inference(turn),
            now=LEASE_TIME + timedelta(minutes=2),
        )

    assert await store.get_current(DURABLE_RUN_ID) == current
