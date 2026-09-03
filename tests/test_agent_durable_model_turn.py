from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentStepId,
)
from phoenix_os.agent.durable_attempts import StoreBackedDurableExecutionAttemptRecorder
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
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_model_turn import (
    DurableModelTurnAttemptBinding,
    DurableModelTurnSubmissionGate,
    prepare_durable_model_turn_submission,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentStateConflictError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentModelTurnResult,
)
from phoenix_os.agent.model_turn import agent_model_turn_inference_messages
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.inference.codec import canonical_inference_request_bytes
from phoenix_os.inference.contracts import InferenceRequest, ModelId, ModelProviderId

NOW = datetime(2026, 8, 31, 12, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
TURN_TIME = NOW + timedelta(seconds=2)

DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000038"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000038"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000038"))
OTHER_STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000039"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000038"))


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
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _attempt(status: ExecutionAttemptStatus) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=TURN_TIME,
        started_at=(
            TURN_TIME + timedelta(seconds=1) if status is ExecutionAttemptStatus.STARTED else None
        ),
        external_request_digest=_digest("e"),
    )


def _checkpoint(
    *,
    step_id: AgentStepId = STEP_ID,
    active_attempt: ExecutionAttempt | None = None,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("50000000-0000-0000-0000-000000000038")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=step_id,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="s5-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=active_attempt,
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


def _turn(*, step_id: AgentStepId = STEP_ID) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=AGENT_RUN_ID,
        step_id=step_id,
        messages=(AgentMessage(AgentMessageRole.USER, "bounded durable turn"),),
        created_at=TURN_TIME,
        deadline=TURN_TIME + timedelta(minutes=2),
    )


def _inference(turn: AgentModelTurnRequest) -> InferenceRequest:
    return InferenceRequest(
        provider_id=ModelProviderId("ollama-local"),
        model_id=ModelId("reviewed-model"),
        messages=agent_model_turn_inference_messages(turn),
        max_output_tokens=128,
        metadata={
            "agent_run_id": str(turn.run_id),
            "agent_step_id": str(turn.step_id),
        },
        correlation_id=str(turn.run_id),
        created_at=turn.created_at,
        deadline=turn.deadline,
    )


async def _created(
    checkpoint: CheckpointEnvelope | None = None,
) -> tuple[InMemoryDurableRunStore, CheckpointEnvelope, DurableLease]:
    current = _checkpoint() if checkpoint is None else checkpoint
    store = InMemoryDurableRunStore()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        current.durable_run_id,
        owner_id="s5-binding-worker",
        now=LEASE_TIME,
    )
    return store, current, lease


@pytest.mark.asyncio
async def test_binding_uses_exact_canonical_inference_request_digest() -> None:
    store, checkpoint, lease = await _created()
    try:
        turn = _turn()
        inference = _inference(turn)
        binding = DurableModelTurnAttemptBinding(
            checkpoint=checkpoint,
            lease=lease,
            turn=turn,
            inference_request=inference,
        )

        assert binding.checkpoint is checkpoint
        assert binding.lease is lease
        assert binding.turn is turn
        assert binding.inference_request is inference
        assert binding.external_request_digest == CheckpointDigest(
            hashlib.sha256(canonical_inference_request_bytes(inference)).hexdigest()
        )
        binding.require_ready(now=TURN_TIME + timedelta(seconds=1))
        assert await store.list_history(DURABLE_RUN_ID, limit=10) == (checkpoint,)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_binding_rejects_inference_substitution_without_durable_mutation() -> None:
    store, checkpoint, lease = await _created()
    try:
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
            DurableModelTurnAttemptBinding(
                checkpoint=checkpoint,
                lease=lease,
                turn=turn,
                inference_request=substituted,
            )

        assert await store.list_history(DURABLE_RUN_ID, limit=10) == (checkpoint,)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_binding_rejects_checkpoint_step_substitution() -> None:
    checkpoint = _checkpoint(step_id=OTHER_STEP_ID)
    store, current, lease = await _created(checkpoint)
    try:
        turn = _turn()
        with pytest.raises(AgentStateConflictError):
            DurableModelTurnAttemptBinding(
                checkpoint=current,
                lease=lease,
                turn=turn,
                inference_request=_inference(turn),
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_binding_rejects_nonterminal_prior_model_attempt() -> None:
    checkpoint = _checkpoint(active_attempt=_attempt(ExecutionAttemptStatus.PREPARED))
    store, current, lease = await _created(checkpoint)
    try:
        turn = _turn()
        with pytest.raises(AgentStateConflictError):
            DurableModelTurnAttemptBinding(
                checkpoint=current,
                lease=lease,
                turn=turn,
                inference_request=_inference(turn),
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_binding_readiness_fails_closed_after_lease_expiry() -> None:
    store, checkpoint, lease = await _created()
    try:
        turn = _turn()
        binding = DurableModelTurnAttemptBinding(
            checkpoint=checkpoint,
            lease=lease,
            turn=turn,
            inference_request=_inference(turn),
        )

        with pytest.raises(AgentStateConflictError):
            binding.require_ready(now=lease.expires_at)
    finally:
        await store.close()


class _StoreObservingModelAdapter:
    def __init__(self, store: InMemoryDurableRunStore) -> None:
        self._store = store
        self.saw_started = False

    @property
    def adapter_id(self) -> str:
        return "s5-store-observing-model"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        history = await self._store.list_history(DURABLE_RUN_ID, limit=16)
        current = history[-1]
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.STARTED
        assert attempt.step_id == request.step_id
        self.saw_started = True
        return AgentModelTurnResult(
            run_id=request.run_id,
            step_id=request.step_id,
            kind=AgentModelTurnKind.FINAL_OUTPUT,
            final_output="bounded",
        )


async def _prepared_submission(
    store: InMemoryDurableRunStore,
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
    *,
    start_time: datetime = TURN_TIME + timedelta(seconds=2),
) -> tuple[DurableModelTurnSubmissionGate, AgentModelTurnRequest, InferenceRequest]:
    turn = _turn()
    inference = _inference(turn)
    binding = DurableModelTurnAttemptBinding(
        checkpoint=checkpoint,
        lease=lease,
        turn=turn,
        inference_request=inference,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    gate = await prepare_durable_model_turn_submission(
        binding,
        recorder,
        now=TURN_TIME + timedelta(seconds=1),
        clock=lambda: start_time,
    )
    return gate, turn, inference


@pytest.mark.asyncio
async def test_prepare_submission_persists_exact_prepared_attempt_only() -> None:
    store, checkpoint, lease = await _created()
    try:
        gate, turn, inference = await _prepared_submission(store, checkpoint, lease)

        prepared = gate.prepared_checkpoint
        attempt = prepared.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.PREPARED
        assert attempt.kind is ExecutionAttemptKind.MODEL_TURN
        assert attempt.agent_run_id == turn.run_id
        assert attempt.step_id == turn.step_id
        assert attempt.external_request_digest == CheckpointDigest(
            hashlib.sha256(canonical_inference_request_bytes(inference)).hexdigest()
        )
        assert gate.started_checkpoint is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_executor_dispatches_only_after_durable_started_checkpoint() -> None:
    store, checkpoint, lease = await _created()
    try:
        gate, turn, _inference_request = await _prepared_submission(store, checkpoint, lease)
        adapter = _StoreObservingModelAdapter(store)

        result = await BoundedAgentExecutor(
            clock=lambda: TURN_TIME + timedelta(seconds=2)
        ).complete_model_turn(
            adapter,
            turn,
            submission_gate=gate,
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
        )

        assert result.kind is AgentModelTurnKind.FINAL_OUTPUT
        assert adapter.saw_started is True
        assert gate.started_checkpoint is not None
        attempt = gate.started_checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.STARTED
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_pre_dispatch_cancellation_leaves_attempt_prepared() -> None:
    store, checkpoint, lease = await _created()
    try:
        gate, turn, _inference_request = await _prepared_submission(store, checkpoint, lease)
        token = AgentCancellationToken()
        token.cancel()

        with pytest.raises(AgentCancelledError):
            await BoundedAgentExecutor(
                clock=lambda: TURN_TIME + timedelta(seconds=2)
            ).complete_model_turn(
                _StoreObservingModelAdapter(store),
                turn,
                submission_gate=gate,
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=token,
            )

        history = await store.list_history(DURABLE_RUN_ID, limit=16)
        attempt = history[-1].metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.PREPARED
        assert gate.started_checkpoint is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_submission_gate_is_single_use_after_started_transition() -> None:
    store, checkpoint, lease = await _created()
    try:
        gate, _turn_request, _inference_request = await _prepared_submission(
            store,
            checkpoint,
            lease,
        )

        await gate.before_submit()
        with pytest.raises(AgentStateConflictError):
            await gate.before_submit()
    finally:
        await store.close()
