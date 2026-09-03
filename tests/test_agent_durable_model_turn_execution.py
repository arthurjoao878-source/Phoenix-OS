from __future__ import annotations

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
    ToolCallId,
    ToolCallProposal,
    ToolEffect,
    ToolId,
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
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_model_turn import DurableModelTurnAttemptBinding
from phoenix_os.agent.durable_model_turn_execution import (
    DurableModelTurnExecutionResult,
    execute_durable_model_turn,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentLimitExceededError,
    AgentMalformedProposalError,
    AgentServiceUnavailableError,
    AgentTimeoutError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentModelTurnResult,
)
from phoenix_os.agent.model_turn import agent_model_turn_inference_messages
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.inference.contracts import InferenceRequest, ModelId, ModelProviderId

NOW = datetime(2026, 8, 31, 14, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
TURN_TIME = NOW + timedelta(seconds=2)
PREPARE_TIME = TURN_TIME + timedelta(seconds=1)
OUTCOME_TIME = TURN_TIME + timedelta(seconds=2)

DURABLE_RUN_ID = DurableAgentRunId(UUID("11000000-0000-0000-0000-000000000038"))
AGENT_RUN_ID = AgentRunId(UUID("21000000-0000-0000-0000-000000000038"))
STEP_ID = AgentStepId(UUID("31000000-0000-0000-0000-000000000038"))


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


def _checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("51000000-0000-0000-0000-000000000038")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="s5-outcome-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


def _object_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"value"}),
    )


def _descriptor() -> ToolDescriptor:
    schema = _object_schema()
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Reviewed lookup",
        description="Return one bounded reviewed value.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=10),
        resolver_id="static-resource",
        adapter_id="s5-tool-proposal",
    )


def _turn(*, tools: tuple[ToolDescriptor, ...] = ()) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        messages=(AgentMessage(AgentMessageRole.USER, "bounded durable outcome"),),
        tools=tools,
        created_at=TURN_TIME,
        deadline=TURN_TIME + timedelta(minutes=2),
    )


def _short_turn() -> AgentModelTurnRequest:
    return replace(_turn(), deadline=TURN_TIME + timedelta(seconds=5))


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


async def _environment(
    turn: AgentModelTurnRequest,
) -> tuple[
    InMemoryDurableRunStore,
    CheckpointEnvelope,
    DurableLease,
    DurableModelTurnAttemptBinding,
    StoreBackedDurableExecutionAttemptRecorder,
]:
    store = InMemoryDurableRunStore()
    checkpoint = _checkpoint()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="s5-outcome-worker",
        now=LEASE_TIME,
    )
    binding = DurableModelTurnAttemptBinding(
        checkpoint=checkpoint,
        lease=lease,
        turn=turn,
        inference_request=_inference(turn),
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    return store, checkpoint, lease, binding, recorder


class _FinalAdapter:
    adapter_id = "s5-final"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        return AgentModelTurnResult(
            run_id=request.run_id,
            step_id=request.step_id,
            kind=AgentModelTurnKind.FINAL_OUTPUT,
            final_output="done",
        )


class _ToolProposalAdapter:
    adapter_id = "s5-tool-proposal"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        descriptor = request.tools[0]
        proposal = ToolCallProposal(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=ToolCallId(UUID("61000000-0000-0000-0000-000000000038")),
            tool_id=descriptor.tool_id,
            arguments={"value": "bounded"},
            created_at=request.created_at,
            deadline=request.deadline,
        )
        return AgentModelTurnResult(
            run_id=request.run_id,
            step_id=request.step_id,
            kind=AgentModelTurnKind.TOOL_PROPOSAL,
            proposal=proposal,
        )


class _RaisingAdapter:
    adapter_id = "s5-raising"

    def __init__(self, exception: Exception) -> None:
        self._exception = exception

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        del request
        raise self._exception


class _ContextRequiredAdapter:
    adapter_id = "s5-context-required"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        del request
        raise AssertionError("legacy path must not run")

    async def complete_turn_with_inference(
        self,
        request: AgentModelTurnRequest,
        inference_request: InferenceRequest,
        context: object,
    ) -> AgentModelTurnResult:
        del request, inference_request, context
        raise AssertionError("contextual path must not run without context")


@pytest.mark.asyncio
async def test_final_output_persists_succeeded_complete_checkpoint() -> None:
    turn = _turn()
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    try:
        execution = await execute_durable_model_turn(
            binding,
            recorder,
            BoundedAgentExecutor(clock=lambda: OUTCOME_TIME),
            _FinalAdapter(),
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
            clock=lambda: OUTCOME_TIME,
        )

        assert isinstance(execution, DurableModelTurnExecutionResult)
        assert execution.result.kind is AgentModelTurnKind.FINAL_OUTPUT
        assert execution.checkpoint.metadata.next_operation is CheckpointNextOperation.COMPLETE
        attempt = execution.checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
        assert execution.checkpoint.status is DurableRunStatus.ACTIVE
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_tool_proposal_persists_succeeded_validate_proposal_checkpoint() -> None:
    turn = _turn(tools=(_descriptor(),))
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    try:
        execution = await execute_durable_model_turn(
            binding,
            recorder,
            BoundedAgentExecutor(clock=lambda: OUTCOME_TIME),
            _ToolProposalAdapter(),
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
            clock=lambda: OUTCOME_TIME,
        )

        assert execution.result.kind is AgentModelTurnKind.TOOL_PROPOSAL
        assert (
            execution.checkpoint.metadata.next_operation
            is CheckpointNextOperation.VALIDATE_PROPOSAL
        )
        attempt = execution.checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_pre_start_cancellation_is_terminal_cancelled_not_indeterminate() -> None:
    turn = _turn()
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    token = AgentCancellationToken()
    token.cancel()
    try:
        with pytest.raises(AgentCancelledError):
            await execute_durable_model_turn(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: OUTCOME_TIME),
                _FinalAdapter(),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=token,
                prepare_time=PREPARE_TIME,
                clock=lambda: OUTCOME_TIME,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.CANCELLED
        assert attempt.indeterminate_reason is None
        assert current.status is DurableRunStatus.PAUSED_OPERATOR
        assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_pre_start_timeout_is_terminal_timed_out_not_indeterminate() -> None:
    turn = _short_turn()
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    deadline = turn.deadline
    try:
        with pytest.raises(AgentTimeoutError):
            await execute_durable_model_turn(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: deadline),
                _FinalAdapter(),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
                clock=lambda: deadline,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.TIMED_OUT
        assert attempt.error_code == "timeout"
        assert attempt.indeterminate_reason is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_pre_start_local_service_unavailable_is_terminal_failed() -> None:
    turn = _turn()
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    try:
        with pytest.raises(AgentServiceUnavailableError):
            await execute_durable_model_turn(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: OUTCOME_TIME),
                _ContextRequiredAdapter(),
                context=None,
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
                clock=lambda: OUTCOME_TIME,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.FAILED
        assert attempt.error_code == "service_unavailable"
        assert attempt.indeterminate_reason is None
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_type",
    (AgentCancelledError, AgentTimeoutError, AgentServiceUnavailableError),
)
async def test_post_start_ambiguous_failures_persist_indeterminate_model(
    exception_type: type[Exception],
) -> None:
    turn = _turn()
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    try:
        with pytest.raises(exception_type):
            await execute_durable_model_turn(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: OUTCOME_TIME),
                _RaisingAdapter(exception_type()),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
                clock=lambda: OUTCOME_TIME,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.INDETERMINATE
        assert attempt.indeterminate_reason is IndeterminateReason.PROVIDER_STATUS_UNKNOWN
        assert current.status is DurableRunStatus.INDETERMINATE_MODEL
        assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_type", "error_code"),
    (
        (AgentAuthorizationRejectedError, "authorization_rejected"),
        (AgentLimitExceededError, "limit_exceeded"),
        (AgentMalformedProposalError, "malformed_proposal"),
    ),
)
async def test_post_start_known_failures_persist_terminal_failed(
    exception_type: type[Exception],
    error_code: str,
) -> None:
    turn = _turn()
    store, _checkpoint_value, _lease, binding, recorder = await _environment(turn)
    try:
        with pytest.raises(exception_type):
            await execute_durable_model_turn(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: OUTCOME_TIME),
                _RaisingAdapter(exception_type()),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
                clock=lambda: OUTCOME_TIME,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.FAILED
        assert attempt.error_code == error_code
        assert attempt.indeterminate_reason is None
        assert current.status is DurableRunStatus.PAUSED_OPERATOR
    finally:
        await store.close()
