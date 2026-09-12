from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.codec import canonical_tool_invocation_request_bytes
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.durable_attempts import StoreBackedDurableExecutionAttemptRecorder
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
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
    IndeterminateReason,
)
from phoenix_os.agent.durable_live_binding import (
    StoreBackedDurableModelTurnBindingProvider,
    StoreBackedDurableToolInvocationBindingProvider,
)
from phoenix_os.agent.durable_live_tool import DurableAgentToolExecutionDriver
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.durable_tool_execution import execute_durable_tool
from phoenix_os.agent.errors import AgentCancelledError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.loop import AgentToolExecutionDriver
from phoenix_os.agent.model_turn import agent_model_turn_inference_messages
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 9, 5, 15, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
INVOCATION_TIME = NOW + timedelta(seconds=2)
BIND_TIME = NOW + timedelta(seconds=3)
PREPARE_TIME = NOW + timedelta(seconds=4)
START_TIME = NOW + timedelta(seconds=5)
NEXT_TURN_TIME = NOW + timedelta(seconds=6)

DURABLE_RUN_ID = DurableAgentRunId(UUID("12000000-0000-0000-0000-000000000039"))
AGENT_RUN_ID = AgentRunId(UUID("22000000-0000-0000-0000-000000000039"))
STEP_ID = AgentStepId(UUID("32000000-0000-0000-0000-000000000039"))
NEXT_STEP_ID = AgentStepId(UUID("32000000-0000-0000-0000-000000000040"))
CALL_ID = ToolCallId(UUID("42000000-0000-0000-0000-000000000039"))
MODEL_ATTEMPT_ID = ExecutionAttemptId(UUID("52000000-0000-0000-0000-000000000039"))


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
        model_turns=1,
        tool_calls=0,
        model_output_bytes=64,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=8,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(minutes=10),
    )


def _model_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=MODEL_ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.SUCCEEDED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=3),
        started_at=NOW - timedelta(seconds=2),
        completed_at=NOW - timedelta(seconds=1),
        external_request_digest=_digest("e"),
    )


def _checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("62000000-0000-0000-0000-000000000039")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="durable-tool-worker",
                next_operation=CheckpointNextOperation.VALIDATE_PROPOSAL,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=_model_attempt(),
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


def _schema() -> ToolSchema:
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
    schema = _schema()
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="Read one reviewed deterministic value.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=30),
        resolver_id="static-resource",
        adapter_id="durable-tool-test",
    )


def _invocation() -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=AgentId("assistant"),
        run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=ToolId("lookup"),
        arguments={"value": "input"},
        resolved_resource="record:fixed",
        created_at=INVOCATION_TIME,
        deadline=INVOCATION_TIME + timedelta(minutes=1),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _next_turn() -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=AGENT_RUN_ID,
        step_id=NEXT_STEP_ID,
        messages=(AgentMessage(AgentMessageRole.USER, "continue after tool"),),
        created_at=NEXT_TURN_TIME,
        deadline=NEXT_TURN_TIME + timedelta(minutes=1),
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


async def _environment() -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
]:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="durable-tool-worker",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    return store, lease, recorder


class _StoreObservingTool:
    adapter_id = "durable-tool-test"
    tool_id = ToolId("lookup")

    def __init__(self, store: InMemoryDurableRunStore) -> None:
        self._store = store
        self.saw_started = False

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        current = await self._store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.STARTED
        assert attempt.tool_call_id == request.call_id
        self.saw_started = True
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "fixed"},
            started_at=START_TIME,
            completed_at=START_TIME,
        )


class _FailingTool:
    adapter_id = "durable-tool-test"
    tool_id = ToolId("lookup")

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise RuntimeError("private tool transport failure")


@pytest.mark.asyncio
async def test_live_tool_cycle_bridges_safe_boundaries_and_records_started_before_adapter() -> None:
    store, lease, recorder = await _environment()
    descriptor = _descriptor()
    invocation = _invocation()
    provider = StoreBackedDurableToolInvocationBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    try:
        binding = await provider.bind(invocation, descriptor, now=BIND_TIME)
        tool_boundary = binding.checkpoint

        assert tool_boundary.metadata.next_operation is CheckpointNextOperation.TOOL_INVOCATION
        assert tool_boundary.metadata.active_attempt is None
        assert binding.invocation is invocation
        assert binding.descriptor is descriptor
        assert binding.external_request_digest == CheckpointDigest(
            hashlib.sha256(canonical_tool_invocation_request_bytes(invocation)).hexdigest()
        )

        adapter = _StoreObservingTool(store)
        executed = await execute_durable_tool(
            binding,
            recorder,
            BoundedAgentExecutor(clock=lambda: START_TIME),
            adapter,
            context=_context(),
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
            clock=lambda: START_TIME,
        )

        assert adapter.saw_started is True
        assert executed.result.status is ToolResultStatus.SUCCEEDED
        assert executed.checkpoint.status is DurableRunStatus.ACTIVE
        assert (
            executed.checkpoint.metadata.next_operation is CheckpointNextOperation.VALIDATE_RESULT
        )
        tool_attempt = executed.checkpoint.metadata.active_attempt
        assert tool_attempt is not None
        assert tool_attempt.status is ExecutionAttemptStatus.SUCCEEDED

        turn = _next_turn()
        model_provider = StoreBackedDurableModelTurnBindingProvider(
            store=store,
            lease_manager=store.lease_manager,
            lease=lease,
        )
        next_binding = await model_provider.bind(
            turn,
            _inference(turn),
            now=NEXT_TURN_TIME,
        )

        assert next_binding.checkpoint.step_id == NEXT_STEP_ID
        assert next_binding.checkpoint.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        assert next_binding.checkpoint.metadata.active_attempt is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_post_start_tool_failure_is_persisted_indeterminate_without_retry() -> None:
    store, lease, recorder = await _environment()
    descriptor = _descriptor()
    invocation = _invocation()
    provider = StoreBackedDurableToolInvocationBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    try:
        binding = await provider.bind(invocation, descriptor, now=BIND_TIME)
        executed = await execute_durable_tool(
            binding,
            recorder,
            BoundedAgentExecutor(clock=lambda: START_TIME),
            _FailingTool(),
            context=_context(),
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
            clock=lambda: START_TIME,
        )

        assert executed.result.status is ToolResultStatus.INDETERMINATE
        assert executed.result.error_code == "execution_indeterminate"
        assert executed.checkpoint.status is DurableRunStatus.INDETERMINATE_TOOL
        assert (
            executed.checkpoint.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
        )
        attempt = executed.checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.INDETERMINATE
        assert attempt.indeterminate_reason is IndeterminateReason.TOOL_STATUS_UNKNOWN
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_pre_start_cancellation_records_cancelled_without_adapter_dispatch() -> None:
    store, lease, recorder = await _environment()
    descriptor = _descriptor()
    invocation = _invocation()
    provider = StoreBackedDurableToolInvocationBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    token = AgentCancellationToken()
    token.cancel()
    try:
        binding = await provider.bind(invocation, descriptor, now=BIND_TIME)
        with pytest.raises(AgentCancelledError):
            await execute_durable_tool(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: START_TIME),
                _StoreObservingTool(store),
                context=_context(),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=token,
                prepare_time=PREPARE_TIME,
                clock=lambda: START_TIME,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.PAUSED_OPERATOR
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.CANCELLED
        assert attempt.started_at is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_runtime_stack_composes_tool_driver_without_taking_lease_ownership() -> None:
    store = InMemoryDurableRunStore()
    lease_manager = store.lease_manager
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    try:
        lease = await lease_manager.acquire(
            DurableAgentRunId(),
            owner_id="live-tool-worker",
            now=NOW,
        )
        before = await lease_manager.get_current(lease.run_id, now=NOW)

        driver = stack.create_tool_execution_driver(lease=lease)

        after = await lease_manager.get_current(lease.run_id, now=NOW)
        assert isinstance(driver, DurableAgentToolExecutionDriver)
        assert isinstance(driver, AgentToolExecutionDriver)
        assert before == lease
        assert after == lease
    finally:
        await stack.close()
