from __future__ import annotations

import asyncio
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
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
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
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_lease_keepalive import (
    DurableLeaseCallKeepalive,
    DurableSubmissionStartedSignal,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.errors import AgentStateConflictError
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
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext

_RENEWAL_INTERVAL = timedelta(milliseconds=10)
_DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000042"))
_AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000042"))
_STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000042"))
_CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000042"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _budget(now: datetime) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=now,
        deadline=now + timedelta(minutes=2),
    )


def _checkpoint(
    now: datetime,
    *,
    next_operation: CheckpointNextOperation,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("50000000-0000-0000-0000-000000000042")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="lease-keeper-test",
                next_operation=next_operation,
                budget=_budget(now),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=now + timedelta(days=1),
            ),
            created_at=now,
            digest=_digest("0"),
        )
    )


def _turn(now: datetime) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=_AGENT_RUN_ID,
        step_id=_STEP_ID,
        messages=(AgentMessage(AgentMessageRole.USER, "renew while inference is in flight"),),
        created_at=now,
        deadline=now + timedelta(minutes=1),
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


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=64,
            )
        },
        required=frozenset({"value"}),
    )


def _descriptor() -> ToolDescriptor:
    schema = _schema()
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="Return one deterministic value.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=30),
        resolver_id="static-resource",
        adapter_id="lease-keeper-tool",
    )


def _invocation(now: datetime) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=AgentId("assistant"),
        run_id=_AGENT_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        tool_id=ToolId("lookup"),
        arguments={"value": "input"},
        resolved_resource="record:fixed",
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )


async def _wait_for_renewal(
    store: InMemoryDurableRunStore,
    *,
    acquired_at: datetime,
) -> datetime:
    for _attempt in range(400):
        now = datetime.now(UTC)
        current = await store.lease_manager.get_current(_DURABLE_RUN_ID, now=now)
        if current is not None and current.acquired_at > acquired_at:
            return current.acquired_at
        await asyncio.sleep(0.005)
    raise AssertionError("durable lease was not renewed while external work was in flight")


class _BlockingModelAdapter:
    adapter_id = "lease-keeper-model"

    def __init__(self, store: InMemoryDurableRunStore) -> None:
        self._store = store
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        current = await self._store.get_current(_DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.STARTED
        self.entered.set()
        await self.release.wait()
        return AgentModelTurnResult(
            run_id=request.run_id,
            step_id=request.step_id,
            kind=AgentModelTurnKind.FINAL_OUTPUT,
            final_output="done",
        )


class _BlockingToolAdapter:
    adapter_id = "lease-keeper-tool"
    tool_id = ToolId("lookup")

    def __init__(self, store: InMemoryDurableRunStore) -> None:
        self._store = store
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        current = await self._store.get_current(_DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.STARTED
        self.entered.set()
        await self.release.wait()
        completed = datetime.now(UTC)
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "fixed"},
            started_at=completed,
            completed_at=completed,
        )


@pytest.mark.asyncio
async def test_keepalive_does_not_renew_before_durable_started_signal() -> None:
    now = datetime.now(UTC)
    store = InMemoryDurableRunStore()
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="lease-keeper",
        now=now,
    )
    token = AgentCancellationToken()
    signal = DurableSubmissionStartedSignal()
    keepalive = DurableLeaseCallKeepalive(
        lease_manager=store.lease_manager,
        lease=lease,
        renewal_interval=_RENEWAL_INTERVAL,
    )
    try:
        keepalive.start(started_signal=signal, cancellation=token)
        await asyncio.sleep(0.04)
        before = await store.lease_manager.get_current(
            _DURABLE_RUN_ID,
            now=datetime.now(UTC),
        )
        assert before == lease

        signal.mark_started()
        renewed_at = await _wait_for_renewal(store, acquired_at=lease.acquired_at)
        assert renewed_at > lease.acquired_at
        assert token.cancelled is False
    finally:
        await keepalive.stop()
        await store.close()


@pytest.mark.asyncio
async def test_keepalive_renewal_failure_cancels_external_call_token() -> None:
    now = datetime.now(UTC)
    store = InMemoryDurableRunStore()
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="lease-keeper",
        now=now,
    )
    token = AgentCancellationToken()
    signal = DurableSubmissionStartedSignal()
    keepalive = DurableLeaseCallKeepalive(
        lease_manager=store.lease_manager,
        lease=lease,
        renewal_interval=_RENEWAL_INTERVAL,
    )
    try:
        keepalive.start(started_signal=signal, cancellation=token)
        signal.mark_started()
        await store.lease_manager.release(lease, now=datetime.now(UTC))
        await asyncio.wait_for(token.wait(), timeout=2)
        await keepalive.stop()

        assert token.cancelled is True
        assert isinstance(keepalive.failure, AgentStateConflictError)
    finally:
        await keepalive.stop()
        await store.close()


@pytest.mark.asyncio
async def test_live_model_driver_renews_only_while_adapter_is_in_flight() -> None:
    now = datetime.now(UTC)
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(now, next_operation=CheckpointNextOperation.MODEL_TURN))
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="model-keeper",
        now=now,
    )
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    adapter = _BlockingModelAdapter(store)
    turn = _turn(now)
    driver = stack.create_model_turn_execution_driver(
        lease=lease,
        lease_renewal_interval=_RENEWAL_INTERVAL,
    )
    try:
        task = asyncio.create_task(
            driver.execute(
                BoundedAgentExecutor(),
                adapter,
                turn,
                _inference(turn),
                _context(),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=datetime.now(UTC),
            )
        )
        await asyncio.wait_for(adapter.entered.wait(), timeout=2)
        renewed_at = await _wait_for_renewal(store, acquired_at=lease.acquired_at)

        adapter.release.set()
        result = await asyncio.wait_for(task, timeout=2)
        assert result.kind is AgentModelTurnKind.FINAL_OUTPUT

        current = await store.get_current(_DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.ACTIVE
        assert current.metadata.next_operation is CheckpointNextOperation.COMPLETE
        terminal_attempt = current.metadata.active_attempt
        assert terminal_attempt is not None
        assert terminal_attempt.status is ExecutionAttemptStatus.SUCCEEDED

        stable = await store.lease_manager.get_current(
            _DURABLE_RUN_ID,
            now=datetime.now(UTC),
        )
        assert stable is not None
        assert stable.acquired_at >= renewed_at
        stable_acquired_at = stable.acquired_at
        await asyncio.sleep(0.04)
        after = await store.lease_manager.get_current(
            _DURABLE_RUN_ID,
            now=datetime.now(UTC),
        )
        assert after is not None
        assert after.acquired_at == stable_acquired_at
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_live_tool_driver_renews_only_while_adapter_is_in_flight() -> None:
    now = datetime.now(UTC)
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(now, next_operation=CheckpointNextOperation.TOOL_INVOCATION))
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="tool-keeper",
        now=now,
    )
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    adapter = _BlockingToolAdapter(store)
    invocation = _invocation(now)
    driver = stack.create_tool_execution_driver(
        lease=lease,
        lease_renewal_interval=_RENEWAL_INTERVAL,
    )
    try:
        task = asyncio.create_task(
            driver.execute(
                BoundedAgentExecutor(),
                adapter,
                invocation,
                _descriptor(),
                _context(),
                final_admission=None,
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=datetime.now(UTC),
            )
        )
        await asyncio.wait_for(adapter.entered.wait(), timeout=2)
        renewed_at = await _wait_for_renewal(store, acquired_at=lease.acquired_at)

        adapter.release.set()
        result = await asyncio.wait_for(task, timeout=2)
        assert result.status is ToolResultStatus.SUCCEEDED

        current = await store.get_current(_DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.ACTIVE
        assert current.metadata.next_operation is CheckpointNextOperation.VALIDATE_RESULT
        terminal_attempt = current.metadata.active_attempt
        assert terminal_attempt is not None
        assert terminal_attempt.status is ExecutionAttemptStatus.SUCCEEDED

        stable = await store.lease_manager.get_current(
            _DURABLE_RUN_ID,
            now=datetime.now(UTC),
        )
        assert stable is not None
        assert stable.acquired_at >= renewed_at
        stable_acquired_at = stable.acquired_at
        await asyncio.sleep(0.04)
        after = await store.lease_manager.get_current(
            _DURABLE_RUN_ID,
            now=datetime.now(UTC),
        )
        assert after is not None
        assert after.acquired_at == stable_acquired_at
    finally:
        await stack.close()
