from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.durable_tool import DurableToolAttemptBinding, DurableToolPreSubmitValidator
from phoenix_os.agent.errors import AgentLimitExceededError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 9, 7, 12, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
INVOCATION_TIME = NOW + timedelta(seconds=2)
PREPARE_TIME = NOW + timedelta(seconds=3)
SUBMIT_TIME = NOW + timedelta(seconds=4)

DURABLE_RUN_ID = DurableAgentRunId(UUID("12000000-0000-0000-0000-000000000042"))
AGENT_RUN_ID = AgentRunId(UUID("22000000-0000-0000-0000-000000000042"))
STEP_ID = AgentStepId(UUID("32000000-0000-0000-0000-000000000042"))
CALL_ID = ToolCallId(UUID("42000000-0000-0000-0000-000000000042"))
MODEL_ATTEMPT_ID = ExecutionAttemptId(UUID("52000000-0000-0000-0000-000000000042"))


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
            checkpoint_id=CheckpointId(UUID("62000000-0000-0000-0000-000000000042")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="durable-pre-submit-validator-test",
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
        adapter_id="durable-pre-submit-validator-test",
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


class _RejectingValidator:
    def __init__(self) -> None:
        self.calls = 0

    def validate_submission(
        self,
        binding: DurableToolAttemptBinding,
        prepared_checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> None:
        self.calls += 1
        assert binding.invocation.call_id == CALL_ID
        assert prepared_checkpoint.durable_run_id == DURABLE_RUN_ID
        assert prepared_checkpoint.run_version != binding.checkpoint.run_version
        attempt = prepared_checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.PREPARED
        assert attempt.started_at is None
        assert now == SUBMIT_TIME
        raise AgentLimitExceededError()


class _AllowingValidator:
    def __init__(self) -> None:
        self.calls = 0

    def validate_submission(
        self,
        binding: DurableToolAttemptBinding,
        prepared_checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> None:
        self.calls += 1
        assert binding.invocation.call_id == CALL_ID
        attempt = prepared_checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.PREPARED
        assert attempt.started_at is None
        assert now == SUBMIT_TIME


class _ObservingAdapter:
    adapter_id = "durable-pre-submit-validator-test"
    tool_id = ToolId("lookup")

    def __init__(self, store: InMemoryDurableRunStore) -> None:
        self._store = store
        self.calls = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.calls += 1
        current = await self._store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.STARTED
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "fixed"},
            started_at=SUBMIT_TIME,
            completed_at=SUBMIT_TIME,
        )


@pytest.mark.asyncio
async def test_limit_rejection_is_persisted_before_started_and_blocks_adapter_io() -> None:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    validator = _RejectingValidator()
    adapter = _ObservingAdapter(store)
    assert isinstance(validator, DurableToolPreSubmitValidator)

    try:
        lease = await store.lease_manager.acquire(
            DURABLE_RUN_ID,
            owner_id="durable-pre-submit-validator-test",
            now=LEASE_TIME,
        )
        driver = stack.create_tool_execution_driver(
            lease=lease,
            pre_submit_validator=validator,
            clock=lambda: SUBMIT_TIME,
        )

        with pytest.raises(AgentLimitExceededError):
            await driver.execute(
                BoundedAgentExecutor(clock=lambda: SUBMIT_TIME),
                adapter,
                _invocation(),
                _descriptor(),
                _context(),
                final_admission=None,
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
            )

        assert validator.calls == 1
        assert adapter.calls == 0
        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.FAILED
        assert attempt.started_at is None
        assert attempt.error_code == "limit_exceeded"
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_runtime_stack_transports_validator_to_last_mile_before_adapter_dispatch() -> None:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    validator = _AllowingValidator()
    adapter = _ObservingAdapter(store)

    try:
        lease = await store.lease_manager.acquire(
            DURABLE_RUN_ID,
            owner_id="durable-pre-submit-validator-test",
            now=LEASE_TIME,
        )
        before = await store.lease_manager.get_current(lease.run_id, now=LEASE_TIME)
        driver = stack.create_tool_execution_driver(
            lease=lease,
            pre_submit_validator=validator,
            clock=lambda: SUBMIT_TIME,
        )
        assert driver._pre_submit_validator is validator

        result = await driver.execute(
            BoundedAgentExecutor(clock=lambda: SUBMIT_TIME),
            adapter,
            _invocation(),
            _descriptor(),
            _context(),
            final_admission=None,
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
        )

        after = await store.lease_manager.get_current(lease.run_id, now=SUBMIT_TIME)
        assert validator.calls == 1
        assert adapter.calls == 1
        assert result.status is ToolResultStatus.SUCCEEDED
        assert before == lease
        assert after == lease
    finally:
        await stack.close()
