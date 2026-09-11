from __future__ import annotations

from collections.abc import Mapping
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
)
from phoenix_os.agent.durable_live_binding import StoreBackedDurableToolInvocationBindingProvider
from phoenix_os.agent.durable_live_tool import DurableAgentToolExecutionDriver
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_metadata import DurableCheckpointMetadataProjector
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.durable_tool import DurableToolAttemptBinding
from phoenix_os.agent.durable_tool_execution import (
    DurableToolResultMetadataProjectorFactory,
    execute_durable_tool,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.schemas import ToolInputSchema, ToolOutputSchema, ToolSchema, ToolSchemaType
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 9, 7, 1, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
INVOCATION_TIME = NOW + timedelta(seconds=2)
BIND_TIME = NOW + timedelta(seconds=3)
PREPARE_TIME = NOW + timedelta(seconds=4)
RESULT_TIME = NOW + timedelta(seconds=5)

DURABLE_RUN_ID = DurableAgentRunId(UUID("14000000-0000-0000-0000-000000000039"))
AGENT_RUN_ID = AgentRunId(UUID("24000000-0000-0000-0000-000000000039"))
STEP_ID = AgentStepId(UUID("34000000-0000-0000-0000-000000000039"))
CALL_ID = ToolCallId(UUID("44000000-0000-0000-0000-000000000039"))
MODEL_ATTEMPT_ID = ExecutionAttemptId(UUID("54000000-0000-0000-0000-000000000039"))


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
            checkpoint_id=CheckpointId(UUID("64000000-0000-0000-0000-000000000039")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="rfc0039-result-projection-test",
                next_operation=CheckpointNextOperation.VALIDATE_PROPOSAL,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=_model_attempt(),
                metadata={"fixture": "base"},
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
        adapter_id="durable-tool-result-projection-test",
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


async def _environment() -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
]:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="rfc0039-result-projection-test",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    return store, lease, recorder


class _SuccessfulTool:
    adapter_id = "durable-tool-result-projection-test"
    tool_id = ToolId("lookup")

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "live-content-that-must-not-be-persisted"},
            started_at=RESULT_TIME,
            completed_at=RESULT_TIME,
        )


class _MarkerProjector:
    def project_metadata(
        self,
        current: CheckpointEnvelope,
        *,
        checkpoint_id: CheckpointId,
        status: DurableRunStatus,
        step_id: AgentStepId | None,
        next_operation: CheckpointNextOperation,
        active_attempt: ExecutionAttempt | None,
        metadata: Mapping[str, str],
    ) -> Mapping[str, str]:
        assert current.durable_run_id == DURABLE_RUN_ID
        assert isinstance(checkpoint_id, CheckpointId)
        assert status is DurableRunStatus.ACTIVE
        assert step_id == STEP_ID
        assert next_operation is CheckpointNextOperation.VALIDATE_RESULT
        assert active_attempt is not None
        assert active_attempt.status is ExecutionAttemptStatus.SUCCEEDED
        projected = dict(metadata)
        projected["rfc0039.test.result_evidence"] = "captured"
        return projected


class _RecordingFactory:
    def __init__(self) -> None:
        self.binding: DurableToolAttemptBinding | None = None
        self.result: ToolInvocationResult | None = None
        self.calls = 0

    def create_projector(
        self,
        binding: DurableToolAttemptBinding,
        result: ToolInvocationResult,
    ) -> DurableCheckpointMetadataProjector | None:
        self.calls += 1
        self.binding = binding
        self.result = result
        return _MarkerProjector()


class _FailingFactory:
    def create_projector(
        self,
        binding: DurableToolAttemptBinding,
        result: ToolInvocationResult,
    ) -> DurableCheckpointMetadataProjector | None:
        del binding, result
        raise RuntimeError("private result projector failure")


@pytest.mark.asyncio
async def test_success_result_is_projected_before_terminal_checkpoint_without_payload() -> None:
    store, lease, recorder = await _environment()
    descriptor = _descriptor()
    invocation = _invocation()
    provider = StoreBackedDurableToolInvocationBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    factory = _RecordingFactory()
    try:
        binding = await provider.bind(invocation, descriptor, now=BIND_TIME)
        executed = await execute_durable_tool(
            binding,
            recorder,
            BoundedAgentExecutor(clock=lambda: RESULT_TIME),
            _SuccessfulTool(),
            context=_context(),
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
            result_metadata_projector_factory=factory,
            clock=lambda: RESULT_TIME,
        )

        assert factory.calls == 1
        assert factory.binding is binding
        assert factory.result is executed.result
        assert executed.checkpoint.metadata.metadata == {
            "fixture": "base",
            "rfc0039.test.result_evidence": "captured",
        }
        assert "live-content-that-must-not-be-persisted" not in repr(
            executed.checkpoint.metadata.metadata
        )
        current = await store.get_current(DURABLE_RUN_ID)
        assert current == executed.checkpoint
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_factory_failure_after_external_return_fails_closed_before_terminal_append() -> None:
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
        with pytest.raises(AgentStateConflictError):
            await execute_durable_tool(
                binding,
                recorder,
                BoundedAgentExecutor(clock=lambda: RESULT_TIME),
                _SuccessfulTool(),
                context=_context(),
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
                result_metadata_projector_factory=_FailingFactory(),
                clock=lambda: RESULT_TIME,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.metadata.next_operation is CheckpointNextOperation.TOOL_INVOCATION
        assert current.metadata.active_attempt is not None
        assert current.metadata.active_attempt.status is ExecutionAttemptStatus.STARTED
        assert current.metadata.metadata == {"fixture": "base"}
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_live_driver_threads_result_projector_factory_to_durable_execution() -> None:
    store, lease, recorder = await _environment()
    descriptor = _descriptor()
    invocation = _invocation()
    provider = StoreBackedDurableToolInvocationBindingProvider(
        store=store,
        lease_manager=store.lease_manager,
        lease=lease,
    )
    factory = _RecordingFactory()
    driver = DurableAgentToolExecutionDriver(
        binding_provider=provider,
        recorder=recorder,
        result_metadata_projector_factory=factory,
        clock=lambda: RESULT_TIME,
    )
    try:
        result = await driver.execute(
            BoundedAgentExecutor(clock=lambda: RESULT_TIME),
            _SuccessfulTool(),
            invocation,
            descriptor,
            _context(),
            final_admission=None,
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
        )

        assert factory.calls == 1
        assert factory.result is result
        assert driver.last_checkpoint is not None
        assert (
            driver.last_checkpoint.metadata.metadata["rfc0039.test.result_evidence"] == "captured"
        )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_runtime_stack_threads_factory_without_taking_lease_ownership() -> None:
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    factory = _RecordingFactory()
    try:
        lease = await store.lease_manager.acquire(
            DurableAgentRunId(),
            owner_id="rfc0039-result-projection-test",
            now=NOW,
        )
        before = await store.lease_manager.get_current(lease.run_id, now=NOW)

        driver = stack.create_tool_execution_driver(
            lease=lease,
            result_metadata_projector_factory=factory,
        )

        after = await store.lease_manager.get_current(lease.run_id, now=NOW)
        assert isinstance(factory, DurableToolResultMetadataProjectorFactory)
        assert isinstance(driver, DurableAgentToolExecutionDriver)
        assert driver._result_metadata_projector_factory is factory
        assert before == after
    finally:
        await stack.close()


def test_live_driver_rejects_invalid_result_projector_factory() -> None:
    class _Provider:
        async def bind(
            self,
            invocation: ToolInvocationRequest,
            descriptor: ToolDescriptor,
            *,
            now: datetime,
        ) -> DurableToolAttemptBinding:
            del invocation, descriptor, now
            raise AssertionError("not called")

    recorder = StoreBackedDurableExecutionAttemptRecorder(store=InMemoryDurableRunStore())
    with pytest.raises(TypeError, match="result_metadata_projector_factory"):
        DurableAgentToolExecutionDriver(
            binding_provider=_Provider(),
            recorder=recorder,
            result_metadata_projector_factory=object(),  # type: ignore[arg-type]
        )
