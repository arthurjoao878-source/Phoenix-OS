from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunStatus,
    ToolInvocationRequest,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    StaticDurableCompatibilityValidator,
)
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
    IndeterminateReason,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentTimeoutError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnRequest,
    AgentModelTurnResult,
)
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentService
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.events import EventBus
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

DURABLE_RUN_ID = DurableAgentRunId(UUID("12000000-0000-0000-0000-000000000038"))
AGENT_RUN_ID = AgentRunId(UUID("22000000-0000-0000-0000-000000000038"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _request(
    configuration: AgentServiceConfiguration,
    *,
    now: datetime,
) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "bounded durable failure matrix",
            ),
        ),
        limits=configuration.limits,
        run_id=AGENT_RUN_ID,
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )


def _checkpoint(
    request: AgentRunRequest,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("52000000-0000-0000-0000-000000000038")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=None,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="s5c1-live-failure-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=request.created_at,
                    deadline=request.deadline,
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=request.deadline + timedelta(days=1),
            ),
            created_at=request.created_at,
            digest=_digest("0"),
        )
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


class _RunAuthorizer:
    async def authorize(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
    ) -> None:
        assert request.run_id == AGENT_RUN_ID
        assert context.authenticated


class _ModelAuthorizer:
    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        assert request.correlation_id == str(AGENT_RUN_ID)
        assert context.authenticated


class _ToolAuthorizer:
    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        del request, descriptor, context
        raise AssertionError("S5c1 failure matrix must not reach tool authorization")


class _FailingAfterStartedAdapter:
    adapter_id = "s5c1-failing-after-started"

    def __init__(
        self,
        store: InMemoryDurableRunStore,
        failure_type: type[Exception],
    ) -> None:
        self._store = store
        self._failure_type = failure_type
        self.calls = 0

    async def complete_turn(
        self,
        request: AgentModelTurnRequest,
    ) -> AgentModelTurnResult:
        self.calls += 1

        current = await self._store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.step_id == request.step_id

        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.agent_run_id == request.run_id
        assert attempt.step_id == request.step_id
        assert attempt.status is ExecutionAttemptStatus.STARTED

        raise self._failure_type()


def _service(
    configuration: AgentServiceConfiguration,
    adapter: AgentModelTurnAdapter,
    *,
    now: datetime,
) -> AgentService:
    registry = ToolRegistry()
    admission = AgentAdmissionController()

    loop = AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=_ModelAuthorizer(),
        tool_authorizer=_ToolAuthorizer(),
        model_adapter=adapter,
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: now),
        admission=admission,
        clock=lambda: now,
    )

    return AgentService(
        loop,
        registry,
        admission,
        configuration,
        events=EventBus(),
        model_adapter=adapter,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_type",
    (
        pytest.param(
            AgentCancelledError,
            id="cancelled-during-dispatch",
        ),
        pytest.param(
            AgentTimeoutError,
            id="timeout-during-dispatch",
        ),
        pytest.param(
            AgentServiceUnavailableError,
            id="provider-unavailable-during-dispatch",
        ),
    ),
)
async def test_live_durable_restart_never_replays_indeterminate_model_attempt(
    failure_type: type[Exception],
) -> None:
    now = datetime.now(UTC)
    configuration = _configuration()
    request = _request(configuration, now=now)

    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(request))

    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )

    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="s5c1-live-failure-worker",
        now=now,
    )

    adapter = _FailingAfterStartedAdapter(
        store,
        failure_type,
    )

    try:
        first_service = _service(
            configuration,
            adapter,
            now=now,
        )
        first_driver = stack.create_model_turn_execution_driver(
            lease=lease,
        )

        await first_service.start(RuntimeContext(services={}))
        try:
            first_result = await first_service.run(
                request,
                _context(),
                _model_turn_execution_driver=first_driver,
            )
        finally:
            await first_service.stop(RuntimeContext(services={}))

        if failure_type is AgentCancelledError:
            expected_status = AgentRunStatus.CANCELLED
            expected_error_code = AgentCancelledError.code.value
        elif failure_type is AgentTimeoutError:
            expected_status = AgentRunStatus.FAILED
            expected_error_code = AgentTimeoutError.code.value
        else:
            assert failure_type is AgentServiceUnavailableError
            expected_status = AgentRunStatus.FAILED
            expected_error_code = AgentServiceUnavailableError.code.value
        assert first_result.status is expected_status
        assert first_result.error_code == expected_error_code
        assert adapter.calls == 1

        indeterminate = await store.get_current(DURABLE_RUN_ID)
        assert indeterminate is not None
        assert indeterminate.status is DurableRunStatus.INDETERMINATE_MODEL
        assert indeterminate.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW

        attempt = indeterminate.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.INDETERMINATE
        assert attempt.indeterminate_reason is IndeterminateReason.PROVIDER_STATUS_UNKNOWN

        history_before_restart = await store.list_history(
            DURABLE_RUN_ID,
            limit=16,
        )

        restart_service = _service(
            configuration,
            adapter,
            now=now,
        )
        restart_driver = stack.create_model_turn_execution_driver(
            lease=lease,
        )

        await restart_service.start(RuntimeContext(services={}))
        try:
            restart_result = await restart_service.run(
                request,
                _context(),
                _model_turn_execution_driver=restart_driver,
            )
        finally:
            await restart_service.stop(RuntimeContext(services={}))

        assert restart_result.status is AgentRunStatus.FAILED
        assert restart_result.error_code == AgentStateConflictError.code.value
        assert adapter.calls == 1
        assert await store.get_current(DURABLE_RUN_ID) == indeterminate
        assert (
            await store.list_history(
                DURABLE_RUN_ID,
                limit=16,
            )
            == history_before_restart
        )

    finally:
        await stack.close()
