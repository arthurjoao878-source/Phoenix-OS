from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    ToolInvocationRequest,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnRequest,
    AgentModelTurnResult,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
)
from phoenix_os.agent.loop import AgentLoop, AgentModelTurnExecutionDriver
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentService
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.events import EventBus
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext


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
        assert request.agent_id == AgentId("assistant")
        assert context.authenticated


class _ModelAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.requests.append(request)


class _ToolAuthorizer:
    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        del request, descriptor, context
        raise AssertionError("final-only test must not authorize a tool")


class _RecordingModelTurnExecutionDriver:
    def __init__(self) -> None:
        self.turn: AgentModelTurnRequest | None = None
        self.inference_request: InferenceRequest | None = None
        self.context: SecurityContext | None = None
        self.prepare_time: datetime | None = None

    async def execute(
        self,
        executor: BoundedAgentExecutor,
        adapter: AgentModelTurnAdapter,
        turn: AgentModelTurnRequest,
        inference_request: InferenceRequest,
        context: SecurityContext,
        *,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
        prepare_time: datetime,
    ) -> AgentModelTurnResult:
        self.turn = turn
        self.inference_request = inference_request
        self.context = context
        self.prepare_time = prepare_time
        return await executor.complete_model_turn(
            adapter,
            turn,
            inference_request=inference_request,
            context=context,
            timeout_seconds=timeout_seconds,
            cancellation_grace=cancellation_grace,
            cancellation=cancellation,
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
        messages=(AgentMessage(AgentMessageRole.USER, "hello"),),
        limits=configuration.limits,
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )


@pytest.mark.asyncio
async def test_service_routes_exact_authorized_request_through_execution_driver() -> None:
    now = datetime.now(UTC)
    configuration = _configuration()
    adapter = DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))
    registry = ToolRegistry()
    admission = AgentAdmissionController()
    model_authorizer = _ModelAuthorizer()
    loop = AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=model_authorizer,
        tool_authorizer=_ToolAuthorizer(),
        model_adapter=adapter,
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: now),
        admission=admission,
        clock=lambda: now,
    )
    service = AgentService(
        loop,
        registry,
        admission,
        configuration,
        events=EventBus(),
        model_adapter=adapter,
    )
    driver = _RecordingModelTurnExecutionDriver()

    await service.start(RuntimeContext(services={}))
    try:
        result = await service.run(
            _request(configuration, now=now),
            _context(),
            _model_turn_execution_driver=driver,
        )
    finally:
        await service.stop(RuntimeContext(services={}))

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "done"
    assert len(model_authorizer.requests) == 2
    assert driver.inference_request is not None
    assert all(authorized is driver.inference_request for authorized in model_authorizer.requests)
    assert driver.turn is not None
    assert driver.turn.run_id == result.run_id
    assert driver.context == _context()
    assert driver.prepare_time == now


@pytest.mark.asyncio
async def test_loop_rejects_non_driver_before_run_side_effects() -> None:
    now = datetime.now(UTC)
    configuration = _configuration()
    adapter = DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))
    loop = AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=_ModelAuthorizer(),
        tool_authorizer=_ToolAuthorizer(),
        model_adapter=adapter,
        registry=ToolRegistry(),
        executor=BoundedAgentExecutor(clock=lambda: now),
        clock=lambda: now,
    )

    with pytest.raises(TypeError, match="AgentModelTurnExecutionDriver"):
        await loop.run(
            _request(configuration, now=now),
            _context(),
            _model_turn_execution_driver=cast(AgentModelTurnExecutionDriver, object()),
        )
