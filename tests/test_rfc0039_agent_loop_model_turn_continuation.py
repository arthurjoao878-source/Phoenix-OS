from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    ToolDescriptor,
    ToolInvocationRequest,
    ToolRegistry,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext

_START = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)
_NOW = _START + timedelta(seconds=10)


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "hello"),),
        created_at=_START,
        deadline=_START + timedelta(minutes=5),
    )


class _RunAuthorizer:
    def __init__(self) -> None:
        self.requests: list[AgentRunRequest] = []

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)


class _ModelAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)


class _ToolAuthorizer:
    def __init__(self) -> None:
        self.requests: list[ToolInvocationRequest] = []

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        del descriptor
        assert context.authenticated
        self.requests.append(request)


def _loop() -> tuple[AgentLoop, _RunAuthorizer, _ModelAuthorizer]:
    run_authorizer = _RunAuthorizer()
    model_authorizer = _ModelAuthorizer()
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=model_authorizer,
        tool_authorizer=_ToolAuthorizer(),
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        registry=ToolRegistry(),
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        clock=lambda: _NOW,
    )
    return loop, run_authorizer, model_authorizer


def _restored_budget(request: AgentRunRequest) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=2,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=17,
        tool_result_bytes=19,
        input_tokens=23,
        output_tokens=29,
        started_at=request.created_at,
        deadline=request.deadline,
    )


@pytest.mark.asyncio
async def test_model_turn_continuation_preserves_budget_and_fresh_authorization() -> None:
    request = _request()
    loop, run_authorizer, model_authorizer = _loop()
    budget = _restored_budget(request)

    result = await loop.run(
        request,
        _context(),
        _restored_budget=budget,
    )

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "done"
    assert result.model_turns == budget.model_turns + 1
    assert result.tool_calls == budget.tool_calls
    assert len(run_authorizer.requests) == 2
    assert run_authorizer.requests[0] is request
    assert run_authorizer.requests[1] is request
    assert len(model_authorizer.requests) == 2
    assert model_authorizer.requests[0] is model_authorizer.requests[1]


@pytest.mark.asyncio
async def test_model_turn_continuation_rejects_budget_request_time_mismatch() -> None:
    request = _request()
    loop, _run_authorizer, _model_authorizer = _loop()
    budget = AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=request.created_at + timedelta(seconds=1),
        deadline=request.deadline,
    )

    with pytest.raises(AgentStateConflictError):
        await loop.run(
            request,
            _context(),
            _restored_budget=budget,
        )


@pytest.mark.asyncio
async def test_normal_agent_loop_run_still_uses_fresh_zero_budget() -> None:
    loop, _run_authorizer, _model_authorizer = _loop()

    result = await loop.run(_request(), _context())

    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_turns == 1
    assert result.tool_calls == 0
