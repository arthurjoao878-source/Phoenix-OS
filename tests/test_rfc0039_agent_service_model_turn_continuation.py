from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentModelTurnRequest,
    AgentModelTurnResult,
    AgentRunRequest,
    AgentRunStatus,
    AgentServiceConfiguration,
    AgentServiceState,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    agent_run_resource,
    create_agent_runtime_stack,
)
from phoenix_os.agent.errors import AgentServiceUnavailableError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import ModelId, ModelProviderId, inference_model_resource
from phoenix_os.policy import PolicyEffect, PolicyEngine, PolicyRule, PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-rfc0039-resume",
    )


def _runtime_context() -> RuntimeContext:
    return RuntimeContext(services={})


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
    )


def _request(configuration: AgentServiceConfiguration) -> AgentRunRequest:
    created_at = datetime.now(UTC)
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, "hello"),),
        limits=configuration.limits,
        created_at=created_at,
        deadline=created_at + timedelta(minutes=1),
    )


def _policy(configuration: AgentServiceConfiguration) -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.agent.run",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({agent_run_resource(configuration.agent_id)}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
            PolicyRule(
                rule_id="allow.agent.model",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"model.infer"}),
                resources=frozenset(
                    {
                        inference_model_resource(
                            configuration.provider_id,
                            configuration.model_id,
                        )
                    }
                ),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )


def _budget(request: AgentRunRequest, *, prior_work: bool = True) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=2 if prior_work else 0,
        model_turns=1 if prior_work else 0,
        tool_calls=1 if prior_work else 0,
        model_output_bytes=17 if prior_work else 0,
        tool_result_bytes=19 if prior_work else 0,
        input_tokens=23 if prior_work else 0,
        output_tokens=29 if prior_work else 0,
        started_at=request.created_at,
        deadline=request.deadline,
    )


class _BlockingModelAdapter:
    adapter_id = "blocking-rfc0039-resume-model"

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        del request
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_service_continuation_preserves_same_run_budget_and_health() -> None:
    configuration = _configuration()
    request = _request(configuration)
    restored = _budget(request)
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(),
        tool_adapters=(),
        policy=_policy(configuration),
    )

    await stack.service.start(_runtime_context())
    result = await stack.service.continue_model_turn(
        request,
        _context(),
        restored_budget=restored,
    )
    snapshot = await stack.service.snapshot()

    assert result.run_id == request.run_id
    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_turns == restored.model_turns + 1
    assert result.tool_calls == restored.tool_calls
    assert snapshot.state is AgentServiceState.RUNNING
    assert snapshot.started == 1
    assert snapshot.completed == 1
    assert snapshot.active == 0

    await stack.service.stop(_runtime_context())


@pytest.mark.asyncio
async def test_service_continuation_is_registered_and_duplicate_run_is_rejected() -> None:
    configuration = _configuration()
    request = _request(configuration)
    adapter = _BlockingModelAdapter()
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=adapter,
        tool_resolvers=(),
        tool_adapters=(),
        policy=_policy(configuration),
    )
    token = AgentCancellationToken()

    await stack.service.start(_runtime_context())
    task = asyncio.create_task(
        stack.service.continue_model_turn(
            request,
            _context(),
            restored_budget=_budget(request, prior_work=False),
            cancellation=token,
        )
    )
    await asyncio.wait_for(adapter.started.wait(), timeout=1)

    active = await stack.service.snapshot()
    assert active.active == 1
    assert active.started == 1

    with pytest.raises(AgentServiceUnavailableError):
        await stack.service.run(request, _context())

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    finished = await stack.service.snapshot()
    assert finished.active == 0
    assert finished.cancelled == 1

    await stack.service.stop(_runtime_context())


@pytest.mark.asyncio
async def test_normal_service_run_still_uses_fresh_agent_loop_semantics() -> None:
    configuration = _configuration()
    request = _request(configuration)
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(),
        tool_adapters=(),
        policy=_policy(configuration),
    )

    await stack.service.start(_runtime_context())
    result = await stack.service.run(request, _context())

    assert result.run_id == request.run_id
    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_turns == 1
    assert result.tool_calls == 0

    await stack.service.stop(_runtime_context())
