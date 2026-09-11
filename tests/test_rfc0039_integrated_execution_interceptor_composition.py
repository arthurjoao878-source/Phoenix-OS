from __future__ import annotations

from typing import Any

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.execution_interceptors import ChainedAgentExecutionInterceptor
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.agent.loop import AgentExecutionInterceptor, AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)
from phoenix_os.integrated_agent.runtime import IntegratedAgentRuntime


class _Authorizer:
    async def authorize(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _NoopInterceptor:
    async def before_model_turn(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def before_tool_authorization(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def before_tool_invocation(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def final_tool_admission(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def after_tool_result(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def before_final_output(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _Service:
    def __init__(self, configuration: AgentServiceConfiguration, runtime: AgentLoop) -> None:
        self._configuration = configuration
        self._runtime = runtime

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    @property
    def state(self) -> AgentServiceState:
        return AgentServiceState.CREATED

    @property
    def runtime(self) -> AgentLoop:
        return self._runtime

    async def start(self, _context: Any) -> None:
        return None

    async def stop(self, _context: Any) -> None:
        return None

    async def run(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("service.run must not execute during constructor tests")


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("rfc0039-interceptor-composition"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=AgentId("assistant"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id="integrated.plan.update",
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="user-model",
                    source_kind=IntegratedDataSourceKind.USER_TASK,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                ),
            )
        ),
    )


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _admission(
    profile: IntegratedExecutionProfile,
    configuration: AgentServiceConfiguration,
) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )


def _loop(interceptor: AgentExecutionInterceptor) -> AgentLoop:
    authorizer = _Authorizer()
    return AgentLoop(
        run_authorizer=authorizer,
        model_authorizer=authorizer,
        tool_authorizer=authorizer,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("unused"),)),
        registry=ToolRegistry(),
        execution_interceptor=interceptor,
    )


def _runtime_for(
    execution_guard: IntegratedAgentExecutionGuard,
    interceptor: AgentExecutionInterceptor,
) -> IntegratedAgentRuntime:
    configuration = _configuration()
    return IntegratedAgentRuntime(
        _Service(configuration, _loop(interceptor)),
        _admission(execution_guard.profile, configuration),
        execution_guard=execution_guard,
    )


def _chain(*items: AgentExecutionInterceptor) -> ChainedAgentExecutionInterceptor:
    return ChainedAgentExecutionInterceptor(tuple(items))


def test_runtime_accepts_chain_with_exact_execution_guard_identity() -> None:
    guard = IntegratedAgentExecutionGuard(_profile())
    runtime = _runtime_for(guard, _chain(_NoopInterceptor(), guard))

    assert runtime.execution_guard is guard


def test_runtime_accepts_nested_chain_with_exact_execution_guard_identity() -> None:
    guard = IntegratedAgentExecutionGuard(_profile())
    runtime = _runtime_for(
        guard,
        _chain(_NoopInterceptor(), _chain(guard, _NoopInterceptor())),
    )

    assert runtime.execution_guard is guard


def test_runtime_rejects_chain_without_integrated_execution_guard() -> None:
    guard = IntegratedAgentExecutionGuard(_profile())

    with pytest.raises(IntegratedAgentConfigurationError):
        _runtime_for(guard, _chain(_NoopInterceptor()))


def test_runtime_rejects_chain_with_different_integrated_execution_guard() -> None:
    profile = _profile()
    expected = IntegratedAgentExecutionGuard(profile)
    different = IntegratedAgentExecutionGuard(profile)

    with pytest.raises(IntegratedAgentConfigurationError):
        _runtime_for(expected, _chain(_NoopInterceptor(), different))


def test_runtime_rejects_multiple_integrated_execution_guards() -> None:
    profile = _profile()
    expected = IntegratedAgentExecutionGuard(profile)
    second = IntegratedAgentExecutionGuard(profile)

    with pytest.raises(IntegratedAgentConfigurationError):
        _runtime_for(expected, _chain(expected, second))


def test_runtime_rejects_same_execution_guard_duplicated_in_chain() -> None:
    guard = IntegratedAgentExecutionGuard(_profile())

    with pytest.raises(IntegratedAgentConfigurationError):
        _runtime_for(guard, _chain(guard, guard))
