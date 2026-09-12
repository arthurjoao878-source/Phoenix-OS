from __future__ import annotations

from datetime import UTC, datetime

import pytest

from phoenix_os.agent.composition import AgentRuntimeStack, create_agent_runtime_stack
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointPayloadProfile,
    CompatibilityDigests,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import (
    DurableAgentRuntimeStack,
    create_durable_agent_runtime_stack,
)
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.control_plane.task_runtime_composition import (
    compose_server_owned_durable_integrated_task_runtime,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
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
from phoenix_os.integrated_agent.durable_recovery import IntegratedDurableRecoveryHistoryValidator
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import PolicyEngine

_NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)
_AGENT_ID = AgentId("assistant")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility(agent_id: AgentId = _AGENT_ID) -> DurableCompatibilityPolicy:
    return DurableCompatibilityPolicy(
        agent_id=agent_id,
        current=CompatibilityDigests(
            configuration=_digest("a"),
            tool_registry=_digest("b"),
            model_provider=_digest("c"),
            checkpoint_codec=_digest("d"),
        ),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
    )


def _profile(agent_id: AgentId = _AGENT_ID) -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("development"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=agent_id,
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
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


def _configuration(agent_id: AgentId = _AGENT_ID) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=agent_id,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _agent_stack(
    guard: IntegratedAgentExecutionGuard,
    *,
    agent_id: AgentId = _AGENT_ID,
) -> AgentRuntimeStack:
    return create_agent_runtime_stack(
        configuration=_configuration(agent_id),
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(),
        tool_adapters=(),
        policy=PolicyEngine(),
        execution_interceptor=guard,
    )


def _durable_stack(
    policy: DurableCompatibilityPolicy,
    *,
    complete_history: bool = True,
) -> DurableAgentRuntimeStack:
    store = InMemoryDurableRunStore()
    history = (
        create_integrated_checkout_durable_history_validator()
        if complete_history
        else IntegratedDurableRecoveryHistoryValidator()
    )
    return create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator((policy,)),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=history,
    )


@pytest.mark.asyncio
async def test_composition_reuses_exact_agent_and_durable_owners() -> None:
    profile = _profile()
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    agent_stack = _agent_stack(guard)
    policy = _compatibility()
    durable_stack = _durable_stack(policy)

    try:
        owner = compose_server_owned_durable_integrated_task_runtime(
            service=agent_stack.service,
            durable_stack=durable_stack,
            profile=profile,
            execution_guard=guard,
            compatibility_policy=policy,
            actor_id="rfc0039-task",
            owner_id="rfc0039-task-runtime",
            clock=lambda: _NOW,
        )

        assert owner.service is agent_stack.service
        assert owner.durable_stack is durable_stack
        assert owner.profile is profile
        assert owner.execution_guard is guard
        assert owner.compatibility_policy is policy
        assert owner.composition is None
        assert owner.admission.service_configuration is agent_stack.service.configuration
        assert owner.admission.profile is profile
        assert owner.root_provider.policy is policy
        assert owner.coordinator.service is agent_stack.service
        assert owner.runtime.service is agent_stack.service
        assert owner.runtime.admission is owner.admission
        assert owner.runtime.execution_guard is guard
        assert owner.runtime.run_executor is owner.coordinator
        assert owner.request_mapper.service_configuration is agent_stack.service.configuration
    finally:
        await durable_stack.close()


@pytest.mark.asyncio
async def test_composition_rejects_compatibility_policy_agent_substitution() -> None:
    profile = _profile()
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    agent_stack = _agent_stack(guard)
    substituted = _compatibility(AgentId("other-agent"))
    durable_stack = _durable_stack(substituted)

    try:
        with pytest.raises(IntegratedAgentConfigurationError):
            compose_server_owned_durable_integrated_task_runtime(
                service=agent_stack.service,
                durable_stack=durable_stack,
                profile=profile,
                execution_guard=guard,
                compatibility_policy=substituted,
                actor_id="rfc0039-task",
                owner_id="rfc0039-task-runtime",
                clock=lambda: _NOW,
            )
    finally:
        await durable_stack.close()


@pytest.mark.asyncio
async def test_composition_rejects_execution_guard_identity_substitution() -> None:
    profile = _profile()
    installed_guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    supplied_guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    agent_stack = _agent_stack(installed_guard)
    policy = _compatibility()
    durable_stack = _durable_stack(policy)

    try:
        with pytest.raises(IntegratedAgentConfigurationError):
            compose_server_owned_durable_integrated_task_runtime(
                service=agent_stack.service,
                durable_stack=durable_stack,
                profile=profile,
                execution_guard=supplied_guard,
                compatibility_policy=policy,
                actor_id="rfc0039-task",
                owner_id="rfc0039-task-runtime",
                clock=lambda: _NOW,
            )
    finally:
        await durable_stack.close()


@pytest.mark.asyncio
async def test_composition_rejects_service_profile_agent_substitution() -> None:
    profile = _profile(AgentId("other-agent"))
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    agent_stack = _agent_stack(guard, agent_id=_AGENT_ID)
    policy = _compatibility(AgentId("other-agent"))
    durable_stack = _durable_stack(policy)

    try:
        with pytest.raises(IntegratedAgentConfigurationError):
            compose_server_owned_durable_integrated_task_runtime(
                service=agent_stack.service,
                durable_stack=durable_stack,
                profile=profile,
                execution_guard=guard,
                compatibility_policy=policy,
                actor_id="rfc0039-task",
                owner_id="rfc0039-task-runtime",
                clock=lambda: _NOW,
            )
    finally:
        await durable_stack.close()


@pytest.mark.asyncio
async def test_composition_rejects_durable_stack_without_checkout_history_order() -> None:
    profile = _profile()
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    agent_stack = _agent_stack(guard)
    policy = _compatibility()
    durable_stack = _durable_stack(policy, complete_history=False)

    try:
        with pytest.raises(
            ValueError,
            match="integrated recovery before checkout-read durable history validation",
        ):
            compose_server_owned_durable_integrated_task_runtime(
                service=agent_stack.service,
                durable_stack=durable_stack,
                profile=profile,
                execution_guard=guard,
                compatibility_policy=policy,
                actor_id="rfc0039-task",
                owner_id="rfc0039-task-runtime",
                clock=lambda: _NOW,
            )
    finally:
        await durable_stack.close()


@pytest.mark.asyncio
async def test_composition_rejects_protected_content_root_policy() -> None:
    profile = _profile()
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    agent_stack = _agent_stack(guard)
    current = CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
        payload_codec=_digest("e"),
    )
    policy = DurableCompatibilityPolicy(
        agent_id=_AGENT_ID,
        current=current,
        payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
        available_protection_key_versions=frozenset({"v1"}),
    )
    durable_stack = _durable_stack(policy)

    try:
        with pytest.raises(
            ValueError,
            match="initial integrated durable roots require metadata-only compatibility",
        ):
            compose_server_owned_durable_integrated_task_runtime(
                service=agent_stack.service,
                durable_stack=durable_stack,
                profile=profile,
                execution_guard=guard,
                compatibility_policy=policy,
                actor_id="rfc0039-task",
                owner_id="rfc0039-task-runtime",
                clock=lambda: _NOW,
            )
    finally:
        await durable_stack.close()
