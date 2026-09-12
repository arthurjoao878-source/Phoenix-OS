from __future__ import annotations

from datetime import UTC, datetime

import pytest

from phoenix_os.agent import AgentId, AgentRunId, AgentToolConfiguration
from phoenix_os.agent.composition import AgentRuntimeStack, create_agent_runtime_stack
from phoenix_os.agent.configuration import AgentServiceConfiguration
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
    compose_server_owned_durable_integrated_task_resume_support,
    compose_server_owned_durable_integrated_task_runtime,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.durable_context_resupply import (
    IntegratedDurableContextResupplyCoordinator,
)
from phoenix_os.integrated_agent.durable_live_revalidation import (
    AgentLoopIntegratedDurableRecoveryLiveRevalidator,
    IntegratedDurableRecoveryLiveProbes,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
    IntegratedDurableRecoveryResumeGate,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

_NOW = datetime(2026, 9, 8, 18, tzinfo=UTC)
_AGENT_ID = AgentId("assistant")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("development"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT_ID,
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


def _compatibility() -> DurableCompatibilityPolicy:
    return DurableCompatibilityPolicy(
        agent_id=_AGENT_ID,
        current=CompatibilityDigests(
            configuration=_digest("a"),
            tool_registry=_digest("b"),
            model_provider=_digest("c"),
            checkpoint_codec=_digest("d"),
        ),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
    )


def _agent_stack(
    planner: IntegratedPlanner,
    guard: IntegratedAgentExecutionGuard,
) -> AgentRuntimeStack:
    configuration = AgentServiceConfiguration(
        agent_id=_AGENT_ID,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(planner.descriptor),),
    )
    return create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(planner.resource_resolver,),
        tool_adapters=(planner.adapter,),
        policy=PolicyEngine(),
        execution_interceptor=guard,
    )


def _durable_stack(policy: DurableCompatibilityPolicy) -> DurableAgentRuntimeStack:
    store = InMemoryDurableRunStore()
    return create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator((policy,)),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
    )


def _cancelled(_run_id: AgentRunId) -> bool:
    return False


def _context_current(_provenance: IntegratedDataProvenance) -> bool:
    return True


@pytest.mark.asyncio
async def test_production_resume_support_reuses_exact_planner_and_durable_stack() -> None:
    profile = _profile()
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(binding, IntegratedLocalTransformBinding)
    composition = IntegratedAgentToolComposition(
        profile,
        (integrated_plan_update_registration(binding, planner),),
    )
    agent_stack = _agent_stack(planner, guard)
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
            composition=composition,
            clock=lambda: _NOW,
        )

        assert owner.planner is planner
        assert owner.runtime.planner is planner
        assert owner.durable_stack is durable_stack

        context = SecurityContext(
            principal="user:operator",
            principal_type=PrincipalType.USER,
            authenticated=True,
        )
        probes = IntegratedDurableRecoveryLiveProbes(
            cancellation_probe=_cancelled,
            context_freshness_probe=_context_current,
        )
        support = compose_server_owned_durable_integrated_task_resume_support(
            owner,
            context=context,
            probes=probes,
        )

        assert support.context is context
        assert isinstance(
            support.live_revalidator,
            AgentLoopIntegratedDurableRecoveryLiveRevalidator,
        )
        assert isinstance(support.resume_gate, IntegratedDurableRecoveryResumeGate)
        assert isinstance(
            support.history_validator,
            IntegratedDurableRecoveryHistoryValidator,
        )
        assert isinstance(
            support.context_resupply,
            IntegratedDurableContextResupplyCoordinator,
        )
        assert support.context_resupply.history_validator is support.history_validator
    finally:
        await durable_stack.close()
