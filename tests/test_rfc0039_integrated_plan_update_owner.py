from __future__ import annotations

import pytest

from phoenix_os.agent import AgentId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedAgentConfigurationError,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedLocalTransformBinding,
    IntegratedPlanner,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.planning import require_integrated_plan_update_owner


def _binding() -> IntegratedLocalTransformBinding:
    return IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id="integrated.plan.update",
        advisory_state_keys=("plan",),
    )


def _profile(binding: IntegratedLocalTransformBinding) -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("integrated-research"),
        generation=IntegratedExecutionProfileGeneration(7),
        agent_id=AgentId("research-agent"),
        tool_bindings=(binding,),
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


def test_reviewed_plan_registration_recovers_exact_original_planner() -> None:
    binding = _binding()
    planner = IntegratedPlanner(_profile(binding))
    registration = integrated_plan_update_registration(binding, planner)

    owner = require_integrated_plan_update_owner(
        descriptor=registration.descriptor,
        resolver=registration.resolver,
        adapter=registration.adapter,
    )

    assert owner is planner
    assert owner.resource_resolver is registration.resolver
    assert owner.adapter is registration.adapter


def test_owner_seam_rejects_resolver_from_different_planner() -> None:
    binding = _binding()
    profile = _profile(binding)
    planner = IntegratedPlanner(profile)
    other = IntegratedPlanner(profile)
    registration = integrated_plan_update_registration(binding, planner)

    with pytest.raises(IntegratedAgentConfigurationError):
        require_integrated_plan_update_owner(
            descriptor=registration.descriptor,
            resolver=other.resource_resolver,
            adapter=registration.adapter,
        )


def test_owner_seam_rejects_adapter_from_different_planner() -> None:
    binding = _binding()
    profile = _profile(binding)
    planner = IntegratedPlanner(profile)
    other = IntegratedPlanner(profile)
    registration = integrated_plan_update_registration(binding, planner)

    with pytest.raises(IntegratedAgentConfigurationError):
        require_integrated_plan_update_owner(
            descriptor=registration.descriptor,
            resolver=registration.resolver,
            adapter=other.adapter,
        )
