from dataclasses import fields

import pytest

from phoenix_os.agent import AgentId, ToolId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedCapabilityProfileBinding,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedLocalTransformBinding,
    IntegratedToolBindingKind,
)


def _policy() -> IntegratedDataFlowPolicy:
    return IntegratedDataFlowPolicy(
        (
            IntegratedDataFlowRoute(
                route_id="browser-model",
                source_kind=IntegratedDataSourceKind.BROWSER,
                sink=IntegratedDataSink.MODEL,
                disposition=IntegratedDataFlowDisposition.ALLOW,
            ),
            IntegratedDataFlowRoute(
                route_id="browser-result",
                source_kind=IntegratedDataSourceKind.BROWSER,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                requires_audience_match=True,
            ),
        )
    )


def _profile() -> IntegratedExecutionProfile:
    browser = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id="browser:profile/supplier-research",
        generation=4,
    )
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("supplier-research"),
        generation=IntegratedExecutionProfileGeneration(3),
        agent_id=AgentId("research-agent"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id="integrated.plan.update",
                advisory_state_keys=("plan",),
            ),
            IntegratedDownstreamBridgeBinding(
                tool_id=ToolId("research.supplier"),
                boundary=IntegratedDownstreamBoundary.BROWSER,
                binding_id=browser.binding_id,
                generation=browser.generation,
                action_family="browser.research",
            ),
        ),
        browser_profile_binding=browser,
        data_flow_policy=_policy(),
    )


def test_local_transform_is_structurally_separate_from_downstream_bridge_authority() -> None:
    local = IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id="integrated.plan.update",
        advisory_state_keys=("plan",),
    )
    assert local.kind is IntegratedToolBindingKind.LOCAL_TRANSFORM

    names = {item.name for item in fields(IntegratedLocalTransformBinding)}
    for forbidden in (
        "adapter",
        "network_profile",
        "browser_profile",
        "workspace",
        "memory",
        "host",
        "secret",
        "credential",
        "callback",
    ):
        assert forbidden not in names

    with pytest.raises(ValueError, match="only advisory plan"):
        IntegratedLocalTransformBinding(
            tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
            transform_id="integrated.plan.update",
            advisory_state_keys=("plan", "authority"),
        )


def test_downstream_bridge_binds_exact_boundary_identity_generation_and_action_family() -> None:
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId("research.supplier"),
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id="browser:profile/supplier-research",
        generation=4,
        action_family="browser.research",
    )
    assert bridge.kind is IntegratedToolBindingKind.DOWNSTREAM_BRIDGE
    assert bridge.generation == 4

    with pytest.raises(ValueError, match="exact profile generation"):
        IntegratedDownstreamBridgeBinding(
            tool_id=ToolId("network.fetch"),
            boundary=IntegratedDownstreamBoundary.NETWORK,
            binding_id="network:profile/research",
            action_family="network.http",
        )


def test_profile_rejects_duplicate_missing_or_substituted_tool_bindings() -> None:
    profile = _profile()
    assert profile.require_tool_binding(ToolId("research.supplier")).kind is (
        IntegratedToolBindingKind.DOWNSTREAM_BRIDGE
    )

    duplicate = profile.tool_bindings[0]
    with pytest.raises(ValueError, match="duplicate tool"):
        IntegratedExecutionProfile(
            profile_id=IntegratedExecutionProfileId("duplicate"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=AgentId("research-agent"),
            tool_bindings=(duplicate, duplicate),
            data_flow_policy=_policy(),
        )

    with pytest.raises(ValueError, match="configured capability"):
        IntegratedExecutionProfile(
            profile_id=IntegratedExecutionProfileId("missing-browser"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=AgentId("research-agent"),
            tool_bindings=(
                IntegratedDownstreamBridgeBinding(
                    tool_id=ToolId("research.supplier"),
                    boundary=IntegratedDownstreamBoundary.BROWSER,
                    binding_id="browser:profile/supplier-research",
                    generation=4,
                    action_family="browser.research",
                ),
            ),
            data_flow_policy=_policy(),
        )

    configured = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id="browser:profile/supplier-research",
        generation=4,
    )
    with pytest.raises(ValueError, match="does not match"):
        IntegratedExecutionProfile(
            profile_id=IntegratedExecutionProfileId("substituted-browser"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=AgentId("research-agent"),
            tool_bindings=(
                IntegratedDownstreamBridgeBinding(
                    tool_id=ToolId("research.supplier"),
                    boundary=IntegratedDownstreamBoundary.BROWSER,
                    binding_id="browser:profile/other",
                    generation=4,
                    action_family="browser.research",
                ),
            ),
            browser_profile_binding=configured,
            data_flow_policy=_policy(),
        )


def test_reserved_plan_update_tool_cannot_be_reclassified_as_bridge() -> None:
    browser = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id="browser:profile/supplier-research",
        generation=1,
    )
    with pytest.raises(ValueError, match="LOCAL_TRANSFORM"):
        IntegratedExecutionProfile(
            profile_id=IntegratedExecutionProfileId("bad-plan-binding"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=AgentId("research-agent"),
            tool_bindings=(
                IntegratedDownstreamBridgeBinding(
                    tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                    boundary=IntegratedDownstreamBoundary.BROWSER,
                    binding_id=browser.binding_id,
                    generation=browser.generation,
                    action_family="browser.research",
                ),
            ),
            browser_profile_binding=browser,
            data_flow_policy=_policy(),
        )


def test_profile_generation_and_catalog_are_positive_finite_server_owned_data() -> None:
    profile = _profile()
    catalog = IntegratedExecutionProfileCatalog((profile,))

    assert catalog.require_profile(profile.profile_id) is profile
    assert catalog.profile_ids == (profile.profile_id,)

    with pytest.raises(ValueError):
        IntegratedExecutionProfileGeneration(0)
    with pytest.raises(ValueError, match="duplicate profile"):
        IntegratedExecutionProfileCatalog((profile, profile))
