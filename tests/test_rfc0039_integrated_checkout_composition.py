from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_TOOL_ID,
    CHECKOUT_TOOL_ADAPTER_ID,
    CHECKOUT_TOOL_RESOLVER_ID,
    CheckoutToolAdapter,
    CheckoutToolResourceResolver,
    checkout_integrated_binding_id,
)
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
)
from phoenix_os.agent.checkout_workspace import RegisteredDevelopmentCheckoutAdapter
from phoenix_os.agent.contracts import AgentId, ToolId
from phoenix_os.agent.workspace_authorization import WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_checkout_tool_registration,
    integrated_checkout_tool_registrations,
    integrated_development_checkout_dogfood_profile,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import SecurityContext

_AGENT_ID = AgentId("rfc0039-checkout-integrated")
_PROFILE_ID = IntegratedExecutionProfileId("rfc0039-development-checkout")
_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(1)
_WORKSPACE_ID = UUID("40e3df88-bdfb-47b8-aee0-4ac850592fb9")


class _CheckoutAuthorizer:
    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context


def _checkout(tmp_path: Path) -> RegisteredDevelopmentCheckoutAdapter:
    (tmp_path / "src").mkdir()
    return RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="rfc0039-development",
        generation=7,
        root=tmp_path,
        read_prefixes=("src",),
    )


def _profile(
    checkout: RegisteredDevelopmentCheckoutAdapter,
) -> IntegratedExecutionProfile:
    return integrated_development_checkout_dogfood_profile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        data_flow_policy=IntegratedDataFlowPolicy(),
        registration=checkout.registration,
        durability_profile="rfc0039-development-checkout",
    ).execution_profile


def _bridge(
    profile: IntegratedExecutionProfile,
    tool_id: ToolId,
) -> IntegratedDownstreamBridgeBinding:
    binding = profile.require_tool_binding(tool_id)
    assert isinstance(binding, IntegratedDownstreamBridgeBinding)
    return binding


def test_checkout_profile_uses_stable_workspace_identity_and_exact_generation(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    profile = _profile(checkout)
    registration = checkout.registration

    assert profile.workspace_binding is not None
    assert profile.workspace_binding.boundary is IntegratedDownstreamBoundary.WORKSPACE
    assert profile.workspace_binding.binding_id == checkout_integrated_binding_id(registration)
    assert profile.workspace_binding.generation == registration.generation
    assert profile.tool_ids == (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        CHECKOUT_LIST_TOOL_ID,
        CHECKOUT_READ_TOOL_ID,
    )

    list_binding = _bridge(profile, CHECKOUT_LIST_TOOL_ID)
    read_binding = _bridge(profile, CHECKOUT_READ_TOOL_ID)
    for binding, action in (
        (list_binding, WORKSPACE_LIST_ACTION),
        (read_binding, WORKSPACE_READ_ACTION),
    ):
        assert binding.boundary is IntegratedDownstreamBoundary.WORKSPACE
        assert binding.binding_id == checkout_integrated_binding_id(registration)
        assert binding.generation == registration.generation
        assert binding.action_family == action


@pytest.mark.parametrize(
    ("tool_id", "action"),
    (
        (CHECKOUT_LIST_TOOL_ID, WORKSPACE_LIST_ACTION),
        (CHECKOUT_READ_TOOL_ID, WORKSPACE_READ_ACTION),
    ),
)
def test_checkout_registration_reuses_exact_checkout_surface(
    tmp_path: Path,
    tool_id: ToolId,
    action: str,
) -> None:
    checkout = _checkout(tmp_path)
    profile = _profile(checkout)
    binding = _bridge(profile, tool_id)

    registration = integrated_checkout_tool_registration(
        binding,
        checkout,
        _CheckoutAuthorizer(),
    )

    assert registration.binding is binding
    assert registration.descriptor.tool_id == tool_id
    assert registration.descriptor.resolver_id == CHECKOUT_TOOL_RESOLVER_ID
    assert registration.descriptor.adapter_id == CHECKOUT_TOOL_ADAPTER_ID
    assert registration.descriptor.metadata["surface"] == "development-checkout"
    assert registration.binding.action_family == action
    assert isinstance(registration.resolver, CheckoutToolResourceResolver)
    assert registration.resolver.registration is checkout.registration
    assert isinstance(registration.adapter, CheckoutToolAdapter)
    assert registration.adapter.registration is checkout.registration


def test_checkout_profile_and_registrations_form_complete_integrated_composition(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    profile = _profile(checkout)
    authorizer = _CheckoutAuthorizer()
    planner = IntegratedPlanner(profile)

    plan_binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(plan_binding, IntegratedLocalTransformBinding)
    plan_registration = integrated_plan_update_registration(plan_binding, planner)
    list_registration, read_registration = integrated_checkout_tool_registrations(
        _bridge(profile, CHECKOUT_LIST_TOOL_ID),
        _bridge(profile, CHECKOUT_READ_TOOL_ID),
        checkout,
        authorizer,
    )

    assert list_registration.resolver is read_registration.resolver

    composition = IntegratedAgentToolComposition(
        profile,
        (
            plan_registration,
            list_registration,
            read_registration,
        ),
    )

    assert composition.tool_ids == profile.tool_ids
    assert composition.runtime_resolvers == (
        plan_registration.resolver,
        list_registration.resolver,
    )
    assert len({resolver.resolver_id for resolver in composition.runtime_resolvers}) == len(
        composition.runtime_resolvers
    )

    registry = composition.build_registry()
    try:
        composition.require_registry(registry)
        assert registry.resolve_resolver(CHECKOUT_LIST_TOOL_ID) is (list_registration.resolver)
        assert registry.resolve_resolver(CHECKOUT_READ_TOOL_ID) is (list_registration.resolver)
        assert registry.resolve_adapter(CHECKOUT_READ_TOOL_ID).adapter_id == (
            CHECKOUT_TOOL_ADAPTER_ID
        )
    finally:
        registry.close()


def test_runtime_resolvers_reject_distinct_instances_for_shared_resolver_id(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    profile = _profile(checkout)
    authorizer = _CheckoutAuthorizer()
    planner = IntegratedPlanner(profile)

    plan_binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(plan_binding, IntegratedLocalTransformBinding)

    composition = IntegratedAgentToolComposition(
        profile,
        (
            integrated_plan_update_registration(plan_binding, planner),
            integrated_checkout_tool_registration(
                _bridge(profile, CHECKOUT_LIST_TOOL_ID),
                checkout,
                authorizer,
            ),
            integrated_checkout_tool_registration(
                _bridge(profile, CHECKOUT_READ_TOOL_ID),
                checkout,
                authorizer,
            ),
        ),
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        _ = composition.runtime_resolvers


def test_checkout_registration_rejects_generic_workspace_identity(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path)
    wrong = IntegratedDownstreamBridgeBinding(
        tool_id=CHECKOUT_LIST_TOOL_ID,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id="agent-workspace:generic/scope:run",
        generation=checkout.registration.generation,
        action_family=WORKSPACE_LIST_ACTION,
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_checkout_tool_registration(wrong, checkout, _CheckoutAuthorizer())


def test_checkout_registration_rejects_generation_substitution(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path)
    wrong = IntegratedDownstreamBridgeBinding(
        tool_id=CHECKOUT_READ_TOOL_ID,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=checkout_integrated_binding_id(checkout.registration),
        generation=checkout.registration.generation + 1,
        action_family=WORKSPACE_READ_ACTION,
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_checkout_tool_registration(wrong, checkout, _CheckoutAuthorizer())


def test_checkout_registration_rejects_action_substitution(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path)
    wrong = IntegratedDownstreamBridgeBinding(
        tool_id=CHECKOUT_LIST_TOOL_ID,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=checkout_integrated_binding_id(checkout.registration),
        generation=checkout.registration.generation,
        action_family=WORKSPACE_READ_ACTION,
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_checkout_tool_registration(wrong, checkout, _CheckoutAuthorizer())
