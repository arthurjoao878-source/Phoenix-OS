from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta

import pytest

from phoenix_os.agent.configuration import (
    AgentServiceConfiguration,
    AgentToolConfiguration,
)
from phoenix_os.agent.contracts import (
    AgentId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
)
from phoenix_os.agent.errors import AgentAdministrationConflictError
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import StaticToolResourceResolver, ToolDescriptor
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    IntegratedAgentAdmission,
    IntegratedAgentConfigurationError,
    IntegratedAgentToolComposition,
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedExecutionProfileSelection,
    IntegratedLocalTransformBinding,
    IntegratedToolBinding,
    IntegratedToolRegistration,
)
from phoenix_os.integrated_agent.composition import _issue_integrated_tool_registration


@dataclass(frozen=True, slots=True)
class _Adapter:
    tool_id: ToolId
    adapter_id: str

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise AssertionError("structural composition test adapter must not be invoked")


def _binding(tool_id: str, *, transform_id: str | None = None) -> IntegratedLocalTransformBinding:
    return IntegratedLocalTransformBinding(
        tool_id=ToolId(tool_id),
        transform_id=transform_id or tool_id,
    )


def _profile(
    *bindings: IntegratedLocalTransformBinding,
) -> IntegratedExecutionProfile:
    selected = bindings or (_binding("local.one"), _binding("local.two"))
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("composition"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=AgentId("composition-agent"),
        tool_bindings=tuple(selected),
        data_flow_policy=IntegratedDataFlowPolicy(),
    )


def _descriptor(tool_id: ToolId, *, suffix: str = "") -> ToolDescriptor:
    normalized = str(tool_id)
    resolver_id = f"resolver.{normalized}{suffix}"
    adapter_id = f"adapter.{normalized}{suffix}"
    empty = ToolSchema(kind=ToolSchemaType.OBJECT)
    return ToolDescriptor(
        tool_id=tool_id,
        name=f"Test {normalized}",
        description="Structural integrated composition test tool.",
        input_schema=ToolInputSchema(empty),
        output_schema=ToolOutputSchema(empty),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=256,
        max_output_bytes=256,
        timeout=timedelta(seconds=1),
        resolver_id=resolver_id,
        adapter_id=adapter_id,
    )


def _registration(
    binding: IntegratedToolBinding,
    *,
    descriptor: ToolDescriptor | None = None,
) -> IntegratedToolRegistration:
    resolved_descriptor = descriptor or _descriptor(binding.tool_id)
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=resolved_descriptor,
        resolver=StaticToolResourceResolver(
            resolved_descriptor.resolver_id,
            f"integrated-test:tool/{binding.tool_id}",
        ),
        adapter=_Adapter(
            tool_id=binding.tool_id,
            adapter_id=resolved_descriptor.adapter_id,
        ),
    )


def _configuration(
    *descriptors: ToolDescriptor,
) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("composition-agent"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=tuple(AgentToolConfiguration(item) for item in descriptors),
    )


def test_admission_rejects_service_tool_without_integrated_binding() -> None:
    binding = _binding("local.one")
    profile = _profile(binding)
    bound_descriptor = _descriptor(binding.tool_id)
    extra_descriptor = _descriptor(ToolId("local.extra"))

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentAdmission(
            IntegratedExecutionProfileCatalog((profile,)),
            IntegratedExecutionProfileSelection(
                profile_id=profile.profile_id,
                generation=profile.generation,
            ),
            _configuration(bound_descriptor, extra_descriptor),
        )


def test_composition_requires_one_exact_registration_per_profile_tool() -> None:
    profile = _profile()
    first = _registration(profile.tool_bindings[0])

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentToolComposition(profile, (first,))


def test_composition_rejects_duplicate_tool_registration() -> None:
    profile = _profile()
    first = _registration(profile.tool_bindings[0])

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentToolComposition(profile, (first, first))


def test_composition_rejects_materially_substituted_binding() -> None:
    expected = _binding("local.one", transform_id="transform.expected")
    profile = _profile(expected)
    substituted = _binding("local.one", transform_id="transform.substituted")

    with pytest.raises(IntegratedAgentConfigurationError):
        IntegratedAgentToolComposition(
            profile,
            (_registration(substituted),),
        )


def test_service_configuration_must_match_complete_exact_composition() -> None:
    profile = _profile()
    registrations = tuple(_registration(binding) for binding in profile.tool_bindings)
    composition = IntegratedAgentToolComposition(profile, registrations)

    exact = _configuration(*composition.descriptors)
    composition.require_service_configuration(exact)

    with pytest.raises(IntegratedAgentConfigurationError):
        composition.require_service_configuration(_configuration(composition.descriptors[0]))

    substituted = _descriptor(composition.descriptors[0].tool_id, suffix=".other")
    with pytest.raises(IntegratedAgentConfigurationError):
        composition.require_service_configuration(
            _configuration(substituted, composition.descriptors[1])
        )


def test_composition_preserves_profile_order_and_exact_implementations() -> None:
    profile = _profile()
    first = _registration(profile.tool_bindings[0])
    second = _registration(profile.tool_bindings[1])
    composition = IntegratedAgentToolComposition(profile, (second, first))

    assert composition.tool_ids == profile.tool_ids
    assert composition.descriptors == (first.descriptor, second.descriptor)
    assert composition.resolvers == (first.resolver, second.resolver)
    assert composition.adapters == (first.adapter, second.adapter)
    assert composition.require_registration(first.tool_id) is first


def test_plan_update_registration_reuses_exact_planner_implementation() -> None:
    from phoenix_os.integrated_agent import (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        IntegratedPlanner,
        integrated_plan_update_registration,
    )

    binding = IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id="integrated.plan.update",
        advisory_state_keys=("plan",),
    )
    profile = _profile(binding)
    planner = IntegratedPlanner(profile)

    registration = integrated_plan_update_registration(binding, planner)

    assert registration.binding is binding
    assert registration.descriptor is planner.descriptor
    assert registration.resolver is planner.resource_resolver
    assert registration.adapter is planner.adapter
    assert IntegratedAgentToolComposition(profile, (registration,)).tool_ids == (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
    )


def test_plan_update_registration_rejects_substituted_local_binding() -> None:
    from phoenix_os.integrated_agent import (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        IntegratedPlanner,
        integrated_plan_update_registration,
    )

    expected = IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id="integrated.plan.update",
        advisory_state_keys=("plan",),
    )
    planner = IntegratedPlanner(_profile(expected))
    substituted = IntegratedLocalTransformBinding(
        tool_id=ToolId("local.other"),
        transform_id="local.other",
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_plan_update_registration(substituted, planner)


def test_public_registration_construction_and_dataclass_replace_are_rejected() -> None:
    binding = _binding("local.sealed")
    descriptor = _descriptor(binding.tool_id)
    resolver = StaticToolResourceResolver(
        descriptor.resolver_id,
        "integrated-test:tool/local.sealed",
    )
    adapter = _Adapter(binding.tool_id, descriptor.adapter_id)

    with pytest.raises(TypeError):
        IntegratedToolRegistration(
            binding=binding,
            descriptor=descriptor,
            resolver=resolver,
            adapter=adapter,
        )

    issued = _registration(binding)
    with pytest.raises((TypeError, ValueError)):
        replace(issued, adapter=adapter)


def test_composition_builds_and_requires_one_sealed_exact_rfc0027_registry() -> None:
    profile = _profile()
    registrations = tuple(_registration(binding) for binding in profile.tool_bindings)
    composition = IntegratedAgentToolComposition(profile, registrations)

    registry = composition.build_registry()

    assert registry.sealed is True
    assert tuple(state.descriptor for state in registry.list_states()) == composition.descriptors
    for registration in registrations:
        assert registry.resolve_adapter(registration.tool_id) is registration.adapter
        assert registry.resolve_resolver(registration.tool_id) is registration.resolver
    composition.require_registry(registry)

    with pytest.raises(AgentAdministrationConflictError):
        registry.register_tool(
            _descriptor(ToolId("local.extra")),
            resolver=StaticToolResourceResolver(
                "resolver.local.extra",
                "integrated-test:tool/local.extra",
            ),
            adapter=_Adapter(ToolId("local.extra"), "adapter.local.extra"),
        )


def test_composition_rejects_same_ids_with_substituted_registry_adapter() -> None:
    profile = _profile()
    registrations = tuple(_registration(binding) for binding in profile.tool_bindings)
    composition = IntegratedAgentToolComposition(profile, registrations)
    registry = ToolRegistry()

    for index, registration in enumerate(registrations):
        adapter = (
            _Adapter(registration.tool_id, registration.descriptor.adapter_id)
            if index == 0
            else registration.adapter
        )
        registry.register_tool(
            registration.descriptor,
            resolver=registration.resolver,
            adapter=adapter,
        )
    registry.seal()

    with pytest.raises(IntegratedAgentConfigurationError):
        composition.require_registry(registry)
