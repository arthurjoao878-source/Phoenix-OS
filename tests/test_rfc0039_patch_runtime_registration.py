from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
)
from phoenix_os.agent.checkout_agent_tools import CHECKOUT_LIST_TOOL_ID, CHECKOUT_READ_TOOL_ID
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutPatchAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    CheckoutWorkspaceAuthorizer,
    PolicyEngineCheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_patch_agent_tool import (
    CHECKOUT_PATCH_TOOL_ID,
    CheckoutPatchToolAdapter,
    CheckoutPatchToolResourceResolver,
)
from phoenix_os.agent.checkout_workspace import RegisteredDevelopmentCheckoutAdapter
from phoenix_os.agent.configuration import AgentServiceConfiguration, AgentToolConfiguration
from phoenix_os.agent.contracts import AgentId, ToolId
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
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.configuration import Configuration
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorProfileConfiguration,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_checkout_patch_tool_registration,
    integrated_checkout_tool_registrations,
    integrated_development_checkout_dogfood_profile,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import PolicyEngine, SecurityContext

_AGENT_ID = AgentId("rfc0039-patch-registration")
_PROFILE_ID = IntegratedExecutionProfileId("rfc0039-patch-registration")
_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(1)
_WORKSPACE_ID = UUID("cffd4c1e-3699-42f8-aa69-5c351d18b29a")


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

    async def authorize_patch(
        self,
        request: CheckoutPatchAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context


def _checkout(tmp_path: Path) -> RegisteredDevelopmentCheckoutAdapter:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True, exist_ok=True)
    return RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="rfc0039-development",
        generation=11,
        root=root,
        read_prefixes=("src",),
    )


def _profile(
    checkout: RegisteredDevelopmentCheckoutAdapter,
    *,
    allow_workspace_patch: bool,
) -> IntegratedExecutionProfile:
    return integrated_development_checkout_dogfood_profile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        data_flow_policy=IntegratedDataFlowPolicy(),
        registration=checkout.registration,
        durability_profile="rfc0039-development-checkout",
        allow_workspace_patch=allow_workspace_patch,
    ).execution_profile


def _bridge(
    profile: IntegratedExecutionProfile,
    tool_id: ToolId,
) -> IntegratedDownstreamBridgeBinding:
    binding = profile.require_tool_binding(tool_id)
    assert isinstance(binding, IntegratedDownstreamBridgeBinding)
    return binding


def _composition(
    checkout: RegisteredDevelopmentCheckoutAdapter,
    profile: IntegratedExecutionProfile,
    authorizer: CheckoutWorkspaceAuthorizer,
) -> IntegratedAgentToolComposition:
    guard = IntegratedAgentExecutionGuard(profile)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    plan_binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(plan_binding, IntegratedLocalTransformBinding)
    list_registration, read_registration = integrated_checkout_tool_registrations(
        _bridge(profile, CHECKOUT_LIST_TOOL_ID),
        _bridge(profile, CHECKOUT_READ_TOOL_ID),
        checkout,
        authorizer,
    )
    registrations = [
        integrated_plan_update_registration(plan_binding, planner),
        list_registration,
        read_registration,
    ]
    if CHECKOUT_PATCH_TOOL_ID in profile.tool_ids:
        registrations.append(
            integrated_checkout_patch_tool_registration(
                _bridge(profile, CHECKOUT_PATCH_TOOL_ID),
                checkout,
                authorizer,
            )
        )
    return IntegratedAgentToolComposition(profile, tuple(registrations))


def _service_configuration(
    composition: IntegratedAgentToolComposition,
) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=_AGENT_ID,
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=tuple(AgentToolConfiguration(item) for item in composition.descriptors),
    )


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


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


async def _base() -> tuple[Configuration, EventBus, Kernel, CapabilityRegistry]:
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    events = EventBus()
    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )
    capabilities = CapabilityRegistry(events=events)
    return configuration, events, kernel, capabilities


def _operator(
    tmp_path: Path,
    *,
    allow_workspace_patch: bool,
) -> tuple[OperatorConfiguration, OperatorProfileConfiguration]:
    profile = OperatorProfileConfiguration(
        profile_name="development",
        model_name="dev",
        workspace_name="project",
        context_paths=(),
        allow_workspace_patch=allow_workspace_patch,
    )
    configuration = OperatorConfiguration(
        source=tmp_path / "phoenix.toml",
        runtime=None,
        inference=None,
        models=(),
        workspaces=(),
        profiles=(profile,),
    )
    return configuration, profile


def test_legacy_checkout_profile_remains_exact_list_read_surface(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path)
    profile = _profile(checkout, allow_workspace_patch=False)

    assert profile.tool_ids == (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        CHECKOUT_LIST_TOOL_ID,
        CHECKOUT_READ_TOOL_ID,
    )
    with pytest.raises(KeyError):
        profile.require_tool_binding(CHECKOUT_PATCH_TOOL_ID)


def test_patch_profile_and_registration_are_explicit_zero_effect_surface(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path)
    profile = _profile(checkout, allow_workspace_patch=True)
    authorizer = _CheckoutAuthorizer()
    list_binding = _bridge(profile, CHECKOUT_LIST_TOOL_ID)
    patch_binding = _bridge(profile, CHECKOUT_PATCH_TOOL_ID)

    registration = integrated_checkout_patch_tool_registration(
        patch_binding,
        checkout,
        authorizer,
    )

    assert profile.tool_ids == (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        CHECKOUT_LIST_TOOL_ID,
        CHECKOUT_READ_TOOL_ID,
        CHECKOUT_PATCH_TOOL_ID,
    )
    assert patch_binding.binding_id == list_binding.binding_id
    assert patch_binding.generation == checkout.registration.generation
    assert patch_binding.action_family == "workspace.patch"
    assert registration.descriptor.metadata["durable_dispatch"] == "specialized"
    assert isinstance(registration.resolver, CheckoutPatchToolResourceResolver)
    assert registration.resolver.registration is checkout.registration
    assert isinstance(registration.adapter, CheckoutPatchToolAdapter)
    assert registration.adapter.registration is checkout.registration
    assert registration.adapter.authorizer is authorizer


@pytest.mark.asyncio
async def test_dependency_validation_requires_patch_flag_and_exact_patch_surface(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    policy = PolicyEngine()
    checkout = _checkout(tmp_path)
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)
    compatibility = _compatibility()
    store = InMemoryDurableRunStore()

    try:
        patch_profile = _profile(checkout, allow_workspace_patch=True)
        patch_composition = _composition(checkout, patch_profile, authorizer)
        patch_guard = IntegratedAgentExecutionGuard(patch_profile)
        patch_operator_configuration, patch_operator_profile = _operator(
            tmp_path,
            allow_workspace_patch=True,
        )

        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=policy,
            agent_enabled=True,
            agent_configuration=_service_configuration(patch_composition),
            agent_model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
            agent_execution_interceptor=patch_guard,
            agent_tool_resolvers=patch_composition.runtime_resolvers,
            agent_tool_adapters=patch_composition.adapters,
            agent_durable_enabled=True,
            agent_durable_store=store,
            agent_durable_lease_manager=store.lease_manager,
            agent_durable_compatibility_validator=StaticDurableCompatibilityValidator(
                (compatibility,)
            ),
            agent_integrated_task_runtime_enabled=True,
            agent_integrated_profile=patch_profile,
            agent_integrated_composition=patch_composition,
            agent_integrated_compatibility_policy=compatibility,
            agent_integrated_actor_id="rfc0039-patch",
            agent_integrated_owner_id="rfc0039-patch-runtime",
            agent_integrated_operator_configuration=patch_operator_configuration,
            agent_integrated_operator_profile=patch_operator_profile,
        )

        disabled_configuration, disabled_profile = _operator(
            tmp_path,
            allow_workspace_patch=False,
        )
        with pytest.raises(ValueError, match="patch-enabled operator profile"):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=policy,
                agent_enabled=True,
                agent_configuration=_service_configuration(patch_composition),
                agent_model_adapter=DeterministicModelTurnAdapter(
                    (DeterministicFinalTurn("done"),)
                ),
                agent_execution_interceptor=patch_guard,
                agent_tool_resolvers=patch_composition.runtime_resolvers,
                agent_tool_adapters=patch_composition.adapters,
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=StaticDurableCompatibilityValidator(
                    (compatibility,)
                ),
                agent_integrated_task_runtime_enabled=True,
                agent_integrated_profile=patch_profile,
                agent_integrated_composition=patch_composition,
                agent_integrated_compatibility_policy=compatibility,
                agent_integrated_actor_id="rfc0039-patch",
                agent_integrated_owner_id="rfc0039-patch-runtime",
                agent_integrated_operator_configuration=disabled_configuration,
                agent_integrated_operator_profile=disabled_profile,
            )

        legacy_profile = _profile(checkout, allow_workspace_patch=False)
        legacy_composition = _composition(checkout, legacy_profile, authorizer)
        legacy_guard = IntegratedAgentExecutionGuard(legacy_profile)
        with pytest.raises(ValueError, match=r"requires workspace\.patch registration"):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=policy,
                agent_enabled=True,
                agent_configuration=_service_configuration(legacy_composition),
                agent_model_adapter=DeterministicModelTurnAdapter(
                    (DeterministicFinalTurn("done"),)
                ),
                agent_execution_interceptor=legacy_guard,
                agent_tool_resolvers=legacy_composition.runtime_resolvers,
                agent_tool_adapters=legacy_composition.adapters,
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=StaticDurableCompatibilityValidator(
                    (compatibility,)
                ),
                agent_integrated_task_runtime_enabled=True,
                agent_integrated_profile=legacy_profile,
                agent_integrated_composition=legacy_composition,
                agent_integrated_compatibility_policy=compatibility,
                agent_integrated_actor_id="rfc0039-patch",
                agent_integrated_owner_id="rfc0039-patch-runtime",
                agent_integrated_operator_configuration=patch_operator_configuration,
                agent_integrated_operator_profile=patch_operator_profile,
            )
    finally:
        await store.close()
        await policy.close()
