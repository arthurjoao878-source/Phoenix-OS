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
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    CheckoutWorkspaceAuthorizer,
    PolicyEngineCheckoutWorkspaceAuthorizer,
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
from phoenix_os.agent.durable_runtime import DurableAgentRuntimeStack
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.configuration import Configuration
from phoenix_os.configuration.dependencies import ServiceDefinition
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorProfileConfiguration,
)
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_checkout_tool_registrations,
    integrated_development_checkout_dogfood_profile,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
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

_AGENT_ID = AgentId("rfc0039-task-runtime")
_PROFILE_ID = IntegratedExecutionProfileId("rfc0039-development-checkout")
_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(1)
_WORKSPACE_ID = UUID("5271ea47-47bb-4865-b8fa-69b1240f8868")


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


def _bridge(
    profile: IntegratedExecutionProfile,
    tool_id: ToolId,
) -> IntegratedDownstreamBridgeBinding:
    binding = profile.require_tool_binding(tool_id)
    assert isinstance(binding, IntegratedDownstreamBridgeBinding)
    return binding


def _surface(
    tmp_path: Path,
    *,
    authorizer: CheckoutWorkspaceAuthorizer | None = None,
) -> tuple[
    IntegratedExecutionProfile,
    IntegratedAgentToolComposition,
    AgentServiceConfiguration,
    IntegratedAgentExecutionGuard,
]:
    (tmp_path / "src").mkdir(exist_ok=True)
    checkout = RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="rfc0039-development",
        generation=9,
        root=tmp_path,
        read_prefixes=("src",),
    )
    profile = integrated_development_checkout_dogfood_profile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        data_flow_policy=IntegratedDataFlowPolicy(),
        registration=checkout.registration,
        durability_profile="rfc0039-development-checkout",
    ).execution_profile
    guard = IntegratedAgentExecutionGuard(profile)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    resolved_authorizer = _CheckoutAuthorizer() if authorizer is None else authorizer
    plan_binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(plan_binding, IntegratedLocalTransformBinding)
    list_registration, read_registration = integrated_checkout_tool_registrations(
        _bridge(profile, ToolId("workspace.list")),
        _bridge(profile, ToolId("workspace.read")),
        checkout,
        resolved_authorizer,
    )
    assert list_registration.resolver is read_registration.resolver
    composition = IntegratedAgentToolComposition(
        profile,
        (
            integrated_plan_update_registration(plan_binding, planner),
            list_registration,
            read_registration,
        ),
    )
    service_configuration = AgentServiceConfiguration(
        agent_id=_AGENT_ID,
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=tuple(AgentToolConfiguration(descriptor) for descriptor in composition.descriptors),
    )
    return profile, composition, service_configuration, guard


def _model_adapter() -> DeterministicModelTurnAdapter:
    return DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))


@pytest.mark.asyncio
async def test_runtime_assembler_omits_task_runtime_by_default() -> None:
    configuration, events, kernel, capabilities = await _base()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
    ).assemble()
    try:
        assert "control_plane.task-runtime" not in runtime.services
        await runtime.start()
    finally:
        await runtime.stop()


def test_task_runtime_service_key_is_reserved() -> None:
    with pytest.raises(ValueError, match="reserved service name"):
        ServiceDefinition(
            name="control_plane.task-runtime",
            factory=lambda _resolver, _configuration: object(),
        )


@pytest.mark.asyncio
async def test_integrated_task_runtime_options_require_explicit_enablement(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    profile, _composition, _service_configuration, _guard = _surface(tmp_path)
    with pytest.raises(
        ValueError,
        match="integrated task runtime options require agent_integrated_task_runtime_enabled",
    ):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            agent_integrated_profile=profile,
        )


@pytest.mark.asyncio
async def test_integrated_task_runtime_requires_exact_guard_and_tool_surface(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    profile, composition, service_configuration, guard = _surface(tmp_path)
    compatibility = _compatibility()
    store = InMemoryDurableRunStore()
    validator = StaticDurableCompatibilityValidator((compatibility,))

    try:
        with pytest.raises(
            ValueError,
            match="enabled integrated task runtime requires IntegratedAgentExecutionGuard",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=PolicyEngine(),
                agent_enabled=True,
                agent_configuration=service_configuration,
                agent_model_adapter=_model_adapter(),
                agent_tool_resolvers=composition.runtime_resolvers,
                agent_tool_adapters=composition.adapters,
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=validator,
                agent_integrated_task_runtime_enabled=True,
                agent_integrated_profile=profile,
                agent_integrated_composition=composition,
                agent_integrated_compatibility_policy=compatibility,
                agent_integrated_actor_id="rfc0039-task",
                agent_integrated_owner_id="rfc0039-task-runtime",
            )

        with pytest.raises(
            ValueError,
            match="integrated task runtime requires exact composition resolvers",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=PolicyEngine(),
                agent_enabled=True,
                agent_configuration=service_configuration,
                agent_model_adapter=_model_adapter(),
                agent_execution_interceptor=guard,
                agent_tool_resolvers=composition.runtime_resolvers[:-1],
                agent_tool_adapters=composition.adapters,
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=validator,
                agent_integrated_task_runtime_enabled=True,
                agent_integrated_profile=profile,
                agent_integrated_composition=composition,
                agent_integrated_compatibility_policy=compatibility,
                agent_integrated_actor_id="rfc0039-task",
                agent_integrated_owner_id="rfc0039-task-runtime",
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_integrated_task_runtime_rejects_compatibility_policy_agent_substitution(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    profile, composition, service_configuration, guard = _surface(tmp_path)
    substituted = _compatibility(AgentId("other-agent"))
    store = InMemoryDurableRunStore()

    try:
        with pytest.raises(
            ValueError,
            match="integrated task runtime compatibility policy agent mismatch",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=PolicyEngine(),
                agent_enabled=True,
                agent_configuration=service_configuration,
                agent_model_adapter=_model_adapter(),
                agent_execution_interceptor=guard,
                agent_tool_resolvers=composition.runtime_resolvers,
                agent_tool_adapters=composition.adapters,
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=(
                    StaticDurableCompatibilityValidator((substituted,))
                ),
                agent_integrated_task_runtime_enabled=True,
                agent_integrated_profile=profile,
                agent_integrated_composition=composition,
                agent_integrated_compatibility_policy=substituted,
                agent_integrated_actor_id="rfc0039-task",
                agent_integrated_owner_id="rfc0039-task-runtime",
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_runtime_assembler_publishes_exact_non_lifecycle_task_runtime(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    policy = PolicyEngine()
    profile, composition, service_configuration, guard = _surface(
        tmp_path,
        authorizer=PolicyEngineCheckoutWorkspaceAuthorizer(policy),
    )
    compatibility = _compatibility()
    store = InMemoryDurableRunStore()
    validator = StaticDurableCompatibilityValidator((compatibility,))
    metadata_projector = IntegratedDurableCheckpointMetadataProjector()
    history_validator = create_integrated_checkout_durable_history_validator()
    operator_profile = OperatorProfileConfiguration(
        profile_name="development",
        model_name="dev",
        workspace_name="project",
        context_paths=(),
        allow_workspace_patch=False,
    )
    operator_configuration = OperatorConfiguration(
        source=tmp_path / "phoenix.toml",
        runtime=None,
        inference=None,
        models=(),
        workspaces=(),
        profiles=(operator_profile,),
    )

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=policy,
        agent_enabled=True,
        agent_configuration=service_configuration,
        agent_model_adapter=_model_adapter(),
        agent_execution_interceptor=guard,
        agent_tool_resolvers=composition.runtime_resolvers,
        agent_tool_adapters=composition.adapters,
        agent_durable_enabled=True,
        agent_durable_store=store,
        agent_durable_lease_manager=store.lease_manager,
        agent_durable_compatibility_validator=validator,
        agent_durable_metadata_projector=metadata_projector,
        agent_durable_history_validator=history_validator,
        agent_integrated_task_runtime_enabled=True,
        agent_integrated_profile=profile,
        agent_integrated_composition=composition,
        agent_integrated_compatibility_policy=compatibility,
        agent_integrated_actor_id="rfc0039-task",
        agent_integrated_owner_id="rfc0039-task-runtime",
        agent_integrated_operator_configuration=operator_configuration,
        agent_integrated_operator_profile=operator_profile,
    ).assemble()

    try:
        facade = runtime.service("control_plane.task-runtime")
        assert isinstance(facade, ServerOwnedDurableIntegratedTaskRuntime)
        assert facade.service is runtime.service("agent")
        assert facade.durable_stack is runtime.service("agent.durable")
        assert facade.profile is profile
        assert facade.execution_guard is guard
        assert facade.compatibility_policy is compatibility
        assert facade.composition is composition
        assert facade.operator_configuration is operator_configuration
        assert facade.operator_profile is operator_profile
        assert facade.root_provider.policy is compatibility
        assert facade.runtime.execution_guard is guard
        assert facade.planner is not None
        assert facade.planner.provenance_provider is guard
        assert facade.runtime.planner is facade.planner

        loop = runtime.service("agent.runtime")
        assert isinstance(loop, AgentLoop)
        assert loop.execution_interceptor is guard

        registry = runtime.service("agent.registry")
        assert isinstance(registry, ToolRegistry)
        composition.require_runtime_registry(registry)

        durable_stack = runtime.service("agent.durable")
        assert isinstance(durable_stack, DurableAgentRuntimeStack)
        assert durable_stack.metadata_projector is metadata_projector
        assert durable_stack.history_validator is history_validator

        components = (await runtime.snapshot()).components
        assert components.count("agent") == 1
        assert "control_plane.task-runtime" not in components

        await runtime.start()
    finally:
        await runtime.stop()

    assert store.closed


@pytest.mark.asyncio
async def test_integrated_task_runtime_operator_surface_rejects_checkout_policy_substitution(
    tmp_path: Path,
) -> None:
    configuration, events, kernel, capabilities = await _base()
    shared_policy = PolicyEngine()
    substituted_policy = PolicyEngine()
    profile, composition, service_configuration, guard = _surface(
        tmp_path,
        authorizer=PolicyEngineCheckoutWorkspaceAuthorizer(substituted_policy),
    )
    compatibility = _compatibility()
    store = InMemoryDurableRunStore()
    operator_profile = OperatorProfileConfiguration(
        profile_name="development",
        model_name="dev",
        workspace_name="project",
        context_paths=(),
        allow_workspace_patch=False,
    )
    operator_configuration = OperatorConfiguration(
        source=tmp_path / "phoenix.toml",
        runtime=None,
        inference=None,
        models=(),
        workspaces=(),
        profiles=(operator_profile,),
    )

    try:
        with pytest.raises(
            ValueError,
            match="checkout authorizer must use shared policy",
        ):
            RuntimeAssembler(
                kernel=kernel,
                events=events,
                capabilities=capabilities,
                configuration=configuration,
                policy=shared_policy,
                agent_enabled=True,
                agent_configuration=service_configuration,
                agent_model_adapter=_model_adapter(),
                agent_execution_interceptor=guard,
                agent_tool_resolvers=composition.runtime_resolvers,
                agent_tool_adapters=composition.adapters,
                agent_durable_enabled=True,
                agent_durable_store=store,
                agent_durable_lease_manager=store.lease_manager,
                agent_durable_compatibility_validator=(
                    StaticDurableCompatibilityValidator((compatibility,))
                ),
                agent_integrated_task_runtime_enabled=True,
                agent_integrated_profile=profile,
                agent_integrated_composition=composition,
                agent_integrated_compatibility_policy=compatibility,
                agent_integrated_actor_id="rfc0039-task",
                agent_integrated_owner_id="rfc0039-task-runtime",
                agent_integrated_operator_configuration=operator_configuration,
                agent_integrated_operator_profile=operator_profile,
            )
    finally:
        await store.close()
        await shared_policy.close()
        await substituted_policy.close()
