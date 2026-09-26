"""Server-owned durable integrated task runtime composition for RFC-0039.

This module composes reviewed existing owners. It does not construct a second
AgentService, durable store, lease manager, PolicyEngine, HTTP server, or task
state machine, and it never derives or fabricates compatibility digests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_TOOL_ID,
    CheckoutToolAdapter,
)
from phoenix_os.agent.durable_compatibility import DurableCompatibilityPolicy
from phoenix_os.agent.durable_runtime import DurableAgentRuntimeStack
from phoenix_os.agent.service import AgentService
from phoenix_os.authority import AuthorityFreshnessValidator
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorProfileConfiguration,
)
from phoenix_os.control_plane.task_policy_binding import (
    TaskCheckoutAuthorityTarget,
    TaskExecutionPolicyTargets,
    TaskToolAuthorityTarget,
)
from phoenix_os.control_plane.task_request_mapping import (
    ServerOwnedTaskRequest,
    ServerOwnedTaskRequestMapper,
)
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.composition import IntegratedAgentToolComposition
from phoenix_os.integrated_agent.durable_context_resupply import (
    IntegratedDurableContextResupplyCoordinator,
)
from phoenix_os.integrated_agent.durable_live_revalidation import (
    AgentLoopIntegratedDurableRecoveryLiveRevalidator,
    IntegratedDurableRecoveryLiveProbes,
    compose_agent_service_integrated_durable_recovery_live_revalidator,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
    IntegratedDurableRecoveryResumeGate,
)
from phoenix_os.integrated_agent.durable_run import (
    IntegratedDurableAgentServiceDelegate,
    IntegratedDurableRunCoordinator,
    PolicyBackedIntegratedDurableRootProvider,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import (
    IntegratedPlanner,
    require_integrated_plan_update_owner,
)
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
)
from phoenix_os.integrated_agent.runtime import IntegratedAgentRuntime
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ServerOwnedDurableIntegratedTaskRuntime:
    """One non-lifecycle facade over already-owned agent and durable services."""

    service: IntegratedDurableAgentServiceDelegate
    durable_stack: DurableAgentRuntimeStack
    profile: IntegratedExecutionProfile
    execution_guard: IntegratedAgentExecutionGuard
    compatibility_policy: DurableCompatibilityPolicy
    composition: IntegratedAgentToolComposition | None
    admission: IntegratedAgentAdmission
    root_provider: PolicyBackedIntegratedDurableRootProvider
    coordinator: IntegratedDurableRunCoordinator
    planner: IntegratedPlanner | None
    runtime: IntegratedAgentRuntime
    request_mapper: ServerOwnedTaskRequestMapper
    operator_configuration: OperatorConfiguration | None = None
    operator_profile: OperatorProfileConfiguration | None = None

    def derive_policy_targets(
        self,
        request: ServerOwnedTaskRequest,
    ) -> TaskExecutionPolicyTargets:
        """Derive exact policy targets from one server-mapped task request."""

        if not isinstance(request, ServerOwnedTaskRequest):
            raise TypeError("request must be ServerOwnedTaskRequest")

        configuration = self.operator_configuration
        operator_profile = self.operator_profile
        composition = self.composition
        if configuration is None or operator_profile is None or composition is None:
            raise IntegratedAgentConfigurationError()
        if request.operator_profile is not operator_profile:
            raise IntegratedAgentConfigurationError()

        try:
            operator_model = configuration.model(operator_profile.model_name)
            workspace = configuration.workspace(operator_profile.workspace_name)
        except KeyError as exception:
            raise IntegratedAgentConfigurationError() from exception
        if request.operator_model is not operator_model or request.workspace is not workspace:
            raise IntegratedAgentConfigurationError()
        if request.operator_profile.context_paths:
            raise IntegratedAgentConfigurationError()
        if workspace.kind != "development-checkout":
            raise IntegratedAgentConfigurationError()

        service_configuration = self.request_mapper.service_configuration
        composition.require_service_configuration(service_configuration)
        run_request = request.run_request
        if (
            run_request.agent_id != self.profile.agent_id
            or run_request.agent_id != service_configuration.agent_id
            or run_request.provider_id != service_configuration.provider_id
            or run_request.model_id != service_configuration.model_id
            or run_request.limits is not service_configuration.limits
            or operator_model.descriptor.provider_id != run_request.provider_id
            or operator_model.descriptor.model_id != run_request.model_id
        ):
            raise IntegratedAgentConfigurationError()

        try:
            list_registration = composition.require_registration(CHECKOUT_LIST_TOOL_ID)
            read_registration = composition.require_registration(CHECKOUT_READ_TOOL_ID)
        except KeyError as exception:
            raise IntegratedAgentConfigurationError() from exception
        if not isinstance(list_registration.adapter, CheckoutToolAdapter) or not isinstance(
            read_registration.adapter, CheckoutToolAdapter
        ):
            raise IntegratedAgentConfigurationError()
        checkout_registration = list_registration.adapter.registration
        if read_registration.adapter.registration is not checkout_registration:
            raise IntegratedAgentConfigurationError()
        if tuple(checkout_registration.read_prefixes) != tuple(workspace.read_prefixes):
            raise IntegratedAgentConfigurationError()
        if tuple(checkout_registration.patch_prefixes) != tuple(workspace.patch_prefixes):
            raise IntegratedAgentConfigurationError()

        tools = tuple(
            TaskToolAuthorityTarget(
                tool_id=registration.tool_id,
                effect=registration.descriptor.effect,
            )
            for registration in composition.registrations
        )
        return TaskExecutionPolicyTargets(
            run_id=run_request.run_id,
            agent_id=run_request.agent_id,
            provider_id=run_request.provider_id,
            model_id=run_request.model_id,
            tools=tools,
            checkout=TaskCheckoutAuthorityTarget(checkout_registration),
        )


@dataclass(frozen=True, slots=True)
class ServerOwnedDurableIntegratedTaskResumeSupport:
    """Caller-scoped resume support over the existing server-owned durable stack."""

    context: SecurityContext
    live_revalidator: AgentLoopIntegratedDurableRecoveryLiveRevalidator
    resume_gate: IntegratedDurableRecoveryResumeGate
    history_validator: IntegratedDurableRecoveryHistoryValidator
    context_resupply: IntegratedDurableContextResupplyCoordinator
    authority_freshness: AuthorityFreshnessValidator | None = None


def compose_server_owned_durable_integrated_task_resume_support(
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    *,
    context: SecurityContext,
    probes: IntegratedDurableRecoveryLiveProbes,
    authority_freshness: AuthorityFreshnessValidator | None = None,
) -> ServerOwnedDurableIntegratedTaskResumeSupport:
    """Compose caller-scoped recovery support without taking durable lease ownership."""

    if not isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime):
        raise TypeError("owner must be ServerOwnedDurableIntegratedTaskRuntime")
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not isinstance(probes, IntegratedDurableRecoveryLiveProbes):
        raise TypeError("probes must be IntegratedDurableRecoveryLiveProbes")
    if authority_freshness is not None and not isinstance(
        authority_freshness,
        AuthorityFreshnessValidator,
    ):
        raise TypeError("authority_freshness must implement AuthorityFreshnessValidator")
    if not isinstance(owner.service, AgentService):
        raise TypeError("resume support requires AgentService public runtime ownership")

    live_revalidator = compose_agent_service_integrated_durable_recovery_live_revalidator(
        service=owner.service,
        context=context,
        probes=probes,
        composition=owner.composition,
        authority_freshness=authority_freshness,
    )
    resume_gate = IntegratedDurableRecoveryResumeGate(
        owner.admission,
        owner.execution_guard,
        planner=owner.planner,
        live_revalidator=live_revalidator,
    )
    history_validator = IntegratedDurableRecoveryHistoryValidator()
    context_resupply = IntegratedDurableContextResupplyCoordinator(
        store=owner.durable_stack.store,
        lease_manager=owner.durable_stack.lease_manager,
        compatibility_validator=owner.durable_stack.compatibility_validator,
        resume_gate=resume_gate,
        history_validator=history_validator,
    )
    return ServerOwnedDurableIntegratedTaskResumeSupport(
        context=context,
        live_revalidator=live_revalidator,
        resume_gate=resume_gate,
        history_validator=history_validator,
        context_resupply=context_resupply,
        authority_freshness=authority_freshness,
    )


def compose_server_owned_durable_integrated_task_runtime(
    *,
    service: IntegratedDurableAgentServiceDelegate,
    durable_stack: DurableAgentRuntimeStack,
    profile: IntegratedExecutionProfile,
    execution_guard: IntegratedAgentExecutionGuard,
    compatibility_policy: DurableCompatibilityPolicy,
    actor_id: str,
    owner_id: str,
    composition: IntegratedAgentToolComposition | None = None,
    operator_configuration: OperatorConfiguration | None = None,
    operator_profile: OperatorProfileConfiguration | None = None,
    lease_renewal_interval: timedelta = timedelta(seconds=10),
    retention: timedelta | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> ServerOwnedDurableIntegratedTaskRuntime:
    """Compose the exact durable integrated facade without acquiring a lease."""

    if not isinstance(service, IntegratedDurableAgentServiceDelegate):
        raise TypeError("service must implement IntegratedDurableAgentServiceDelegate")
    if not isinstance(durable_stack, DurableAgentRuntimeStack):
        raise TypeError("durable_stack must be DurableAgentRuntimeStack")
    if not isinstance(profile, IntegratedExecutionProfile):
        raise TypeError("profile must be IntegratedExecutionProfile")
    if not isinstance(execution_guard, IntegratedAgentExecutionGuard):
        raise TypeError("execution_guard must be IntegratedAgentExecutionGuard")
    if not isinstance(compatibility_policy, DurableCompatibilityPolicy):
        raise TypeError("compatibility_policy must be DurableCompatibilityPolicy")
    if composition is not None and not isinstance(composition, IntegratedAgentToolComposition):
        raise TypeError("composition must be IntegratedAgentToolComposition or None")
    if operator_configuration is None:
        if operator_profile is not None:
            raise ValueError("operator configuration and profile must be provided together")
    else:
        if not isinstance(operator_configuration, OperatorConfiguration):
            raise TypeError("operator_configuration must be OperatorConfiguration or None")
        if operator_profile is None:
            raise ValueError("operator configuration and profile must be provided together")
        if not isinstance(operator_profile, OperatorProfileConfiguration):
            raise TypeError("operator_profile must be OperatorProfileConfiguration or None")
        matching_profiles = tuple(
            item
            for item in operator_configuration.profiles
            if item.profile_name == operator_profile.profile_name
        )
        if len(matching_profiles) != 1 or matching_profiles[0] is not operator_profile:
            raise IntegratedAgentConfigurationError()
    if not callable(clock):
        raise TypeError("clock must be callable")
    if execution_guard.profile != profile:
        raise IntegratedAgentConfigurationError()
    if compatibility_policy.agent_id != profile.agent_id:
        raise IntegratedAgentConfigurationError()
    if composition is not None and composition.profile != profile:
        raise IntegratedAgentConfigurationError()

    catalog = IntegratedExecutionProfileCatalog((profile,))
    admission = IntegratedAgentAdmission(
        catalog,
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        service.configuration,
    )
    root_provider = PolicyBackedIntegratedDurableRootProvider(
        policy=compatibility_policy,
        actor_id=actor_id,
        retention=retention,
        clock=clock,
    )
    coordinator = IntegratedDurableRunCoordinator(
        service=service,
        durable_stack=durable_stack,
        root_provider=root_provider,
        owner_id=owner_id,
        lease_renewal_interval=lease_renewal_interval,
        clock=clock,
    )
    planner: IntegratedPlanner | None = None
    if composition is not None and INTEGRATED_PLAN_UPDATE_TOOL_ID in composition.tool_ids:
        registration = composition.require_registration(INTEGRATED_PLAN_UPDATE_TOOL_ID)
        planner = require_integrated_plan_update_owner(
            descriptor=registration.descriptor,
            resolver=registration.resolver,
            adapter=registration.adapter,
        )
    runtime = IntegratedAgentRuntime(
        service,
        admission,
        composition=composition,
        execution_guard=execution_guard,
        planner=planner,
        run_executor=coordinator,
    )
    request_mapper = ServerOwnedTaskRequestMapper(service.configuration, clock=clock)

    return ServerOwnedDurableIntegratedTaskRuntime(
        service=service,
        durable_stack=durable_stack,
        profile=profile,
        execution_guard=execution_guard,
        compatibility_policy=compatibility_policy,
        composition=composition,
        admission=admission,
        root_provider=root_provider,
        coordinator=coordinator,
        planner=planner,
        runtime=runtime,
        request_mapper=request_mapper,
        operator_configuration=operator_configuration,
        operator_profile=operator_profile,
    )
