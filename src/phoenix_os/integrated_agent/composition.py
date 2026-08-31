"""Exact server-owned RFC-0036 S4 tool composition without a second registry."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import InitVar, dataclass, field

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId, AgentLimits, ToolId
from phoenix_os.agent.errors import AgentError
from phoenix_os.agent.memory_agent_tools import (
    MemoryAgentToolBinding,
    MemoryToolAdapter,
    memory_tool_descriptor,
    memory_tool_resolver,
)
from phoenix_os.agent.memory_authorization import MEMORY_READ_ACTION, MEMORY_SEARCH_ACTION
from phoenix_os.agent.memory_retrieval import AgentMemoryService
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.tools import ToolAdapter, ToolDescriptor, ToolResourceResolver
from phoenix_os.agent.workspace_agent_tools import (
    WorkspaceAgentToolBinding,
    WorkspaceToolAdapter,
    workspace_tool_descriptor,
    workspace_tool_resolver,
)
from phoenix_os.agent.workspace_authorization import WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION
from phoenix_os.agent.workspace_service import AgentWorkspaceService
from phoenix_os.authority.catalog import NETWORK_HTTP_REQUEST_ACTION
from phoenix_os.browser_automation.agent_tools import (
    BrowserToolAdapter,
    BrowserToolBinding,
    browser_tool_descriptor,
    browser_tool_resolver,
)
from phoenix_os.browser_automation.authorization import (
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
)
from phoenix_os.browser_automation.profiles import BrowserProfile
from phoenix_os.browser_automation.service import BrowserAutomationService
from phoenix_os.host_automation.agent_control_tools import (
    HostApplicationCloseToolAdapter,
    HostApplicationLaunchToolAdapter,
    HostClipboardReadToolAdapter,
    HostClipboardWriteToolAdapter,
    HostWindowFocusToolAdapter,
    host_application_close_tool_descriptor,
    host_application_close_tool_resolver,
    host_application_launch_tool_descriptor,
    host_application_launch_tool_resolver,
    host_clipboard_read_tool_descriptor,
    host_clipboard_read_tool_resolver,
    host_clipboard_write_tool_descriptor,
    host_clipboard_write_tool_resolver,
    host_window_focus_tool_descriptor,
    host_window_focus_tool_resolver,
)
from phoenix_os.host_automation.agent_tools import (
    HostProcessListToolAdapter,
    HostWindowListToolAdapter,
    host_process_list_tool_descriptor,
    host_process_list_tool_resolver,
    host_window_list_tool_descriptor,
    host_window_list_tool_resolver,
)
from phoenix_os.host_automation.authorization import (
    HOST_APPLICATION_CLOSE_ACTION,
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_FOCUS_ACTION,
    HOST_WINDOW_LIST_ACTION,
    host_resource,
)
from phoenix_os.host_automation.contracts import (
    HostApplicationId,
    HostAutomationLimits,
    HostId,
)
from phoenix_os.host_automation.service import HostAutomationService
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.dogfood_profiles import (
    DogfoodTaskClass,
    IntegratedDogfoodProfile,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedCapabilityProfileBinding,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
    IntegratedToolBinding,
)
from phoenix_os.network_egress.agent_tools import (
    NetworkEgressToolBinding,
    NetworkHttpToolAdapter,
    network_http_tool_descriptor,
    network_http_tool_resolver,
)
from phoenix_os.network_egress.profiles import (
    NetworkEgressProfile,
    NetworkOperationEffect,
)
from phoenix_os.network_egress.service import NetworkEgressService

_INTEGRATED_TOOL_REGISTRATION_ISSUER = object()


@dataclass(frozen=True, slots=True)
class IntegratedToolRegistration:
    # Opaque reviewed binding/implementation tuple issued only by S4 factories.

    binding: IntegratedToolBinding
    descriptor: ToolDescriptor
    resolver: ToolResourceResolver
    adapter: ToolAdapter
    _issuer: InitVar[object] = None
    _issued: bool = field(init=False, repr=False, compare=False, default=False)

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _INTEGRATED_TOOL_REGISTRATION_ISSUER:
            raise TypeError("IntegratedToolRegistration values are issued by reviewed factories")
        if not isinstance(
            self.binding,
            (IntegratedLocalTransformBinding, IntegratedDownstreamBridgeBinding),
        ):
            raise TypeError("binding must be an IntegratedToolBinding")
        if not isinstance(self.descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if not isinstance(self.resolver, ToolResourceResolver):
            raise TypeError("resolver must implement ToolResourceResolver")
        if not isinstance(self.adapter, ToolAdapter):
            raise TypeError("adapter must implement ToolAdapter")
        if (
            self.descriptor.tool_id != self.binding.tool_id
            or self.resolver.resolver_id != self.descriptor.resolver_id
            or self.adapter.adapter_id != self.descriptor.adapter_id
            or self.adapter.tool_id != self.descriptor.tool_id
        ):
            raise IntegratedAgentConfigurationError()
        object.__setattr__(self, "_issued", True)

    @property
    def tool_id(self) -> ToolId:
        return self.binding.tool_id


def _issue_integrated_tool_registration(
    *,
    binding: IntegratedToolBinding,
    descriptor: ToolDescriptor,
    resolver: ToolResourceResolver,
    adapter: ToolAdapter,
) -> IntegratedToolRegistration:
    return IntegratedToolRegistration(
        binding=binding,
        descriptor=descriptor,
        resolver=resolver,
        adapter=adapter,
        _issuer=_INTEGRATED_TOOL_REGISTRATION_ISSUER,
    )


class IntegratedAgentToolComposition:
    """Validate one complete finite integrated tool surface against one exact profile."""

    def __init__(
        self,
        profile: IntegratedExecutionProfile,
        registrations: tuple[IntegratedToolRegistration, ...],
    ) -> None:
        if not isinstance(profile, IntegratedExecutionProfile):
            raise TypeError("profile must be IntegratedExecutionProfile")
        supplied = tuple(registrations)
        if any(not isinstance(item, IntegratedToolRegistration) for item in supplied):
            raise TypeError("registrations must contain IntegratedToolRegistration values")
        if any(not item._issued for item in supplied):
            raise IntegratedAgentConfigurationError()
        if len(supplied) != len(profile.tool_bindings):
            raise IntegratedAgentConfigurationError()

        by_id: dict[ToolId, IntegratedToolRegistration] = {}
        for registration in supplied:
            tool_id = registration.tool_id
            if tool_id in by_id:
                raise IntegratedAgentConfigurationError()
            try:
                expected = profile.require_tool_binding(tool_id)
            except KeyError as exception:
                raise IntegratedAgentConfigurationError() from exception
            if registration.binding != expected:
                raise IntegratedAgentConfigurationError()
            by_id[tool_id] = registration

        if frozenset(by_id) != frozenset(profile.tool_ids):
            raise IntegratedAgentConfigurationError()

        self._profile = profile
        self._registrations = tuple(by_id[binding.tool_id] for binding in profile.tool_bindings)

    @property
    def profile(self) -> IntegratedExecutionProfile:
        return self._profile

    @property
    def registrations(self) -> tuple[IntegratedToolRegistration, ...]:
        return self._registrations

    @property
    def tool_ids(self) -> tuple[ToolId, ...]:
        return tuple(item.tool_id for item in self._registrations)

    @property
    def descriptors(self) -> tuple[ToolDescriptor, ...]:
        return tuple(item.descriptor for item in self._registrations)

    @property
    def resolvers(self) -> tuple[ToolResourceResolver, ...]:
        return tuple(item.resolver for item in self._registrations)

    @property
    def adapters(self) -> tuple[ToolAdapter, ...]:
        return tuple(item.adapter for item in self._registrations)

    def build_registry(self) -> ToolRegistry:
        registry = ToolRegistry()
        self.install_registry(registry)
        return registry

    def install_registry(self, registry: ToolRegistry) -> None:
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be ToolRegistry")
        try:
            if registry.sealed or registry.list_states():
                raise IntegratedAgentConfigurationError()
            for registration in self._registrations:
                registry.register_tool(
                    registration.descriptor,
                    resolver=registration.resolver,
                    adapter=registration.adapter,
                )
            registry.seal()
            self.require_registry(registry)
        except IntegratedAgentConfigurationError:
            if not registry.closed:
                registry.close()
            raise
        except (AgentError, TypeError, ValueError) as exception:
            if not registry.closed:
                registry.close()
            raise IntegratedAgentConfigurationError() from exception

    def require_registry(self, registry: ToolRegistry) -> None:
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be ToolRegistry")
        if not registry.sealed:
            raise IntegratedAgentConfigurationError()
        try:
            states = registry.list_states()
            if tuple(state.descriptor.tool_id for state in states) != self.tool_ids:
                raise IntegratedAgentConfigurationError()
            for state, registration in zip(states, self._registrations, strict=True):
                if (
                    not state.enabled
                    or state.descriptor != registration.descriptor
                    or registry.resolve_adapter(registration.tool_id) is not registration.adapter
                    or registry.resolve_resolver(registration.tool_id) is not registration.resolver
                ):
                    raise IntegratedAgentConfigurationError()
        except AgentError as exception:
            raise IntegratedAgentConfigurationError() from exception

    def require_registration(self, tool_id: ToolId) -> IntegratedToolRegistration:
        if not isinstance(tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        for registration in self._registrations:
            if registration.tool_id == tool_id:
                return registration
        raise KeyError(f"unknown integrated tool registration: {tool_id}")

    def require_service_configuration(
        self,
        configuration: AgentServiceConfiguration,
    ) -> None:
        """Require the service-visible descriptors to match this exact composition."""

        if not isinstance(configuration, AgentServiceConfiguration):
            raise TypeError("configuration must be AgentServiceConfiguration")
        if configuration.agent_id != self._profile.agent_id or frozenset(
            configuration.tool_ids
        ) != frozenset(self.tool_ids):
            raise IntegratedAgentConfigurationError()

        configured = {tool.tool_id: tool.descriptor for tool in configuration.tools}
        for registration in self._registrations:
            if configured.get(registration.tool_id) != registration.descriptor:
                raise IntegratedAgentConfigurationError()


def integrated_host_binding_id(host_id: HostId) -> str:
    """Return the exact configured host identity used by an integrated host capability binding."""

    if not isinstance(host_id, HostId):
        raise TypeError("host_id must be HostId")
    return host_resource(host_id)


def integrated_network_profile_binding_id(profile: NetworkEgressProfile) -> str:
    """Return the exact generation-bearing network profile identity for RFC-0036."""

    if not isinstance(profile, NetworkEgressProfile):
        raise TypeError("profile must be NetworkEgressProfile")
    return f"network:profile/{profile.profile_id}"


def integrated_browser_profile_binding_id(profile: BrowserProfile) -> str:
    """Return the exact generation-bearing browser profile identity for RFC-0036."""

    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")
    return f"browser:profile/{profile.profile_id}"


def integrated_host_process_list_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_PROCESS_LIST_ACTION),
        action_family=HOST_PROCESS_LIST_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_process_list_tool_descriptor(limits),
        resolver=host_process_list_tool_resolver(host_id),
        adapter=HostProcessListToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
        ),
    )


def integrated_host_window_list_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_WINDOW_LIST_ACTION),
        action_family=HOST_WINDOW_LIST_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_window_list_tool_descriptor(limits),
        resolver=host_window_list_tool_resolver(host_id),
        adapter=HostWindowListToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
        ),
    )


def integrated_host_application_launch_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
    applications: Sequence[HostApplicationId],
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_APPLICATION_LAUNCH_ACTION),
        action_family=HOST_APPLICATION_LAUNCH_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_application_launch_tool_descriptor(limits),
        resolver=host_application_launch_tool_resolver(host_id, applications),
        adapter=HostApplicationLaunchToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
            applications=applications,
        ),
    )


def integrated_host_window_focus_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
    applications: Sequence[HostApplicationId],
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_WINDOW_FOCUS_ACTION),
        action_family=HOST_WINDOW_FOCUS_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_window_focus_tool_descriptor(limits),
        resolver=host_window_focus_tool_resolver(host_id, applications),
        adapter=HostWindowFocusToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
            applications=applications,
        ),
    )


def integrated_host_application_close_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
    applications: Sequence[HostApplicationId],
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_APPLICATION_CLOSE_ACTION),
        action_family=HOST_APPLICATION_CLOSE_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_application_close_tool_descriptor(limits),
        resolver=host_application_close_tool_resolver(host_id, applications),
        adapter=HostApplicationCloseToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
            applications=applications,
        ),
    )


def integrated_host_clipboard_write_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_CLIPBOARD_WRITE_ACTION),
        action_family=HOST_CLIPBOARD_WRITE_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_clipboard_write_tool_descriptor(limits),
        resolver=host_clipboard_write_tool_resolver(host_id),
        adapter=HostClipboardWriteToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
        ),
    )


def integrated_host_clipboard_read_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: HostAutomationService,
    *,
    host_id: HostId,
    limits: HostAutomationLimits,
) -> IntegratedToolRegistration:
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        generation=None,
        tool_id=ToolId(HOST_CLIPBOARD_READ_ACTION),
        action_family=HOST_CLIPBOARD_READ_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=host_clipboard_read_tool_descriptor(limits),
        resolver=host_clipboard_read_tool_resolver(host_id),
        adapter=HostClipboardReadToolAdapter(
            service,
            host_id=host_id,
            limits=limits,
        ),
    )


def integrated_network_http_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: NetworkEgressService,
    downstream_binding: NetworkEgressToolBinding,
) -> IntegratedToolRegistration:
    if not isinstance(downstream_binding, NetworkEgressToolBinding):
        raise TypeError("downstream_binding must be NetworkEgressToolBinding")
    profile = downstream_binding.profile
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=integrated_network_profile_binding_id(profile),
        generation=profile.generation,
        tool_id=downstream_binding.tool_id,
        action_family=NETWORK_HTTP_REQUEST_ACTION,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=network_http_tool_descriptor(downstream_binding),
        resolver=network_http_tool_resolver(downstream_binding),
        adapter=NetworkHttpToolAdapter(service, downstream_binding),
    )


def integrated_browser_tool_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: BrowserAutomationService,
    downstream_binding: BrowserToolBinding,
    profile: BrowserProfile,
) -> IntegratedToolRegistration:
    if not isinstance(downstream_binding, BrowserToolBinding):
        raise TypeError("downstream_binding must be BrowserToolBinding")
    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id=integrated_browser_profile_binding_id(profile),
        generation=profile.generation,
        tool_id=downstream_binding.tool_id,
        action_family=downstream_binding.browser_action,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=browser_tool_descriptor(downstream_binding, profile),
        resolver=browser_tool_resolver(downstream_binding),
        adapter=BrowserToolAdapter(
            service,
            binding=downstream_binding,
            profile=profile,
        ),
    )


def integrated_plan_update_registration(
    binding: IntegratedLocalTransformBinding,
    planner: IntegratedPlanner,
) -> IntegratedToolRegistration:
    # Bind the reserved plan transform to the exact reviewed planner implementation.
    if not isinstance(binding, IntegratedLocalTransformBinding):
        raise TypeError("binding must be IntegratedLocalTransformBinding")
    if not isinstance(planner, IntegratedPlanner):
        raise TypeError("planner must be IntegratedPlanner")
    try:
        expected = planner.profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    except KeyError as exception:
        raise IntegratedAgentConfigurationError() from exception
    if (
        not isinstance(expected, IntegratedLocalTransformBinding)
        or binding != expected
        or binding.tool_id != INTEGRATED_PLAN_UPDATE_TOOL_ID
        or binding.transform_id != INTEGRATED_PLAN_UPDATE_TRANSFORM_ID
        or binding.advisory_state_keys != ("plan",)
    ):
        raise IntegratedAgentConfigurationError()
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=planner.descriptor,
        resolver=planner.resource_resolver,
        adapter=planner.adapter,
    )


def integrated_memory_tool_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: AgentMemoryService,
    downstream_binding: MemoryAgentToolBinding,
) -> IntegratedToolRegistration:
    """Bind one reviewed memory tool to its exact integrated capability."""

    if not isinstance(downstream_binding, MemoryAgentToolBinding):
        raise TypeError("downstream_binding must be MemoryAgentToolBinding")
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=downstream_binding.binding_id,
        generation=None,
        tool_id=downstream_binding.tool_id,
        action_family=downstream_binding.action,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=memory_tool_descriptor(downstream_binding, service.limits),
        resolver=memory_tool_resolver(downstream_binding),
        adapter=MemoryToolAdapter(service, downstream_binding),
    )


def integrated_workspace_tool_registration(
    binding: IntegratedDownstreamBridgeBinding,
    service: AgentWorkspaceService,
    downstream_binding: WorkspaceAgentToolBinding,
) -> IntegratedToolRegistration:
    """Bind one reviewed workspace tool to its exact integrated capability."""

    if not isinstance(downstream_binding, WorkspaceAgentToolBinding):
        raise TypeError("downstream_binding must be WorkspaceAgentToolBinding")
    _require_downstream_bridge(
        binding,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=downstream_binding.binding_id,
        generation=None,
        tool_id=downstream_binding.tool_id,
        action_family=downstream_binding.action,
    )
    return _issue_integrated_tool_registration(
        binding=binding,
        descriptor=workspace_tool_descriptor(downstream_binding, service.limits),
        resolver=workspace_tool_resolver(downstream_binding),
        adapter=WorkspaceToolAdapter(service, downstream_binding),
    )


def _require_downstream_bridge(
    binding: IntegratedDownstreamBridgeBinding,
    *,
    boundary: IntegratedDownstreamBoundary,
    binding_id: str,
    generation: int | None,
    tool_id: ToolId,
    action_family: str,
) -> None:
    if not isinstance(binding, IntegratedDownstreamBridgeBinding):
        raise TypeError("binding must be IntegratedDownstreamBridgeBinding")
    if not isinstance(boundary, IntegratedDownstreamBoundary):
        raise TypeError("boundary must be IntegratedDownstreamBoundary")
    if not isinstance(tool_id, ToolId):
        raise TypeError("tool_id must be ToolId")
    if (
        binding.boundary is not boundary
        or binding.binding_id != binding_id
        or binding.generation != generation
        or binding.tool_id != tool_id
        or binding.action_family != action_family
    ):
        raise IntegratedAgentConfigurationError()


def integrated_development_dogfood_profile(
    *,
    profile_id: IntegratedExecutionProfileId,
    generation: IntegratedExecutionProfileGeneration,
    agent_id: AgentId,
    data_flow_policy: IntegratedDataFlowPolicy,
    workspace_list_binding: WorkspaceAgentToolBinding,
    workspace_read_binding: WorkspaceAgentToolBinding,
    limits: AgentLimits | None = None,
    budget_extension: IntegratedBudgetExtension | None = None,
    durability_profile: str | None = None,
) -> IntegratedDogfoodProfile:
    """Compose the minimal development deployment profile from exact workspace authority."""

    _require_workspace_dogfood_binding(
        workspace_list_binding,
        agent_id=agent_id,
        action=WORKSPACE_LIST_ACTION,
    )
    _require_workspace_dogfood_binding(
        workspace_read_binding,
        agent_id=agent_id,
        action=WORKSPACE_READ_ACTION,
    )
    if workspace_list_binding.binding_id != workspace_read_binding.binding_id:
        raise IntegratedAgentConfigurationError()

    workspace = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=workspace_list_binding.binding_id,
    )
    execution = IntegratedExecutionProfile(
        profile_id=profile_id,
        generation=generation,
        agent_id=agent_id,
        tool_bindings=(
            _dogfood_plan_binding(),
            _dogfood_bridge(
                workspace_list_binding.tool_id,
                workspace,
                WORKSPACE_LIST_ACTION,
            ),
            _dogfood_bridge(
                workspace_read_binding.tool_id,
                workspace,
                WORKSPACE_READ_ACTION,
            ),
        ),
        data_flow_policy=data_flow_policy,
        limits=AgentLimits() if limits is None else limits,
        budget_extension=(
            IntegratedBudgetExtension() if budget_extension is None else budget_extension
        ),
        workspace_binding=workspace,
        durability_profile=durability_profile,
    )
    return IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, execution)


def integrated_research_dogfood_profile(
    *,
    profile_id: IntegratedExecutionProfileId,
    generation: IntegratedExecutionProfileGeneration,
    agent_id: AgentId,
    data_flow_policy: IntegratedDataFlowPolicy,
    memory_search_binding: MemoryAgentToolBinding,
    memory_read_binding: MemoryAgentToolBinding,
    workspace_list_binding: WorkspaceAgentToolBinding,
    workspace_read_binding: WorkspaceAgentToolBinding,
    network_http_binding: NetworkEgressToolBinding,
    browser_profile: BrowserProfile,
    browser_open_binding: BrowserToolBinding,
    browser_navigate_binding: BrowserToolBinding,
    browser_read_binding: BrowserToolBinding,
    browser_close_binding: BrowserToolBinding,
    limits: AgentLimits | None = None,
    budget_extension: IntegratedBudgetExtension | None = None,
    durability_profile: str | None = None,
) -> IntegratedDogfoodProfile:
    """Compose the minimal research profile from reviewed existing Phoenix authorities."""

    _require_memory_dogfood_binding(
        memory_search_binding,
        agent_id=agent_id,
        action=MEMORY_SEARCH_ACTION,
    )
    _require_memory_dogfood_binding(
        memory_read_binding,
        agent_id=agent_id,
        action=MEMORY_READ_ACTION,
    )
    if memory_search_binding.binding_id != memory_read_binding.binding_id:
        raise IntegratedAgentConfigurationError()

    _require_workspace_dogfood_binding(
        workspace_list_binding,
        agent_id=agent_id,
        action=WORKSPACE_LIST_ACTION,
    )
    _require_workspace_dogfood_binding(
        workspace_read_binding,
        agent_id=agent_id,
        action=WORKSPACE_READ_ACTION,
    )
    if workspace_list_binding.binding_id != workspace_read_binding.binding_id:
        raise IntegratedAgentConfigurationError()

    if not isinstance(network_http_binding, NetworkEgressToolBinding):
        raise TypeError("network_http_binding must be NetworkEgressToolBinding")
    if network_http_binding.agent_id != agent_id:
        raise IntegratedAgentConfigurationError()
    network_operation = network_http_binding.profile.require_operation(
        network_http_binding.operation_id
    )
    if network_operation.effect is not NetworkOperationEffect.READ_ONLY:
        raise IntegratedAgentConfigurationError()

    if not isinstance(browser_profile, BrowserProfile):
        raise TypeError("browser_profile must be BrowserProfile")
    for binding, action in (
        (browser_open_binding, BROWSER_SESSION_OPEN_ACTION),
        (browser_navigate_binding, BROWSER_PAGE_NAVIGATE_ACTION),
        (browser_read_binding, BROWSER_PAGE_READ_ACTION),
        (browser_close_binding, BROWSER_SESSION_CLOSE_ACTION),
    ):
        _require_browser_dogfood_binding(
            binding,
            agent_id=agent_id,
            profile=browser_profile,
            action=action,
        )

    memory = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=memory_search_binding.binding_id,
    )
    workspace = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=workspace_list_binding.binding_id,
    )
    network = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=integrated_network_profile_binding_id(network_http_binding.profile),
        generation=network_http_binding.profile.generation,
    )
    browser = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id=integrated_browser_profile_binding_id(browser_profile),
        generation=browser_profile.generation,
    )

    execution = IntegratedExecutionProfile(
        profile_id=profile_id,
        generation=generation,
        agent_id=agent_id,
        tool_bindings=(
            _dogfood_plan_binding(),
            _dogfood_bridge(memory_search_binding.tool_id, memory, MEMORY_SEARCH_ACTION),
            _dogfood_bridge(memory_read_binding.tool_id, memory, MEMORY_READ_ACTION),
            _dogfood_bridge(workspace_list_binding.tool_id, workspace, WORKSPACE_LIST_ACTION),
            _dogfood_bridge(workspace_read_binding.tool_id, workspace, WORKSPACE_READ_ACTION),
            _dogfood_bridge(
                network_http_binding.tool_id,
                network,
                NETWORK_HTTP_REQUEST_ACTION,
            ),
            _dogfood_bridge(
                browser_open_binding.tool_id,
                browser,
                BROWSER_SESSION_OPEN_ACTION,
            ),
            _dogfood_bridge(
                browser_navigate_binding.tool_id,
                browser,
                BROWSER_PAGE_NAVIGATE_ACTION,
            ),
            _dogfood_bridge(
                browser_read_binding.tool_id,
                browser,
                BROWSER_PAGE_READ_ACTION,
            ),
            _dogfood_bridge(
                browser_close_binding.tool_id,
                browser,
                BROWSER_SESSION_CLOSE_ACTION,
            ),
        ),
        data_flow_policy=data_flow_policy,
        limits=AgentLimits() if limits is None else limits,
        budget_extension=(
            IntegratedBudgetExtension() if budget_extension is None else budget_extension
        ),
        memory_binding=memory,
        workspace_binding=workspace,
        network_profile_binding=network,
        browser_profile_binding=browser,
        durability_profile=durability_profile,
    )
    return IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, execution)


def integrated_desktop_dogfood_profile(
    *,
    profile_id: IntegratedExecutionProfileId,
    generation: IntegratedExecutionProfileGeneration,
    agent_id: AgentId,
    data_flow_policy: IntegratedDataFlowPolicy,
    host_id: HostId,
    limits: AgentLimits | None = None,
    budget_extension: IntegratedBudgetExtension | None = None,
    durability_profile: str | None = None,
) -> IntegratedDogfoodProfile:
    """Compose the minimal desktop/integrated profile with observation-only host tools."""

    host = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
    )
    execution = IntegratedExecutionProfile(
        profile_id=profile_id,
        generation=generation,
        agent_id=agent_id,
        tool_bindings=(
            _dogfood_plan_binding(),
            _dogfood_bridge(ToolId(HOST_PROCESS_LIST_ACTION), host, HOST_PROCESS_LIST_ACTION),
            _dogfood_bridge(ToolId(HOST_WINDOW_LIST_ACTION), host, HOST_WINDOW_LIST_ACTION),
        ),
        data_flow_policy=data_flow_policy,
        limits=AgentLimits() if limits is None else limits,
        budget_extension=(
            IntegratedBudgetExtension() if budget_extension is None else budget_extension
        ),
        host_profile_binding=host,
        durability_profile=durability_profile,
    )
    return IntegratedDogfoodProfile(DogfoodTaskClass.DESKTOP_INTEGRATED, execution)


def _dogfood_plan_binding() -> IntegratedLocalTransformBinding:
    return IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
        advisory_state_keys=("plan",),
    )


def _dogfood_bridge(
    tool_id: ToolId,
    capability: IntegratedCapabilityProfileBinding,
    action_family: str,
) -> IntegratedDownstreamBridgeBinding:
    return IntegratedDownstreamBridgeBinding(
        tool_id=tool_id,
        boundary=capability.boundary,
        binding_id=capability.binding_id,
        generation=capability.generation,
        action_family=action_family,
    )


def _require_memory_dogfood_binding(
    binding: MemoryAgentToolBinding,
    *,
    agent_id: AgentId,
    action: str,
) -> None:
    if not isinstance(binding, MemoryAgentToolBinding):
        raise TypeError("memory dogfood binding must be MemoryAgentToolBinding")
    if binding.agent_id != agent_id or binding.action != action:
        raise IntegratedAgentConfigurationError()


def _require_workspace_dogfood_binding(
    binding: WorkspaceAgentToolBinding,
    *,
    agent_id: AgentId,
    action: str,
) -> None:
    if not isinstance(binding, WorkspaceAgentToolBinding):
        raise TypeError("workspace dogfood binding must be WorkspaceAgentToolBinding")
    if binding.agent_id != agent_id or binding.action != action:
        raise IntegratedAgentConfigurationError()


def _require_browser_dogfood_binding(
    binding: BrowserToolBinding,
    *,
    agent_id: AgentId,
    profile: BrowserProfile,
    action: str,
) -> None:
    if not isinstance(binding, BrowserToolBinding):
        raise TypeError("browser dogfood binding must be BrowserToolBinding")
    if (
        binding.agent_id != agent_id
        or binding.browser_action != action
        or binding.profile_id != profile.profile_id
        or binding.profile_generation != profile.generation
    ):
        raise IntegratedAgentConfigurationError()
    target = binding.navigation_target_id
    if action == BROWSER_PAGE_NAVIGATE_ACTION:
        if target is None:
            raise IntegratedAgentConfigurationError()
        try:
            profile.require_target(target)
        except KeyError as exception:
            raise IntegratedAgentConfigurationError() from exception
    elif target is not None:
        raise IntegratedAgentConfigurationError()
