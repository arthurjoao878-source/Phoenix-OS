from __future__ import annotations

from dataclasses import replace

import pytest

from phoenix_os.agent import AgentId, ToolId
from phoenix_os.agent.memory_agent_tools import (
    MemoryAgentToolBinding,
    MemoryToolAdapter,
)
from phoenix_os.agent.memory_authorization import (
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
)
from phoenix_os.agent.memory_contracts import MemoryLimits, MemoryNamespace, MemoryScopeKind
from phoenix_os.agent.memory_retrieval import AgentMemoryService
from phoenix_os.agent.workspace_agent_tools import (
    WorkspaceAgentToolBinding,
    WorkspaceToolAdapter,
)
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
)
from phoenix_os.agent.workspace_contracts import (
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceScopeKind,
)
from phoenix_os.agent.workspace_service import AgentWorkspaceService
from phoenix_os.authority.catalog import NETWORK_HTTP_REQUEST_ACTION
from phoenix_os.browser_automation.agent_tools import (
    BrowserToolAdapter,
    BrowserToolBinding,
    browser_tool_resource,
)
from phoenix_os.browser_automation.authorization import BROWSER_PAGE_READ_ACTION
from phoenix_os.browser_automation.contracts import (
    BrowserAdapterId,
    BrowserNavigationTargetId,
    BrowserProfileId,
)
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserOrigin,
    BrowserProfile,
)
from phoenix_os.browser_automation.service import BrowserAutomationService
from phoenix_os.host_automation.agent_control_tools import (
    HOST_APPLICATION_LAUNCH_TOOL_ID,
)
from phoenix_os.host_automation.agent_tools import HostProcessListToolAdapter
from phoenix_os.host_automation.authorization import (
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_PROCESS_LIST_ACTION,
    host_application_resource,
    host_process_collection_resource,
)
from phoenix_os.host_automation.contracts import (
    HostApplicationId,
    HostAutomationLimits,
    HostId,
)
from phoenix_os.host_automation.service import HostAutomationService
from phoenix_os.integrated_agent import (
    IntegratedAgentConfigurationError,
    IntegratedAgentToolComposition,
    IntegratedCapabilityProfileBinding,
    IntegratedDataFlowPolicy,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    integrated_browser_profile_binding_id,
    integrated_browser_tool_registration,
    integrated_host_application_launch_registration,
    integrated_host_binding_id,
    integrated_host_process_list_registration,
    integrated_memory_tool_registration,
    integrated_network_http_registration,
    integrated_network_profile_binding_id,
    integrated_workspace_tool_registration,
)
from phoenix_os.network_egress.agent_tools import (
    NetworkEgressToolBinding,
    NetworkHttpToolAdapter,
)
from phoenix_os.network_egress.authorization import network_http_resource
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)
from phoenix_os.network_egress.service import NetworkEgressService


def _host_service() -> HostAutomationService:
    return object.__new__(HostAutomationService)


def _network_service() -> NetworkEgressService:
    return object.__new__(NetworkEgressService)


def _browser_service() -> BrowserAutomationService:
    return object.__new__(BrowserAutomationService)


class _MemoryCompositionService(AgentMemoryService):
    def __init__(self) -> None:
        pass

    @property
    def limits(self) -> MemoryLimits:
        return MemoryLimits()


class _WorkspaceCompositionService(AgentWorkspaceService):
    def __init__(self) -> None:
        pass

    @property
    def limits(self) -> WorkspaceLimits:
        return WorkspaceLimits()


def _memory_service() -> AgentMemoryService:
    return _MemoryCompositionService()


def _workspace_service() -> AgentWorkspaceService:
    return _WorkspaceCompositionService()


def _network_fixture() -> tuple[
    NetworkEgressProfile,
    NetworkEgressToolBinding,
    IntegratedDownstreamBridgeBinding,
]:
    operation = NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("supplier-read"),
        method=NetworkHttpMethod.GET,
        request_target="/supplier",
        effect=NetworkOperationEffect.READ_ONLY,
        limits=NetworkOperationLimits(max_response_body_bytes=131_072),
    )
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("supplier-api"),
        generation=7,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="example.com",
        operations=(operation,),
    )
    downstream = NetworkEgressToolBinding(
        agent_id=AgentId("research-agent"),
        tool_id=ToolId("research.network.supplier"),
        profile=profile,
        operation_id=operation.operation_id,
    )
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=downstream.tool_id,
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=integrated_network_profile_binding_id(profile),
        generation=profile.generation,
        action_family=NETWORK_HTTP_REQUEST_ACTION,
    )
    return profile, downstream, bridge


def _browser_fixture() -> tuple[
    BrowserProfile,
    BrowserToolBinding,
    IntegratedDownstreamBridgeBinding,
]:
    origin = BrowserOrigin(
        mode=BrowserDestinationMode.HOSTED_HTTPS,
        host="example.com",
    )
    target = BrowserNavigationTarget(
        target_id=BrowserNavigationTargetId("supplier-home"),
        origin=origin,
        request_target="/supplier",
    )
    profile = BrowserProfile(
        profile_id=BrowserProfileId("supplier-research"),
        generation=4,
        adapter_id=BrowserAdapterId("deterministic"),
        allowed_origins=(origin,),
        initial_targets=(target,),
    )
    downstream = BrowserToolBinding(
        agent_id=AgentId("research-agent"),
        tool_id=ToolId("research.browser.read"),
        browser_action=BROWSER_PAGE_READ_ACTION,
        profile_id=profile.profile_id,
        profile_generation=profile.generation,
    )
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=downstream.tool_id,
        boundary=IntegratedDownstreamBoundary.BROWSER,
        binding_id=integrated_browser_profile_binding_id(profile),
        generation=profile.generation,
        action_family=downstream.browser_action,
    )
    return profile, downstream, bridge


def _substitute_host_bridge(
    bridge: IntegratedDownstreamBridgeBinding,
    substitution: str,
) -> IntegratedDownstreamBridgeBinding:
    if substitution == "binding_id":
        return replace(bridge, binding_id="host-automation:host:other")
    if substitution == "generation":
        return replace(bridge, generation=1)
    if substitution == "tool_id":
        return replace(bridge, tool_id=ToolId("host.window.list"))
    if substitution == "action_family":
        return replace(bridge, action_family="host.window.list")
    raise AssertionError(f"unknown host substitution: {substitution}")


def _substitute_network_bridge(
    bridge: IntegratedDownstreamBridgeBinding,
    substitution: str,
) -> IntegratedDownstreamBridgeBinding:
    if substitution == "binding_id":
        return replace(bridge, binding_id="network:profile/other")
    if substitution == "generation":
        return replace(bridge, generation=8)
    if substitution == "tool_id":
        return replace(bridge, tool_id=ToolId("research.network.other"))
    if substitution == "action_family":
        return replace(bridge, action_family="network.http.other")
    raise AssertionError(f"unknown network substitution: {substitution}")


def _substitute_browser_bridge(
    bridge: IntegratedDownstreamBridgeBinding,
    substitution: str,
) -> IntegratedDownstreamBridgeBinding:
    if substitution == "binding_id":
        return replace(bridge, binding_id="browser:profile/other")
    if substitution == "generation":
        return replace(bridge, generation=5)
    if substitution == "tool_id":
        return replace(bridge, tool_id=ToolId("research.browser.other"))
    if substitution == "action_family":
        return replace(bridge, action_family="browser.page.navigate")
    raise AssertionError(f"unknown browser substitution: {substitution}")


def test_host_process_bridge_reuses_exact_reviewed_facade_and_host_resource() -> None:
    host_id = HostId("desktop")
    limits = HostAutomationLimits()
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId(HOST_PROCESS_LIST_ACTION),
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        action_family=HOST_PROCESS_LIST_ACTION,
    )

    registration = integrated_host_process_list_registration(
        bridge,
        _host_service(),
        host_id=host_id,
        limits=limits,
    )

    assert isinstance(registration.adapter, HostProcessListToolAdapter)
    assert registration.tool_id == ToolId(HOST_PROCESS_LIST_ACTION)
    assert registration.resolver.resolve_resource({"limit": 1}) == (
        host_process_collection_resource(host_id)
    )


def test_host_control_bridge_keeps_application_selection_inside_reviewed_resolver() -> None:
    host_id = HostId("desktop")
    application = HostApplicationId("editor")
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=HOST_APPLICATION_LAUNCH_TOOL_ID,
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        action_family=HOST_APPLICATION_LAUNCH_ACTION,
    )

    registration = integrated_host_application_launch_registration(
        bridge,
        _host_service(),
        host_id=host_id,
        limits=HostAutomationLimits(),
        applications=(application,),
    )

    assert registration.resolver.resolve_resource(
        {"application_id": str(application)}
    ) == host_application_resource(host_id, application)


@pytest.mark.parametrize(
    "substitution",
    ("binding_id", "generation", "tool_id", "action_family"),
)
def test_host_bridge_rejects_binding_generation_tool_or_action_substitution(
    substitution: str,
) -> None:
    host_id = HostId("desktop")
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=ToolId(HOST_PROCESS_LIST_ACTION),
        boundary=IntegratedDownstreamBoundary.HOST,
        binding_id=integrated_host_binding_id(host_id),
        action_family=HOST_PROCESS_LIST_ACTION,
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_host_process_list_registration(
            _substitute_host_bridge(bridge, substitution),
            _host_service(),
            host_id=host_id,
            limits=HostAutomationLimits(),
        )


def test_network_bridge_reuses_exact_profile_operation_resource_and_adapter() -> None:
    profile, downstream, bridge = _network_fixture()

    registration = integrated_network_http_registration(
        bridge,
        _network_service(),
        downstream,
    )

    assert isinstance(registration.adapter, NetworkHttpToolAdapter)
    assert registration.resolver.resolve_resource({}) == network_http_resource(
        profile,
        downstream.operation,
    )


@pytest.mark.parametrize(
    "substitution",
    ("binding_id", "generation", "tool_id", "action_family"),
)
def test_network_bridge_rejects_profile_generation_tool_or_action_substitution(
    substitution: str,
) -> None:
    _profile, downstream, bridge = _network_fixture()

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_network_http_registration(
            _substitute_network_bridge(bridge, substitution),
            _network_service(),
            downstream,
        )


def test_network_bridge_registration_composes_with_exact_integrated_profile() -> None:
    profile, downstream, bridge = _network_fixture()
    capability = IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary.NETWORK,
        binding_id=integrated_network_profile_binding_id(profile),
        generation=profile.generation,
    )
    integrated_profile = IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("network-composition"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=AgentId("research-agent"),
        tool_bindings=(bridge,),
        network_profile_binding=capability,
        data_flow_policy=IntegratedDataFlowPolicy(),
    )
    registration = integrated_network_http_registration(
        bridge,
        _network_service(),
        downstream,
    )

    composition = IntegratedAgentToolComposition(
        integrated_profile,
        (registration,),
    )
    assert composition.tool_ids == (bridge.tool_id,)


def test_browser_bridge_reuses_exact_profile_generation_action_and_resource() -> None:
    profile, downstream, bridge = _browser_fixture()

    registration = integrated_browser_tool_registration(
        bridge,
        _browser_service(),
        downstream,
        profile,
    )

    assert isinstance(registration.adapter, BrowserToolAdapter)
    assert registration.resolver.resolve_resource({}) == browser_tool_resource(downstream)


@pytest.mark.parametrize(
    "substitution",
    ("binding_id", "generation", "tool_id", "action_family"),
)
def test_browser_bridge_rejects_profile_generation_tool_or_action_substitution(
    substitution: str,
) -> None:
    profile, downstream, bridge = _browser_fixture()

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_browser_tool_registration(
            _substitute_browser_bridge(bridge, substitution),
            _browser_service(),
            downstream,
            profile,
        )


def _memory_bridge_fixture() -> tuple[
    MemoryAgentToolBinding,
    IntegratedDownstreamBridgeBinding,
]:
    downstream = MemoryAgentToolBinding(
        agent_id=AgentId("research-agent"),
        tool_id=ToolId("research.memory.search"),
        namespace=MemoryNamespace("research-memory"),
        scope_kind=MemoryScopeKind.AGENT,
        action=MEMORY_SEARCH_ACTION,
    )
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=downstream.tool_id,
        boundary=IntegratedDownstreamBoundary.MEMORY,
        binding_id=downstream.binding_id,
        action_family=downstream.action,
    )
    return downstream, bridge


def _workspace_bridge_fixture() -> tuple[
    WorkspaceAgentToolBinding,
    IntegratedDownstreamBridgeBinding,
]:
    downstream = WorkspaceAgentToolBinding(
        agent_id=AgentId("research-agent"),
        tool_id=ToolId("research.workspace.list"),
        namespace=WorkspaceNamespace("research-workspace"),
        scope_kind=WorkspaceScopeKind.AGENT,
        action=WORKSPACE_LIST_ACTION,
    )
    bridge = IntegratedDownstreamBridgeBinding(
        tool_id=downstream.tool_id,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=downstream.binding_id,
        action_family=downstream.action,
    )
    return downstream, bridge


def test_memory_bridge_reuses_contextual_facade_and_exact_capability_binding() -> None:
    downstream, bridge = _memory_bridge_fixture()

    registration = integrated_memory_tool_registration(
        bridge,
        _memory_service(),
        downstream,
    )

    assert isinstance(registration.adapter, MemoryToolAdapter)
    assert registration.binding == bridge
    assert registration.tool_id == downstream.tool_id


def test_memory_bridge_rejects_scope_generation_tool_or_action_substitution() -> None:
    downstream, bridge = _memory_bridge_fixture()
    substitutions = (
        replace(bridge, binding_id="agent-memory:other/scope:agent"),
        replace(bridge, generation=1),
        replace(bridge, tool_id=ToolId("research.memory.other")),
        replace(bridge, action_family=MEMORY_READ_ACTION),
    )

    for substituted in substitutions:
        with pytest.raises(IntegratedAgentConfigurationError):
            integrated_memory_tool_registration(
                substituted,
                _memory_service(),
                downstream,
            )


def test_workspace_bridge_reuses_contextual_facade_and_exact_capability_binding() -> None:
    downstream, bridge = _workspace_bridge_fixture()

    registration = integrated_workspace_tool_registration(
        bridge,
        _workspace_service(),
        downstream,
    )

    assert isinstance(registration.adapter, WorkspaceToolAdapter)
    assert registration.binding == bridge
    assert registration.tool_id == downstream.tool_id


def test_workspace_bridge_rejects_scope_generation_tool_or_action_substitution() -> None:
    downstream, bridge = _workspace_bridge_fixture()
    substitutions = (
        replace(bridge, binding_id="agent-workspace:other/scope:agent"),
        replace(bridge, generation=1),
        replace(bridge, tool_id=ToolId("research.workspace.other")),
        replace(bridge, action_family=WORKSPACE_READ_ACTION),
    )

    for substituted in substitutions:
        with pytest.raises(IntegratedAgentConfigurationError):
            integrated_workspace_tool_registration(
                substituted,
                _workspace_service(),
                downstream,
            )


def test_memory_and_workspace_registrations_compose_with_exact_profile() -> None:
    memory_downstream, memory_bridge = _memory_bridge_fixture()
    workspace_downstream, workspace_bridge = _workspace_bridge_fixture()
    profile = IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("memory-workspace-composition"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=AgentId("research-agent"),
        tool_bindings=(memory_bridge, workspace_bridge),
        memory_binding=IntegratedCapabilityProfileBinding(
            boundary=IntegratedDownstreamBoundary.MEMORY,
            binding_id=memory_downstream.binding_id,
        ),
        workspace_binding=IntegratedCapabilityProfileBinding(
            boundary=IntegratedDownstreamBoundary.WORKSPACE,
            binding_id=workspace_downstream.binding_id,
        ),
        data_flow_policy=IntegratedDataFlowPolicy(),
    )

    composition = IntegratedAgentToolComposition(
        profile,
        (
            integrated_memory_tool_registration(
                memory_bridge,
                _memory_service(),
                memory_downstream,
            ),
            integrated_workspace_tool_registration(
                workspace_bridge,
                _workspace_service(),
                workspace_downstream,
            ),
        ),
    )

    assert composition.tool_ids == (
        memory_bridge.tool_id,
        workspace_bridge.tool_id,
    )
