from __future__ import annotations

import inspect

import pytest

from phoenix_os.agent import AgentId, ToolId
from phoenix_os.agent.memory_agent_tools import MemoryAgentToolBinding
from phoenix_os.agent.memory_authorization import MEMORY_READ_ACTION, MEMORY_SEARCH_ACTION
from phoenix_os.agent.memory_contracts import MemoryNamespace, MemoryScopeKind
from phoenix_os.agent.workspace_agent_tools import WorkspaceAgentToolBinding
from phoenix_os.agent.workspace_authorization import WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION
from phoenix_os.agent.workspace_contracts import WorkspaceNamespace, WorkspaceScopeKind
from phoenix_os.browser_automation.agent_tools import BrowserToolBinding
from phoenix_os.browser_automation.authorization import (
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
)
from phoenix_os.browser_automation.contracts import (
    BrowserAdapterId,
    BrowserNavigationTargetId,
    BrowserProfileId,
)
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserNetworkPolicy,
    BrowserOrigin,
    BrowserProfile,
)
from phoenix_os.host_automation.authorization import (
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_LIST_ACTION,
)
from phoenix_os.host_automation.contracts import HostId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    DogfoodTaskClass,
    IntegratedAgentConfigurationError,
    IntegratedDataFlowPolicy,
    IntegratedDogfoodProfile,
    IntegratedDogfoodProfileCatalog,
    IntegratedDownstreamBoundary,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.composition import (
    integrated_browser_profile_binding_id,
    integrated_desktop_dogfood_profile,
    integrated_development_dogfood_profile,
    integrated_host_binding_id,
    integrated_network_profile_binding_id,
    integrated_research_dogfood_profile,
)
from phoenix_os.network_egress.agent_tools import (
    MAX_NETWORK_AGENT_TOOL_BODY_BYTES,
    NetworkEgressToolBinding,
)
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

_AGENT = AgentId("dogfood-agent")


def _workspace(action: str, tool_id: str) -> WorkspaceAgentToolBinding:
    return WorkspaceAgentToolBinding(
        agent_id=_AGENT,
        tool_id=ToolId(tool_id),
        namespace=WorkspaceNamespace("dogfood"),
        scope_kind=WorkspaceScopeKind.RUN,
        action=action,
    )


def _memory(action: str, tool_id: str) -> MemoryAgentToolBinding:
    return MemoryAgentToolBinding(
        agent_id=_AGENT,
        tool_id=ToolId(tool_id),
        namespace=MemoryNamespace("dogfood"),
        scope_kind=MemoryScopeKind.RUN,
        action=action,
    )


def _network() -> NetworkEgressToolBinding:
    operation = NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("research-fetch"),
        method=NetworkHttpMethod.GET,
        request_target="/research",
        effect=NetworkOperationEffect.READ_ONLY,
        limits=NetworkOperationLimits(
            max_response_body_bytes=MAX_NETWORK_AGENT_TOOL_BODY_BYTES,
        ),
    )
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("dogfood-research"),
        generation=4,
        mode=NetworkDestinationMode.LOOPBACK_HTTP,
        host="127.0.0.1",
        port=18081,
        operations=(operation,),
    )
    return NetworkEgressToolBinding(
        agent_id=_AGENT,
        tool_id=ToolId("research.network.fetch"),
        profile=profile,
        operation_id=operation.operation_id,
    )


def _remote_effect_network() -> NetworkEgressToolBinding:
    operation = NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("research-write"),
        method=NetworkHttpMethod.POST,
        request_target="/research",
        effect=NetworkOperationEffect.REMOTE_EFFECT,
        limits=NetworkOperationLimits(
            max_request_body_bytes=1_024,
            max_response_body_bytes=MAX_NETWORK_AGENT_TOOL_BODY_BYTES,
        ),
        content_type="application/json",
    )
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("dogfood-research-write"),
        generation=5,
        mode=NetworkDestinationMode.LOOPBACK_HTTP,
        host="127.0.0.1",
        port=18083,
        operations=(operation,),
    )
    return NetworkEgressToolBinding(
        agent_id=_AGENT,
        tool_id=ToolId("research.network.write"),
        profile=profile,
        operation_id=operation.operation_id,
    )


def _browser() -> tuple[
    BrowserProfile,
    BrowserToolBinding,
    BrowserToolBinding,
    BrowserToolBinding,
    BrowserToolBinding,
]:
    origin = BrowserOrigin(
        BrowserDestinationMode.LOOPBACK_HTTP,
        "127.0.0.1",
        18082,
    )
    target = BrowserNavigationTarget(
        BrowserNavigationTargetId("research-home"),
        origin,
        "/",
    )
    profile = BrowserProfile(
        profile_id=BrowserProfileId("dogfood-research"),
        generation=7,
        adapter_id=BrowserAdapterId("test-browser"),
        allowed_origins=(origin,),
        initial_targets=(target,),
        network_policy=BrowserNetworkPolicy(allow_public_networks=False),
    )
    return (
        profile,
        BrowserToolBinding(
            agent_id=_AGENT,
            tool_id=ToolId(BROWSER_SESSION_OPEN_ACTION),
            browser_action=BROWSER_SESSION_OPEN_ACTION,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
        ),
        BrowserToolBinding(
            agent_id=_AGENT,
            tool_id=ToolId("research.browser.navigate"),
            browser_action=BROWSER_PAGE_NAVIGATE_ACTION,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
            navigation_target_id=target.target_id,
        ),
        BrowserToolBinding(
            agent_id=_AGENT,
            tool_id=ToolId(BROWSER_PAGE_READ_ACTION),
            browser_action=BROWSER_PAGE_READ_ACTION,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
        ),
        BrowserToolBinding(
            agent_id=_AGENT,
            tool_id=ToolId(BROWSER_SESSION_CLOSE_ACTION),
            browser_action=BROWSER_SESSION_CLOSE_ACTION,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
        ),
    )


def _development() -> IntegratedDogfoodProfile:
    return integrated_development_dogfood_profile(
        profile_id=IntegratedExecutionProfileId("dogfood-development"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT,
        data_flow_policy=IntegratedDataFlowPolicy(),
        workspace_list_binding=_workspace(WORKSPACE_LIST_ACTION, WORKSPACE_LIST_ACTION),
        workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
    )


def _research() -> IntegratedDogfoodProfile:
    browser_profile, browser_open, browser_navigate, browser_read, browser_close = _browser()
    return integrated_research_dogfood_profile(
        profile_id=IntegratedExecutionProfileId("dogfood-research"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT,
        data_flow_policy=IntegratedDataFlowPolicy(),
        memory_search_binding=_memory(MEMORY_SEARCH_ACTION, MEMORY_SEARCH_ACTION),
        memory_read_binding=_memory(MEMORY_READ_ACTION, MEMORY_READ_ACTION),
        workspace_list_binding=_workspace(WORKSPACE_LIST_ACTION, WORKSPACE_LIST_ACTION),
        workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
        network_http_binding=_network(),
        browser_profile=browser_profile,
        browser_open_binding=browser_open,
        browser_navigate_binding=browser_navigate,
        browser_read_binding=browser_read,
        browser_close_binding=browser_close,
    )


def _desktop() -> IntegratedDogfoodProfile:
    return integrated_desktop_dogfood_profile(
        profile_id=IntegratedExecutionProfileId("dogfood-desktop"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT,
        data_flow_policy=IntegratedDataFlowPolicy(),
        host_id=HostId("dogfood-host"),
    )


def test_development_factory_reuses_exact_workspace_authority_and_stays_read_only() -> None:
    profile = _development()
    execution = profile.execution_profile

    assert profile.task_class is DogfoodTaskClass.DEVELOPMENT
    assert execution.workspace_binding is not None
    assert execution.workspace_binding.boundary is IntegratedDownstreamBoundary.WORKSPACE
    assert execution.workspace_binding.binding_id == "agent-workspace:dogfood/scope:run"
    assert execution.tool_ids == (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        ToolId(WORKSPACE_LIST_ACTION),
        ToolId(WORKSPACE_READ_ACTION),
    )


def test_research_factory_reuses_generation_bound_network_and_browser_authority() -> None:
    network = _network()
    browser_profile, browser_open, browser_navigate, browser_read, browser_close = _browser()
    profile = integrated_research_dogfood_profile(
        profile_id=IntegratedExecutionProfileId("dogfood-research-exact"),
        generation=IntegratedExecutionProfileGeneration(2),
        agent_id=_AGENT,
        data_flow_policy=IntegratedDataFlowPolicy(),
        memory_search_binding=_memory(MEMORY_SEARCH_ACTION, MEMORY_SEARCH_ACTION),
        memory_read_binding=_memory(MEMORY_READ_ACTION, MEMORY_READ_ACTION),
        workspace_list_binding=_workspace(WORKSPACE_LIST_ACTION, WORKSPACE_LIST_ACTION),
        workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
        network_http_binding=network,
        browser_profile=browser_profile,
        browser_open_binding=browser_open,
        browser_navigate_binding=browser_navigate,
        browser_read_binding=browser_read,
        browser_close_binding=browser_close,
    )
    execution = profile.execution_profile

    assert profile.task_class is DogfoodTaskClass.RESEARCH
    assert execution.network_profile_binding is not None
    assert execution.network_profile_binding.binding_id == integrated_network_profile_binding_id(
        network.profile
    )
    assert execution.network_profile_binding.generation == network.profile.generation
    assert execution.browser_profile_binding is not None
    assert execution.browser_profile_binding.binding_id == integrated_browser_profile_binding_id(
        browser_profile
    )
    assert execution.browser_profile_binding.generation == browser_profile.generation


def test_research_factory_rejects_remote_effect_network_operation() -> None:
    browser_profile, browser_open, browser_navigate, browser_read, browser_close = _browser()

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_research_dogfood_profile(
            profile_id=IntegratedExecutionProfileId("dogfood-research-remote-effect"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=_AGENT,
            data_flow_policy=IntegratedDataFlowPolicy(),
            memory_search_binding=_memory(MEMORY_SEARCH_ACTION, MEMORY_SEARCH_ACTION),
            memory_read_binding=_memory(MEMORY_READ_ACTION, MEMORY_READ_ACTION),
            workspace_list_binding=_workspace(WORKSPACE_LIST_ACTION, WORKSPACE_LIST_ACTION),
            workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
            network_http_binding=_remote_effect_network(),
            browser_profile=browser_profile,
            browser_open_binding=browser_open,
            browser_navigate_binding=browser_navigate,
            browser_read_binding=browser_read,
            browser_close_binding=browser_close,
        )


def test_research_factory_rejects_navigation_target_not_in_exact_profile() -> None:
    browser_profile, browser_open, _browser_navigate, browser_read, browser_close = _browser()
    substituted_navigate = BrowserToolBinding(
        agent_id=_AGENT,
        tool_id=ToolId("research.browser.navigate"),
        browser_action=BROWSER_PAGE_NAVIGATE_ACTION,
        profile_id=browser_profile.profile_id,
        profile_generation=browser_profile.generation,
        navigation_target_id=BrowserNavigationTargetId("not-configured"),
    )

    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_research_dogfood_profile(
            profile_id=IntegratedExecutionProfileId("dogfood-research-target-substitution"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=_AGENT,
            data_flow_policy=IntegratedDataFlowPolicy(),
            memory_search_binding=_memory(MEMORY_SEARCH_ACTION, MEMORY_SEARCH_ACTION),
            memory_read_binding=_memory(MEMORY_READ_ACTION, MEMORY_READ_ACTION),
            workspace_list_binding=_workspace(WORKSPACE_LIST_ACTION, WORKSPACE_LIST_ACTION),
            workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
            network_http_binding=_network(),
            browser_profile=browser_profile,
            browser_open_binding=browser_open,
            browser_navigate_binding=substituted_navigate,
            browser_read_binding=browser_read,
            browser_close_binding=browser_close,
        )


def test_desktop_factory_exposes_only_observation_tools_for_exact_host() -> None:
    host_id = HostId("dogfood-host")
    profile = integrated_desktop_dogfood_profile(
        profile_id=IntegratedExecutionProfileId("dogfood-desktop-exact"),
        generation=IntegratedExecutionProfileGeneration(3),
        agent_id=_AGENT,
        data_flow_policy=IntegratedDataFlowPolicy(),
        host_id=host_id,
    )
    execution = profile.execution_profile

    assert profile.task_class is DogfoodTaskClass.DESKTOP_INTEGRATED
    assert execution.host_profile_binding is not None
    assert execution.host_profile_binding.binding_id == integrated_host_binding_id(host_id)
    assert execution.tool_ids == (
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        ToolId(HOST_PROCESS_LIST_ACTION),
        ToolId(HOST_WINDOW_LIST_ACTION),
    )


def test_concrete_factories_form_the_complete_evidence_matrix() -> None:
    catalog = IntegratedDogfoodProfileCatalog((_development(), _research(), _desktop()))

    assert catalog.require_complete_matrix() == (
        catalog.require(DogfoodTaskClass.DEVELOPMENT),
        catalog.require(DogfoodTaskClass.RESEARCH),
        catalog.require(DogfoodTaskClass.DESKTOP_INTEGRATED),
    )


def test_concrete_factories_fail_closed_on_cross_agent_or_profile_substitution() -> None:
    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_development_dogfood_profile(
            profile_id=IntegratedExecutionProfileId("cross-agent"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=_AGENT,
            data_flow_policy=IntegratedDataFlowPolicy(),
            workspace_list_binding=WorkspaceAgentToolBinding(
                agent_id=AgentId("other-agent"),
                tool_id=ToolId(WORKSPACE_LIST_ACTION),
                namespace=WorkspaceNamespace("dogfood"),
                scope_kind=WorkspaceScopeKind.RUN,
                action=WORKSPACE_LIST_ACTION,
            ),
            workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
        )

    browser_profile, browser_open, browser_navigate, browser_read, browser_close = _browser()
    substituted = BrowserProfile(
        profile_id=BrowserProfileId("dogfood-research-other"),
        generation=browser_profile.generation,
        adapter_id=browser_profile.adapter_id,
        allowed_origins=browser_profile.allowed_origins,
        initial_targets=browser_profile.initial_targets,
        network_policy=browser_profile.network_policy,
        limits=browser_profile.limits,
    )
    with pytest.raises(IntegratedAgentConfigurationError):
        integrated_research_dogfood_profile(
            profile_id=IntegratedExecutionProfileId("browser-substitution"),
            generation=IntegratedExecutionProfileGeneration(1),
            agent_id=_AGENT,
            data_flow_policy=IntegratedDataFlowPolicy(),
            memory_search_binding=_memory(MEMORY_SEARCH_ACTION, MEMORY_SEARCH_ACTION),
            memory_read_binding=_memory(MEMORY_READ_ACTION, MEMORY_READ_ACTION),
            workspace_list_binding=_workspace(WORKSPACE_LIST_ACTION, WORKSPACE_LIST_ACTION),
            workspace_read_binding=_workspace(WORKSPACE_READ_ACTION, WORKSPACE_READ_ACTION),
            network_http_binding=_network(),
            browser_profile=substituted,
            browser_open_binding=browser_open,
            browser_navigate_binding=browser_navigate,
            browser_read_binding=browser_read,
            browser_close_binding=browser_close,
        )


def test_factory_signatures_are_provider_neutral_and_authority_only() -> None:
    forbidden = {
        "provider",
        "provider_id",
        "model",
        "model_id",
        "endpoint",
        "credential",
        "secret",
        "shell",
        "filesystem",
    }
    for factory in (
        integrated_development_dogfood_profile,
        integrated_research_dogfood_profile,
        integrated_desktop_dogfood_profile,
    ):
        assert forbidden.isdisjoint(inspect.signature(factory).parameters)
