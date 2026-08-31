from dataclasses import fields

import pytest

from phoenix_os.agent import AgentId, ToolId
from phoenix_os.agent.memory_authorization import MEMORY_READ_ACTION, MEMORY_SEARCH_ACTION
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
    WORKSPACE_WRITE_ACTION,
)
from phoenix_os.authority.catalog import (
    BROWSER_ELEMENT_CLICK_ACTION,
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
    NETWORK_HTTP_REQUEST_ACTION,
)
from phoenix_os.host_automation.authorization import (
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_LIST_ACTION,
)
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    DogfoodTaskClass,
    IntegratedCapabilityProfileBinding,
    IntegratedDataFlowPolicy,
    IntegratedDogfoodProfile,
    IntegratedDogfoodProfileCatalog,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedLocalTransformBinding,
)


def _plan() -> IntegratedLocalTransformBinding:
    return IntegratedLocalTransformBinding(
        tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
        transform_id="integrated.plan.update",
        advisory_state_keys=("plan",),
    )


def _capability(
    boundary: IntegratedDownstreamBoundary,
    binding_id: str,
    *,
    generation: int | None = None,
) -> IntegratedCapabilityProfileBinding:
    return IntegratedCapabilityProfileBinding(
        boundary=boundary,
        binding_id=binding_id,
        generation=generation,
    )


def _bridge(
    tool_id: str,
    boundary: IntegratedDownstreamBoundary,
    capability: IntegratedCapabilityProfileBinding,
    action: str,
) -> IntegratedDownstreamBridgeBinding:
    return IntegratedDownstreamBridgeBinding(
        tool_id=ToolId(tool_id),
        boundary=boundary,
        binding_id=capability.binding_id,
        generation=capability.generation,
        action_family=action,
    )


def _profile(
    profile_id: str,
    capabilities: tuple[IntegratedCapabilityProfileBinding, ...],
    bridges: tuple[IntegratedDownstreamBridgeBinding, ...],
) -> IntegratedExecutionProfile:
    by_boundary = {item.boundary: item for item in capabilities}
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId(profile_id),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=AgentId(f"{profile_id}-agent"),
        tool_bindings=(_plan(), *bridges),
        data_flow_policy=IntegratedDataFlowPolicy(),
        memory_binding=by_boundary.get(IntegratedDownstreamBoundary.MEMORY),
        workspace_binding=by_boundary.get(IntegratedDownstreamBoundary.WORKSPACE),
        host_profile_binding=by_boundary.get(IntegratedDownstreamBoundary.HOST),
        network_profile_binding=by_boundary.get(IntegratedDownstreamBoundary.NETWORK),
        browser_profile_binding=by_boundary.get(IntegratedDownstreamBoundary.BROWSER),
    )


def _downstream_bridges(
    profile: IntegratedExecutionProfile,
) -> tuple[IntegratedDownstreamBridgeBinding, ...]:
    return tuple(
        binding
        for binding in profile.tool_bindings
        if isinstance(binding, IntegratedDownstreamBridgeBinding)
    )


def _development() -> IntegratedExecutionProfile:
    workspace = _capability(
        IntegratedDownstreamBoundary.WORKSPACE,
        "agent-workspace:dogfood-development/scope:run",
    )
    return _profile(
        "dogfood-development",
        (workspace,),
        (
            _bridge(
                WORKSPACE_LIST_ACTION,
                IntegratedDownstreamBoundary.WORKSPACE,
                workspace,
                WORKSPACE_LIST_ACTION,
            ),
            _bridge(
                WORKSPACE_READ_ACTION,
                IntegratedDownstreamBoundary.WORKSPACE,
                workspace,
                WORKSPACE_READ_ACTION,
            ),
        ),
    )


def _research() -> IntegratedExecutionProfile:
    memory = _capability(
        IntegratedDownstreamBoundary.MEMORY,
        "agent-memory:dogfood-research/scope:run",
    )
    workspace = _capability(
        IntegratedDownstreamBoundary.WORKSPACE,
        "agent-workspace:dogfood-research/scope:run",
    )
    network = _capability(
        IntegratedDownstreamBoundary.NETWORK,
        "network:profile/dogfood-research",
        generation=2,
    )
    browser = _capability(
        IntegratedDownstreamBoundary.BROWSER,
        "browser:profile/dogfood-research",
        generation=3,
    )
    return _profile(
        "dogfood-research",
        (memory, workspace, network, browser),
        (
            _bridge(
                MEMORY_SEARCH_ACTION,
                IntegratedDownstreamBoundary.MEMORY,
                memory,
                MEMORY_SEARCH_ACTION,
            ),
            _bridge(
                MEMORY_READ_ACTION,
                IntegratedDownstreamBoundary.MEMORY,
                memory,
                MEMORY_READ_ACTION,
            ),
            _bridge(
                WORKSPACE_LIST_ACTION,
                IntegratedDownstreamBoundary.WORKSPACE,
                workspace,
                WORKSPACE_LIST_ACTION,
            ),
            _bridge(
                WORKSPACE_READ_ACTION,
                IntegratedDownstreamBoundary.WORKSPACE,
                workspace,
                WORKSPACE_READ_ACTION,
            ),
            _bridge(
                "research.network.fetch",
                IntegratedDownstreamBoundary.NETWORK,
                network,
                NETWORK_HTTP_REQUEST_ACTION,
            ),
            _bridge(
                BROWSER_SESSION_OPEN_ACTION,
                IntegratedDownstreamBoundary.BROWSER,
                browser,
                BROWSER_SESSION_OPEN_ACTION,
            ),
            _bridge(
                "research.browser.navigate",
                IntegratedDownstreamBoundary.BROWSER,
                browser,
                BROWSER_PAGE_NAVIGATE_ACTION,
            ),
            _bridge(
                BROWSER_PAGE_READ_ACTION,
                IntegratedDownstreamBoundary.BROWSER,
                browser,
                BROWSER_PAGE_READ_ACTION,
            ),
            _bridge(
                BROWSER_SESSION_CLOSE_ACTION,
                IntegratedDownstreamBoundary.BROWSER,
                browser,
                BROWSER_SESSION_CLOSE_ACTION,
            ),
        ),
    )


def _desktop() -> IntegratedExecutionProfile:
    host = _capability(
        IntegratedDownstreamBoundary.HOST,
        "host-automation:host:dogfood-desktop",
    )
    return _profile(
        "dogfood-desktop",
        (host,),
        (
            _bridge(
                HOST_PROCESS_LIST_ACTION,
                IntegratedDownstreamBoundary.HOST,
                host,
                HOST_PROCESS_LIST_ACTION,
            ),
            _bridge(
                HOST_WINDOW_LIST_ACTION,
                IntegratedDownstreamBoundary.HOST,
                host,
                HOST_WINDOW_LIST_ACTION,
            ),
        ),
    )


def test_initial_catalog_requires_exact_three_bounded_task_classes() -> None:
    development = IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, _development())
    research = IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, _research())
    desktop = IntegratedDogfoodProfile(
        DogfoodTaskClass.DESKTOP_INTEGRATED,
        _desktop(),
    )

    catalog = IntegratedDogfoodProfileCatalog((development, research, desktop))

    assert DogfoodTaskClass.DESKTOP_INTEGRATED.value == "desktop/integrated"
    assert catalog.task_classes == tuple(DogfoodTaskClass)
    assert catalog.require(DogfoodTaskClass.DEVELOPMENT) is development
    assert catalog.require(DogfoodTaskClass.RESEARCH) is research
    assert catalog.require(DogfoodTaskClass.DESKTOP_INTEGRATED) is desktop
    assert catalog.require_complete_matrix() == (development, research, desktop)


def test_deployment_catalog_allows_one_profile_without_implying_full_release_matrix() -> None:
    development = IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, _development())
    catalog = IntegratedDogfoodProfileCatalog((development,))

    assert catalog.task_classes == (DogfoodTaskClass.DEVELOPMENT,)
    assert catalog.require(DogfoodTaskClass.DEVELOPMENT) is development
    with pytest.raises(ValueError, match="evidence matrix"):
        catalog.require_complete_matrix()

    with pytest.raises(ValueError, match="at least one"):
        IntegratedDogfoodProfileCatalog(())


def test_development_surface_is_workspace_read_only_and_rejects_write_or_extra_boundary() -> None:
    valid = _development()
    wrapped = IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, valid)
    assert wrapped.execution_profile is valid
    assert set(wrapped.tool_ids) == {
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        ToolId(WORKSPACE_LIST_ACTION),
        ToolId(WORKSPACE_READ_ACTION),
    }

    workspace = valid.workspace_binding
    assert workspace is not None
    write_profile = _profile(
        "dogfood-development-write",
        (workspace,),
        (
            _bridge(
                WORKSPACE_LIST_ACTION,
                IntegratedDownstreamBoundary.WORKSPACE,
                workspace,
                WORKSPACE_LIST_ACTION,
            ),
            _bridge(
                WORKSPACE_WRITE_ACTION,
                IntegratedDownstreamBoundary.WORKSPACE,
                workspace,
                WORKSPACE_WRITE_ACTION,
            ),
        ),
    )
    with pytest.raises(ValueError, match="minimal surface"):
        IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, write_profile)

    host = _capability(
        IntegratedDownstreamBoundary.HOST,
        "host-automation:host:unexpected",
    )
    extra = _profile(
        "dogfood-development-host",
        (workspace, host),
        _downstream_bridges(valid),
    )
    with pytest.raises(ValueError, match="capability boundaries"):
        IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, extra)


def test_development_rejects_duplicate_alias_for_an_allowed_action() -> None:
    valid = _development()
    workspace = valid.workspace_binding
    assert workspace is not None

    duplicate_read = _bridge(
        "workspace.read.alias",
        IntegratedDownstreamBoundary.WORKSPACE,
        workspace,
        WORKSPACE_READ_ACTION,
    )
    duplicated = _profile(
        "dogfood-development-duplicate-read",
        (workspace,),
        (*_downstream_bridges(valid), duplicate_read),
    )

    with pytest.raises(ValueError, match="exactly once"):
        IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, duplicated)


def test_research_requires_all_existing_boundaries_and_excludes_browser_effect_escape_hatches() -> (
    None
):
    valid = _research()
    wrapped = IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, valid)
    assert wrapped.execution_profile is valid

    capabilities = valid.capability_bindings
    without_network = tuple(
        item for item in capabilities if item.boundary is not IntegratedDownstreamBoundary.NETWORK
    )
    bridges_without_network = tuple(
        item
        for item in _downstream_bridges(valid)
        if not (
            isinstance(item, IntegratedDownstreamBridgeBinding)
            and item.boundary is IntegratedDownstreamBoundary.NETWORK
        )
    )
    missing = _profile("dogfood-research-no-network", without_network, bridges_without_network)
    with pytest.raises(ValueError, match="capability boundaries"):
        IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, missing)

    browser = valid.browser_profile_binding
    assert browser is not None
    click = _bridge(
        "research.browser.click",
        IntegratedDownstreamBoundary.BROWSER,
        browser,
        BROWSER_ELEMENT_CLICK_ACTION,
    )
    replaced = _profile(
        "dogfood-research-click",
        capabilities,
        (*_downstream_bridges(valid), click),
    )
    with pytest.raises(ValueError, match="minimal surface"):
        IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, replaced)


def test_desktop_surface_is_read_only_host_observation() -> None:
    valid = _desktop()
    wrapped = IntegratedDogfoodProfile(DogfoodTaskClass.DESKTOP_INTEGRATED, valid)
    assert set(wrapped.tool_ids) == {
        INTEGRATED_PLAN_UPDATE_TOOL_ID,
        ToolId(HOST_PROCESS_LIST_ACTION),
        ToolId(HOST_WINDOW_LIST_ACTION),
    }

    host = valid.host_profile_binding
    assert host is not None
    launch = _bridge(
        HOST_APPLICATION_LAUNCH_ACTION,
        IntegratedDownstreamBoundary.HOST,
        host,
        HOST_APPLICATION_LAUNCH_ACTION,
    )
    expanded = _profile(
        "dogfood-desktop-launch",
        (host,),
        (*_downstream_bridges(valid), launch),
    )
    with pytest.raises(ValueError, match="minimal surface"):
        IntegratedDogfoodProfile(DogfoodTaskClass.DESKTOP_INTEGRATED, expanded)


def test_initial_profiles_reject_lifecycle_shell_filesystem_and_repo_write_namespaces() -> None:
    valid = _development()
    workspace = valid.workspace_binding
    assert workspace is not None

    for forbidden in (
        "git.commit",
        "git.push.force",
        "git.merge",
        "git.tag.release",
        "release.publish",
        "shell.exec",
        "powershell.run",
        "filesystem.write",
        "repo.patch",
        "repo.write.file",
    ):
        profile = _profile(
            f"forbidden-{forbidden.replace('.', '-')}",
            (workspace,),
            (
                _bridge(
                    forbidden,
                    IntegratedDownstreamBoundary.WORKSPACE,
                    workspace,
                    WORKSPACE_LIST_ACTION,
                ),
                _bridge(
                    WORKSPACE_READ_ACTION,
                    IntegratedDownstreamBoundary.WORKSPACE,
                    workspace,
                    WORKSPACE_READ_ACTION,
                ),
            ),
        )
        with pytest.raises(ValueError, match="forbidden autonomous tool"):
            IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, profile)


def test_dogfood_wrapper_is_provider_neutral_and_does_not_rewrite_core_profile() -> None:
    profile = _research()
    wrapped = IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, profile)

    assert wrapped.execution_profile is profile
    wrapper_fields = {item.name for item in fields(IntegratedDogfoodProfile)}
    core_fields = {item.name for item in fields(IntegratedExecutionProfile)}
    for forbidden in (
        "provider",
        "provider_id",
        "model",
        "model_id",
        "endpoint",
        "credential",
        "secret",
        "adapter",
    ):
        assert forbidden not in wrapper_fields
        assert forbidden not in core_fields


def test_catalog_rejects_duplicate_class_or_reused_profile_identity() -> None:
    development = IntegratedDogfoodProfile(DogfoodTaskClass.DEVELOPMENT, _development())
    research = IntegratedDogfoodProfile(DogfoodTaskClass.RESEARCH, _research())
    desktop = IntegratedDogfoodProfile(
        DogfoodTaskClass.DESKTOP_INTEGRATED,
        _desktop(),
    )

    with pytest.raises(ValueError, match="duplicate task classes"):
        IntegratedDogfoodProfileCatalog((development, development, desktop))

    desktop_profile = _desktop()
    reused = IntegratedDogfoodProfile(
        DogfoodTaskClass.DESKTOP_INTEGRATED,
        _profile(
            str(development.profile_id),
            desktop_profile.capability_bindings,
            _downstream_bridges(desktop_profile),
        ),
    )
    with pytest.raises(ValueError, match="duplicate execution profile ids"):
        IntegratedDogfoodProfileCatalog((development, research, reused))
