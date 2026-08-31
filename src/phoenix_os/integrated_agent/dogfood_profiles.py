"""RFC-0038 S4 deployment-profile guardrails over existing integrated authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from phoenix_os.agent.contracts import AgentId, ToolId
from phoenix_os.agent.memory_authorization import MEMORY_READ_ACTION, MEMORY_SEARCH_ACTION
from phoenix_os.agent.workspace_authorization import WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION
from phoenix_os.authority.catalog import (
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
    NETWORK_HTTP_REQUEST_ACTION,
)
from phoenix_os.host_automation.authorization import (
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_LIST_ACTION,
)
from phoenix_os.integrated_agent.contracts import IntegratedExecutionProfileId
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)

MAX_DOGFOOD_PROFILE_COUNT = 3


class DogfoodTaskClass(StrEnum):
    """Finite deployment task classes required by the initial RFC-0038 dogfood matrix."""

    DEVELOPMENT = "development"
    RESEARCH = "research"
    DESKTOP_INTEGRATED = "desktop/integrated"


_REQUIRED_BOUNDARIES: Mapping[
    DogfoodTaskClass,
    frozenset[IntegratedDownstreamBoundary],
] = MappingProxyType(
    {
        DogfoodTaskClass.DEVELOPMENT: frozenset({IntegratedDownstreamBoundary.WORKSPACE}),
        DogfoodTaskClass.RESEARCH: frozenset(
            {
                IntegratedDownstreamBoundary.MEMORY,
                IntegratedDownstreamBoundary.WORKSPACE,
                IntegratedDownstreamBoundary.NETWORK,
                IntegratedDownstreamBoundary.BROWSER,
            }
        ),
        DogfoodTaskClass.DESKTOP_INTEGRATED: frozenset({IntegratedDownstreamBoundary.HOST}),
    }
)

_ALLOWED_ACTIONS: Mapping[
    DogfoodTaskClass,
    Mapping[IntegratedDownstreamBoundary, frozenset[str]],
] = MappingProxyType(
    {
        DogfoodTaskClass.DEVELOPMENT: MappingProxyType(
            {
                IntegratedDownstreamBoundary.WORKSPACE: frozenset(
                    {WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION}
                )
            }
        ),
        DogfoodTaskClass.RESEARCH: MappingProxyType(
            {
                IntegratedDownstreamBoundary.MEMORY: frozenset(
                    {MEMORY_SEARCH_ACTION, MEMORY_READ_ACTION}
                ),
                IntegratedDownstreamBoundary.WORKSPACE: frozenset(
                    {WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION}
                ),
                IntegratedDownstreamBoundary.NETWORK: frozenset({NETWORK_HTTP_REQUEST_ACTION}),
                IntegratedDownstreamBoundary.BROWSER: frozenset(
                    {
                        BROWSER_SESSION_OPEN_ACTION,
                        BROWSER_SESSION_CLOSE_ACTION,
                        BROWSER_PAGE_NAVIGATE_ACTION,
                        BROWSER_PAGE_READ_ACTION,
                    }
                ),
            }
        ),
        DogfoodTaskClass.DESKTOP_INTEGRATED: MappingProxyType(
            {
                IntegratedDownstreamBoundary.HOST: frozenset(
                    {HOST_PROCESS_LIST_ACTION, HOST_WINDOW_LIST_ACTION}
                )
            }
        ),
    }
)

_FORBIDDEN_TOOL_NAMESPACES = (
    "git.commit",
    "git.push",
    "git.merge",
    "git.tag",
    "release",
    "shell",
    "powershell",
    "filesystem",
    "repo.patch",
    "repo.write",
)


@dataclass(frozen=True, slots=True)
class IntegratedDogfoodProfile:
    """Deployment classification that only narrows an existing integrated profile.

    The wrapper contains no provider/model selection and grants no authority itself.
    Development deliberately starts with bounded workspace list/read operations only;
    direct repository writers or test-process tools remain absent until dogfood proves
    a narrow general capability is necessary.
    """

    task_class: DogfoodTaskClass
    execution_profile: IntegratedExecutionProfile

    def __post_init__(self) -> None:
        if not isinstance(self.task_class, DogfoodTaskClass):
            raise TypeError("task_class must be DogfoodTaskClass")
        if not isinstance(self.execution_profile, IntegratedExecutionProfile):
            raise TypeError("execution_profile must be IntegratedExecutionProfile")
        _validate_profile(self.task_class, self.execution_profile)

    @property
    def profile_id(self) -> IntegratedExecutionProfileId:
        return self.execution_profile.profile_id

    @property
    def agent_id(self) -> AgentId:
        return self.execution_profile.agent_id

    @property
    def tool_ids(self) -> tuple[ToolId, ...]:
        return self.execution_profile.tool_ids


class IntegratedDogfoodProfileCatalog:
    """Finite deployment catalog; full matrix is required only for evidence."""

    def __init__(self, profiles: tuple[IntegratedDogfoodProfile, ...]) -> None:
        supplied = tuple(profiles)
        if not supplied:
            raise ValueError("dogfood catalog requires at least one deployment profile")
        if len(supplied) > MAX_DOGFOOD_PROFILE_COUNT:
            raise ValueError("dogfood catalog exceeds the supported profile count")
        if any(not isinstance(item, IntegratedDogfoodProfile) for item in supplied):
            raise TypeError("profiles must contain IntegratedDogfoodProfile values")

        by_class: dict[DogfoodTaskClass, IntegratedDogfoodProfile] = {}
        profile_ids: set[IntegratedExecutionProfileId] = set()
        for item in supplied:
            if item.task_class in by_class:
                raise ValueError("dogfood catalog contains duplicate task classes")
            if item.profile_id in profile_ids:
                raise ValueError("dogfood catalog contains duplicate execution profile ids")
            by_class[item.task_class] = item
            profile_ids.add(item.profile_id)

        self._profiles: Mapping[
            DogfoodTaskClass,
            IntegratedDogfoodProfile,
        ] = MappingProxyType(by_class)

    @property
    def task_classes(self) -> tuple[DogfoodTaskClass, ...]:
        return tuple(task_class for task_class in DogfoodTaskClass if task_class in self._profiles)

    def require(self, task_class: DogfoodTaskClass) -> IntegratedDogfoodProfile:
        if not isinstance(task_class, DogfoodTaskClass):
            raise TypeError("task_class must be DogfoodTaskClass")
        return self._profiles[task_class]

    def require_complete_matrix(self) -> tuple[IntegratedDogfoodProfile, ...]:
        """Require all three RFC-0038 classes only for dogfood/release evidence."""

        if frozenset(self._profiles) != frozenset(DogfoodTaskClass):
            raise ValueError("dogfood evidence matrix requires all three task classes")
        return tuple(self._profiles[task_class] for task_class in DogfoodTaskClass)


def _validate_profile(
    task_class: DogfoodTaskClass,
    profile: IntegratedExecutionProfile,
) -> None:
    if not profile.enabled:
        raise ValueError("dogfood execution profile must be enabled")

    local = tuple(
        binding
        for binding in profile.tool_bindings
        if isinstance(binding, IntegratedLocalTransformBinding)
    )
    if len(local) != 1 or local[0].tool_id != INTEGRATED_PLAN_UPDATE_TOOL_ID:
        raise ValueError("dogfood profile requires only the reviewed advisory plan transform")

    bridges = tuple(
        binding
        for binding in profile.tool_bindings
        if isinstance(binding, IntegratedDownstreamBridgeBinding)
    )
    if not bridges:
        raise ValueError("dogfood profile requires bounded downstream tools")

    capability_boundaries = frozenset(binding.boundary for binding in profile.capability_bindings)
    expected_boundaries = _REQUIRED_BOUNDARIES[task_class]
    if capability_boundaries != expected_boundaries:
        raise ValueError("dogfood profile capability boundaries do not match its task class")

    allowed_by_boundary = _ALLOWED_ACTIONS[task_class]

    observed_actions: dict[IntegratedDownstreamBoundary, list[str]] = {
        boundary: [] for boundary in expected_boundaries
    }
    for binding in bridges:
        if _forbidden_tool_id(binding.tool_id):
            raise ValueError("dogfood profile contains a forbidden autonomous tool namespace")
        allowed = allowed_by_boundary.get(binding.boundary)
        if allowed is None or binding.action_family not in allowed:
            raise ValueError("dogfood profile contains an action outside its minimal surface")
        observed_actions[binding.boundary].append(binding.action_family)

    for boundary, required_actions in allowed_by_boundary.items():
        observed = observed_actions.get(boundary, [])
        if len(observed) != len(required_actions) or frozenset(observed) != required_actions:
            raise ValueError("dogfood profile must contain each minimal action exactly once")


def _forbidden_tool_id(tool_id: ToolId) -> bool:
    value = str(tool_id)
    return any(
        value == namespace or value.startswith(f"{namespace}.")
        for namespace in _FORBIDDEN_TOOL_NAMESPACES
    )
