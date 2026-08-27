"""Immutable server-owned profiles and exact tool bindings for RFC-0036."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from phoenix_os.agent.contracts import AgentId, AgentLimits, ToolId
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    _normalize_binding,
    _normalize_identifier,
    _positive_int,
)

MAX_INTEGRATED_PROFILE_COUNT = 256
MAX_INTEGRATED_TOOL_BINDINGS = 256
MAX_INTEGRATED_LOCAL_STATE_KEYS = 16
MAX_INTEGRATED_CAPABILITY_BINDINGS = 5

INTEGRATED_PLAN_UPDATE_TOOL_ID = ToolId("integrated.plan.update")
INTEGRATED_PLAN_UPDATE_TRANSFORM_ID = "integrated.plan.update"


class IntegratedToolBindingKind(StrEnum):
    """Every integrated tool is exactly one reviewed binding kind."""

    LOCAL_TRANSFORM = "local_transform"
    DOWNSTREAM_BRIDGE = "downstream_bridge"


class IntegratedDownstreamBoundary(StrEnum):
    """Finite existing Phoenix capability boundaries reachable by S4 bridges."""

    MEMORY = "memory"
    WORKSPACE = "workspace"
    HOST = "host"
    NETWORK = "network"
    BROWSER = "browser"


@dataclass(frozen=True, slots=True)
class IntegratedCapabilityProfileBinding:
    """Exact server-owned downstream profile/scope identity, never adapter-selected."""

    boundary: IntegratedDownstreamBoundary
    binding_id: str
    generation: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, IntegratedDownstreamBoundary):
            raise TypeError("boundary must be IntegratedDownstreamBoundary")
        object.__setattr__(
            self,
            "binding_id",
            _normalize_binding(self.binding_id, label="integrated capability binding id"),
        )
        generation = self.generation
        if generation is not None:
            generation = _positive_int(
                generation,
                label="integrated capability binding generation",
                maximum=2_147_483_647,
            )
        if (
            self.boundary
            in {
                IntegratedDownstreamBoundary.NETWORK,
                IntegratedDownstreamBoundary.BROWSER,
            }
            and generation is None
        ):
            raise ValueError("network and browser capability bindings require an exact generation")
        object.__setattr__(self, "generation", generation)


@dataclass(frozen=True, slots=True)
class IntegratedLocalTransformBinding:
    """Reviewed bounded Phoenix-owned transform with no downstream adapter authority."""

    tool_id: ToolId
    transform_id: str
    advisory_state_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        object.__setattr__(
            self,
            "transform_id",
            _normalize_identifier(self.transform_id, label="integrated local transform id"),
        )
        supplied = tuple(self.advisory_state_keys)
        if len(supplied) > MAX_INTEGRATED_LOCAL_STATE_KEYS:
            raise ValueError("local transform exposes too many advisory state keys")
        normalized = tuple(
            sorted(
                {
                    _normalize_identifier(item, label="integrated advisory state key")
                    for item in supplied
                }
            )
        )
        object.__setattr__(self, "advisory_state_keys", normalized)

        if self.tool_id == INTEGRATED_PLAN_UPDATE_TOOL_ID:
            if self.transform_id != INTEGRATED_PLAN_UPDATE_TRANSFORM_ID:
                raise ValueError("integrated.plan.update must use its exact server-owned transform")
            if normalized != ("plan",):
                raise ValueError("integrated.plan.update may mutate only advisory plan state")

    @property
    def kind(self) -> IntegratedToolBindingKind:
        return IntegratedToolBindingKind.LOCAL_TRANSFORM


@dataclass(frozen=True, slots=True)
class IntegratedDownstreamBridgeBinding:
    """Exact bridge from one RFC-0027 tool to one existing Phoenix capability boundary."""

    tool_id: ToolId
    boundary: IntegratedDownstreamBoundary
    binding_id: str
    action_family: str
    generation: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.boundary, IntegratedDownstreamBoundary):
            raise TypeError("boundary must be IntegratedDownstreamBoundary")
        object.__setattr__(
            self,
            "binding_id",
            _normalize_binding(self.binding_id, label="integrated bridge binding id"),
        )
        object.__setattr__(
            self,
            "action_family",
            _normalize_identifier(self.action_family, label="integrated bridge action family"),
        )
        generation = self.generation
        if generation is not None:
            generation = _positive_int(
                generation,
                label="integrated bridge generation",
                maximum=2_147_483_647,
            )
        if (
            self.boundary
            in {
                IntegratedDownstreamBoundary.NETWORK,
                IntegratedDownstreamBoundary.BROWSER,
            }
            and generation is None
        ):
            raise ValueError("network and browser bridges require an exact profile generation")
        object.__setattr__(self, "generation", generation)

    @property
    def kind(self) -> IntegratedToolBindingKind:
        return IntegratedToolBindingKind.DOWNSTREAM_BRIDGE


type IntegratedToolBinding = IntegratedLocalTransformBinding | IntegratedDownstreamBridgeBinding


@dataclass(frozen=True, slots=True)
class IntegratedExecutionProfile:
    """Finite immutable server-owned integrated execution configuration."""

    profile_id: IntegratedExecutionProfileId
    generation: IntegratedExecutionProfileGeneration
    agent_id: AgentId
    tool_bindings: tuple[IntegratedToolBinding, ...]
    data_flow_policy: IntegratedDataFlowPolicy
    limits: AgentLimits = field(default_factory=AgentLimits)
    budget_extension: IntegratedBudgetExtension = field(default_factory=IntegratedBudgetExtension)
    memory_binding: IntegratedCapabilityProfileBinding | None = None
    workspace_binding: IntegratedCapabilityProfileBinding | None = None
    host_profile_binding: IntegratedCapabilityProfileBinding | None = None
    network_profile_binding: IntegratedCapabilityProfileBinding | None = None
    browser_profile_binding: IntegratedCapabilityProfileBinding | None = None
    durability_profile: str | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        if not isinstance(self.generation, IntegratedExecutionProfileGeneration):
            raise TypeError("generation must be IntegratedExecutionProfileGeneration")
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.data_flow_policy, IntegratedDataFlowPolicy):
            raise TypeError("data_flow_policy must be IntegratedDataFlowPolicy")
        if not isinstance(self.limits, AgentLimits):
            raise TypeError("limits must be AgentLimits")
        if not isinstance(self.budget_extension, IntegratedBudgetExtension):
            raise TypeError("budget_extension must be IntegratedBudgetExtension")
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be a boolean")

        tools = tuple(self.tool_bindings)
        if self.enabled and not tools:
            raise ValueError("enabled integrated profile requires at least one tool binding")
        if len(tools) > MAX_INTEGRATED_TOOL_BINDINGS:
            raise ValueError("integrated profile contains too many tool bindings")
        if any(
            not isinstance(
                binding,
                (IntegratedLocalTransformBinding, IntegratedDownstreamBridgeBinding),
            )
            for binding in tools
        ):
            raise TypeError("tool_bindings contains an unsupported binding type")
        tool_ids = tuple(binding.tool_id for binding in tools)
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("integrated profile contains duplicate tool bindings")

        plan_binding = next(
            (binding for binding in tools if binding.tool_id == INTEGRATED_PLAN_UPDATE_TOOL_ID),
            None,
        )
        if plan_binding is not None and not isinstance(
            plan_binding,
            IntegratedLocalTransformBinding,
        ):
            raise ValueError("integrated.plan.update must be a LOCAL_TRANSFORM")

        named_capabilities = (
            ("memory_binding", self.memory_binding, IntegratedDownstreamBoundary.MEMORY),
            (
                "workspace_binding",
                self.workspace_binding,
                IntegratedDownstreamBoundary.WORKSPACE,
            ),
            ("host_profile_binding", self.host_profile_binding, IntegratedDownstreamBoundary.HOST),
            (
                "network_profile_binding",
                self.network_profile_binding,
                IntegratedDownstreamBoundary.NETWORK,
            ),
            (
                "browser_profile_binding",
                self.browser_profile_binding,
                IntegratedDownstreamBoundary.BROWSER,
            ),
        )
        capabilities: list[IntegratedCapabilityProfileBinding] = []
        for field_name, capability, expected_boundary in named_capabilities:
            if capability is None:
                continue
            if not isinstance(capability, IntegratedCapabilityProfileBinding):
                raise TypeError(f"{field_name} must be IntegratedCapabilityProfileBinding or None")
            if capability.boundary is not expected_boundary:
                raise ValueError(f"{field_name} has the wrong downstream boundary")
            capabilities.append(capability)

        by_boundary = {item.boundary: item for item in capabilities}
        for binding in tools:
            if isinstance(binding, IntegratedLocalTransformBinding):
                continue
            configured = by_boundary.get(binding.boundary)
            if configured is None:
                raise ValueError(
                    "downstream bridge requires its exact configured capability binding"
                )
            if (
                configured.binding_id != binding.binding_id
                or configured.generation != binding.generation
            ):
                raise ValueError(
                    "downstream bridge does not match the exact configured capability binding"
                )

        durability_profile = self.durability_profile
        if durability_profile is not None:
            durability_profile = _normalize_binding(
                durability_profile,
                label="integrated durability profile binding",
            )

        object.__setattr__(self, "tool_bindings", tools)
        object.__setattr__(self, "durability_profile", durability_profile)

    @property
    def capability_bindings(self) -> tuple[IntegratedCapabilityProfileBinding, ...]:
        return tuple(
            binding
            for binding in (
                self.memory_binding,
                self.workspace_binding,
                self.host_profile_binding,
                self.network_profile_binding,
                self.browser_profile_binding,
            )
            if binding is not None
        )

    @property
    def tool_ids(self) -> tuple[ToolId, ...]:
        return tuple(binding.tool_id for binding in self.tool_bindings)

    def require_tool_binding(self, tool_id: ToolId) -> IntegratedToolBinding:
        if not isinstance(tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        for binding in self.tool_bindings:
            if binding.tool_id == tool_id:
                return binding
        raise KeyError(f"unknown integrated tool binding: {tool_id}")

    def require_capability_binding(
        self,
        boundary: IntegratedDownstreamBoundary,
    ) -> IntegratedCapabilityProfileBinding:
        if not isinstance(boundary, IntegratedDownstreamBoundary):
            raise TypeError("boundary must be IntegratedDownstreamBoundary")
        for binding in self.capability_bindings:
            if binding.boundary is boundary:
                return binding
        raise KeyError(f"unknown integrated capability binding: {boundary.value}")


class IntegratedExecutionProfileCatalog:
    """Finite immutable lookup for server-owned integrated profiles."""

    def __init__(self, profiles: tuple[IntegratedExecutionProfile, ...]) -> None:
        supplied = tuple(profiles)
        if not supplied:
            raise ValueError("enabled integrated execution requires at least one profile")
        if len(supplied) > MAX_INTEGRATED_PROFILE_COUNT:
            raise ValueError("integrated profile count exceeds the supported maximum")
        by_id: dict[IntegratedExecutionProfileId, IntegratedExecutionProfile] = {}
        for profile in supplied:
            if not isinstance(profile, IntegratedExecutionProfile):
                raise TypeError("profiles must contain IntegratedExecutionProfile values")
            if profile.profile_id in by_id:
                raise ValueError("integrated profile catalog contains duplicate profile ids")
            by_id[profile.profile_id] = profile
        self._profiles: Mapping[
            IntegratedExecutionProfileId,
            IntegratedExecutionProfile,
        ] = MappingProxyType(by_id)

    @property
    def profile_ids(self) -> tuple[IntegratedExecutionProfileId, ...]:
        return tuple(self._profiles)

    def require_profile(
        self,
        profile_id: IntegratedExecutionProfileId,
    ) -> IntegratedExecutionProfile:
        if not isinstance(profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        try:
            return self._profiles[profile_id]
        except KeyError as exception:
            raise KeyError(f"unknown integrated execution profile: {profile_id}") from exception
