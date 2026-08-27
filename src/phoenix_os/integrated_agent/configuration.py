"""Strict typed configuration for optional RFC-0036 integrated execution."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import cast

from phoenix_os.agent.contracts import AgentId, AgentLimits, ToolId
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.profiles import (
    IntegratedCapabilityProfileBinding,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
    IntegratedToolBinding,
    IntegratedToolBindingKind,
)

_CONFIG_KEYS = frozenset({"enabled", "profiles"})
_PROFILE_KEYS = frozenset(
    {
        "profile_id",
        "generation",
        "agent_id",
        "tool_bindings",
        "memory_binding",
        "workspace_binding",
        "host_profile_binding",
        "network_profile_binding",
        "browser_profile_binding",
        "data_flow_routes",
        "limits",
        "budget_extension",
        "durability_profile",
        "enabled",
    }
)
_TOOL_BASE_KEYS = frozenset({"kind", "tool_id"})
_LOCAL_TOOL_KEYS = frozenset({"kind", "tool_id", "transform_id", "advisory_state_keys"})
_BRIDGE_TOOL_KEYS = frozenset(
    {"kind", "tool_id", "boundary", "binding_id", "generation", "action_family"}
)
_CAPABILITY_KEYS = frozenset({"boundary", "binding_id", "generation"})
_ROUTE_KEYS = frozenset(
    {
        "route_id",
        "source_kind",
        "sink",
        "disposition",
        "source_scope",
        "required_freshness_bindings",
        "requires_audience_match",
    }
)
_BUDGET_KEYS = frozenset(
    {
        "total_duration_microseconds",
        "max_plan_revisions",
        "max_integrated_steps",
        "max_browser_operations",
        "max_network_operations",
        "max_memory_operations",
        "max_workspace_operations",
        "max_workspace_mutation_bytes",
        "max_host_operations",
    }
)
_AGENT_LIMIT_INTEGER_KEYS = frozenset(
    {
        "max_steps",
        "max_model_turns",
        "max_tool_calls",
        "max_prompt_bytes",
        "max_model_output_bytes",
        "max_tool_result_bytes",
        "max_input_tokens",
        "max_output_tokens",
        "max_argument_bytes",
        "max_result_bytes",
        "max_structured_depth",
        "max_structured_items",
        "max_queue_depth",
        "max_concurrent_runs",
        "max_concurrent_model_calls",
        "max_concurrent_tool_calls",
    }
)
_AGENT_LIMIT_DURATION_KEYS = frozenset(
    {
        "model_turn_timeout_microseconds",
        "tool_call_timeout_microseconds",
        "approval_wait_timeout_microseconds",
        "total_duration_microseconds",
        "cancellation_grace_microseconds",
        "shutdown_grace_microseconds",
    }
)
_AGENT_LIMIT_KEYS = _AGENT_LIMIT_INTEGER_KEYS | _AGENT_LIMIT_DURATION_KEYS


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise TypeError(f"{label} keys must be strings")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{label} must be a sequence")
    return cast(Sequence[object], value)


def _require_exact_keys(
    value: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    label: str,
) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise ValueError(f"{label} contains unknown keys: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"{label} is missing required keys: {', '.join(sorted(missing))}")


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    return value


def _int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    return value


def _bool(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a boolean")
    return value


def _optional_int(value: object, *, label: str) -> int | None:
    if value is None:
        return None
    return _int(value, label=label)


def _duration_to_microseconds(value: timedelta) -> int:
    return value // timedelta(microseconds=1)


def _duration_from_microseconds(value: object, *, label: str) -> timedelta:
    return timedelta(microseconds=_int(value, label=label))


def _decode_agent_limits(value: object | None) -> AgentLimits:
    defaults = AgentLimits()
    if value is None:
        return defaults
    mapping = _mapping(value, label="integrated agent limits")
    _require_exact_keys(
        mapping,
        allowed=_AGENT_LIMIT_KEYS,
        required=frozenset(),
        label="integrated agent limits",
    )

    def duration(key: str, default: timedelta) -> timedelta:
        raw = mapping.get(key)
        return default if raw is None else _duration_from_microseconds(raw, label=key)

    return AgentLimits(
        max_steps=_int(mapping.get("max_steps", defaults.max_steps), label="max_steps"),
        max_model_turns=_int(
            mapping.get("max_model_turns", defaults.max_model_turns),
            label="max_model_turns",
        ),
        max_tool_calls=_int(
            mapping.get("max_tool_calls", defaults.max_tool_calls),
            label="max_tool_calls",
        ),
        max_prompt_bytes=_int(
            mapping.get("max_prompt_bytes", defaults.max_prompt_bytes),
            label="max_prompt_bytes",
        ),
        max_model_output_bytes=_int(
            mapping.get("max_model_output_bytes", defaults.max_model_output_bytes),
            label="max_model_output_bytes",
        ),
        max_tool_result_bytes=_int(
            mapping.get("max_tool_result_bytes", defaults.max_tool_result_bytes),
            label="max_tool_result_bytes",
        ),
        max_input_tokens=_int(
            mapping.get("max_input_tokens", defaults.max_input_tokens),
            label="max_input_tokens",
        ),
        max_output_tokens=_int(
            mapping.get("max_output_tokens", defaults.max_output_tokens),
            label="max_output_tokens",
        ),
        max_argument_bytes=_int(
            mapping.get("max_argument_bytes", defaults.max_argument_bytes),
            label="max_argument_bytes",
        ),
        max_result_bytes=_int(
            mapping.get("max_result_bytes", defaults.max_result_bytes),
            label="max_result_bytes",
        ),
        max_structured_depth=_int(
            mapping.get("max_structured_depth", defaults.max_structured_depth),
            label="max_structured_depth",
        ),
        max_structured_items=_int(
            mapping.get("max_structured_items", defaults.max_structured_items),
            label="max_structured_items",
        ),
        max_queue_depth=_int(
            mapping.get("max_queue_depth", defaults.max_queue_depth),
            label="max_queue_depth",
        ),
        max_concurrent_runs=_int(
            mapping.get("max_concurrent_runs", defaults.max_concurrent_runs),
            label="max_concurrent_runs",
        ),
        max_concurrent_model_calls=_int(
            mapping.get(
                "max_concurrent_model_calls",
                defaults.max_concurrent_model_calls,
            ),
            label="max_concurrent_model_calls",
        ),
        max_concurrent_tool_calls=_int(
            mapping.get(
                "max_concurrent_tool_calls",
                defaults.max_concurrent_tool_calls,
            ),
            label="max_concurrent_tool_calls",
        ),
        model_turn_timeout=duration(
            "model_turn_timeout_microseconds",
            defaults.model_turn_timeout,
        ),
        tool_call_timeout=duration(
            "tool_call_timeout_microseconds",
            defaults.tool_call_timeout,
        ),
        approval_wait_timeout=duration(
            "approval_wait_timeout_microseconds",
            defaults.approval_wait_timeout,
        ),
        total_duration=duration(
            "total_duration_microseconds",
            defaults.total_duration,
        ),
        cancellation_grace=duration(
            "cancellation_grace_microseconds",
            defaults.cancellation_grace,
        ),
        shutdown_grace=duration(
            "shutdown_grace_microseconds",
            defaults.shutdown_grace,
        ),
    )


def _encode_agent_limits(value: AgentLimits) -> dict[str, object]:
    return {
        "max_steps": value.max_steps,
        "max_model_turns": value.max_model_turns,
        "max_tool_calls": value.max_tool_calls,
        "max_prompt_bytes": value.max_prompt_bytes,
        "max_model_output_bytes": value.max_model_output_bytes,
        "max_tool_result_bytes": value.max_tool_result_bytes,
        "max_input_tokens": value.max_input_tokens,
        "max_output_tokens": value.max_output_tokens,
        "max_argument_bytes": value.max_argument_bytes,
        "max_result_bytes": value.max_result_bytes,
        "max_structured_depth": value.max_structured_depth,
        "max_structured_items": value.max_structured_items,
        "max_queue_depth": value.max_queue_depth,
        "max_concurrent_runs": value.max_concurrent_runs,
        "max_concurrent_model_calls": value.max_concurrent_model_calls,
        "max_concurrent_tool_calls": value.max_concurrent_tool_calls,
        "model_turn_timeout_microseconds": _duration_to_microseconds(value.model_turn_timeout),
        "tool_call_timeout_microseconds": _duration_to_microseconds(value.tool_call_timeout),
        "approval_wait_timeout_microseconds": _duration_to_microseconds(
            value.approval_wait_timeout
        ),
        "total_duration_microseconds": _duration_to_microseconds(value.total_duration),
        "cancellation_grace_microseconds": _duration_to_microseconds(value.cancellation_grace),
        "shutdown_grace_microseconds": _duration_to_microseconds(value.shutdown_grace),
    }


def _decode_budget(value: object | None) -> IntegratedBudgetExtension:
    defaults = IntegratedBudgetExtension()
    if value is None:
        return defaults
    mapping = _mapping(value, label="integrated budget extension")
    _require_exact_keys(
        mapping,
        allowed=_BUDGET_KEYS,
        required=frozenset(),
        label="integrated budget extension",
    )
    return IntegratedBudgetExtension(
        total_duration=(
            defaults.total_duration
            if "total_duration_microseconds" not in mapping
            else _duration_from_microseconds(
                mapping["total_duration_microseconds"],
                label="total_duration_microseconds",
            )
        ),
        max_plan_revisions=_int(
            mapping.get("max_plan_revisions", defaults.max_plan_revisions),
            label="max_plan_revisions",
        ),
        max_integrated_steps=_int(
            mapping.get("max_integrated_steps", defaults.max_integrated_steps),
            label="max_integrated_steps",
        ),
        max_browser_operations=_int(
            mapping.get("max_browser_operations", defaults.max_browser_operations),
            label="max_browser_operations",
        ),
        max_network_operations=_int(
            mapping.get("max_network_operations", defaults.max_network_operations),
            label="max_network_operations",
        ),
        max_memory_operations=_int(
            mapping.get("max_memory_operations", defaults.max_memory_operations),
            label="max_memory_operations",
        ),
        max_workspace_operations=_int(
            mapping.get("max_workspace_operations", defaults.max_workspace_operations),
            label="max_workspace_operations",
        ),
        max_workspace_mutation_bytes=_int(
            mapping.get(
                "max_workspace_mutation_bytes",
                defaults.max_workspace_mutation_bytes,
            ),
            label="max_workspace_mutation_bytes",
        ),
        max_host_operations=_int(
            mapping.get("max_host_operations", defaults.max_host_operations),
            label="max_host_operations",
        ),
    )


def _encode_budget(value: IntegratedBudgetExtension) -> dict[str, object]:
    return {
        "total_duration_microseconds": _duration_to_microseconds(value.total_duration),
        "max_plan_revisions": value.max_plan_revisions,
        "max_integrated_steps": value.max_integrated_steps,
        "max_browser_operations": value.max_browser_operations,
        "max_network_operations": value.max_network_operations,
        "max_memory_operations": value.max_memory_operations,
        "max_workspace_operations": value.max_workspace_operations,
        "max_workspace_mutation_bytes": value.max_workspace_mutation_bytes,
        "max_host_operations": value.max_host_operations,
    }


def _decode_tool_binding(value: object) -> IntegratedToolBinding:
    mapping = _mapping(value, label="integrated tool binding")
    _require_exact_keys(
        mapping,
        allowed=_LOCAL_TOOL_KEYS | _BRIDGE_TOOL_KEYS,
        required=_TOOL_BASE_KEYS,
        label="integrated tool binding",
    )
    kind = IntegratedToolBindingKind(_string(mapping["kind"], label="integrated tool binding kind"))
    tool_id = ToolId(_string(mapping["tool_id"], label="integrated tool id"))
    if kind is IntegratedToolBindingKind.LOCAL_TRANSFORM:
        _require_exact_keys(
            mapping,
            allowed=_LOCAL_TOOL_KEYS,
            required=frozenset({"kind", "tool_id", "transform_id"}),
            label="integrated local transform binding",
        )
        return IntegratedLocalTransformBinding(
            tool_id=tool_id,
            transform_id=_string(mapping["transform_id"], label="integrated transform id"),
            advisory_state_keys=tuple(
                _string(item, label="integrated advisory state key")
                for item in _sequence(
                    mapping.get("advisory_state_keys", ()),
                    label="integrated advisory state keys",
                )
            ),
        )
    _require_exact_keys(
        mapping,
        allowed=_BRIDGE_TOOL_KEYS,
        required=frozenset({"kind", "tool_id", "boundary", "binding_id", "action_family"}),
        label="integrated downstream bridge binding",
    )
    return IntegratedDownstreamBridgeBinding(
        tool_id=tool_id,
        boundary=IntegratedDownstreamBoundary(
            _string(mapping["boundary"], label="integrated downstream boundary")
        ),
        binding_id=_string(mapping["binding_id"], label="integrated bridge binding id"),
        generation=_optional_int(mapping.get("generation"), label="integrated bridge generation"),
        action_family=_string(mapping["action_family"], label="integrated bridge action family"),
    )


def _encode_tool_binding(value: IntegratedToolBinding) -> dict[str, object]:
    if isinstance(value, IntegratedLocalTransformBinding):
        return {
            "kind": value.kind.value,
            "tool_id": str(value.tool_id),
            "transform_id": value.transform_id,
            "advisory_state_keys": list(value.advisory_state_keys),
        }
    return {
        "kind": value.kind.value,
        "tool_id": str(value.tool_id),
        "boundary": value.boundary.value,
        "binding_id": value.binding_id,
        "generation": value.generation,
        "action_family": value.action_family,
    }


def _decode_capability_binding(value: object) -> IntegratedCapabilityProfileBinding:
    mapping = _mapping(value, label="integrated capability binding")
    _require_exact_keys(
        mapping,
        allowed=_CAPABILITY_KEYS,
        required=frozenset({"boundary", "binding_id"}),
        label="integrated capability binding",
    )
    return IntegratedCapabilityProfileBinding(
        boundary=IntegratedDownstreamBoundary(
            _string(mapping["boundary"], label="integrated capability boundary")
        ),
        binding_id=_string(mapping["binding_id"], label="integrated capability binding id"),
        generation=_optional_int(
            mapping.get("generation"),
            label="integrated capability binding generation",
        ),
    )


def _encode_capability_binding(
    value: IntegratedCapabilityProfileBinding,
) -> dict[str, object]:
    return {
        "boundary": value.boundary.value,
        "binding_id": value.binding_id,
        "generation": value.generation,
    }


def _decode_route(value: object) -> IntegratedDataFlowRoute:
    mapping = _mapping(value, label="integrated data-flow route")
    _require_exact_keys(
        mapping,
        allowed=_ROUTE_KEYS,
        required=frozenset({"route_id", "source_kind", "sink", "disposition"}),
        label="integrated data-flow route",
    )
    return IntegratedDataFlowRoute(
        route_id=_string(mapping["route_id"], label="integrated data-flow route id"),
        source_kind=IntegratedDataSourceKind(
            _string(mapping["source_kind"], label="integrated data-flow source kind")
        ),
        sink=IntegratedDataSink(_string(mapping["sink"], label="integrated data-flow sink")),
        disposition=IntegratedDataFlowDisposition(
            _string(mapping["disposition"], label="integrated data-flow disposition")
        ),
        source_scope=(
            None
            if mapping.get("source_scope") is None
            else _string(mapping["source_scope"], label="integrated data-flow source scope")
        ),
        required_freshness_bindings=tuple(
            _string(item, label="integrated data-flow required freshness binding")
            for item in _sequence(
                mapping.get("required_freshness_bindings", ()),
                label="integrated data-flow required freshness bindings",
            )
        ),
        requires_audience_match=_bool(
            mapping.get("requires_audience_match", False),
            label="requires_audience_match",
        ),
    )


def _encode_route(value: IntegratedDataFlowRoute) -> dict[str, object]:
    return {
        "route_id": value.route_id,
        "source_kind": value.source_kind.value,
        "sink": value.sink.value,
        "disposition": value.disposition.value,
        "source_scope": value.source_scope,
        "required_freshness_bindings": list(value.required_freshness_bindings),
        "requires_audience_match": value.requires_audience_match,
    }


def _decode_profile(value: object) -> IntegratedExecutionProfile:
    mapping = _mapping(value, label="integrated execution profile")
    _require_exact_keys(
        mapping,
        allowed=_PROFILE_KEYS,
        required=frozenset(
            {
                "profile_id",
                "generation",
                "agent_id",
                "tool_bindings",
                "data_flow_routes",
            }
        ),
        label="integrated execution profile",
    )
    tools = tuple(
        _decode_tool_binding(item)
        for item in _sequence(mapping["tool_bindings"], label="integrated tool bindings")
    )

    def optional_capability(key: str) -> IntegratedCapabilityProfileBinding | None:
        raw = mapping.get(key)
        if raw is None:
            return None
        return _decode_capability_binding(raw)

    routes = tuple(
        _decode_route(item)
        for item in _sequence(
            mapping["data_flow_routes"],
            label="integrated data-flow routes",
        )
    )
    raw_durability = mapping.get("durability_profile")
    durability_profile: str | None = (
        None
        if raw_durability is None
        else _string(raw_durability, label="integrated durability profile")
    )
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId(
            _string(mapping["profile_id"], label="integrated execution profile id")
        ),
        generation=IntegratedExecutionProfileGeneration(
            _int(mapping["generation"], label="integrated execution profile generation")
        ),
        agent_id=AgentId(_string(mapping["agent_id"], label="integrated agent id")),
        tool_bindings=tools,
        memory_binding=optional_capability("memory_binding"),
        workspace_binding=optional_capability("workspace_binding"),
        host_profile_binding=optional_capability("host_profile_binding"),
        network_profile_binding=optional_capability("network_profile_binding"),
        browser_profile_binding=optional_capability("browser_profile_binding"),
        data_flow_policy=IntegratedDataFlowPolicy(routes),
        limits=_decode_agent_limits(mapping.get("limits")),
        budget_extension=_decode_budget(mapping.get("budget_extension")),
        durability_profile=durability_profile,
        enabled=_bool(mapping.get("enabled", True), label="integrated profile enabled"),
    )


def _encode_profile(value: IntegratedExecutionProfile) -> dict[str, object]:
    return {
        "profile_id": str(value.profile_id),
        "generation": value.generation.value,
        "agent_id": str(value.agent_id),
        "tool_bindings": [_encode_tool_binding(item) for item in value.tool_bindings],
        "memory_binding": (
            None
            if value.memory_binding is None
            else _encode_capability_binding(value.memory_binding)
        ),
        "workspace_binding": (
            None
            if value.workspace_binding is None
            else _encode_capability_binding(value.workspace_binding)
        ),
        "host_profile_binding": (
            None
            if value.host_profile_binding is None
            else _encode_capability_binding(value.host_profile_binding)
        ),
        "network_profile_binding": (
            None
            if value.network_profile_binding is None
            else _encode_capability_binding(value.network_profile_binding)
        ),
        "browser_profile_binding": (
            None
            if value.browser_profile_binding is None
            else _encode_capability_binding(value.browser_profile_binding)
        ),
        "data_flow_routes": [_encode_route(item) for item in value.data_flow_policy.routes],
        "limits": _encode_agent_limits(value.limits),
        "budget_extension": _encode_budget(value.budget_extension),
        "durability_profile": value.durability_profile,
        "enabled": value.enabled,
    }


@dataclass(frozen=True, slots=True)
class IntegratedAgentConfiguration:
    """Optional integrated-execution configuration; omission/disabled state has no effects."""

    enabled: bool = False
    profiles: tuple[IntegratedExecutionProfile, ...] = ()

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be a boolean")
        profiles = tuple(self.profiles)
        if any(not isinstance(profile, IntegratedExecutionProfile) for profile in profiles):
            raise TypeError("profiles must contain IntegratedExecutionProfile values")
        profile_ids = tuple(profile.profile_id for profile in profiles)
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("integrated configuration contains duplicate profile ids")
        if self.enabled and not profiles:
            raise ValueError("enabled integrated execution requires at least one profile")
        if profiles:
            IntegratedExecutionProfileCatalog(profiles)
        object.__setattr__(self, "profiles", profiles)

    @property
    def catalog(self) -> IntegratedExecutionProfileCatalog | None:
        if not self.profiles:
            return None
        return IntegratedExecutionProfileCatalog(self.profiles)


def decode_integrated_agent_configuration(
    value: Mapping[str, object] | None,
) -> IntegratedAgentConfiguration:
    """Decode strict server-owned configuration; `None` means disabled by omission."""

    if value is None:
        return IntegratedAgentConfiguration()
    mapping = _mapping(value, label="integrated agent configuration")
    _require_exact_keys(
        mapping,
        allowed=_CONFIG_KEYS,
        required=frozenset(),
        label="integrated agent configuration",
    )
    enabled = _bool(mapping.get("enabled", False), label="integrated agent enabled")
    profiles = tuple(
        _decode_profile(item)
        for item in _sequence(mapping.get("profiles", ()), label="integrated profiles")
    )
    return IntegratedAgentConfiguration(enabled=enabled, profiles=profiles)


def encode_integrated_agent_configuration(
    value: IntegratedAgentConfiguration,
) -> dict[str, object]:
    """Encode one deterministic built-in mapping for server-owned configuration."""

    if not isinstance(value, IntegratedAgentConfiguration):
        raise TypeError("value must be IntegratedAgentConfiguration")
    return {
        "enabled": value.enabled,
        "profiles": [_encode_profile(profile) for profile in value.profiles],
    }


def integrated_agent_configuration_json(
    value: IntegratedAgentConfiguration,
) -> str:
    """Return canonical deterministic JSON for S1 configuration validation."""

    return json.dumps(
        encode_integrated_agent_configuration(value),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
