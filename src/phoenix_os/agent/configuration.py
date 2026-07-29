"""Typed immutable configuration for optional agent composition."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from phoenix_os.agent.contracts import AgentId, AgentLimits, ToolId
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.inference.contracts import ModelId, ModelProviderId

MAX_AGENT_CONFIG_TOOLS = 256
MAX_AGENT_CONFIG_METADATA_ITEMS = 64
MAX_AGENT_CONFIG_METADATA_TEXT = 1_024

_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


def _freeze_metadata(values: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(values, Mapping):
        raise TypeError("metadata must be a mapping")
    if len(values) > MAX_AGENT_CONFIG_METADATA_ITEMS:
        raise ValueError("agent configuration metadata exceeds the supported item count")

    frozen: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("agent configuration metadata must contain strings")
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if not normalized_key or not normalized_value:
            raise ValueError("agent configuration metadata must not contain blank values")
        if (
            len(normalized_key) > MAX_AGENT_CONFIG_METADATA_TEXT
            or len(normalized_value) > MAX_AGENT_CONFIG_METADATA_TEXT
        ):
            raise ValueError("agent configuration metadata exceeds the supported text length")
        if normalized_key in frozen:
            raise ValueError("agent configuration metadata contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


@dataclass(frozen=True, slots=True)
class AgentObservabilityConfiguration:
    """Content-free audit, metrics, log, and Event Bus observation switches."""

    audit_enabled: bool = True
    metrics_enabled: bool = True
    logs_enabled: bool = True
    events_enabled: bool = True

    def __post_init__(self) -> None:
        values = (
            self.audit_enabled,
            self.metrics_enabled,
            self.logs_enabled,
            self.events_enabled,
        )
        if any(type(value) is not bool for value in values):
            raise TypeError("agent observability switches must be booleans")

    @property
    def any_enabled(self) -> bool:
        return any(
            (
                self.audit_enabled,
                self.metrics_enabled,
                self.logs_enabled,
                self.events_enabled,
            )
        )


@dataclass(frozen=True, slots=True)
class AgentToolConfiguration:
    """One reviewed tool descriptor admitted for optional Runtime composition."""

    descriptor: ToolDescriptor

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")

    @property
    def tool_id(self) -> ToolId:
        return self.descriptor.tool_id


@dataclass(frozen=True, slots=True)
class AgentServiceConfiguration:
    """Finite trusted configuration for one optional Runtime-owned agent service."""

    agent_id: AgentId
    provider_id: ModelProviderId
    model_id: ModelId
    tools: tuple[AgentToolConfiguration, ...] = ()
    limits: AgentLimits = field(default_factory=AgentLimits)
    observability: AgentObservabilityConfiguration = field(
        default_factory=AgentObservabilityConfiguration
    )
    source: str = "phoenix.agent"
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        tools = tuple(self.tools)
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        if len(tools) > MAX_AGENT_CONFIG_TOOLS:
            raise ValueError("agent tool configuration exceeds the supported count")
        if any(not isinstance(tool, AgentToolConfiguration) for tool in tools):
            raise TypeError("tools must contain AgentToolConfiguration values")
        if not isinstance(self.limits, AgentLimits):
            raise TypeError("limits must be AgentLimits")
        if not isinstance(self.observability, AgentObservabilityConfiguration):
            raise TypeError("observability must be AgentObservabilityConfiguration")
        if not isinstance(self.source, str):
            raise TypeError("source must be a string")

        tool_ids = tuple(tool.tool_id for tool in tools)
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("agent configuration contains duplicate tools")

        source = self.source.strip().lower()
        if _SOURCE_PATTERN.fullmatch(source) is None:
            raise ValueError("source must be a lowercase Phoenix identifier")

        object.__setattr__(self, "tools", tools)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def tool_ids(self) -> tuple[ToolId, ...]:
        return tuple(tool.tool_id for tool in self.tools)

    @property
    def descriptors(self) -> tuple[ToolDescriptor, ...]:
        return tuple(tool.descriptor for tool in self.tools)
