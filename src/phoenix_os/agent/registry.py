"""Deterministic duplicate-rejecting registry for reviewed Phoenix tools."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import (
    AgentJsonInput,
    ToolAvailability,
    ToolId,
    canonical_agent_json_bytes,
)
from phoenix_os.agent.errors import (
    AgentLimitExceededError,
    AgentRegistryClosedError,
    ToolAlreadyRegisteredError,
    ToolNotFoundError,
)
from phoenix_os.agent.schemas import validate_tool_input
from phoenix_os.agent.tools import (
    ToolAdapter,
    ToolDescriptor,
    ToolResolution,
    ToolResourceResolver,
    resolve_server_resource,
)


@dataclass(frozen=True, slots=True)
class ToolRegistration:
    id: UUID
    tool_id: ToolId

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise TypeError("id must be UUID")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")


@dataclass(slots=True)
class _RegisteredTool:
    registration: ToolRegistration
    descriptor: ToolDescriptor
    resolver: ToolResourceResolver
    adapter: ToolAdapter
    sequence: int


class ToolRegistry:
    """Own reviewed tool registration, validation, resolution, and lookup."""

    def __init__(self) -> None:
        self._tools: dict[ToolId, _RegisteredTool] = {}
        self._sequence = 0
        self._closed = False
        self._lock = RLock()

    @property
    def closed(self) -> bool:
        return self._closed

    def register_tool(
        self,
        descriptor: ToolDescriptor,
        *,
        resolver: ToolResourceResolver,
        adapter: ToolAdapter,
    ) -> ToolRegistration:
        self._ensure_open()
        _validate_registration(descriptor, resolver, adapter)
        with self._lock:
            self._ensure_open()
            if descriptor.tool_id in self._tools:
                raise ToolAlreadyRegisteredError()
            registration = ToolRegistration(id=uuid4(), tool_id=descriptor.tool_id)
            self._tools[descriptor.tool_id] = _RegisteredTool(
                registration=registration,
                descriptor=descriptor,
                resolver=resolver,
                adapter=adapter,
                sequence=self._sequence,
            )
            self._sequence += 1
            return registration

    def resolve_descriptor(self, tool_id: ToolId | str) -> ToolDescriptor:
        return self._resolve_active(tool_id).descriptor

    def resolve_adapter(self, tool_id: ToolId | str) -> ToolAdapter:
        return self._resolve_active(tool_id).adapter

    def admit_tool_call(
        self,
        tool_id: ToolId | str,
        arguments: Mapping[str, AgentJsonInput],
    ) -> ToolResolution:
        registered = self._resolve_active(tool_id)
        validated = validate_tool_input(registered.descriptor.input_schema, arguments)
        encoded = canonical_agent_json_bytes(validated)
        if len(encoded) > registered.descriptor.max_input_bytes:
            raise AgentLimitExceededError()
        resource = resolve_server_resource(registered.resolver, validated)
        return ToolResolution(
            descriptor=registered.descriptor,
            arguments=validated,
            resolved_resource=resource,
        )

    def list_descriptors(self) -> tuple[ToolDescriptor, ...]:
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            ordered = sorted(self._tools.values(), key=lambda item: item.sequence)
            return tuple(
                item.descriptor
                for item in ordered
                if item.descriptor.availability is ToolAvailability.ACTIVE
            )

    def close(self) -> None:
        with self._lock:
            self._tools.clear()
            self._closed = True

    def _resolve_active(self, tool_id: ToolId | str) -> _RegisteredTool:
        normalized = tool_id if isinstance(tool_id, ToolId) else ToolId(tool_id)
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            registered = self._tools.get(normalized)
            if (
                registered is None
                or registered.descriptor.availability is not ToolAvailability.ACTIVE
            ):
                raise ToolNotFoundError()
            return registered

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentRegistryClosedError()


def _validate_registration(
    descriptor: ToolDescriptor,
    resolver: ToolResourceResolver,
    adapter: ToolAdapter,
) -> None:
    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    if not isinstance(resolver, ToolResourceResolver):
        raise TypeError("resolver must implement ToolResourceResolver")
    if not isinstance(adapter, ToolAdapter):
        raise TypeError("adapter must implement ToolAdapter")
    if resolver.resolver_id != descriptor.resolver_id:
        raise ValueError("resolver identity does not match descriptor")
    if adapter.adapter_id != descriptor.adapter_id:
        raise ValueError("adapter identity does not match descriptor")
    if adapter.tool_id != descriptor.tool_id:
        raise ValueError("adapter tool id does not match descriptor")
