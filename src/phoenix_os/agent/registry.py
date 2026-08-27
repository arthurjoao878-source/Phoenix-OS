"""Deterministic duplicate-rejecting registry for reviewed Phoenix tools."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from threading import RLock
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import (
    AgentJsonInput,
    ToolAvailability,
    ToolId,
    canonical_agent_json_bytes,
)
from phoenix_os.agent.errors import (
    AgentAdministrationConflictError,
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
    ToolResourceResolutionContext,
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


@dataclass(frozen=True, slots=True)
class ToolLifecycleState:
    """Content-free administrative state for one reviewed tool registration."""

    descriptor: ToolDescriptor
    revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("revision must be an integer")
        if self.revision <= 0:
            raise ValueError("tool lifecycle revision must be positive")

    @property
    def enabled(self) -> bool:
        return self.descriptor.availability is ToolAvailability.ACTIVE


@dataclass(slots=True)
class _RegisteredTool:
    registration: ToolRegistration
    descriptor: ToolDescriptor
    resolver: ToolResourceResolver
    adapter: ToolAdapter
    sequence: int
    revision: int = 1


class ToolRegistry:
    """Own reviewed tool registration, validation, resolution, and lookup."""

    def __init__(self) -> None:
        self._tools: dict[ToolId, _RegisteredTool] = {}
        self._sequence = 0
        self._closed = False
        self._sealed = False
        self._lock = RLock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def sealed(self) -> bool:
        return self._sealed

    def register_tool(
        self,
        descriptor: ToolDescriptor,
        *,
        resolver: ToolResourceResolver,
        adapter: ToolAdapter,
    ) -> ToolRegistration:
        self._ensure_open()
        self._ensure_mutable()
        _validate_registration(descriptor, resolver, adapter)
        with self._lock:
            self._ensure_open()
            self._ensure_mutable()
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

    def resolve_resolver(self, tool_id: ToolId | str) -> ToolResourceResolver:
        return self._resolve_active(tool_id).resolver

    def describe(self, tool_id: ToolId | str) -> ToolLifecycleState:
        """Return reviewed descriptor and lifecycle revision even when disabled."""

        normalized = tool_id if isinstance(tool_id, ToolId) else ToolId(tool_id)
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            registered = self._tools.get(normalized)
            if registered is None:
                raise ToolNotFoundError()
            return _tool_state(registered)

    def list_states(self) -> tuple[ToolLifecycleState, ...]:
        """Return all reviewed registrations in deterministic composition order."""

        self._ensure_open()
        with self._lock:
            self._ensure_open()
            ordered = sorted(self._tools.values(), key=lambda item: item.sequence)
            return tuple(_tool_state(item) for item in ordered)

    def set_enabled(
        self,
        tool_id: ToolId | str,
        *,
        enabled: bool,
        expected_revision: int,
    ) -> ToolLifecycleState:
        """Apply one optimistic enable/disable transition without changing installation."""

        normalized = tool_id if isinstance(tool_id, ToolId) else ToolId(tool_id)
        _validate_lifecycle_inputs(enabled, expected_revision)
        self._ensure_open()
        self._ensure_mutable()
        with self._lock:
            self._ensure_open()
            self._ensure_mutable()
            registered = self._tools.get(normalized)
            if registered is None:
                raise ToolNotFoundError()
            if registered.revision != expected_revision:
                raise AgentAdministrationConflictError()
            availability = ToolAvailability.ACTIVE if enabled else ToolAvailability.DISABLED
            if registered.descriptor.availability is not availability:
                registered.descriptor = replace(
                    registered.descriptor,
                    availability=availability,
                )
                registered.revision += 1
            return _tool_state(registered)

    def admit_tool_call(
        self,
        tool_id: ToolId | str,
        arguments: Mapping[str, AgentJsonInput],
        *,
        resolution_context: ToolResourceResolutionContext | None = None,
    ) -> ToolResolution:
        if resolution_context is not None and not isinstance(
            resolution_context,
            ToolResourceResolutionContext,
        ):
            raise TypeError("resolution_context must be ToolResourceResolutionContext or None")
        registered = self._resolve_active(tool_id)
        validated = validate_tool_input(registered.descriptor.input_schema, arguments)
        encoded = canonical_agent_json_bytes(validated)
        if len(encoded) > registered.descriptor.max_input_bytes:
            raise AgentLimitExceededError()
        resource = resolve_server_resource(
            registered.resolver,
            validated,
            context=resolution_context,
        )
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

    def seal(self) -> None:
        # Permanently freeze registration/lifecycle mutation while preserving reads.
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            self._sealed = True

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

    def _ensure_mutable(self) -> None:
        if self._sealed:
            raise AgentAdministrationConflictError()

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


def _tool_state(registered: _RegisteredTool) -> ToolLifecycleState:
    return ToolLifecycleState(
        descriptor=registered.descriptor,
        revision=registered.revision,
    )


def _validate_lifecycle_inputs(enabled: bool, expected_revision: int) -> None:
    if not isinstance(enabled, bool):
        raise TypeError("enabled must be bool")
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise TypeError("expected_revision must be an integer")
    if expected_revision <= 0:
        raise ValueError("expected_revision must be positive")
