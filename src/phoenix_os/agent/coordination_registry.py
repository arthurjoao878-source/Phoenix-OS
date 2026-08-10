"""Server-owned closed-world registry for delegable Phoenix agents."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from threading import RLock
from uuid import UUID, uuid4

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.coordination_contracts import (
    CoordinationNamespace,
    DelegationDepth,
    DelegationLimits,
    DelegationRequest,
)
from phoenix_os.agent.errors import (
    AgentDelegationRegistryClosedError,
    DelegableAgentAlreadyRegisteredError,
    DelegableAgentNotFoundError,
)

_COMPATIBILITY_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class DelegableAgentDescriptor:
    """Reviewed immutable child-agent configuration eligible for delegation."""

    configuration: AgentServiceConfiguration
    namespace: CoordinationNamespace
    allowed_parent_agents: tuple[AgentId, ...]
    compatibility_digest: str
    allow_inbound: bool = True
    allow_nested_delegation: bool = False
    max_accepted_depth: DelegationDepth = field(default_factory=lambda: DelegationDepth(1))
    delegation_limits: DelegationLimits = field(default_factory=DelegationLimits)

    def __post_init__(self) -> None:
        if not isinstance(self.configuration, AgentServiceConfiguration):
            raise TypeError("configuration must be AgentServiceConfiguration")
        if not isinstance(self.namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
        parents = tuple(self.allowed_parent_agents)
        if not parents:
            raise ValueError("allowed_parent_agents must not be empty")
        if any(not isinstance(parent, AgentId) for parent in parents):
            raise TypeError("allowed_parent_agents must contain AgentId values")
        if len(parents) != len(set(parents)):
            raise ValueError("allowed_parent_agents contains duplicates")
        if self.configuration.agent_id in parents:
            raise ValueError("a delegable child cannot list itself as an allowed parent")
        if type(self.allow_inbound) is not bool:
            raise TypeError("allow_inbound must be bool")
        if type(self.allow_nested_delegation) is not bool:
            raise TypeError("allow_nested_delegation must be bool")
        if not isinstance(self.max_accepted_depth, DelegationDepth):
            raise TypeError("max_accepted_depth must be DelegationDepth")
        if self.max_accepted_depth.value <= 0:
            raise ValueError("max_accepted_depth must be greater than zero")
        if not isinstance(self.delegation_limits, DelegationLimits):
            raise TypeError("delegation_limits must be DelegationLimits")
        if self.max_accepted_depth.value > self.delegation_limits.max_depth:
            raise ValueError("max_accepted_depth cannot exceed delegation_limits.max_depth")
        if not isinstance(self.compatibility_digest, str):
            raise TypeError("compatibility_digest must be a string")
        normalized_digest = self.compatibility_digest.strip().lower()
        if _COMPATIBILITY_DIGEST_PATTERN.fullmatch(normalized_digest) is None:
            raise ValueError("compatibility_digest must be a canonical sha256 digest")

        object.__setattr__(self, "allowed_parent_agents", parents)
        object.__setattr__(self, "compatibility_digest", normalized_digest)

    @property
    def agent_id(self) -> AgentId:
        return self.configuration.agent_id


@dataclass(frozen=True, slots=True)
class AgentDelegationRegistration:
    id: UUID
    agent_id: AgentId
    namespace: CoordinationNamespace

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise TypeError("id must be UUID")
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")


@dataclass(slots=True)
class _RegisteredDelegableAgent:
    registration: AgentDelegationRegistration
    descriptor: DelegableAgentDescriptor
    sequence: int


class AgentDelegationRegistry:
    """Own reviewed delegable-agent registration and closed-world resolution."""

    def __init__(self) -> None:
        self._agents: dict[
            tuple[CoordinationNamespace, AgentId],
            _RegisteredDelegableAgent,
        ] = {}
        self._sequence = 0
        self._closed = False
        self._lock = RLock()

    @property
    def closed(self) -> bool:
        return self._closed

    def register_agent(
        self,
        descriptor: DelegableAgentDescriptor,
    ) -> AgentDelegationRegistration:
        if not isinstance(descriptor, DelegableAgentDescriptor):
            raise TypeError("descriptor must be DelegableAgentDescriptor")
        self._ensure_open()
        key = (descriptor.namespace, descriptor.agent_id)
        with self._lock:
            self._ensure_open()
            if key in self._agents:
                raise DelegableAgentAlreadyRegisteredError()
            registration = AgentDelegationRegistration(
                id=uuid4(),
                agent_id=descriptor.agent_id,
                namespace=descriptor.namespace,
            )
            self._agents[key] = _RegisteredDelegableAgent(
                registration=registration,
                descriptor=descriptor,
                sequence=self._sequence,
            )
            self._sequence += 1
            return registration

    def resolve_request(self, request: DelegationRequest) -> DelegableAgentDescriptor:
        if not isinstance(request, DelegationRequest):
            raise TypeError("request must be DelegationRequest")
        return self.resolve(
            request.child_agent_id,
            namespace=request.namespace,
            parent_agent_id=request.parent_agent_id,
            depth=request.child_depth,
        )

    def resolve(
        self,
        agent_id: AgentId | str,
        *,
        namespace: CoordinationNamespace,
        parent_agent_id: AgentId,
        depth: DelegationDepth,
    ) -> DelegableAgentDescriptor:
        normalized_agent_id = agent_id if isinstance(agent_id, AgentId) else AgentId(agent_id)
        if not isinstance(namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
        if not isinstance(parent_agent_id, AgentId):
            raise TypeError("parent_agent_id must be AgentId")
        if not isinstance(depth, DelegationDepth):
            raise TypeError("depth must be DelegationDepth")
        if depth.value <= 0:
            raise ValueError("delegated child depth must be greater than zero")

        self._ensure_open()
        with self._lock:
            self._ensure_open()
            registered = self._agents.get((namespace, normalized_agent_id))
            if registered is None:
                raise DelegableAgentNotFoundError()
            descriptor = registered.descriptor
            if (
                not descriptor.allow_inbound
                or parent_agent_id not in descriptor.allowed_parent_agents
                or depth.value > descriptor.max_accepted_depth.value
                or (depth.value > 1 and not descriptor.allow_nested_delegation)
            ):
                raise DelegableAgentNotFoundError()
            return descriptor

    def list_descriptors(
        self,
        *,
        namespace: CoordinationNamespace | None = None,
    ) -> tuple[DelegableAgentDescriptor, ...]:
        if namespace is not None and not isinstance(namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace or None")
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            ordered = sorted(self._agents.values(), key=lambda item: item.sequence)
            return tuple(
                item.descriptor
                for item in ordered
                if namespace is None or item.descriptor.namespace == namespace
            )

    def close(self) -> None:
        with self._lock:
            self._agents.clear()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentDelegationRegistryClosedError()
