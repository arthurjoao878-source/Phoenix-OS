"""Explicit opt-in composition for runtime-owned secure agent coordination."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.coordination import AgentDelegationCoordinator
from phoenix_os.agent.coordination_administration import AgentCoordinationAdministration
from phoenix_os.agent.coordination_authorization import PolicyEngineDelegationAuthorizer
from phoenix_os.agent.coordination_observer import (
    AgentCoordinationObserver,
    ContentFreeAgentCoordinationObserver,
)
from phoenix_os.agent.coordination_registry import (
    AgentDelegationRegistry,
    DelegableAgentDescriptor,
)
from phoenix_os.agent.coordination_runtime import (
    AgentCoordinationConfiguration,
    AgentCoordinationRuntime,
    DelegatedAgentService,
)
from phoenix_os.audit import AuditLedger
from phoenix_os.events import EventBus
from phoenix_os.observability import ObservabilityHub
from phoenix_os.policy import PolicyEngine

AgentCoordinationRuntimeLifecycle = AgentCoordinationRuntime


@dataclass(frozen=True, slots=True)
class AgentCoordinationRuntimeStack:
    """Reviewed Runtime-owned services created only when coordination is opted in."""

    configuration: AgentCoordinationConfiguration
    registry: AgentDelegationRegistry
    coordinator: AgentDelegationCoordinator
    observer: AgentCoordinationObserver
    runtime: AgentCoordinationRuntime
    administration: AgentCoordinationAdministration
    lifecycle: AgentCoordinationRuntime


def create_agent_coordination_runtime_stack(
    *,
    configuration: AgentCoordinationConfiguration,
    descriptors: Iterable[DelegableAgentDescriptor],
    child_services: Mapping[AgentId, DelegatedAgentService],
    policy: PolicyEngine,
    events: EventBus | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> AgentCoordinationRuntimeStack:
    """Compose coordination separately so legacy agent stacks remain unchanged by omission."""

    if not isinstance(configuration, AgentCoordinationConfiguration):
        raise TypeError("configuration must be AgentCoordinationConfiguration")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    resolved_events = EventBus() if events is None else events
    if not isinstance(resolved_events, EventBus):
        raise TypeError("events must be EventBus")
    if audit is not None and not isinstance(audit, AuditLedger):
        raise TypeError("audit must be AuditLedger")
    if observability is not None and not isinstance(observability, ObservabilityHub):
        raise TypeError("observability must be ObservabilityHub")

    descriptor_values = tuple(descriptors)
    if not descriptor_values:
        raise ValueError("coordination descriptors must not be empty")
    if any(not isinstance(item, DelegableAgentDescriptor) for item in descriptor_values):
        raise TypeError("descriptors must contain DelegableAgentDescriptor values")
    if any(item.namespace != configuration.namespace for item in descriptor_values):
        raise ValueError("coordination descriptor namespace must match configuration")

    descriptor_by_id = {item.agent_id: item for item in descriptor_values}
    if len(descriptor_by_id) != len(descriptor_values):
        raise ValueError("coordination descriptors contain duplicate agent ids")

    services = dict(child_services)
    if set(services) != set(descriptor_by_id):
        raise ValueError("child services must exactly match coordination descriptors")
    for agent_id, service in services.items():
        if not isinstance(agent_id, AgentId):
            raise TypeError("child service keys must be AgentId values")
        if not isinstance(service, DelegatedAgentService):
            raise TypeError("child services must implement DelegatedAgentService")
        if service.configuration != descriptor_by_id[agent_id].configuration:
            raise ValueError("child service configuration must match reviewed descriptor")

    registry = AgentDelegationRegistry()
    try:
        for descriptor in descriptor_values:
            registry.register_agent(descriptor)

        coordinator = AgentDelegationCoordinator(
            registry,
            PolicyEngineDelegationAuthorizer(policy),
            limits=configuration.limits,
            root_budget_limit=configuration.root_budget_limit,
        )
        observer = ContentFreeAgentCoordinationObserver(
            events=resolved_events,
            audit=audit,
            observability=observability,
            source=configuration.source,
        )
        runtime = AgentCoordinationRuntime(
            coordinator,
            configuration,
            services,
            observer=observer,
        )
        administration = AgentCoordinationAdministration(
            runtime,
            coordinator,
            configuration.namespace,
        )
    except BaseException:
        registry.close()
        raise

    return AgentCoordinationRuntimeStack(
        configuration=configuration,
        registry=registry,
        coordinator=coordinator,
        observer=observer,
        runtime=runtime,
        administration=administration,
        lifecycle=runtime,
    )
