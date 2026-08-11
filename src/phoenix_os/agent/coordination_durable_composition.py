"""Explicit durable composition for secure agent coordination."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.coordination_administration import AgentCoordinationAdministration
from phoenix_os.agent.coordination_authorization import PolicyEngineDelegationAuthorizer
from phoenix_os.agent.coordination_durable_contracts import DurableDelegationStore
from phoenix_os.agent.coordination_durable_recovery import (
    DurableAgentDelegationCoordinator,
    DurableDelegationRecoveryCoordinator,
    DurableDelegationRecoveryReport,
)
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
from phoenix_os.runtime import RuntimeContext


class DurableAgentCoordinationLifecycle:
    """Recover before accepting work and close durable ownership after bounded drain."""

    def __init__(
        self,
        runtime: AgentCoordinationRuntime,
        recovery: DurableDelegationRecoveryCoordinator,
        registry: AgentDelegationRegistry,
        store: DurableDelegationStore,
    ) -> None:
        if not isinstance(runtime, AgentCoordinationRuntime):
            raise TypeError("runtime must be AgentCoordinationRuntime")
        if not isinstance(recovery, DurableDelegationRecoveryCoordinator):
            raise TypeError("recovery must be DurableDelegationRecoveryCoordinator")
        if not isinstance(registry, AgentDelegationRegistry):
            raise TypeError("registry must be AgentDelegationRegistry")
        if not isinstance(store, DurableDelegationStore):
            raise TypeError("store must implement DurableDelegationStore")
        self._runtime = runtime
        self._recovery = recovery
        self._registry = registry
        self._store = store
        self._last_recovery_report: DurableDelegationRecoveryReport | None = None

    @property
    def last_recovery_report(self) -> DurableDelegationRecoveryReport | None:
        return self._last_recovery_report

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        self._last_recovery_report = await self._recovery.recover()
        await self._runtime.start(context)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        try:
            await self._runtime.stop(context)
        finally:
            try:
                self._registry.close()
            finally:
                await self._store.close()


@dataclass(frozen=True, slots=True)
class DurableAgentCoordinationRuntimeStack:
    """Runtime-owned durable coordination components for one explicit installation."""

    configuration: AgentCoordinationConfiguration
    registry: AgentDelegationRegistry
    store: DurableDelegationStore
    coordinator: DurableAgentDelegationCoordinator
    recovery: DurableDelegationRecoveryCoordinator
    observer: AgentCoordinationObserver
    runtime: AgentCoordinationRuntime
    administration: AgentCoordinationAdministration
    lifecycle: DurableAgentCoordinationLifecycle


def create_durable_agent_coordination_runtime_stack(
    *,
    configuration: AgentCoordinationConfiguration,
    descriptors: Iterable[DelegableAgentDescriptor],
    child_services: Mapping[AgentId, DelegatedAgentService],
    policy: PolicyEngine,
    store: DurableDelegationStore,
    events: EventBus | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> DurableAgentCoordinationRuntimeStack:
    """Compose durable coordination only when an explicit durable store is installed."""

    if not isinstance(configuration, AgentCoordinationConfiguration):
        raise TypeError("configuration must be AgentCoordinationConfiguration")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    if not isinstance(store, DurableDelegationStore):
        raise TypeError("store must implement DurableDelegationStore")
    if store.closed:
        raise ValueError("store must be open")
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

        coordinator = DurableAgentDelegationCoordinator(
            registry,
            PolicyEngineDelegationAuthorizer(policy),
            store=store,
            limits=configuration.limits,
            root_budget_limit=configuration.root_budget_limit,
        )
        recovery = DurableDelegationRecoveryCoordinator(store)
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
        lifecycle = DurableAgentCoordinationLifecycle(
            runtime,
            recovery,
            registry,
            store,
        )
    except BaseException:
        registry.close()
        raise

    return DurableAgentCoordinationRuntimeStack(
        configuration=configuration,
        registry=registry,
        store=store,
        coordinator=coordinator,
        recovery=recovery,
        observer=observer,
        runtime=runtime,
        administration=administration,
        lifecycle=lifecycle,
    )
