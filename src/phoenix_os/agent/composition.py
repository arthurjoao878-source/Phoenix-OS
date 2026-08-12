"""Deterministic optional composition for the bounded agent subsystem."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from phoenix_os.agent.administration import AgentAdministration
from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.approval import ToolApprovalService, tool_descriptor_requires_approval
from phoenix_os.agent.authorization import (
    DelegatingAgentModelTurnAuthorizer,
    PolicyEngineAgentRunAuthorizer,
    PolicyEngineToolAuthorizer,
)
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import ToolId
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import AgentModelTurnAdapter
from phoenix_os.agent.loop import AgentLoop, ToolApprovalResolver
from phoenix_os.agent.memory_retrieval import AgentMemoryContextProvider
from phoenix_os.agent.observer import AgentObserver, ContentFreeAgentObserver
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentService
from phoenix_os.agent.tools import ToolAdapter, ToolResourceResolver
from phoenix_os.audit import AuditLedger
from phoenix_os.events import EventBus
from phoenix_os.inference.authorization import PolicyEngineInferenceAuthorizer
from phoenix_os.observability import ObservabilityHub
from phoenix_os.policy import PolicyEngine

AgentRuntimeLifecycle = AgentService


@dataclass(frozen=True, slots=True)
class AgentRuntimeStack:
    """Reviewed Runtime-owned services created for one enabled agent."""

    configuration: AgentServiceConfiguration
    registry: ToolRegistry
    admission: AgentAdmissionController
    executor: BoundedAgentExecutor
    runtime: AgentLoop
    observer: AgentObserver
    service: AgentService
    administration: AgentAdministration
    lifecycle: AgentService
    approval_service: ToolApprovalService | None = None
    memory_context: AgentMemoryContextProvider | None = None


def create_agent_runtime_stack(
    *,
    configuration: AgentServiceConfiguration,
    model_adapter: AgentModelTurnAdapter,
    tool_resolvers: Iterable[ToolResourceResolver],
    tool_adapters: Iterable[ToolAdapter],
    policy: PolicyEngine,
    events: EventBus | None = None,
    approval_service: ToolApprovalService | None = None,
    approval_resolver: ToolApprovalResolver | None = None,
    memory_context: AgentMemoryContextProvider | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> AgentRuntimeStack:
    """Validate exact installations and compose one closed-world agent stack."""

    if not isinstance(configuration, AgentServiceConfiguration):
        raise TypeError("configuration must be AgentServiceConfiguration")
    if not isinstance(model_adapter, AgentModelTurnAdapter):
        raise TypeError("model_adapter must implement AgentModelTurnAdapter")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    resolved_events = EventBus() if events is None else events
    if not isinstance(resolved_events, EventBus):
        raise TypeError("events must be EventBus")
    if approval_service is not None and not isinstance(
        approval_service,
        ToolApprovalService,
    ):
        raise TypeError("approval_service must implement ToolApprovalService")
    if approval_resolver is not None and not isinstance(
        approval_resolver,
        ToolApprovalResolver,
    ):
        raise TypeError("approval_resolver must implement ToolApprovalResolver")
    if (approval_service is None) != (approval_resolver is None):
        raise ValueError("approval_service and approval_resolver must be configured together")
    if memory_context is not None and not isinstance(memory_context, AgentMemoryContextProvider):
        raise TypeError("memory_context must implement AgentMemoryContextProvider")
    if (
        any(
            tool_descriptor_requires_approval(descriptor)
            for descriptor in configuration.descriptors
        )
        and approval_service is None
    ):
        raise ValueError("approval-required agent tools require approval services")
    if audit is not None and not isinstance(audit, AuditLedger):
        raise TypeError("audit must be AuditLedger")
    if observability is not None and not isinstance(observability, ObservabilityHub):
        raise TypeError("observability must be ObservabilityHub")

    resolver_values = tuple(tool_resolvers)
    installed_resolvers: dict[str, ToolResourceResolver] = {}
    for resolver in resolver_values:
        if not isinstance(resolver, ToolResourceResolver):
            raise TypeError("installed resolver must implement ToolResourceResolver")
        if resolver.resolver_id in installed_resolvers:
            raise ValueError("installed agent tool resolvers contain a duplicate")
        installed_resolvers[resolver.resolver_id] = resolver

    configured_resolver_ids = {descriptor.resolver_id for descriptor in configuration.descriptors}
    if set(installed_resolvers) != configured_resolver_ids:
        raise ValueError("installed agent tool resolvers must exactly match configuration")

    adapter_values = tuple(tool_adapters)
    installed_adapters: dict[ToolId, ToolAdapter] = {}
    for adapter in adapter_values:
        if not isinstance(adapter, ToolAdapter):
            raise TypeError("installed adapter must implement ToolAdapter")
        if adapter.tool_id in installed_adapters:
            raise ValueError("installed agent tool adapters contain a duplicate")
        installed_adapters[adapter.tool_id] = adapter

    configured_tool_ids = set(configuration.tool_ids)
    if set(installed_adapters) != configured_tool_ids:
        raise ValueError("installed agent tool adapters must exactly match configuration")

    ordered_adapters = tuple(installed_adapters[tool_id] for tool_id in configuration.tool_ids)
    registry = ToolRegistry()
    try:
        for configured_tool in configuration.tools:
            descriptor = configured_tool.descriptor
            registry.register_tool(
                descriptor,
                resolver=installed_resolvers[descriptor.resolver_id],
                adapter=installed_adapters[descriptor.tool_id],
            )

        admission = AgentAdmissionController(configuration.limits)
        executor = BoundedAgentExecutor()
        observer = ContentFreeAgentObserver(
            configuration,
            events=resolved_events,
            audit=audit,
            observability=observability,
        )
        runtime = AgentLoop(
            run_authorizer=PolicyEngineAgentRunAuthorizer(policy),
            model_authorizer=DelegatingAgentModelTurnAuthorizer(
                PolicyEngineInferenceAuthorizer(policy)
            ),
            tool_authorizer=PolicyEngineToolAuthorizer(policy),
            model_adapter=model_adapter,
            registry=registry,
            executor=executor,
            approval_service=approval_service,
            approval_resolver=approval_resolver,
            admission=admission,
            observer=observer,
            memory_context=memory_context,
        )
        service = AgentService(
            runtime,
            registry,
            admission,
            configuration,
            events=resolved_events,
            model_adapter=model_adapter,
            tool_adapters=ordered_adapters,
            approval_service=approval_service,
            audit=audit,
            observability=observability,
        )
        administration = AgentAdministration(
            registry,
            service,
            configuration,
            events=resolved_events,
            audit=audit,
            observability=observability,
        )
    except BaseException:
        registry.close()
        raise

    return AgentRuntimeStack(
        configuration=configuration,
        registry=registry,
        admission=admission,
        executor=executor,
        runtime=runtime,
        observer=observer,
        service=service,
        administration=administration,
        lifecycle=service,
        approval_service=approval_service,
        memory_context=memory_context,
    )
