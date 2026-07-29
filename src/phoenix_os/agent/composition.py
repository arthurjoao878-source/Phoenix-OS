"""Deterministic optional composition for the bounded agent subsystem."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass

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
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.tools import ToolAdapter, ToolResourceResolver
from phoenix_os.inference.authorization import PolicyEngineInferenceAuthorizer
from phoenix_os.policy import PolicyEngine
from phoenix_os.runtime import RuntimeContext


@dataclass(frozen=True, slots=True)
class AgentRuntimeStack:
    """Reviewed Runtime-owned services created for one enabled agent."""

    configuration: AgentServiceConfiguration
    registry: ToolRegistry
    admission: AgentAdmissionController
    executor: BoundedAgentExecutor
    runtime: AgentLoop
    lifecycle: AgentRuntimeLifecycle
    approval_service: ToolApprovalService | None = None


class AgentRuntimeLifecycle:
    """Own finite agent composition cleanup without starting background work."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        admission: AgentAdmissionController,
        approval_service: ToolApprovalService | None = None,
    ) -> None:
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be ToolRegistry")
        if not isinstance(admission, AgentAdmissionController):
            raise TypeError("admission must be AgentAdmissionController")
        if approval_service is not None and not isinstance(
            approval_service,
            ToolApprovalService,
        ):
            raise TypeError("approval_service must implement ToolApprovalService")
        self._registry = registry
        self._admission = admission
        self._approval_service = approval_service
        self._started = False
        self._stopped = False

    @property
    def started(self) -> bool:
        return self._started

    @property
    def stopped(self) -> bool:
        return self._stopped

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._stopped:
            raise RuntimeError("stopped agent composition cannot be restarted")
        self._started = True

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._stopped:
            return

        failure: BaseException | None = None
        try:
            await self._admission.close()
        except (Exception, asyncio.CancelledError) as exception:
            failure = exception

        approval = self._approval_service
        if approval is not None:
            try:
                await approval.close()
            except (Exception, asyncio.CancelledError) as exception:
                if failure is None:
                    failure = exception

        try:
            self._registry.close()
        except Exception as exception:
            if failure is None:
                failure = exception

        self._stopped = True
        if failure is not None:
            raise failure


def create_agent_runtime_stack(
    *,
    configuration: AgentServiceConfiguration,
    model_adapter: AgentModelTurnAdapter,
    tool_resolvers: Iterable[ToolResourceResolver],
    tool_adapters: Iterable[ToolAdapter],
    policy: PolicyEngine,
    approval_service: ToolApprovalService | None = None,
    approval_resolver: ToolApprovalResolver | None = None,
) -> AgentRuntimeStack:
    """Validate exact installations and compose one closed-world agent stack."""

    if not isinstance(configuration, AgentServiceConfiguration):
        raise TypeError("configuration must be AgentServiceConfiguration")
    if not isinstance(model_adapter, AgentModelTurnAdapter):
        raise TypeError("model_adapter must implement AgentModelTurnAdapter")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
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
    if (
        any(
            tool_descriptor_requires_approval(descriptor)
            for descriptor in configuration.descriptors
        )
        and approval_service is None
    ):
        raise ValueError("approval-required agent tools require approval services")

    installed_resolvers: dict[str, ToolResourceResolver] = {}
    for resolver in tuple(tool_resolvers):
        if not isinstance(resolver, ToolResourceResolver):
            raise TypeError("installed resolver must implement ToolResourceResolver")
        if resolver.resolver_id in installed_resolvers:
            raise ValueError("installed agent tool resolvers contain a duplicate")
        installed_resolvers[resolver.resolver_id] = resolver

    configured_resolver_ids = {descriptor.resolver_id for descriptor in configuration.descriptors}
    if set(installed_resolvers) != configured_resolver_ids:
        raise ValueError("installed agent tool resolvers must exactly match configuration")

    installed_adapters: dict[ToolId, ToolAdapter] = {}
    for adapter in tuple(tool_adapters):
        if not isinstance(adapter, ToolAdapter):
            raise TypeError("installed adapter must implement ToolAdapter")
        if adapter.tool_id in installed_adapters:
            raise ValueError("installed agent tool adapters contain a duplicate")
        installed_adapters[adapter.tool_id] = adapter

    configured_tool_ids = set(configuration.tool_ids)
    if set(installed_adapters) != configured_tool_ids:
        raise ValueError("installed agent tool adapters must exactly match configuration")

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
        )
        lifecycle = AgentRuntimeLifecycle(
            registry=registry,
            admission=admission,
            approval_service=approval_service,
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
        lifecycle=lifecycle,
        approval_service=approval_service,
    )
