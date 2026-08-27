"""Integrated runtime lifecycle adapter for RFC-0036 S2."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentRunRequest, AgentRunResult
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.integrated_agent.admission import IntegratedAgentAdmission
from phoenix_os.integrated_agent.composition import IntegratedAgentToolComposition
from phoenix_os.integrated_agent.contracts import IntegratedTaskRequest
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext


@runtime_checkable
class IntegratedAgentServiceDelegate(Protocol):
    """Existing RFC-0027 AgentService surface reused by integrated execution."""

    @property
    def configuration(self) -> AgentServiceConfiguration: ...

    @property
    def state(self) -> AgentServiceState: ...

    async def start(self, context: RuntimeContext) -> None: ...

    async def stop(self, context: RuntimeContext) -> None: ...

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult: ...


class IntegratedAgentRuntime:
    """Bind integrated admission into the existing AgentService/AgentLoop lifecycle."""

    def __init__(
        self,
        service: IntegratedAgentServiceDelegate,
        admission: IntegratedAgentAdmission,
        *,
        planner: IntegratedPlanner | None = None,
        composition: IntegratedAgentToolComposition | None = None,
    ) -> None:
        if not isinstance(service, IntegratedAgentServiceDelegate):
            raise TypeError("service must implement IntegratedAgentServiceDelegate")
        if not isinstance(admission, IntegratedAgentAdmission):
            raise TypeError("admission must be IntegratedAgentAdmission")
        if service.configuration != admission.service_configuration:
            raise IntegratedAgentConfigurationError()
        if planner is not None and not isinstance(planner, IntegratedPlanner):
            raise TypeError("planner must be IntegratedPlanner or None")
        if composition is not None and not isinstance(
            composition,
            IntegratedAgentToolComposition,
        ):
            raise TypeError("composition must be IntegratedAgentToolComposition or None")

        registry: ToolRegistry | None = None
        if service.configuration.tool_ids:
            if composition is None or composition.profile != admission.profile:
                raise IntegratedAgentConfigurationError()
            composition.require_service_configuration(service.configuration)
            candidate = getattr(service, "registry", None)
            if not isinstance(candidate, ToolRegistry):
                raise IntegratedAgentConfigurationError()
            composition.require_registry(candidate)
            service_runtime = getattr(service, "runtime", None)
            if service_runtime is not None and (
                not isinstance(service_runtime, AgentLoop)
                or service_runtime.registry is not candidate
            ):
                raise IntegratedAgentConfigurationError()
            registry = candidate
        elif composition is not None:
            raise IntegratedAgentConfigurationError()

        if planner is not None:
            if planner.profile != admission.profile:
                raise IntegratedAgentConfigurationError()
            configured_descriptor = next(
                (
                    descriptor
                    for descriptor in service.configuration.descriptors
                    if descriptor.tool_id == planner.descriptor.tool_id
                ),
                None,
            )
            if configured_descriptor != planner.descriptor:
                raise IntegratedAgentConfigurationError()
            if composition is None:
                raise IntegratedAgentConfigurationError()
            registration = composition.require_registration(planner.descriptor.tool_id)
            if (
                registration.descriptor != planner.descriptor
                or registration.resolver is not planner.resource_resolver
                or registration.adapter is not planner.adapter
            ):
                raise IntegratedAgentConfigurationError()

        self._service = service
        self._admission = admission
        self._planner = planner
        self._composition = composition
        self._registry = registry

    @property
    def service(self) -> IntegratedAgentServiceDelegate:
        return self._service

    @property
    def admission(self) -> IntegratedAgentAdmission:
        return self._admission

    @property
    def planner(self) -> IntegratedPlanner | None:
        return self._planner

    @property
    def composition(self) -> IntegratedAgentToolComposition | None:
        return self._composition

    @property
    def state(self) -> AgentServiceState:
        return self._service.state

    def _require_current_tool_surface(self) -> None:
        if self._composition is None:
            return
        assert self._registry is not None
        self._composition.require_registry(self._registry)

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        self._require_current_tool_surface()
        await self._service.start(context)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._planner is not None:
            self._planner.close()
        await self._admission.close()
        await self._service.stop(context)

    async def run(
        self,
        task: IntegratedTaskRequest,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
    ) -> AgentRunResult:
        if not isinstance(task, IntegratedTaskRequest):
            raise TypeError("task must be IntegratedTaskRequest")
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if cancellation is not None and not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        self._require_current_tool_surface()

        lease = await self._admission.admit(task, request)
        planner_started = False
        try:
            if self._planner is not None:
                self._planner.begin_run(lease.binding)
                planner_started = True
            return await self._service.run(
                lease.request,
                context,
                cancellation=cancellation,
                _authority_binding=lease.binding.authority,
            )
        finally:
            try:
                if planner_started and self._planner is not None:
                    self._planner.release_run(lease.binding.run_id)
            finally:
                await lease.release()
