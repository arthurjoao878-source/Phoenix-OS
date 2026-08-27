"""Integrated runtime lifecycle adapter for RFC-0036 S2."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentRunRequest, AgentRunResult
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.integrated_agent.admission import IntegratedAgentAdmission
from phoenix_os.integrated_agent.contracts import IntegratedTaskRequest
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
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
    ) -> None:
        if not isinstance(service, IntegratedAgentServiceDelegate):
            raise TypeError("service must implement IntegratedAgentServiceDelegate")
        if not isinstance(admission, IntegratedAgentAdmission):
            raise TypeError("admission must be IntegratedAgentAdmission")
        if service.configuration != admission.service_configuration:
            raise IntegratedAgentConfigurationError()

        self._service = service
        self._admission = admission

    @property
    def service(self) -> IntegratedAgentServiceDelegate:
        return self._service

    @property
    def admission(self) -> IntegratedAgentAdmission:
        return self._admission

    @property
    def state(self) -> AgentServiceState:
        return self._service.state

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self._service.start(context)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
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

        lease = await self._admission.admit(task, request)
        try:
            return await self._service.run(
                lease.request,
                context,
                cancellation=cancellation,
                _authority_binding=lease.binding.authority,
            )
        finally:
            await lease.release()
