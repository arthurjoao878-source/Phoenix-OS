"""Least-privilege maintainer administration for the bounded agent Runtime."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId, ToolAvailability, ToolEffect, ToolId
from phoenix_os.agent.errors import AgentAdministrationAccessDeniedError
from phoenix_os.agent.registry import ToolLifecycleState, ToolRegistry
from phoenix_os.agent.service import AgentService, AgentServiceSnapshot
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import PrincipalType, SecurityContext

AGENT_TOOLS_READ_PERMISSION = "agent.tool.read"
AGENT_TOOLS_DISABLE_PERMISSION = "agent.tool.disable"
AGENT_TOOLS_ENABLE_PERMISSION = "agent.tool.enable"
AGENT_HEALTH_READ_PERMISSION = "agent.health.read"


def agent_tools_resource(agent_id: AgentId | str) -> str:
    agent = agent_id if isinstance(agent_id, AgentId) else AgentId(agent_id)
    return f"agent:{agent}/tools"


def agent_tool_resource(agent_id: AgentId | str, tool_id: ToolId | str) -> str:
    agent = agent_id if isinstance(agent_id, AgentId) else AgentId(agent_id)
    tool = tool_id if isinstance(tool_id, ToolId) else ToolId(tool_id)
    return f"agent:{agent}/tool:{tool}"


def agent_health_resource(agent_id: AgentId | str) -> str:
    agent = agent_id if isinstance(agent_id, AgentId) else AgentId(agent_id)
    return f"agent:{agent}/health"


@dataclass(frozen=True, slots=True)
class AgentToolView:
    """Safe reviewed tool inventory without schemas or implementation details."""

    tool_id: ToolId
    name: str
    description: str
    effect: ToolEffect
    availability: ToolAvailability
    revision: int
    approval_may_be_required: bool
    max_input_bytes: int
    max_output_bytes: int
    timeout_seconds: float
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.effect, ToolEffect):
            raise TypeError("effect must be ToolEffect")
        if not isinstance(self.availability, ToolAvailability):
            raise TypeError("availability must be ToolAvailability")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("revision must be an integer")
        if self.revision <= 0:
            raise ValueError("revision must be positive")
        if not isinstance(self.approval_may_be_required, bool):
            raise TypeError("approval_may_be_required must be bool")
        if min(self.max_input_bytes, self.max_output_bytes) <= 0:
            raise ValueError("tool byte limits must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("tool timeout must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported agent tool view version")

    @property
    def enabled(self) -> bool:
        return self.availability is ToolAvailability.ACTIVE


@dataclass(frozen=True, slots=True)
class AgentAdministrationSnapshot:
    """Content-free subsystem health and reviewed lifecycle counts."""

    runtime: AgentServiceSnapshot
    tools: int
    enabled_tools: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if min(self.tools, self.enabled_tools) < 0 or self.enabled_tools > self.tools:
            raise ValueError("agent administration counters are invalid")
        if self.schema_version != 1:
            raise ValueError("unsupported agent administration snapshot version")


class AgentAdministration:
    """Expose bounded health and optimistic tool lifecycle transitions only."""

    def __init__(
        self,
        registry: ToolRegistry,
        service: AgentService,
        configuration: AgentServiceConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be ToolRegistry")
        if not isinstance(service, AgentService):
            raise TypeError("service must be AgentService")
        if not isinstance(configuration, AgentServiceConfiguration):
            raise TypeError("configuration must be AgentServiceConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        if audit is not None and not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if observability is not None and not isinstance(observability, ObservabilityHub):
            raise TypeError("observability must be ObservabilityHub")
        self._registry = registry
        self._service = service
        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability

    async def list_tools(self, context: SecurityContext) -> tuple[AgentToolView, ...]:
        self._authorize(
            context,
            AGENT_TOOLS_READ_PERMISSION,
            agent_tools_resource(self._configuration.agent_id),
        )
        return tuple(_tool_view(state) for state in self._registry.list_states())

    async def tool(
        self,
        tool_id: ToolId | str,
        context: SecurityContext,
    ) -> AgentToolView:
        resource = agent_tool_resource(self._configuration.agent_id, tool_id)
        self._authorize(context, AGENT_TOOLS_READ_PERMISSION, resource)
        return _tool_view(self._registry.describe(tool_id))

    async def set_tool_enabled(
        self,
        tool_id: ToolId | str,
        context: SecurityContext,
        *,
        enabled: bool,
        expected_revision: int,
    ) -> AgentToolView:
        permission = AGENT_TOOLS_ENABLE_PERMISSION if enabled else AGENT_TOOLS_DISABLE_PERMISSION
        resource = agent_tool_resource(self._configuration.agent_id, tool_id)
        self._authorize(context, permission, resource)
        state = self._registry.set_enabled(
            tool_id,
            enabled=enabled,
            expected_revision=expected_revision,
        )
        await self._signal(state, permission=permission, resource=resource, context=context)
        return _tool_view(state)

    async def snapshot(self, context: SecurityContext) -> AgentAdministrationSnapshot:
        self._authorize(
            context,
            AGENT_HEALTH_READ_PERMISSION,
            agent_health_resource(self._configuration.agent_id),
        )
        states = self._registry.list_states()
        return AgentAdministrationSnapshot(
            runtime=await self._service.snapshot(),
            tools=len(states),
            enabled_tools=sum(item.enabled for item in states),
        )

    @staticmethod
    def _authorize(context: SecurityContext, permission: str, resource: str) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise AgentAdministrationAccessDeniedError()
        if permission not in context.permissions and "*" not in context.permissions:
            raise AgentAdministrationAccessDeniedError()
        if (
            context.principal_type is PrincipalType.SERVICE
            and context.attributes.get("resource") != resource
        ):
            raise AgentAdministrationAccessDeniedError()

    async def _signal(
        self,
        state: ToolLifecycleState,
        *,
        permission: str,
        resource: str,
        context: SecurityContext,
    ) -> None:
        descriptor = state.descriptor
        name = f"agent.tool.{descriptor.availability.value}"
        metadata = {
            "agent_id": str(self._configuration.agent_id),
            "tool_id": str(descriptor.tool_id),
            "effect": descriptor.effect.value,
            "availability": descriptor.availability.value,
            "revision": str(state.revision),
        }
        options = self._configuration.observability
        if options.events_enabled:
            try:
                await self._events.emit(
                    name,
                    source=self._configuration.source,
                    payload={},
                    metadata=metadata,
                    correlation_id=context.correlation_id,
                    causation_id=context.causation_id,
                )
            except Exception:
                pass
        if options.audit_enabled and self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.CONFIGURATION,
                    action=permission,
                    resource=resource,
                    context=context,
                    outcome=AuditOutcome.SUCCEEDED,
                    severity=AuditSeverity.INFO,
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass
        if self._observability is not None:
            try:
                if options.logs_enabled:
                    await self._observability.log(
                        name,
                        source=self._configuration.source,
                        message="agent tool lifecycle changed",
                        severity=Severity.INFO,
                        attributes=metadata,
                        correlation_id=context.correlation_id,
                        causation_id=context.causation_id,
                    )
                if options.metrics_enabled:
                    await self._observability.metric(
                        "agent.administration.changes",
                        1,
                        source=self._configuration.source,
                        kind=MetricKind.COUNTER,
                        unit="change",
                        attributes={
                            "availability": descriptor.availability.value,
                            "effect": descriptor.effect.value,
                        },
                        correlation_id=context.correlation_id,
                        causation_id=context.causation_id,
                    )
            except Exception:
                pass


def _tool_view(state: ToolLifecycleState) -> AgentToolView:
    descriptor = state.descriptor
    return AgentToolView(
        tool_id=descriptor.tool_id,
        name=descriptor.name,
        description=descriptor.description,
        effect=descriptor.effect,
        availability=descriptor.availability,
        revision=state.revision,
        approval_may_be_required=descriptor.approval_may_be_required,
        max_input_bytes=descriptor.max_input_bytes,
        max_output_bytes=descriptor.max_output_bytes,
        timeout_seconds=descriptor.timeout.total_seconds(),
    )
