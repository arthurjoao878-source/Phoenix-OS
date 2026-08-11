"""Least-privilege content-free administration for agent coordination."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.agent.coordination import (
    AgentDelegationCoordinator,
    AgentDelegationCoordinatorSnapshot,
    DelegatedChildRun,
)
from phoenix_os.agent.coordination_contracts import CoordinationNamespace, DelegationId
from phoenix_os.agent.coordination_runtime import (
    AgentCoordinationRuntime,
    AgentCoordinationRuntimeSnapshot,
)
from phoenix_os.agent.errors import AgentAdministrationAccessDeniedError
from phoenix_os.policy import PrincipalType, SecurityContext

AGENT_COORDINATION_HEALTH_READ_PERMISSION = "agent.coordination.health.read"
AGENT_COORDINATION_DELEGATION_READ_PERMISSION = "agent.coordination.delegation.read"


def coordination_health_resource(namespace: CoordinationNamespace) -> str:
    if not isinstance(namespace, CoordinationNamespace):
        raise TypeError("namespace must be CoordinationNamespace")
    return f"agent-coordination:{namespace}/health"


def coordination_delegation_resource(
    namespace: CoordinationNamespace,
    delegation_id: DelegationId,
) -> str:
    if not isinstance(namespace, CoordinationNamespace):
        raise TypeError("namespace must be CoordinationNamespace")
    if not isinstance(delegation_id, DelegationId):
        raise TypeError("delegation_id must be DelegationId")
    return f"agent-coordination:{namespace}/delegation:{delegation_id}"


@dataclass(frozen=True, slots=True)
class AgentCoordinationAdministrationSnapshot:
    """Content-free runtime and coordinator health."""

    runtime: AgentCoordinationRuntimeSnapshot
    coordinator: AgentDelegationCoordinatorSnapshot
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, AgentCoordinationRuntimeSnapshot):
            raise TypeError("runtime must be AgentCoordinationRuntimeSnapshot")
        if not isinstance(self.coordinator, AgentDelegationCoordinatorSnapshot):
            raise TypeError("coordinator must be AgentDelegationCoordinatorSnapshot")
        if self.schema_version != 1:
            raise ValueError("unsupported coordination administration snapshot version")


class AgentCoordinationAdministration:
    """Expose only content-free health and child lifecycle identities."""

    def __init__(
        self,
        runtime: AgentCoordinationRuntime,
        coordinator: AgentDelegationCoordinator,
        namespace: CoordinationNamespace,
    ) -> None:
        if not isinstance(runtime, AgentCoordinationRuntime):
            raise TypeError("runtime must be AgentCoordinationRuntime")
        if not isinstance(coordinator, AgentDelegationCoordinator):
            raise TypeError("coordinator must be AgentDelegationCoordinator")
        if not isinstance(namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
        self._runtime = runtime
        self._coordinator = coordinator
        self._namespace = namespace

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> AgentCoordinationAdministrationSnapshot:
        self._authorize(
            context,
            AGENT_COORDINATION_HEALTH_READ_PERMISSION,
            coordination_health_resource(self._namespace),
        )
        return AgentCoordinationAdministrationSnapshot(
            runtime=await self._runtime.snapshot(),
            coordinator=await self._coordinator.snapshot(),
        )

    async def delegation(
        self,
        delegation_id: DelegationId,
        context: SecurityContext,
    ) -> DelegatedChildRun:
        resource = coordination_delegation_resource(self._namespace, delegation_id)
        self._authorize(
            context,
            AGENT_COORDINATION_DELEGATION_READ_PERMISSION,
            resource,
        )
        return await self._coordinator.get(delegation_id)

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
