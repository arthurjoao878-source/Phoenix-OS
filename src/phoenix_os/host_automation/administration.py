"""Least-privilege content-free administration for host automation."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.host_automation.authorization import host_resource
from phoenix_os.host_automation.contracts import HostId
from phoenix_os.host_automation.errors import HostAutomationAdministrationAccessDeniedError
from phoenix_os.host_automation.service import (
    HostAutomationService,
    HostAutomationServiceSnapshot,
)
from phoenix_os.policy import PrincipalType, SecurityContext

HOST_HEALTH_READ_PERMISSION = "host.health.read"


def host_health_resource(host_id: HostId | str) -> str:
    host = host_id if isinstance(host_id, HostId) else HostId(host_id)
    return f"{host_resource(host)}/health"


@dataclass(frozen=True, slots=True)
class HostAutomationAdministrationSnapshot:
    """Content-free bounded health for one configured host service."""

    runtime: HostAutomationServiceSnapshot
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, HostAutomationServiceSnapshot):
            raise TypeError("runtime must be HostAutomationServiceSnapshot")
        if self.schema_version != 1:
            raise ValueError("unsupported host administration snapshot version")


class HostAutomationAdministration:
    """Expose one read-only bounded host health surface."""

    def __init__(self, service: HostAutomationService) -> None:
        if not isinstance(service, HostAutomationService):
            raise TypeError("service must be HostAutomationService")
        self._service = service

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> HostAutomationAdministrationSnapshot:
        self._authorize(
            context,
            HOST_HEALTH_READ_PERMISSION,
            host_health_resource(self._service.host_id),
        )
        return HostAutomationAdministrationSnapshot(runtime=await self._service.snapshot())

    @staticmethod
    def _authorize(context: SecurityContext, permission: str, resource: str) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise HostAutomationAdministrationAccessDeniedError()
        if permission not in context.permissions and "*" not in context.permissions:
            raise HostAutomationAdministrationAccessDeniedError()
        if (
            context.principal_type is PrincipalType.SERVICE
            and context.attributes.get("resource") != resource
        ):
            raise HostAutomationAdministrationAccessDeniedError()
