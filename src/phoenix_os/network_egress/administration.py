"""Least-privilege content-free administration for network egress."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.network_egress.service import NetworkEgressService, NetworkEgressServiceSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NETWORK_EGRESS_HEALTH_READ_PERMISSION = "network.egress.health.read"
NETWORK_EGRESS_HEALTH_RESOURCE = "network-egress:health"


class NetworkEgressAdministrationAccessDeniedError(PermissionError):
    """Sanitized denial for the bounded network-egress administration surface."""

    def __init__(self) -> None:
        super().__init__("network egress administration access denied")


@dataclass(frozen=True, slots=True)
class NetworkEgressAdministrationSnapshot:
    """Content-free bounded health for the configured network-egress service."""

    runtime: NetworkEgressServiceSnapshot
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, NetworkEgressServiceSnapshot):
            raise TypeError("runtime must be NetworkEgressServiceSnapshot")
        if self.schema_version != 1:
            raise ValueError("unsupported network egress administration snapshot version")


class NetworkEgressAdministration:
    """Expose one read-only bounded network-egress health surface."""

    def __init__(self, service: NetworkEgressService) -> None:
        if not isinstance(service, NetworkEgressService):
            raise TypeError("service must be NetworkEgressService")
        self._service = service

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> NetworkEgressAdministrationSnapshot:
        self._authorize(context)
        return NetworkEgressAdministrationSnapshot(runtime=await self._service.snapshot())

    @staticmethod
    def _authorize(context: SecurityContext) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise NetworkEgressAdministrationAccessDeniedError()
        if (
            NETWORK_EGRESS_HEALTH_READ_PERMISSION not in context.permissions
            and "*" not in context.permissions
        ):
            raise NetworkEgressAdministrationAccessDeniedError()
        if (
            context.principal_type is PrincipalType.SERVICE
            and context.attributes.get("resource") != NETWORK_EGRESS_HEALTH_RESOURCE
        ):
            raise NetworkEgressAdministrationAccessDeniedError()
