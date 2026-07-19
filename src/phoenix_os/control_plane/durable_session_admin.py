"""Compatibility administration bridge from operator management to durable sessions."""

from __future__ import annotations

from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.durable_session_access import ControlPlaneDurableSessionAccessService
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableSessionTerminationReason,
)
from phoenix_os.control_plane.errors import ControlPlaneOperatorPermissionDeniedError
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
)
from phoenix_os.control_plane.operator_sessions import (
    ControlPlaneOperatorSessionRevocationReason,
)


class ControlPlaneDurableSessionAdministration:
    """Expose the RFC-0020 session-admin shape over durable session storage."""

    def __init__(self, access: ControlPlaneDurableSessionAccessService) -> None:
        self._access = access

    async def revoke_session(
        self,
        session_id: UUID,
        *,
        actor: ControlPlanePrincipal,
    ) -> bool:
        self._require(actor)
        return await self._access.revoke_session(
            session_id,
            reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        )

    async def revoke_operator_sessions(
        self,
        operator_id: UUID,
        *,
        actor: ControlPlanePrincipal,
        reason: ControlPlaneOperatorSessionRevocationReason = (
            ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE
        ),
    ) -> int:
        self._require(actor)
        return await self.invalidate_operator_sessions(
            operator_id,
            actor=actor.name,
            reason=reason,
        )

    async def invalidate_operator_sessions(
        self,
        operator_id: UUID,
        *,
        actor: str,
        reason: ControlPlaneOperatorSessionRevocationReason,
    ) -> int:
        del actor
        return await self._access.revoke_operator_sessions(
            operator_id,
            reason=_map_reason(reason),
        )

    @staticmethod
    def _require(actor: ControlPlanePrincipal) -> None:
        if CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION not in actor.permissions:
            raise ControlPlaneOperatorPermissionDeniedError(
                "operator session revocation permission denied"
            )


def _map_reason(
    reason: ControlPlaneOperatorSessionRevocationReason,
) -> ControlPlaneDurableSessionTerminationReason:
    normalized = ControlPlaneOperatorSessionRevocationReason(reason)
    if normalized is ControlPlaneOperatorSessionRevocationReason.LOGOUT:
        return ControlPlaneDurableSessionTerminationReason.LOGOUT
    if normalized is ControlPlaneOperatorSessionRevocationReason.OPERATOR_INACTIVE:
        return ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE
    if normalized is ControlPlaneOperatorSessionRevocationReason.CREDENTIAL_ROTATED:
        return ControlPlaneDurableSessionTerminationReason.CREDENTIAL_ROTATED
    return ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE
