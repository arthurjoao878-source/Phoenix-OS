"""Trusted service-account guard for RFC-0028 durable machine administration."""

from __future__ import annotations

from typing import Never

from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountAuthorizer,
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_policy import (
    current_control_plane_service_account_api_context,
)
from phoenix_os.policy import SecurityContext

_DENIED_MESSAGE = "service-account authorization denied"


class ControlPlaneDurableMachineAdministrationGuard:
    """Require one trusted API context with exact durable action and resource grants."""

    def __init__(self) -> None:
        self._authorizer = ControlPlaneServiceAccountAuthorizer()

    async def authorize(
        self,
        context: SecurityContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("durable machine administration requires SecurityContext")

        api_context = current_control_plane_service_account_api_context()
        if api_context is None or context is not api_context.security_context:
            _deny()

        authentication = api_context.authentication
        if action not in authentication.scopes or resource not in authentication.resources:
            _deny()

        try:
            self._authorizer.require(
                authentication,
                action=action,
                resource=resource,
            )
        except (
            ControlPlaneServiceAccountPermissionDeniedError,
            TypeError,
            ValueError,
        ):
            _deny()


def _deny() -> Never:
    raise ControlPlaneServiceAccountPermissionDeniedError(_DENIED_MESSAGE) from None
