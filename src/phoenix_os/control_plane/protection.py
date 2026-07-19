"""Combined browser-command protection enforcing CSRF and destructive proof policy."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.commands import ControlPlaneCommandIntent
from phoenix_os.control_plane.confirmation import (
    ControlPlaneConfirmationChallenge,
    ControlPlaneConfirmationProof,
    ControlPlaneConfirmationService,
    ControlPlaneConfirmationVerification,
)
from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfToken,
    ControlPlaneCsrfVerification,
)
from phoenix_os.control_plane.errors import ControlPlaneConfirmationRejectedError


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandProtection:
    """Safe evidence returned before a command handler may mutate state."""

    csrf: ControlPlaneCsrfVerification
    confirmation: ControlPlaneConfirmationVerification | None


class ControlPlaneCommandProtector:
    """Centralize browser-origin and destructive-confirmation enforcement."""

    def __init__(
        self,
        csrf: ControlPlaneCsrfProtector,
        confirmations: ControlPlaneConfirmationService,
    ) -> None:
        self._csrf = csrf
        self._confirmations = confirmations

    async def issue_confirmation(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneConfirmationChallenge:
        self._csrf.verify(csrf_token, principal, origin)
        return await self._confirmations.issue(principal, intent)

    async def verify(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
        confirmation: ControlPlaneConfirmationProof | None = None,
    ) -> ControlPlaneCommandProtection:
        csrf = self._csrf.verify(csrf_token, principal, origin)
        verified_confirmation: ControlPlaneConfirmationVerification | None = None
        if intent.action.destructive:
            if confirmation is None:
                raise ControlPlaneConfirmationRejectedError("command confirmation failed")
            verified_confirmation = await self._confirmations.verify_and_consume(
                principal,
                intent,
                confirmation,
            )
        return ControlPlaneCommandProtection(
            csrf=csrf,
            confirmation=verified_confirmation,
        )
