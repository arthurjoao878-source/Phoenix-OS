"""Human control-plane orchestration for bounded durable cleanup confirmation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_cleanup_administration import (
    DurableCleanupAdministrationBounds,
)
from phoenix_os.agent.durable_retention_worker import DurableRetentionWorkerReport
from phoenix_os.control_plane.durable_administration_protection import (
    ControlPlaneDurableAdministrationConfirmationChallenge,
    ControlPlaneDurableAdministrationConfirmationVerification,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableCleanupBounds,
    ControlPlaneDurableCleanupIntent,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
)
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION,
)
from phoenix_os.policy import PrincipalType, SecurityContext

type ControlPlaneDurableCleanupClock = Callable[[], datetime]


@runtime_checkable
class _DurableCleanupCoordinator(Protocol):
    @property
    def closed(self) -> bool: ...

    def bounds(
        self,
        context: SecurityContext,
    ) -> DurableCleanupAdministrationBounds: ...

    async def run(
        self,
        context: SecurityContext,
        *,
        expected_bounds: DurableCleanupAdministrationBounds,
        requested_at: datetime,
    ) -> DurableRetentionWorkerReport: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableCleanupConfirmation:
    """Safe server-owned handle binding one cleanup pass to one confirmation."""

    intent: ControlPlaneDurableCleanupIntent
    challenge: ControlPlaneDurableAdministrationConfirmationChallenge = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.intent, ControlPlaneDurableCleanupIntent):
            raise TypeError("intent must be ControlPlaneDurableCleanupIntent")
        if not isinstance(
            self.challenge,
            ControlPlaneDurableAdministrationConfirmationChallenge,
        ):
            raise TypeError(
                "challenge must be ControlPlaneDurableAdministrationConfirmationChallenge"
            )
        if (
            self.challenge.intent_id != self.intent.id
            or self.challenge.action != self.intent.action
            or self.challenge.resource != self.intent.resource
            or self.challenge.fingerprint != self.intent.fingerprint
        ):
            raise ValueError("durable cleanup challenge does not match intent")
        if self.schema_version != 1:
            raise ValueError("unsupported durable cleanup confirmation version")

    @property
    def expires_at(self) -> datetime:
        return self.challenge.expires_at


class ControlPlaneDurableCleanupAdministration:
    """Bind trusted cleanup bounds, recent step-up, confirmation, and one bounded pass."""

    def __init__(
        self,
        *,
        coordinator: _DurableCleanupCoordinator,
        protection: ControlPlaneDurableAdministrationProtection,
        clock: ControlPlaneDurableCleanupClock | None = None,
    ) -> None:
        if not isinstance(coordinator, _DurableCleanupCoordinator):
            raise TypeError("durable cleanup administration requires coordinator")
        if not isinstance(protection, ControlPlaneDurableAdministrationProtection):
            raise TypeError("durable cleanup administration requires protection")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("durable cleanup administration clock must be callable")

        self._coordinator = coordinator
        self._protection = protection
        self._clock: ControlPlaneDurableCleanupClock = selected_clock

    async def prepare_confirmation(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        step_up_token: str | None,
    ) -> ControlPlaneDurableCleanupConfirmation:
        """Read current server bounds and issue one exact cleanup confirmation."""

        self._require_authentication(authentication)
        self._require_permission(authentication)
        context = _security_context(authentication)
        requested_at = self._now()
        bounds = self._coordinator.bounds(context)
        intent = ControlPlaneDurableCleanupIntent(
            bounds=_control_plane_bounds(bounds),
            requested_at=requested_at,
        )
        challenge = await self._protection.issue_confirmation(
            authentication,
            intent,
            step_up_token=step_up_token,
        )
        confirmation = ControlPlaneDurableCleanupConfirmation(
            intent=intent,
            challenge=challenge,
        )
        return confirmation

    async def confirm_and_run(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        confirmation: ControlPlaneDurableCleanupConfirmation,
        *,
        step_up_token: str | None,
    ) -> DurableRetentionWorkerReport:
        """Consume one exact confirmation then request its server-bounded cleanup pass."""

        self._require_authentication(authentication)
        self._require_permission(authentication)
        if not isinstance(confirmation, ControlPlaneDurableCleanupConfirmation):
            raise TypeError("confirmation must be ControlPlaneDurableCleanupConfirmation")

        verification = await self._protection.verify_and_consume(
            authentication,
            confirmation.intent,
            step_up_token=step_up_token,
            confirmation=confirmation.challenge.proof,
        )
        if (
            not isinstance(
                verification,
                ControlPlaneDurableAdministrationConfirmationVerification,
            )
            or verification.intent_id != confirmation.intent.id
            or verification.action != confirmation.intent.action
            or verification.resource != confirmation.intent.resource
            or verification.fingerprint != confirmation.intent.fingerprint
        ):
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            )

        return await self._coordinator.run(
            _security_context(authentication),
            expected_bounds=_agent_bounds(confirmation.intent.bounds),
            requested_at=confirmation.intent.requested_at,
        )

    @staticmethod
    def _require_authentication(
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> None:
        if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
            raise TypeError(
                "durable cleanup administration requires durable session authentication"
            )

    @staticmethod
    def _require_permission(
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> None:
        if CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION not in authentication.principal.permissions:
            raise ControlPlaneCommandPermissionDeniedError(
                "durable administration permission denied"
            )

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception:
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            ) from None
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            )
        return value


def _security_context(
    authentication: ControlPlaneDurableSessionAuthentication,
) -> SecurityContext:
    return SecurityContext(
        principal=authentication.principal.name,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=authentication.principal.permissions,
        attributes={"durable_actor_id": str(authentication.operator_id)},
    )


def _control_plane_bounds(
    bounds: DurableCleanupAdministrationBounds,
) -> ControlPlaneDurableCleanupBounds:
    if not isinstance(bounds, DurableCleanupAdministrationBounds):
        raise TypeError("bounds must be DurableCleanupAdministrationBounds")
    return ControlPlaneDurableCleanupBounds(
        page_size=bounds.page_size,
        max_candidates=bounds.max_candidates,
        pass_timeout_microseconds=bounds.pass_timeout_microseconds,
        payload_retention_microseconds=bounds.payload_retention_microseconds,
        metadata_retention_microseconds=bounds.metadata_retention_microseconds,
        tombstone_retention_microseconds=bounds.tombstone_retention_microseconds,
        schema_version=bounds.schema_version,
    )


def _agent_bounds(
    bounds: ControlPlaneDurableCleanupBounds,
) -> DurableCleanupAdministrationBounds:
    if not isinstance(bounds, ControlPlaneDurableCleanupBounds):
        raise TypeError("bounds must be ControlPlaneDurableCleanupBounds")
    return DurableCleanupAdministrationBounds(
        page_size=bounds.page_size,
        max_candidates=bounds.max_candidates,
        pass_timeout_microseconds=bounds.pass_timeout_microseconds,
        payload_retention_microseconds=bounds.payload_retention_microseconds,
        metadata_retention_microseconds=bounds.metadata_retention_microseconds,
        tombstone_retention_microseconds=bounds.tombstone_retention_microseconds,
        schema_version=bounds.schema_version,
    )
