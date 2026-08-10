"""Human control-plane orchestration for durable reconciliation confirmation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    DurableRunVersion,
    ExecutionAttemptId,
    ReconciliationDecision,
)
from phoenix_os.agent.durable_reconciliation_administration import (
    DurableReconciliationAdministrationPreparation,
    DurableReconciliationAdministrationResult,
)
from phoenix_os.control_plane.durable_administration_protection import (
    ControlPlaneDurableAdministrationConfirmationChallenge,
    ControlPlaneDurableAdministrationConfirmationVerification,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableReconciliationEvidenceBinding,
    ControlPlaneDurableReconciliationIntent,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
    PhoenixControlPlaneError,
)
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION,
)
from phoenix_os.policy import PrincipalType, SecurityContext

type ControlPlaneDurableReconciliationClock = Callable[[], datetime]


@runtime_checkable
class _DurableReconciliationCoordinator(Protocol):
    async def prepare(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationPreparation: ...

    async def apply(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationResult: ...

    async def discard(self, preparation_id: UUID) -> None: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableReconciliationConfirmation:
    """Safe two-phase handle binding one reserved preparation to one confirmation."""

    preparation: DurableReconciliationAdministrationPreparation = field(repr=False)
    intent: ControlPlaneDurableReconciliationIntent
    challenge: ControlPlaneDurableAdministrationConfirmationChallenge = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(
            self.preparation,
            DurableReconciliationAdministrationPreparation,
        ):
            raise TypeError("preparation must be DurableReconciliationAdministrationPreparation")
        if not isinstance(self.intent, ControlPlaneDurableReconciliationIntent):
            raise TypeError("intent must be ControlPlaneDurableReconciliationIntent")
        if not isinstance(
            self.challenge,
            ControlPlaneDurableAdministrationConfirmationChallenge,
        ):
            raise TypeError(
                "challenge must be ControlPlaneDurableAdministrationConfirmationChallenge"
            )
        if not _intent_matches_preparation(self.intent, self.preparation):
            raise ValueError("durable reconciliation intent does not match preparation")
        if (
            self.challenge.intent_id != self.intent.id
            or self.challenge.action != self.intent.action
            or self.challenge.resource != self.intent.resource
            or self.challenge.fingerprint != self.intent.fingerprint
        ):
            raise ValueError("durable reconciliation challenge does not match intent")
        if self.schema_version != 1:
            raise ValueError("unsupported durable reconciliation confirmation version")

    @property
    def expires_at(self) -> datetime:
        """Earliest authority boundary across lease-backed preparation and proof."""

        return min(self.preparation.expires_at, self.challenge.expires_at)


class ControlPlaneDurableReconciliationAdministration:
    """Bind durable preparation, recent step-up, confirmation, and fenced apply."""

    def __init__(
        self,
        *,
        coordinator: _DurableReconciliationCoordinator,
        protection: ControlPlaneDurableAdministrationProtection,
        clock: ControlPlaneDurableReconciliationClock | None = None,
    ) -> None:
        if not isinstance(coordinator, _DurableReconciliationCoordinator):
            raise TypeError("durable reconciliation administration requires coordinator")
        if not isinstance(protection, ControlPlaneDurableAdministrationProtection):
            raise TypeError("durable reconciliation administration requires protection")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("durable reconciliation administration clock must be callable")

        self._coordinator = coordinator
        self._protection = protection
        self._clock: ControlPlaneDurableReconciliationClock = selected_clock

    async def prepare_confirmation(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        *,
        step_up_token: str | None,
    ) -> ControlPlaneDurableReconciliationConfirmation:
        """Reserve trusted reconciliation state then issue one exact confirmation."""

        self._require_authentication(authentication)
        self._require_permission(authentication)
        context = _security_context(authentication)
        preparation = await self._coordinator.prepare(
            run_id,
            attempt_id,
            expected_version,
            decision,
            context,
        )

        try:
            intent = _intent_from_preparation(preparation)
            challenge = await self._protection.issue_confirmation(
                authentication,
                intent,
                step_up_token=step_up_token,
            )
            confirmation = ControlPlaneDurableReconciliationConfirmation(
                preparation=preparation,
                intent=intent,
                challenge=challenge,
            )
            if self._now() >= confirmation.expires_at:
                raise ControlPlaneConfirmationRejectedError(
                    "durable administration confirmation failed"
                )
            return confirmation
        except asyncio.CancelledError:
            await self._discard_without_masking(preparation.id)
            raise
        except PhoenixControlPlaneError:
            await self._discard_without_masking(preparation.id)
            raise
        except Exception:
            await self._discard_without_masking(preparation.id)
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            ) from None

    async def confirm_and_apply(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        confirmation: ControlPlaneDurableReconciliationConfirmation,
        *,
        step_up_token: str | None,
    ) -> DurableReconciliationAdministrationResult:
        """Consume one exact confirmation then apply its reserved fenced preparation."""

        self._require_authentication(authentication)
        self._require_permission(authentication)
        if not isinstance(
            confirmation,
            ControlPlaneDurableReconciliationConfirmation,
        ):
            raise TypeError("confirmation must be ControlPlaneDurableReconciliationConfirmation")

        context = _security_context(authentication)
        try:
            now = self._now()
        except PhoenixControlPlaneError:
            await self._discard_without_masking(confirmation.preparation.id)
            raise
        if now >= confirmation.expires_at:
            await self._discard_without_masking(confirmation.preparation.id)
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            )

        try:
            verification = await self._protection.verify_and_consume(
                authentication,
                confirmation.intent,
                step_up_token=step_up_token,
                confirmation=confirmation.challenge.proof,
            )
        except asyncio.CancelledError:
            await self._discard_without_masking(confirmation.preparation.id)
            raise
        except PhoenixControlPlaneError:
            await self._discard_without_masking(confirmation.preparation.id)
            raise
        except Exception:
            await self._discard_without_masking(confirmation.preparation.id)
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            ) from None

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
            await self._discard_without_masking(confirmation.preparation.id)
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            )

        try:
            return await self._coordinator.apply(
                confirmation.preparation,
                context,
            )
        except BaseException:
            await self._discard_without_masking(confirmation.preparation.id)
            raise

    async def discard_confirmation(
        self,
        confirmation: ControlPlaneDurableReconciliationConfirmation,
    ) -> None:
        """Discard one server-owned unused confirmation reservation."""

        if not isinstance(
            confirmation,
            ControlPlaneDurableReconciliationConfirmation,
        ):
            raise TypeError("confirmation must be ControlPlaneDurableReconciliationConfirmation")
        await self._discard_without_masking(confirmation.preparation.id)

    async def _discard_without_masking(self, preparation_id: UUID) -> None:
        try:
            await _await_drain(self._coordinator.discard(preparation_id))
        except BaseException:
            pass

    @staticmethod
    def _require_authentication(
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> None:
        if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
            raise TypeError(
                "durable reconciliation administration requires durable session authentication"
            )

    @staticmethod
    def _require_permission(
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> None:
        if CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION not in (authentication.principal.permissions):
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


def _intent_from_preparation(
    preparation: DurableReconciliationAdministrationPreparation,
) -> ControlPlaneDurableReconciliationIntent:
    if not isinstance(
        preparation,
        DurableReconciliationAdministrationPreparation,
    ):
        raise TypeError("preparation must be DurableReconciliationAdministrationPreparation")
    return ControlPlaneDurableReconciliationIntent(
        run_id=preparation.run_id,
        attempt_id=preparation.attempt_id,
        expected_version=preparation.expected_version,
        decision=preparation.decision,
        requested_at=preparation.requested_at,
        evidence_binding=_evidence_binding_from_preparation(preparation),
        id=preparation.id,
    )


def _evidence_binding_from_preparation(
    preparation: DurableReconciliationAdministrationPreparation,
) -> ControlPlaneDurableReconciliationEvidenceBinding | None:
    if preparation.evidence_type is None:
        return None
    if preparation.evidence_digest is None or preparation.evidence_observed_at is None:
        raise ValueError("reconciliation preparation evidence projection is incomplete")
    return ControlPlaneDurableReconciliationEvidenceBinding(
        evidence_type=preparation.evidence_type,
        evidence_digest=preparation.evidence_digest,
        evidence_observed_at=preparation.evidence_observed_at,
    )


def _intent_matches_preparation(
    intent: ControlPlaneDurableReconciliationIntent,
    preparation: DurableReconciliationAdministrationPreparation,
) -> bool:
    try:
        binding = _evidence_binding_from_preparation(preparation)
    except (TypeError, ValueError):
        return False
    return (
        intent.id == preparation.id
        and intent.run_id == preparation.run_id
        and intent.attempt_id == preparation.attempt_id
        and intent.expected_version == preparation.expected_version
        and intent.decision is preparation.decision
        and intent.requested_at == preparation.requested_at
        and intent.evidence_binding == binding
    )


async def _await_drain(operation: Awaitable[None]) -> None:
    task = asyncio.ensure_future(operation)
    cancelled = False
    while True:
        try:
            await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            cancelled = True
            if task.done():
                break
    task.result()
    if cancelled:
        raise asyncio.CancelledError()
