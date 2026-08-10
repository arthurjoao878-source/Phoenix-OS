from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    CheckpointDigest,
    CheckpointId,
    CheckpointSequence,
    DurableAgentRunId,
    DurableReconciliationAdministrationPreparation,
    DurableReconciliationAdministrationResult,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptId,
    FencingGeneration,
    ReconciliationDecision,
)
from phoenix_os.control_plane import (
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableReconciliationAdministration,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneOperatorRole,
    ControlPlanePrincipal,
    ControlPlaneStepUpAction,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 9, 1, tzinfo=UTC)
_RUN_ID = DurableAgentRunId(UUID("10000000-0000-4000-8000-000000000028"))
_ATTEMPT_ID = ExecutionAttemptId(UUID("20000000-0000-4000-8000-000000000028"))
_CHECKPOINT_ID = CheckpointId(UUID("30000000-0000-4000-8000-000000000028"))
_PREPARATION_ID = UUID("40000000-0000-4000-8000-000000000028")
_SESSION_ID = UUID("50000000-0000-4000-8000-000000000028")
_OPERATOR_ID = UUID("60000000-0000-4000-8000-000000000028")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


class _Clock:
    def __init__(self) -> None:
        self.now = _NOW + timedelta(seconds=2)

    def __call__(self) -> datetime:
        return self.now


class _StepUp:
    def __init__(self, *, block_call: int | None = None) -> None:
        self.calls: list[tuple[str | None, UUID, ControlPlaneStepUpAction]] = []
        self.block_call = block_call
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        self.calls.append((token_value, session.session_id, action))
        if token_value != "recent-step-up":
            raise ControlPlaneStepUpRejectedError("step-up authentication rejected")
        if self.block_call == len(self.calls):
            self.started.set()
            await self.release.wait()
        return object()


def _authentication(
    *,
    session_id: UUID = _SESSION_ID,
    operator_id: UUID = _OPERATOR_ID,
    permissions: frozenset[str] | None = None,
) -> ControlPlaneDurableSessionAuthentication:
    selected = (
        ControlPlaneOperatorRole.MAINTAINER.permissions if permissions is None else permissions
    )
    return ControlPlaneDurableSessionAuthentication(
        session_id=session_id,
        operator_id=operator_id,
        principal=ControlPlanePrincipal("Alice Operator", selected),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _preparation(
    decision: ReconciliationDecision,
    *,
    preparation_id: UUID = _PREPARATION_ID,
) -> DurableReconciliationAdministrationPreparation:
    if decision in {
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        ReconciliationDecision.CONFIRM_FAILED,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
    }:
        return DurableReconciliationAdministrationPreparation(
            run_id=_RUN_ID,
            attempt_id=_ATTEMPT_ID,
            expected_version=DurableRunVersion(7),
            checkpoint_id=_CHECKPOINT_ID,
            checkpoint_digest=_digest("c"),
            decision=decision,
            requested_at=_NOW,
            prepared_at=_NOW + timedelta(seconds=1),
            expires_at=_NOW + timedelta(seconds=90),
            evidence_type="provider_receipt",
            evidence_digest=_digest("e"),
            evidence_observed_at=_NOW,
            id=preparation_id,
        )
    return DurableReconciliationAdministrationPreparation(
        run_id=_RUN_ID,
        attempt_id=_ATTEMPT_ID,
        expected_version=DurableRunVersion(7),
        checkpoint_id=_CHECKPOINT_ID,
        checkpoint_digest=_digest("c"),
        decision=decision,
        requested_at=_NOW,
        prepared_at=_NOW + timedelta(seconds=1),
        expires_at=_NOW + timedelta(seconds=90),
        id=preparation_id,
    )


def _result(
    preparation: DurableReconciliationAdministrationPreparation,
) -> DurableReconciliationAdministrationResult:
    return DurableReconciliationAdministrationResult(
        run_id=preparation.run_id,
        attempt_id=preparation.attempt_id,
        status=DurableRunStatus.FAILED,
        run_version=DurableRunVersion(8),
        checkpoint_id=CheckpointId(UUID("70000000-0000-4000-8000-000000000028")),
        checkpoint_sequence=CheckpointSequence(2),
        fencing_generation=FencingGeneration(9),
        decision=preparation.decision,
        applied_at=_NOW + timedelta(seconds=3),
        checkpoint_digest=_digest("f"),
    )


class _Coordinator:
    def __init__(self) -> None:
        self.prepare_calls: list[
            tuple[
                DurableAgentRunId,
                ExecutionAttemptId,
                DurableRunVersion,
                ReconciliationDecision,
                SecurityContext,
            ]
        ] = []
        self.apply_calls: list[
            tuple[
                DurableReconciliationAdministrationPreparation,
                SecurityContext,
            ]
        ] = []
        self.discard_calls: list[UUID] = []
        self.apply_error: BaseException | None = None

    async def prepare(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationPreparation:
        self.prepare_calls.append(
            (
                run_id,
                attempt_id,
                expected_version,
                decision,
                context,
            )
        )
        return _preparation(decision)

    async def apply(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationResult:
        self.apply_calls.append((preparation, context))
        if self.apply_error is not None:
            raise self.apply_error
        return _result(preparation)

    async def discard(self, preparation_id: UUID) -> None:
        self.discard_calls.append(preparation_id)


def _service(
    *,
    step_up: _StepUp | None = None,
    clock: _Clock | None = None,
) -> tuple[
    _Coordinator,
    _StepUp,
    _Clock,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableReconciliationAdministration,
]:
    coordinator = _Coordinator()
    selected_step_up = _StepUp() if step_up is None else step_up
    selected_clock = _Clock() if clock is None else clock
    protection = ControlPlaneDurableAdministrationProtection(
        step_up=selected_step_up,
        clock=selected_clock,
        nonce_source=lambda size: b"n" * size,
    )
    service = ControlPlaneDurableReconciliationAdministration(
        coordinator=coordinator,
        protection=protection,
        clock=selected_clock,
    )
    return coordinator, selected_step_up, selected_clock, protection, service


@pytest.mark.asyncio
async def test_prepare_confirmation_binds_safe_evidence_and_exact_user_context() -> None:
    coordinator, step_up, _clock, _protection, service = _service()
    authentication = _authentication()

    confirmation = await service.prepare_confirmation(
        authentication,
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CONFIRM_FAILED,
        step_up_token="recent-step-up",
    )

    assert len(coordinator.prepare_calls) == 1
    call = coordinator.prepare_calls[0]
    assert call[:4] == (
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CONFIRM_FAILED,
    )
    context = call[4]
    assert context.principal == "Alice Operator"
    assert context.principal_type is PrincipalType.USER
    assert context.authenticated is True
    assert context.permissions == authentication.principal.permissions
    assert context.attributes == {"durable_actor_id": str(authentication.operator_id)}
    assert context.confirmed is False

    preparation = confirmation.preparation
    binding = confirmation.intent.evidence_binding
    assert confirmation.intent.run_id == preparation.run_id
    assert confirmation.intent.attempt_id == preparation.attempt_id
    assert confirmation.intent.expected_version == preparation.expected_version
    assert confirmation.intent.decision is preparation.decision
    assert confirmation.intent.requested_at == preparation.requested_at
    assert confirmation.intent.id == preparation.id
    assert binding is not None
    assert binding.evidence_type == preparation.evidence_type
    assert binding.evidence_digest == preparation.evidence_digest
    assert binding.evidence_observed_at == preparation.evidence_observed_at
    assert confirmation.challenge.intent_id == confirmation.intent.id
    assert confirmation.challenge.fingerprint == confirmation.intent.fingerprint
    assert confirmation.expires_at == preparation.expires_at
    assert step_up.calls == [
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.RECONCILE_DURABLE_RUN,
        )
    ]


@pytest.mark.asyncio
async def test_non_confirm_preparation_carries_no_evidence_binding() -> None:
    _coordinator, _step_up, _clock, _protection, service = _service()

    confirmation = await service.prepare_confirmation(
        _authentication(),
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )

    assert confirmation.intent.evidence_binding is None
    assert confirmation.preparation.evidence_type is None
    assert confirmation.preparation.evidence_digest is None
    assert confirmation.preparation.evidence_observed_at is None


@pytest.mark.asyncio
async def test_wildcard_permission_does_not_authorize_or_touch_coordinator() -> None:
    coordinator, step_up, _clock, _protection, service = _service()
    authentication = _authentication(permissions=frozenset({"control-plane.read", "*"}))

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await service.prepare_confirmation(
            authentication,
            _RUN_ID,
            _ATTEMPT_ID,
            DurableRunVersion(7),
            ReconciliationDecision.CANCEL_RUN,
            step_up_token="recent-step-up",
        )

    assert coordinator.prepare_calls == []
    assert step_up.calls == []


@pytest.mark.asyncio
async def test_invalid_step_up_discards_reserved_preparation() -> None:
    coordinator, _step_up, _clock, _protection, service = _service()

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await service.prepare_confirmation(
            _authentication(),
            _RUN_ID,
            _ATTEMPT_ID,
            DurableRunVersion(7),
            ReconciliationDecision.CANCEL_RUN,
            step_up_token="invalid-step-up",
        )

    assert coordinator.discard_calls == [_PREPARATION_ID]
    assert coordinator.apply_calls == []


@pytest.mark.asyncio
async def test_cancelled_step_up_discards_before_cancellation_escapes() -> None:
    step_up = _StepUp(block_call=1)
    coordinator, _step_up, _clock, _protection, service = _service(step_up=step_up)

    task = asyncio.create_task(
        service.prepare_confirmation(
            _authentication(),
            _RUN_ID,
            _ATTEMPT_ID,
            DurableRunVersion(7),
            ReconciliationDecision.CANCEL_RUN,
            step_up_token="recent-step-up",
        )
    )
    await step_up.started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert coordinator.discard_calls == [_PREPARATION_ID]
    assert coordinator.apply_calls == []


@pytest.mark.asyncio
async def test_confirm_and_apply_consumes_proof_then_uses_same_operator_context() -> None:
    coordinator, step_up, _clock, _protection, service = _service()
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CONFIRM_FAILED,
        step_up_token="recent-step-up",
    )

    result = await service.confirm_and_apply(
        authentication,
        confirmation,
        step_up_token="recent-step-up",
    )

    assert result == _result(confirmation.preparation)
    assert coordinator.discard_calls == []
    assert len(coordinator.apply_calls) == 1
    applied_preparation, context = coordinator.apply_calls[0]
    assert applied_preparation == confirmation.preparation
    assert context.principal_type is PrincipalType.USER
    assert context.permissions == authentication.principal.permissions
    assert context.attributes["durable_actor_id"] == str(_OPERATOR_ID)
    assert context.confirmed is False
    assert len(step_up.calls) == 2


@pytest.mark.asyncio
async def test_confirmation_replay_is_rejected_and_never_reapplies() -> None:
    coordinator, _step_up, _clock, _protection, service = _service()
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )
    await service.confirm_and_apply(
        authentication,
        confirmation,
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await service.confirm_and_apply(
            authentication,
            confirmation,
            step_up_token="recent-step-up",
        )

    assert len(coordinator.apply_calls) == 1
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_confirmation_is_bound_to_exact_session_and_operator() -> None:
    coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await service.confirm_and_apply(
            _authentication(
                session_id=UUID("50000000-0000-4000-8000-000000000029"),
                operator_id=UUID("60000000-0000-4000-8000-000000000029"),
            ),
            confirmation,
            step_up_token="recent-step-up",
        )

    assert coordinator.apply_calls == []
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_effective_expiry_discards_before_consuming_confirmation_proof() -> None:
    coordinator, _step_up, clock, protection, service = _service()
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )
    before = await protection.snapshot()
    assert before.active == 1

    clock.now = confirmation.preparation.expires_at

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await service.confirm_and_apply(
            authentication,
            confirmation,
            step_up_token="recent-step-up",
        )

    after = await protection.snapshot()
    assert after.active == 1
    assert after.consumed == 0
    assert coordinator.apply_calls == []
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_apply_failure_attempts_discard_without_masking_original_error() -> None:
    coordinator, _step_up, _clock, _protection, service = _service()
    coordinator.apply_error = RuntimeError("apply failed")
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )

    with pytest.raises(RuntimeError, match="apply failed"):
        await service.confirm_and_apply(
            authentication,
            confirmation,
            step_up_token="recent-step-up",
        )

    assert len(coordinator.apply_calls) == 1
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_cancelled_verification_discards_reserved_preparation() -> None:
    step_up = _StepUp(block_call=2)
    coordinator, _step_up, _clock, _protection, service = _service(step_up=step_up)
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )

    task = asyncio.create_task(
        service.confirm_and_apply(
            authentication,
            confirmation,
            step_up_token="recent-step-up",
        )
    )
    await step_up.started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert coordinator.apply_calls == []
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_confirmation_handle_rejects_forged_preparation_rebinding() -> None:
    _coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )
    forged = replace(
        confirmation.preparation,
        requested_at=confirmation.preparation.requested_at - timedelta(seconds=1),
    )

    with pytest.raises(
        ValueError,
        match="intent does not match preparation",
    ):
        replace(confirmation, preparation=forged)


@pytest.mark.asyncio
async def test_confirmation_cannot_rebind_to_different_reserved_preparation_id() -> None:
    _coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )
    rebound = replace(
        confirmation.preparation,
        id=UUID("40000000-0000-4000-8000-000000000029"),
    )

    with pytest.raises(
        ValueError,
        match="intent does not match preparation",
    ):
        replace(confirmation, preparation=rebound)


@pytest.mark.asyncio
async def test_confirmation_repr_redacts_proof_and_exposes_no_fencing_generation() -> None:
    _coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        _RUN_ID,
        _ATTEMPT_ID,
        DurableRunVersion(7),
        ReconciliationDecision.CANCEL_RUN,
        step_up_token="recent-step-up",
    )

    rendered = repr(confirmation)
    assert confirmation.challenge.proof.value not in rendered
    assert "proof" not in rendered.lower()
    assert not hasattr(confirmation.preparation, "generation")
    assert not hasattr(confirmation.intent, "generation")
