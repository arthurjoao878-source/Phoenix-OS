from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    DurableCleanupAdministrationBounds,
    DurableRetentionWorkerReport,
)
from phoenix_os.control_plane import (
    CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableCleanupAdministration,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneOperatorRole,
    ControlPlanePrincipal,
    ControlPlaneStepUpAction,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 10, 1, tzinfo=UTC)
_SESSION_ID = UUID("10000000-0000-4000-8000-000000000029")
_OPERATOR_ID = UUID("20000000-0000-4000-8000-000000000029")

_BOUNDS = DurableCleanupAdministrationBounds(
    page_size=32,
    max_candidates=16,
    pass_timeout_microseconds=30_000_000,
    payload_retention_microseconds=7 * 86_400_000_000,
    metadata_retention_microseconds=30 * 86_400_000_000,
    tombstone_retention_microseconds=90 * 86_400_000_000,
)
_REPORT = DurableRetentionWorkerReport(
    admitted=3,
    payloads_deleted=1,
    tombstoned=1,
    purged=1,
    conflicts=0,
    failed=0,
    pages=2,
    exhausted=True,
    timed_out=False,
    stopped=False,
    started_at=_NOW,
    completed_at=_NOW + timedelta(seconds=1),
)


class _Clock:
    def __init__(self) -> None:
        self.now = _NOW

    def __call__(self) -> datetime:
        return self.now


class _StepUp:
    def __init__(self) -> None:
        self.calls: list[tuple[str | None, UUID, ControlPlaneStepUpAction]] = []

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        self.calls.append((token_value, session.session_id, action))
        if token_value != "recent-step-up":
            raise ControlPlaneStepUpRejectedError("step-up authentication rejected")
        return object()


class _Coordinator:
    def __init__(self) -> None:
        self.closed = False
        self.bounds_value = _BOUNDS
        self.bounds_calls: list[SecurityContext] = []
        self.run_calls: list[
            tuple[SecurityContext, DurableCleanupAdministrationBounds, datetime]
        ] = []

    def bounds(
        self,
        context: SecurityContext,
    ) -> DurableCleanupAdministrationBounds:
        self.bounds_calls.append(context)
        return self.bounds_value

    async def run(
        self,
        context: SecurityContext,
        *,
        expected_bounds: DurableCleanupAdministrationBounds,
        requested_at: datetime,
    ) -> DurableRetentionWorkerReport:
        self.run_calls.append((context, expected_bounds, requested_at))
        return _REPORT


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


def _service() -> tuple[
    _Coordinator,
    _StepUp,
    _Clock,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableCleanupAdministration,
]:
    coordinator = _Coordinator()
    step_up = _StepUp()
    clock = _Clock()
    protection = ControlPlaneDurableAdministrationProtection(
        step_up=step_up,
        clock=clock,
        nonce_source=lambda size: b"n" * size,
    )
    service = ControlPlaneDurableCleanupAdministration(
        coordinator=coordinator,
        protection=protection,
        clock=clock,
    )
    return coordinator, step_up, clock, protection, service


@pytest.mark.asyncio
async def test_prepare_confirmation_derives_server_bounds_and_exact_user_context() -> None:
    coordinator, step_up, clock, _protection, service = _service()
    authentication = _authentication()

    confirmation = await service.prepare_confirmation(
        authentication,
        step_up_token="recent-step-up",
    )

    assert len(coordinator.bounds_calls) == 1
    context = coordinator.bounds_calls[0]
    assert context.principal == "Alice Operator"
    assert context.principal_type is PrincipalType.USER
    assert context.authenticated is True
    assert context.permissions == authentication.principal.permissions
    assert context.attributes == {"durable_actor_id": str(_OPERATOR_ID)}
    assert context.confirmed is False

    bounds = confirmation.intent.bounds
    assert bounds.page_size == _BOUNDS.page_size
    assert bounds.max_candidates == _BOUNDS.max_candidates
    assert bounds.pass_timeout_microseconds == _BOUNDS.pass_timeout_microseconds
    assert bounds.payload_retention_microseconds == _BOUNDS.payload_retention_microseconds
    assert bounds.metadata_retention_microseconds == _BOUNDS.metadata_retention_microseconds
    assert bounds.tombstone_retention_microseconds == _BOUNDS.tombstone_retention_microseconds
    assert confirmation.intent.requested_at == clock.now
    assert confirmation.challenge.intent_id == confirmation.intent.id
    assert confirmation.challenge.action == CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION
    assert confirmation.challenge.fingerprint == confirmation.intent.fingerprint
    assert not hasattr(bounds, "owner_id")
    assert not hasattr(bounds, "generation")
    assert not hasattr(bounds, "payload")
    assert step_up.calls == [
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.CLEANUP_DURABLE_RUNS,
        )
    ]


@pytest.mark.asyncio
async def test_wildcard_permission_does_not_authorize_or_read_cleanup_bounds() -> None:
    coordinator, step_up, _clock, _protection, service = _service()
    authentication = _authentication(permissions=frozenset({"control-plane.read", "*"}))

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await service.prepare_confirmation(
            authentication,
            step_up_token="recent-step-up",
        )

    assert coordinator.bounds_calls == []
    assert coordinator.run_calls == []
    assert step_up.calls == []


@pytest.mark.asyncio
async def test_invalid_step_up_never_runs_cleanup() -> None:
    coordinator, step_up, _clock, _protection, service = _service()

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await service.prepare_confirmation(
            _authentication(),
            step_up_token="invalid-step-up",
        )

    assert len(coordinator.bounds_calls) == 1
    assert coordinator.run_calls == []
    assert len(step_up.calls) == 1


@pytest.mark.asyncio
async def test_confirm_and_run_consumes_proof_and_uses_bound_server_bounds() -> None:
    coordinator, step_up, _clock, _protection, service = _service()
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        step_up_token="recent-step-up",
    )

    result = await service.confirm_and_run(
        authentication,
        confirmation,
        step_up_token="recent-step-up",
    )

    assert result == _REPORT
    assert len(coordinator.run_calls) == 1
    context, expected_bounds, requested_at = coordinator.run_calls[0]
    assert expected_bounds == _BOUNDS
    assert requested_at == confirmation.intent.requested_at
    assert context.principal_type is PrincipalType.USER
    assert context.permissions == authentication.principal.permissions
    assert context.attributes == {"durable_actor_id": str(_OPERATOR_ID)}
    assert context.confirmed is False
    assert len(step_up.calls) == 2


@pytest.mark.asyncio
async def test_confirmation_replay_is_rejected_and_never_reruns_cleanup() -> None:
    coordinator, _step_up, _clock, _protection, service = _service()
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        step_up_token="recent-step-up",
    )
    await service.confirm_and_run(
        authentication,
        confirmation,
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await service.confirm_and_run(
            authentication,
            confirmation,
            step_up_token="recent-step-up",
        )

    assert len(coordinator.run_calls) == 1


@pytest.mark.asyncio
async def test_confirmation_is_bound_to_exact_session_and_operator() -> None:
    coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await service.confirm_and_run(
            _authentication(
                session_id=UUID("30000000-0000-4000-8000-000000000029"),
                operator_id=UUID("40000000-0000-4000-8000-000000000029"),
            ),
            confirmation,
            step_up_token="recent-step-up",
        )

    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_expired_confirmation_is_rejected_before_proof_consumption() -> None:
    coordinator, _step_up, clock, protection, service = _service()
    authentication = _authentication()
    confirmation = await service.prepare_confirmation(
        authentication,
        step_up_token="recent-step-up",
    )
    before = await protection.snapshot()
    assert before.active == 1

    clock.now = confirmation.expires_at

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await service.confirm_and_run(
            authentication,
            confirmation,
            step_up_token="recent-step-up",
        )

    after = await protection.snapshot()
    assert after.active == 1
    assert after.consumed == 0
    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_confirmation_handle_rejects_forged_cleanup_bounds_rebinding() -> None:
    _coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        step_up_token="recent-step-up",
    )
    forged_intent = replace(
        confirmation.intent,
        bounds=replace(
            confirmation.intent.bounds,
            max_candidates=confirmation.intent.bounds.max_candidates + 1,
        ),
    )

    with pytest.raises(
        ValueError,
        match="cleanup challenge does not match intent",
    ):
        replace(confirmation, intent=forged_intent)


@pytest.mark.asyncio
async def test_confirmation_repr_redacts_proof_and_exposes_only_safe_bounds() -> None:
    _coordinator, _step_up, _clock, _protection, service = _service()
    confirmation = await service.prepare_confirmation(
        _authentication(),
        step_up_token="recent-step-up",
    )

    rendered = repr(confirmation)
    assert confirmation.challenge.proof.value not in rendered
    assert "proof" not in rendered.lower()
    assert "owner_id" not in rendered
    assert "generation" not in rendered
    assert "payload_ref" not in rendered
