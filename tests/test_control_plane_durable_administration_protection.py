from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.agent import (
    CheckpointDigest,
    DurableAgentRunId,
    DurableRunVersion,
    ExecutionAttemptId,
    ReconciliationDecision,
    ReconciliationEvidence,
)
from phoenix_os.agent.durable_authorization import (
    AGENT_RECONCILE_ACTION,
    durable_reconciliation_resource,
)
from phoenix_os.control_plane import (
    CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneConfirmationStoreClosedError,
    ControlPlaneDurableAdministrationConfirmationProof,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableReconciliationIntent,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneOperatorRole,
    ControlPlanePrincipal,
    ControlPlaneStepUpAction,
    ControlPlaneStepUpRejectedError,
)

_NOW = datetime(2026, 8, 8, 15, tzinfo=UTC)
_RUN_ID = DurableAgentRunId(UUID("10000000-0000-4000-8000-000000000028"))
_ATTEMPT_ID = ExecutionAttemptId(UUID("20000000-0000-4000-8000-000000000028"))
_SESSION_ID = UUID("30000000-0000-4000-8000-000000000028")
_OPERATOR_ID = UUID("40000000-0000-4000-8000-000000000028")
_INTENT_ID = UUID("50000000-0000-4000-8000-000000000028")
_EVIDENCE_SECRET = "RAW-EVIDENCE-MUST-NOT-LEAK"


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


def _authentication(
    *,
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.MAINTAINER,
    session_id: UUID = _SESSION_ID,
    operator_id: UUID = _OPERATOR_ID,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=session_id,
        operator_id=operator_id,
        principal=ControlPlanePrincipal("alice", role.permissions),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _evidence() -> ReconciliationEvidence:
    return ReconciliationEvidence(
        evidence_type="provider_receipt",
        evidence_digest=CheckpointDigest("a" * 64),
        observed_at=_NOW - timedelta(seconds=10),
        metadata={"receipt": _EVIDENCE_SECRET},
    )


def _intent(
    **overrides: Any,
) -> ControlPlaneDurableReconciliationIntent:
    values: dict[str, Any] = {
        "run_id": _RUN_ID,
        "attempt_id": _ATTEMPT_ID,
        "expected_version": DurableRunVersion(7),
        "decision": ReconciliationDecision.CONFIRM_FAILED,
        "requested_at": _NOW,
        "evidence": _evidence(),
        "id": _INTENT_ID,
    }
    values.update(overrides)
    return ControlPlaneDurableReconciliationIntent(**values)


def _protection(
    step_up: _StepUp,
    *,
    clock: _Clock | None = None,
    capacity: int = 1024,
    ttl: timedelta = timedelta(minutes=2),
) -> ControlPlaneDurableAdministrationProtection:
    return ControlPlaneDurableAdministrationProtection(
        step_up=step_up,
        capacity=capacity,
        ttl=ttl,
        clock=clock or _Clock(),
        nonce_source=lambda size: b"n" * size,
    )


def test_durable_reconcile_permission_is_maintainer_only() -> None:
    assert CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION == AGENT_RECONCILE_ACTION
    assert (
        CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION
        not in ControlPlaneOperatorRole.OPERATOR.permissions
    )
    assert (
        CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION
        in ControlPlaneOperatorRole.MAINTAINER.permissions
    )


def test_reconciliation_intent_binds_exact_safe_mutation_fields() -> None:
    intent = _intent()

    assert intent.action == AGENT_RECONCILE_ACTION
    assert intent.resource == durable_reconciliation_resource(_RUN_ID, _ATTEMPT_ID)
    assert len(intent.fingerprint) == 64
    assert _EVIDENCE_SECRET not in repr(intent)
    assert (
        intent.fingerprint
        != replace(
            intent,
            decision=ReconciliationDecision.FAIL_RUN,
        ).fingerprint
    )
    assert (
        intent.fingerprint
        != replace(
            intent,
            expected_version=DurableRunVersion(8),
        ).fingerprint
    )
    assert (
        intent.fingerprint
        != replace(
            intent,
            evidence=ReconciliationEvidence(
                evidence_type="provider_receipt",
                evidence_digest=CheckpointDigest("b" * 64),
                observed_at=_NOW - timedelta(seconds=10),
                metadata={"receipt": _EVIDENCE_SECRET},
            ),
        ).fingerprint
    )
    assert (
        intent.fingerprint
        != replace(
            intent,
            requested_at=_NOW + timedelta(seconds=1),
        ).fingerprint
    )
    assert (
        intent.fingerprint
        != replace(
            intent,
            evidence=ReconciliationEvidence(
                evidence_type="provider_receipt",
                evidence_digest=CheckpointDigest("a" * 64),
                observed_at=_NOW - timedelta(seconds=10),
                metadata={"receipt": "different-evidence-metadata"},
            ),
        ).fingerprint
    )


def test_confirmation_proof_is_redacted() -> None:
    proof = ControlPlaneDurableAdministrationConfirmationProof("A" * 43)
    assert str(proof) == "<redacted>"
    assert proof.value not in repr(proof)


@pytest.mark.asyncio
async def test_confirmation_requires_recent_step_up_and_consumes_once() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    intent = _intent()

    challenge = await protection.issue_confirmation(
        authentication,
        intent,
        step_up_token="recent-step-up",
    )
    verification = await protection.verify_and_consume(
        authentication,
        intent,
        step_up_token="recent-step-up",
        confirmation=challenge.proof,
    )

    assert challenge.intent_id == intent.id
    assert challenge.action == AGENT_RECONCILE_ACTION
    assert challenge.resource == intent.resource
    assert challenge.fingerprint == intent.fingerprint
    assert verification.intent_id == intent.id
    assert verification.fingerprint == intent.fingerprint
    assert step_up.calls == [
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.RECONCILE_DURABLE_RUN,
        ),
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.RECONCILE_DURABLE_RUN,
        ),
    ]

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.verify_and_consume(
            authentication,
            intent,
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )


@pytest.mark.asyncio
async def test_operator_role_cannot_issue_durable_reconciliation_confirmation() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await protection.issue_confirmation(
            _authentication(role=ControlPlaneOperatorRole.OPERATOR),
            _intent(),
            step_up_token="recent-step-up",
        )

    assert step_up.calls == []


@pytest.mark.asyncio
async def test_invalid_step_up_never_issues_confirmation() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await protection.issue_confirmation(
            _authentication(),
            _intent(),
            step_up_token="invalid-step-up",
        )

    snapshot = await protection.snapshot()
    assert snapshot.entries == 0
    assert snapshot.issued == 0
    assert snapshot.rejected == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    [
        {"id": UUID("50000000-0000-4000-8000-000000000029")},
        {"attempt_id": ExecutionAttemptId(UUID("20000000-0000-4000-8000-000000000029"))},
        {"expected_version": DurableRunVersion(8)},
        {"decision": ReconciliationDecision.FAIL_RUN},
        {"requested_at": _NOW + timedelta(seconds=1)},
        {
            "evidence": ReconciliationEvidence(
                evidence_type="provider_receipt",
                evidence_digest=CheckpointDigest("b" * 64),
                observed_at=_NOW - timedelta(seconds=10),
                metadata={"receipt": _EVIDENCE_SECRET},
            )
        },
        {
            "evidence": ReconciliationEvidence(
                evidence_type="provider_receipt",
                evidence_digest=CheckpointDigest("a" * 64),
                observed_at=_NOW - timedelta(seconds=10),
                metadata={"receipt": "different-evidence-metadata"},
            )
        },
    ],
)
async def test_confirmation_is_bound_to_exact_reconciliation_intent(
    changed: dict[str, object],
) -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    challenge = await protection.issue_confirmation(
        authentication,
        _intent(),
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.verify_and_consume(
            authentication,
            _intent(**changed),
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )


@pytest.mark.asyncio
async def test_confirmation_is_bound_to_exact_session_and_operator() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    challenge = await protection.issue_confirmation(
        _authentication(),
        _intent(),
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.verify_and_consume(
            _authentication(
                session_id=UUID("30000000-0000-4000-8000-000000000029"),
                operator_id=UUID("40000000-0000-4000-8000-000000000029"),
            ),
            _intent(),
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )


@pytest.mark.asyncio
async def test_confirmation_expires_at_exact_ttl_boundary() -> None:
    clock = _Clock()
    step_up = _StepUp()
    protection = _protection(
        step_up,
        clock=clock,
        ttl=timedelta(seconds=30),
    )
    authentication = _authentication()
    challenge = await protection.issue_confirmation(
        authentication,
        _intent(),
        step_up_token="recent-step-up",
    )
    clock.now += timedelta(seconds=30)

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.verify_and_consume(
            authentication,
            _intent(),
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )


@pytest.mark.asyncio
async def test_repeated_nonce_cannot_overwrite_an_active_confirmation() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    intent = _intent()
    challenge = await protection.issue_confirmation(
        authentication,
        intent,
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.issue_confirmation(
            authentication,
            replace(
                intent,
                id=UUID("50000000-0000-4000-8000-000000000029"),
            ),
            step_up_token="recent-step-up",
        )

    verification = await protection.verify_and_consume(
        authentication,
        intent,
        step_up_token="recent-step-up",
        confirmation=challenge.proof,
    )
    assert verification.intent_id == intent.id


@pytest.mark.asyncio
async def test_closed_protection_preserves_lifecycle_error_on_verification() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    intent = _intent()
    challenge = await protection.issue_confirmation(
        authentication,
        intent,
        step_up_token="recent-step-up",
    )
    await protection.close()

    with pytest.raises(ControlPlaneConfirmationStoreClosedError):
        await protection.verify_and_consume(
            authentication,
            intent,
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )


@pytest.mark.asyncio
async def test_snapshot_is_content_free_and_close_clears_proofs() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    intent = _intent()
    challenge = await protection.issue_confirmation(
        authentication,
        intent,
        step_up_token="recent-step-up",
    )
    await protection.verify_and_consume(
        authentication,
        intent,
        step_up_token="recent-step-up",
        confirmation=challenge.proof,
    )

    snapshot = await protection.snapshot()
    assert snapshot.entries == 1
    assert snapshot.active == 0
    assert snapshot.consumed == 1
    assert snapshot.issued == 1
    assert snapshot.verified == 1
    assert challenge.proof.value not in repr(snapshot)

    await protection.close()

    closed = await protection.snapshot()
    assert closed.closed is True
    assert closed.entries == 0
