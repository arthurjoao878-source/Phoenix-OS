from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AGENT_DURABLE_CLEANUP_ACTION,
    DURABLE_ADMINISTRATION_CLEANUP_RESOURCE,
    CheckpointDigest,
    DurableAgentRunId,
    DurableRunVersion,
    ExecutionAttemptId,
    ReconciliationDecision,
)
from phoenix_os.agent.durable_authorization import (
    AGENT_RECONCILE_ACTION,
    durable_reconciliation_resource,
)
from phoenix_os.control_plane import (
    CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION,
    CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneConfirmationStoreClosedError,
    ControlPlaneDurableAdministrationConfirmationProof,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableCleanupBounds,
    ControlPlaneDurableCleanupIntent,
    ControlPlaneDurableReconciliationEvidenceBinding,
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
_CLEANUP_INTENT_ID = UUID("60000000-0000-4000-8000-000000000028")


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
    permissions: frozenset[str] | None = None,
) -> ControlPlaneDurableSessionAuthentication:
    selected_permissions = role.permissions if permissions is None else permissions
    return ControlPlaneDurableSessionAuthentication(
        session_id=session_id,
        operator_id=operator_id,
        principal=ControlPlanePrincipal("alice", selected_permissions),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _evidence_binding(
    *,
    evidence_type: str = "provider_receipt",
    evidence_digest: CheckpointDigest | None = None,
    evidence_observed_at: datetime | None = None,
) -> ControlPlaneDurableReconciliationEvidenceBinding:
    return ControlPlaneDurableReconciliationEvidenceBinding(
        evidence_type=evidence_type,
        evidence_digest=CheckpointDigest("a" * 64) if evidence_digest is None else evidence_digest,
        evidence_observed_at=(
            _NOW - timedelta(seconds=10) if evidence_observed_at is None else evidence_observed_at
        ),
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
        "evidence_binding": _evidence_binding(),
        "id": _INTENT_ID,
    }
    values.update(overrides)
    return ControlPlaneDurableReconciliationIntent(**values)


def _cleanup_bounds(
    **overrides: Any,
) -> ControlPlaneDurableCleanupBounds:
    values: dict[str, Any] = {
        "page_size": 32,
        "max_candidates": 256,
        "pass_timeout_microseconds": 30_000_000,
        "payload_retention_microseconds": 7 * 86_400_000_000,
        "metadata_retention_microseconds": 30 * 86_400_000_000,
        "tombstone_retention_microseconds": 90 * 86_400_000_000,
    }
    values.update(overrides)
    return ControlPlaneDurableCleanupBounds(**values)


def _cleanup_intent(
    **overrides: Any,
) -> ControlPlaneDurableCleanupIntent:
    values: dict[str, Any] = {
        "bounds": _cleanup_bounds(),
        "requested_at": _NOW,
        "id": _CLEANUP_INTENT_ID,
    }
    values.update(overrides)
    return ControlPlaneDurableCleanupIntent(**values)


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


def test_durable_destructive_permissions_are_maintainer_only() -> None:
    assert CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION == AGENT_DURABLE_CLEANUP_ACTION
    assert CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION == AGENT_RECONCILE_ACTION
    for permission in (
        CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION,
        CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION,
    ):
        assert permission not in ControlPlaneOperatorRole.OPERATOR.permissions
        assert permission in ControlPlaneOperatorRole.MAINTAINER.permissions


def test_cleanup_intent_binds_exact_safe_policy_and_pass_bounds() -> None:
    intent = _cleanup_intent()

    assert intent.action == AGENT_DURABLE_CLEANUP_ACTION
    assert intent.resource == DURABLE_ADMINISTRATION_CLEANUP_RESOURCE
    assert len(intent.fingerprint) == 64
    assert not hasattr(intent, "generation")
    assert not hasattr(intent, "lease")
    assert not hasattr(intent, "payload")

    for changed_bounds in (
        {"page_size": 16},
        {"max_candidates": 128},
        {"pass_timeout_microseconds": 20_000_000},
        {"payload_retention_microseconds": 6 * 86_400_000_000},
        {"metadata_retention_microseconds": 29 * 86_400_000_000},
        {"tombstone_retention_microseconds": 89 * 86_400_000_000},
    ):
        assert (
            intent.fingerprint
            != replace(
                intent,
                bounds=_cleanup_bounds(**changed_bounds),
            ).fingerprint
        )

    assert (
        intent.fingerprint != replace(intent, requested_at=_NOW + timedelta(seconds=1)).fingerprint
    )


def test_cleanup_bounds_match_valid_worker_page_candidate_semantics() -> None:
    bounds = _cleanup_bounds(
        page_size=32,
        max_candidates=16,
    )

    assert bounds.page_size == 32
    assert bounds.max_candidates == 16


def test_reconciliation_intent_binds_exact_safe_mutation_fields() -> None:
    intent = _intent()

    assert intent.action == AGENT_RECONCILE_ACTION
    assert intent.resource == durable_reconciliation_resource(_RUN_ID, _ATTEMPT_ID)
    assert len(intent.fingerprint) == 64
    assert not hasattr(intent, "evidence")
    assert intent.evidence_binding == _evidence_binding()
    assert (
        intent.fingerprint
        != replace(
            intent,
            decision=ReconciliationDecision.CONFIRM_SUCCEEDED,
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
            evidence_binding=_evidence_binding(
                evidence_digest=CheckpointDigest("b" * 64),
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
            evidence_binding=_evidence_binding(
                evidence_type="provider_status",
            ),
        ).fingerprint
    )
    assert (
        intent.fingerprint
        != replace(
            intent,
            evidence_binding=_evidence_binding(
                evidence_observed_at=_NOW - timedelta(seconds=11),
            ),
        ).fingerprint
    )


def test_reconciliation_evidence_binding_is_content_free_and_canonical() -> None:
    binding = _evidence_binding()

    assert binding.evidence_type == "provider_receipt"
    assert binding.evidence_digest == CheckpointDigest("a" * 64)
    assert binding.evidence_observed_at == _NOW - timedelta(seconds=10)
    assert not hasattr(binding, "metadata")

    with pytest.raises(ValueError):
        replace(binding, evidence_type="Provider Receipt")


@pytest.mark.parametrize(
    "decision",
    [
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        ReconciliationDecision.CONFIRM_FAILED,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
    ],
)
def test_confirm_reconciliation_intent_requires_safe_evidence_binding(
    decision: ReconciliationDecision,
) -> None:
    with pytest.raises(ValueError, match="requires evidence binding"):
        _intent(
            decision=decision,
            evidence_binding=None,
        )


@pytest.mark.parametrize(
    "decision",
    [
        ReconciliationDecision.REMAIN_INDETERMINATE,
        ReconciliationDecision.CANCEL_RUN,
        ReconciliationDecision.FAIL_RUN,
    ],
)
def test_non_confirm_reconciliation_intent_rejects_evidence_binding(
    decision: ReconciliationDecision,
) -> None:
    with pytest.raises(ValueError, match="cannot carry evidence binding"):
        _intent(decision=decision)


def test_reconciliation_intent_rejects_evidence_after_requested_at() -> None:
    with pytest.raises(ValueError, match="cannot follow the request"):
        _intent(
            evidence_binding=_evidence_binding(
                evidence_observed_at=_NOW + timedelta(seconds=1),
            )
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
async def test_cleanup_confirmation_requires_recent_step_up_and_consumes_once() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    intent = _cleanup_intent()

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
    assert challenge.action == AGENT_DURABLE_CLEANUP_ACTION
    assert challenge.resource == DURABLE_ADMINISTRATION_CLEANUP_RESOURCE
    assert challenge.fingerprint == intent.fingerprint
    assert verification.intent_id == intent.id
    assert verification.action == AGENT_DURABLE_CLEANUP_ACTION
    assert verification.resource == DURABLE_ADMINISTRATION_CLEANUP_RESOURCE
    assert step_up.calls == [
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.CLEANUP_DURABLE_RUNS,
        ),
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.CLEANUP_DURABLE_RUNS,
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
async def test_cleanup_confirmation_requires_exact_cleanup_permission() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    cleanup_only = _authentication(
        permissions=ControlPlaneOperatorRole.OPERATOR.permissions
        | frozenset({CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION})
    )
    reconciliation_only = _authentication(
        permissions=ControlPlaneOperatorRole.OPERATOR.permissions
        | frozenset({CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION})
    )

    challenge = await protection.issue_confirmation(
        cleanup_only,
        _cleanup_intent(),
        step_up_token="recent-step-up",
    )
    verification = await protection.verify_and_consume(
        cleanup_only,
        _cleanup_intent(),
        step_up_token="recent-step-up",
        confirmation=challenge.proof,
    )
    assert verification.action == AGENT_DURABLE_CLEANUP_ACTION

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await protection.issue_confirmation(
            reconciliation_only,
            _cleanup_intent(),
            step_up_token="recent-step-up",
        )


@pytest.mark.asyncio
async def test_operator_and_wildcard_cannot_issue_cleanup_confirmation() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)

    for authentication in (
        _authentication(role=ControlPlaneOperatorRole.OPERATOR),
        _authentication(
            permissions=ControlPlaneOperatorRole.OPERATOR.permissions | frozenset({"*"})
        ),
    ):
        with pytest.raises(ControlPlaneCommandPermissionDeniedError):
            await protection.issue_confirmation(
                authentication,
                _cleanup_intent(),
                step_up_token="recent-step-up",
            )

    assert step_up.calls == []


@pytest.mark.asyncio
async def test_reconciliation_proof_cannot_be_rebound_to_cleanup_intent() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    reconciliation = _intent()
    challenge = await protection.issue_confirmation(
        authentication,
        reconciliation,
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.verify_and_consume(
            authentication,
            _cleanup_intent(),
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )

    verification = await protection.verify_and_consume(
        authentication,
        reconciliation,
        step_up_token="recent-step-up",
        confirmation=challenge.proof,
    )
    assert verification.intent_id == reconciliation.id


@pytest.mark.asyncio
async def test_cleanup_proof_cannot_be_rebound_to_reconciliation_intent() -> None:
    step_up = _StepUp()
    protection = _protection(step_up)
    authentication = _authentication()
    cleanup = _cleanup_intent()
    challenge = await protection.issue_confirmation(
        authentication,
        cleanup,
        step_up_token="recent-step-up",
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await protection.verify_and_consume(
            authentication,
            _intent(),
            step_up_token="recent-step-up",
            confirmation=challenge.proof,
        )

    verification = await protection.verify_and_consume(
        authentication,
        cleanup,
        step_up_token="recent-step-up",
        confirmation=challenge.proof,
    )
    assert verification.intent_id == cleanup.id


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
        {"decision": ReconciliationDecision.CONFIRM_SUCCEEDED},
        {"requested_at": _NOW + timedelta(seconds=1)},
        {
            "evidence_binding": _evidence_binding(
                evidence_digest=CheckpointDigest("b" * 64),
            )
        },
        {
            "evidence_binding": _evidence_binding(
                evidence_type="provider_status",
            )
        },
        {
            "evidence_binding": _evidence_binding(
                evidence_observed_at=_NOW - timedelta(seconds=11),
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
