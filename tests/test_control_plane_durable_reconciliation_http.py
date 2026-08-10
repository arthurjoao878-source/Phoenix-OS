from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
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
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableReconciliationAdministration,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneOperatorRole,
    ControlPlanePrincipal,
    ControlPlaneStepUpAction,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_reconciliation_http import (
    DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH,
    ControlPlaneDurableReconciliationHttpAdapter,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
)
from phoenix_os.policy import SecurityContext

_NOW = datetime(2026, 8, 10, 3, 0, tzinfo=UTC)
_RUN_ID = DurableAgentRunId(UUID("10000000-0000-4000-8000-000000000028"))
_ATTEMPT_ID = ExecutionAttemptId(UUID("20000000-0000-4000-8000-000000000028"))
_PREPARATION_ID = UUID("30000000-0000-4000-8000-000000000028")
_CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-4000-8000-000000000028"))
_SESSION_ID = UUID("50000000-0000-4000-8000-000000000028")
_OPERATOR_ID = UUID("60000000-0000-4000-8000-000000000028")
_OTHER_SESSION_ID = UUID("70000000-0000-4000-8000-000000000028")
_ORIGIN = ControlPlaneBrowserOrigin("https://phoenix.example")
_PREPARE_PATH = f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/prepare"


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


class _Clock:
    def __init__(self) -> None:
        self.now = _NOW

    def __call__(self) -> datetime:
        return self.now


class _StepUp:
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        assert session.operator_id == _OPERATOR_ID
        assert action is ControlPlaneStepUpAction.RECONCILE_DURABLE_RUN
        if token_value != "recent-step-up":
            raise ControlPlaneStepUpRejectedError("step-up authentication rejected")
        return object()


class _Csrf:
    def __init__(self) -> None:
        self.calls = 0

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object:
        self.calls += 1
        assert authentication.operator_id == _OPERATOR_ID
        if token_value != "csrf" or supplied_origin != _ORIGIN or expected_origin != _ORIGIN:
            raise ControlPlaneDurableSessionCsrfRejectedError(
                "durable reconciliation request rejected"
            )
        return object()


def _authentication(
    *,
    session_id: UUID = _SESSION_ID,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=session_id,
        operator_id=_OPERATOR_ID,
        principal=ControlPlanePrincipal(
            "Alice Operator",
            ControlPlaneOperatorRole.MAINTAINER.permissions,
        ),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _preparation(
    decision: ReconciliationDecision,
) -> DurableReconciliationAdministrationPreparation:
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
        id=_PREPARATION_ID,
    )


def _result(
    preparation: DurableReconciliationAdministrationPreparation,
) -> DurableReconciliationAdministrationResult:
    return DurableReconciliationAdministrationResult(
        run_id=preparation.run_id,
        attempt_id=preparation.attempt_id,
        status=DurableRunStatus.FAILED,
        run_version=DurableRunVersion(8),
        checkpoint_id=CheckpointId(UUID("80000000-0000-4000-8000-000000000028")),
        checkpoint_sequence=CheckpointSequence(2),
        fencing_generation=FencingGeneration(9),
        decision=preparation.decision,
        applied_at=_NOW + timedelta(seconds=3),
        checkpoint_digest=_digest("f"),
    )


class _Coordinator:
    def __init__(self) -> None:
        self.prepare_calls = 0
        self.apply_calls = 0
        self.discard_calls: list[UUID] = []

    async def prepare(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationPreparation:
        assert run_id == _RUN_ID
        assert attempt_id == _ATTEMPT_ID
        assert expected_version == DurableRunVersion(7)
        assert context.attributes["durable_actor_id"] == str(_OPERATOR_ID)
        self.prepare_calls += 1
        return _preparation(decision)

    async def apply(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationResult:
        assert context.attributes["durable_actor_id"] == str(_OPERATOR_ID)
        self.apply_calls += 1
        return _result(preparation)

    async def discard(self, preparation_id: UUID) -> None:
        self.discard_calls.append(preparation_id)


def _adapter(
    *,
    capacity: int = 256,
) -> tuple[
    _Clock,
    _Csrf,
    _Coordinator,
    ControlPlaneDurableReconciliationHttpAdapter,
]:
    clock = _Clock()
    csrf = _Csrf()
    coordinator = _Coordinator()
    protection = ControlPlaneDurableAdministrationProtection(
        step_up=_StepUp(),
        clock=clock,
        nonce_source=lambda size: b"n" * size,
    )
    administration = ControlPlaneDurableReconciliationAdministration(
        coordinator=coordinator,
        protection=protection,
        clock=clock,
    )
    adapter = ControlPlaneDurableReconciliationHttpAdapter(
        administration=administration,
        boundary=csrf,
        capacity=capacity,
        clock=clock,
    )
    return clock, csrf, coordinator, adapter


def _headers(
    *,
    csrf: str = "csrf",
    step_up: str = "recent-step-up",
    origin: str = "https://phoenix.example",
) -> dict[str, tuple[str, ...]]:
    return {
        "origin": (origin,),
        "x-phoenix-csrf": (csrf,),
        "x-phoenix-step-up": (step_up,),
    }


def _prepare_body(
    *,
    extra: Mapping[str, object] | None = None,
) -> bytes:
    document: dict[str, object] = {
        "run_id": str(_RUN_ID),
        "attempt_id": str(_ATTEMPT_ID),
        "expected_version": 7,
        "decision": ReconciliationDecision.CANCEL_RUN.value,
    }
    if extra is not None:
        document.update(extra)
    return json.dumps(document).encode()


async def _prepare(
    adapter: ControlPlaneDurableReconciliationHttpAdapter,
    *,
    authentication: ControlPlaneDurableSessionAuthentication | None = None,
) -> tuple[str, str, Mapping[str, object]]:
    status, payload, _headers_out = await adapter.dispatch(
        authentication=_authentication() if authentication is None else authentication,
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=_prepare_body(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.CREATED
    assert isinstance(payload, dict)
    confirmation = payload["confirmation"]
    assert isinstance(confirmation, dict)
    confirmation_id = confirmation["id"]
    proof = confirmation["proof"]
    assert isinstance(confirmation_id, str)
    assert isinstance(proof, str)
    return confirmation_id, proof, payload


@pytest.mark.asyncio
async def test_prepare_returns_only_safe_server_projection_and_proof() -> None:
    _clock, csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, payload = await _prepare(adapter)

    assert confirmation_id == str(_PREPARATION_ID)
    assert len(proof) == 43
    assert coordinator.prepare_calls == 1
    assert csrf.calls == 1
    serialized = json.dumps(payload, sort_keys=True)
    assert "fencing_generation" not in serialized
    assert "lookup_result" not in serialized
    assert '"generation"' not in serialized
    assert "provider_receipt" not in serialized
    assert payload["schema_version"] == 1


@pytest.mark.asyncio
async def test_prepare_rejects_client_authority_fields_before_administration() -> None:
    _clock, _csrf, coordinator, adapter = _adapter()

    forbidden_cases: tuple[Mapping[str, object], ...] = (
        {"generation": 99},
        {"fencing_generation": 99},
        {"lookup_result": {}},
        {"evidence": {"metadata": {"unsafe": "value"}}},
        {"confirmed": True},
    )
    for forbidden in forbidden_cases:
        status, payload, _ = await adapter.dispatch(
            authentication=_authentication(),
            method="POST",
            path=_PREPARE_PATH,
            query={},
            headers=_headers(),
            body=_prepare_body(extra=forbidden),
            server_origin=_ORIGIN,
        )
        assert status is HTTPStatus.BAD_REQUEST
        assert payload == {"error": "invalid_reconciliation_request"}

    assert coordinator.prepare_calls == 0


@pytest.mark.asyncio
async def test_prepare_requires_exact_origin_csrf_and_step_up() -> None:
    _clock, _csrf, coordinator, adapter = _adapter()

    for headers in (
        _headers(origin="https://evil.example"),
        _headers(csrf="wrong"),
        _headers(step_up="wrong"),
    ):
        status, payload, _ = await adapter.dispatch(
            authentication=_authentication(),
            method="POST",
            path=_PREPARE_PATH,
            query={},
            headers=headers,
            body=_prepare_body(),
            server_origin=_ORIGIN,
        )
        assert status is HTTPStatus.FORBIDDEN
        assert payload == {"error": "request_rejected"}

    assert coordinator.prepare_calls == 1
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_wrong_confirmation_proof_does_not_invalidate_reservation() -> None:
    _clock, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = (
        f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    )

    status, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": "A" * 43}).encode(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert coordinator.apply_calls == 0
    assert coordinator.discard_calls == []

    status, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": proof}).encode(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert coordinator.apply_calls == 1
    serialized = json.dumps(payload, sort_keys=True)
    assert "fencing_generation" not in serialized
    assert '"generation"' not in serialized


@pytest.mark.asyncio
async def test_wrong_session_does_not_invalidate_reservation() -> None:
    _clock, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = (
        f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    )

    status, _payload, _ = await adapter.dispatch(
        authentication=_authentication(session_id=_OTHER_SESSION_ID),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": proof}).encode(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.FORBIDDEN
    assert coordinator.apply_calls == 0
    assert coordinator.discard_calls == []

    status, _payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": proof}).encode(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert coordinator.apply_calls == 1


@pytest.mark.asyncio
async def test_confirmation_is_one_time_at_http_boundary() -> None:
    _clock, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = (
        f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    )
    body = json.dumps({"proof": proof}).encode()

    first, _payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=body,
        server_origin=_ORIGIN,
    )
    second, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=body,
        server_origin=_ORIGIN,
    )

    assert first is HTTPStatus.OK
    assert second is HTTPStatus.NOT_FOUND
    assert payload == {"error": "confirmation_not_found"}
    assert coordinator.apply_calls == 1


@pytest.mark.asyncio
async def test_expired_pending_confirmation_is_discarded_before_apply() -> None:
    clock, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, payload = await _prepare(adapter)
    preparation = payload["preparation"]
    assert isinstance(preparation, dict)
    expires_at = preparation["expires_at"]
    assert isinstance(expires_at, str)
    clock.now = datetime.fromisoformat(expires_at)

    path = (
        f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    )
    status, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": proof}).encode(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.NOT_FOUND
    assert payload == {"error": "confirmation_not_found"}
    assert coordinator.apply_calls == 0
    assert coordinator.discard_calls == [_PREPARATION_ID]


@pytest.mark.asyncio
async def test_close_discards_pending_and_rejects_new_admission() -> None:
    _clock, _csrf, coordinator, adapter = _adapter()
    await _prepare(adapter)

    await adapter.close()

    assert adapter.closed
    assert coordinator.discard_calls == [_PREPARATION_ID]

    status, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=_prepare_body(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.SERVICE_UNAVAILABLE
    assert payload == {"error": "reconciliation_unavailable"}
    assert coordinator.prepare_calls == 1


@pytest.mark.asyncio
async def test_pending_capacity_is_bounded_before_second_reservation() -> None:
    _clock, _csrf, coordinator, adapter = _adapter(capacity=1)
    await _prepare(adapter)

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=_prepare_body(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.TOO_MANY_REQUESTS
    assert payload == {"error": "reconciliation_capacity_exhausted"}
    assert headers["Retry-After"] == "1"
    assert coordinator.prepare_calls == 1


def test_route_matching_is_exact() -> None:
    assert ControlPlaneDurableReconciliationHttpAdapter.handles(_PREPARE_PATH)
    assert ControlPlaneDurableReconciliationHttpAdapter.handles(
        f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/confirmations/{_PREPARATION_ID}/confirm"
    )
    assert not ControlPlaneDurableReconciliationHttpAdapter.handles(
        DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH
    )
    assert not ControlPlaneDurableReconciliationHttpAdapter.handles(
        f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/"
        f"confirmations/{_PREPARATION_ID}/confirm/extra"
    )
