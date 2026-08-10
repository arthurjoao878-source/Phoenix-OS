from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from uuid import UUID

import pytest

from phoenix_os.agent import (
    DurableCleanupAdministrationBounds,
    DurableRetentionWorkerReport,
)
from phoenix_os.control_plane import (
    CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION,
    ControlPlaneDurableAdministrationProtection,
    ControlPlaneDurableCleanupAdministration,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneOperatorRole,
    ControlPlanePrincipal,
    ControlPlaneStepUpAction,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_cleanup_http import (
    DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH,
    ControlPlaneDurableCleanupHttpAdapter,
)
from phoenix_os.control_plane.errors import ControlPlaneDurableSessionCsrfRejectedError
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 10, 2, tzinfo=UTC)
_ORIGIN = ControlPlaneBrowserOrigin("https://phoenix.example")
_SESSION_ID = UUID("10000000-0000-4000-8000-000000000030")
_OTHER_SESSION_ID = UUID("30000000-0000-4000-8000-000000000030")
_OPERATOR_ID = UUID("20000000-0000-4000-8000-000000000030")

_PREPARE_PATH = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/prepare"

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
        del authentication
        self.calls += 1
        if token_value != "csrf" or supplied_origin != expected_origin:
            raise ControlPlaneDurableSessionCsrfRejectedError("csrf rejected")
        return object()


class _Coordinator:
    def __init__(self) -> None:
        self.closed = False
        self.bounds_calls: list[SecurityContext] = []
        self.run_calls: list[
            tuple[SecurityContext, DurableCleanupAdministrationBounds, datetime]
        ] = []

    def bounds(
        self,
        context: SecurityContext,
    ) -> DurableCleanupAdministrationBounds:
        self.bounds_calls.append(context)
        return _BOUNDS

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
    permissions: frozenset[str] | None = None,
) -> ControlPlaneDurableSessionAuthentication:
    selected = (
        ControlPlaneOperatorRole.MAINTAINER.permissions if permissions is None else permissions
    )
    return ControlPlaneDurableSessionAuthentication(
        session_id=session_id,
        operator_id=_OPERATOR_ID,
        principal=ControlPlanePrincipal("Alice Operator", selected),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _adapter(
    *,
    capacity: int = 256,
) -> tuple[
    _Clock,
    _StepUp,
    _Csrf,
    _Coordinator,
    ControlPlaneDurableCleanupHttpAdapter,
]:
    clock = _Clock()
    step_up = _StepUp()
    csrf = _Csrf()
    coordinator = _Coordinator()
    protection = ControlPlaneDurableAdministrationProtection(
        step_up=step_up,
        clock=clock,
        nonce_source=lambda size: b"n" * size,
    )
    administration = ControlPlaneDurableCleanupAdministration(
        coordinator=coordinator,
        protection=protection,
        clock=clock,
    )
    adapter = ControlPlaneDurableCleanupHttpAdapter(
        administration=administration,
        boundary=csrf,
        capacity=capacity,
        clock=clock,
    )
    return clock, step_up, csrf, coordinator, adapter


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


async def _prepare(
    adapter: ControlPlaneDurableCleanupHttpAdapter,
    *,
    authentication: ControlPlaneDurableSessionAuthentication | None = None,
) -> tuple[str, str, Mapping[str, object]]:
    status, payload, headers = await adapter.dispatch(
        authentication=_authentication() if authentication is None else authentication,
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=b"{}",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.CREATED
    assert headers["Cache-Control"] == "no-store"
    assert isinstance(payload, dict)
    confirmation = payload["confirmation"]
    assert isinstance(confirmation, dict)
    confirmation_id = confirmation["id"]
    proof = confirmation["proof"]
    assert isinstance(confirmation_id, str)
    assert isinstance(proof, str)
    return confirmation_id, proof, payload


@pytest.mark.asyncio
async def test_prepare_returns_only_safe_server_bounds_and_confirmation_proof() -> None:
    _clock, step_up, csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, payload = await _prepare(adapter)

    parsed_id = UUID(confirmation_id)
    assert str(parsed_id) == confirmation_id
    assert len(proof) == 43
    assert len(coordinator.bounds_calls) == 1
    context = coordinator.bounds_calls[0]
    assert context.principal_type is PrincipalType.USER
    assert context.authenticated is True
    assert context.attributes == {"durable_actor_id": str(_OPERATOR_ID)}
    assert context.confirmed is False
    assert csrf.calls == 1
    assert step_up.calls == [
        (
            "recent-step-up",
            _SESSION_ID,
            ControlPlaneStepUpAction.CLEANUP_DURABLE_RUNS,
        )
    ]

    cleanup = payload["cleanup"]
    assert isinstance(cleanup, dict)
    bounds = cleanup["bounds"]
    assert isinstance(bounds, dict)
    assert bounds == {
        "page_size": _BOUNDS.page_size,
        "max_candidates": _BOUNDS.max_candidates,
        "pass_timeout_microseconds": _BOUNDS.pass_timeout_microseconds,
        "payload_retention_microseconds": _BOUNDS.payload_retention_microseconds,
        "metadata_retention_microseconds": _BOUNDS.metadata_retention_microseconds,
        "tombstone_retention_microseconds": _BOUNDS.tombstone_retention_microseconds,
        "schema_version": 1,
    }

    serialized = json.dumps(payload, sort_keys=True)
    for forbidden in (
        "owner_id",
        "generation",
        "candidate_ids",
        "payload_ref",
        "storage",
        "retention_policy",
        "confirmed",
    ):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_prepare_rejects_all_client_cleanup_authority_fields_before_bounds_read() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()

    forbidden_documents: tuple[Mapping[str, object], ...] = (
        {"page_size": 1},
        {"max_candidates": 1},
        {"retention_policy": {}},
        {"candidate_ids": []},
        {"generation": 7},
        {"owner_id": "client"},
        {"confirmed": True},
    )
    for document in forbidden_documents:
        status, payload, headers = await adapter.dispatch(
            authentication=_authentication(),
            method="POST",
            path=_PREPARE_PATH,
            query={},
            headers=_headers(),
            body=json.dumps(document).encode(),
            server_origin=_ORIGIN,
        )
        assert status is HTTPStatus.BAD_REQUEST
        assert payload == {"error": "invalid_cleanup_request"}
        assert headers["Cache-Control"] == "no-store"

    assert coordinator.bounds_calls == []
    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_prepare_requires_exact_origin_csrf_and_recent_step_up() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()

    for headers in (
        _headers(origin="https://evil.example"),
        _headers(csrf="wrong"),
        _headers(step_up="wrong"),
    ):
        status, payload, response_headers = await adapter.dispatch(
            authentication=_authentication(),
            method="POST",
            path=_PREPARE_PATH,
            query={},
            headers=headers,
            body=b"{}",
            server_origin=_ORIGIN,
        )
        assert status is HTTPStatus.FORBIDDEN
        assert payload == {"error": "request_rejected"}
        assert response_headers["Cache-Control"] == "no-store"

    assert len(coordinator.bounds_calls) == 1
    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_wildcard_permission_cannot_reach_cleanup_bounds() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()
    authentication = _authentication(permissions=frozenset({"control-plane.read", "*"}))

    status, payload, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=b"{}",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert coordinator.bounds_calls == []
    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_wrong_confirmation_proof_does_not_invalidate_pending_cleanup() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"

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
    assert coordinator.run_calls == []

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
    assert len(coordinator.run_calls) == 1
    assert payload["schema_version"] == 1


@pytest.mark.asyncio
async def test_wrong_session_does_not_invalidate_pending_cleanup() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    body = json.dumps({"proof": proof}).encode()

    status, _payload, _ = await adapter.dispatch(
        authentication=_authentication(session_id=_OTHER_SESSION_ID),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=body,
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.FORBIDDEN
    assert coordinator.run_calls == []

    status, _payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=body,
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert len(coordinator.run_calls) == 1


@pytest.mark.asyncio
async def test_confirmation_is_one_time_at_http_boundary() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
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
    assert len(coordinator.run_calls) == 1


@pytest.mark.asyncio
async def test_confirm_returns_only_safe_cleanup_report_counters() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, _payload = await _prepare(adapter)
    path = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": proof}).encode(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert headers["Cache-Control"] == "no-store"
    assert payload == {
        "schema_version": 1,
        "cleanup": {
            "admitted": 3,
            "payloads_deleted": 1,
            "tombstoned": 1,
            "purged": 1,
            "conflicts": 0,
            "failed": 0,
            "pages": 2,
            "exhausted": True,
            "timed_out": False,
            "stopped": False,
        },
    }
    serialized = json.dumps(payload, sort_keys=True)
    assert "started_at" not in serialized
    assert "completed_at" not in serialized
    assert "owner_id" not in serialized
    assert "generation" not in serialized
    assert len(coordinator.run_calls) == 1


@pytest.mark.asyncio
async def test_expired_pending_cleanup_confirmation_is_not_runnable() -> None:
    clock, _step_up, _csrf, coordinator, adapter = _adapter()
    confirmation_id, proof, payload = await _prepare(adapter)
    confirmation = payload["confirmation"]
    assert isinstance(confirmation, dict)
    expires_at = confirmation["expires_at"]
    assert isinstance(expires_at, str)
    clock.now = datetime.fromisoformat(expires_at)

    path = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    status, response, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=path,
        query={},
        headers=_headers(),
        body=json.dumps({"proof": proof}).encode(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.NOT_FOUND
    assert response == {"error": "confirmation_not_found"}
    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_close_forgets_pending_and_rejects_new_cleanup_admission() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()
    await _prepare(adapter)

    await adapter.close()

    assert adapter.closed
    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=b"{}",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.SERVICE_UNAVAILABLE
    assert payload == {"error": "cleanup_unavailable"}
    assert headers["Cache-Control"] == "no-store"
    assert len(coordinator.bounds_calls) == 1
    assert coordinator.run_calls == []


@pytest.mark.asyncio
async def test_pending_cleanup_capacity_is_bounded_before_second_bounds_read() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter(capacity=1)
    await _prepare(adapter)

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=b"{}",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.TOO_MANY_REQUESTS
    assert payload == {"error": "cleanup_capacity_exhausted"}
    assert headers["Retry-After"] == "1"
    assert headers["Cache-Control"] == "no-store"
    assert len(coordinator.bounds_calls) == 1


@pytest.mark.asyncio
async def test_cleanup_http_rejects_get_query_and_nonempty_prepare_contract() -> None:
    _clock, _step_up, _csrf, coordinator, adapter = _adapter()

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="GET",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=b"",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.METHOD_NOT_ALLOWED
    assert payload == {"error": "method_not_allowed"}
    assert headers["Allow"] == "POST"

    status, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=_PREPARE_PATH,
        query={"candidate": ("1",)},
        headers=_headers(),
        body=b"{}",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_request"}

    status, payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=_PREPARE_PATH,
        query={},
        headers=_headers(),
        body=json.dumps({"permission": CONTROL_PLANE_DURABLE_CLEANUP_PERMISSION}).encode(),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_cleanup_request"}
    assert coordinator.bounds_calls == []


def test_cleanup_http_route_matching_is_exact_and_has_no_list_route() -> None:
    confirmation_id = UUID("50000000-0000-4000-8000-000000000030")

    assert ControlPlaneDurableCleanupHttpAdapter.handles(_PREPARE_PATH)
    assert ControlPlaneDurableCleanupHttpAdapter.handles(
        f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm"
    )
    assert not ControlPlaneDurableCleanupHttpAdapter.handles(
        DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH
    )
    assert not ControlPlaneDurableCleanupHttpAdapter.handles(
        f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations"
    )
    assert not ControlPlaneDurableCleanupHttpAdapter.handles(
        f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/{confirmation_id}/confirm/extra"
    )
