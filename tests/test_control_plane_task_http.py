from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import cast
from uuid import UUID

import pytest

import phoenix_os.control_plane.http as http_module
import phoenix_os.control_plane.task_http as task_http_module
from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.contracts import ControlPlaneReader
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionHttpBoundary,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneServerStateError,
)
from phoenix_os.control_plane.http import ControlPlaneHttpServer
from phoenix_os.control_plane.task_http import (
    TASK_CONTROL_PLANE_BASE_PATH,
    ControlPlaneTaskHttpAdapter,
)
from phoenix_os.control_plane.task_resume_context_resupply import (
    MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES,
)
from phoenix_os.control_plane.task_runtime_bridge import TaskStatusSummary

_NOW = datetime(2026, 9, 8, 6, 0, tzinfo=UTC)
_SESSION_ID = UUID("10000000-0000-4000-8000-000000000039")
_OPERATOR_ID = UUID("20000000-0000-4000-8000-000000000039")
_RUN_ID = "30000000-0000-4000-8000-000000000039"
_TASK_ID = "40000000-0000-4000-8000-000000000039"
_ORIGIN = ControlPlaneBrowserOrigin("https://phoenix.example")


def _authentication() -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=ControlPlanePrincipal(
            "Alice Operator",
            frozenset({"control-plane.read"}),
        ),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _summary(*, state: str = "running") -> TaskStatusSummary:
    return TaskStatusSummary(
        schema_version=1,
        task_id=_TASK_ID,
        run_id=_RUN_ID,
        profile_name="reviewed",
        provider_id="provider",
        model_id="model",
        run_state=state,
        current_step_category="model" if state == "running" else None,
        model_turns_used=1,
        model_turns_max=8,
        tool_calls_used=0,
        tool_calls_max=8,
        accepted_tool_proposals=None,
        rejected_tool_proposals=None,
        deadline_state="remaining",
        cancellation_state="not_recorded",
        provider_failure_category=None,
        durable_recovery_disposition="resume" if state == "running" else None,
        terminal_category=None,
    )


class _Csrf:
    def __init__(self) -> None:
        self.calls = 0
        self.reject = False

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
        if (
            self.reject
            or token_value != "csrf"
            or supplied_origin != _ORIGIN
            or expected_origin != _ORIGIN
        ):
            raise ControlPlaneDurableSessionCsrfRejectedError("durable task request rejected")
        return object()


class _Administration:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.resume_context: object | None = None

    async def run(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        profile_name: str,
        workspace_name: str,
        task_text: str,
    ) -> TaskStatusSummary:
        assert authentication.operator_id == _OPERATOR_ID
        self.calls.append(("run", (profile_name, workspace_name, task_text)))
        return _summary()

    async def status(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
    ) -> TaskStatusSummary:
        assert authentication.operator_id == _OPERATOR_ID
        self.calls.append(("status", (run_id,)))
        return _summary()

    async def cancel(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
    ) -> TaskStatusSummary:
        assert authentication.operator_id == _OPERATOR_ID
        self.calls.append(("cancel", (run_id,)))
        return _summary(state="cancelled")

    async def resume(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
        context_resupply: object,
    ) -> TaskStatusSummary:
        assert authentication.operator_id == _OPERATOR_ID
        self.resume_context = context_resupply
        self.calls.append(("resume", (run_id,)))
        return _summary()


def _headers() -> dict[str, tuple[str, ...]]:
    return {
        "origin": (str(_ORIGIN),),
        "x-phoenix-csrf": ("csrf",),
    }


def _run_body(*, include_run_id: bool = False) -> bytes:
    document: dict[str, object] = {
        "profile_name": "reviewed",
        "workspace_name": "checkout",
        "task_text": "inspect the workspace",
    }
    if include_run_id:
        document["run_id"] = _RUN_ID
    return json.dumps(document).encode()


def _adapter() -> tuple[_Csrf, _Administration, ControlPlaneTaskHttpAdapter]:
    csrf = _Csrf()
    administration = _Administration()
    return (
        csrf,
        administration,
        ControlPlaneTaskHttpAdapter(
            administration=administration,
            boundary=csrf,
        ),
    )


@pytest.mark.asyncio
async def test_task_http_run_uses_durable_csrf_and_server_owned_ids() -> None:
    csrf, administration, adapter = _adapter()

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=TASK_CONTROL_PLANE_BASE_PATH,
        query={},
        headers=_headers(),
        body=_run_body(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CREATED
    assert payload["task_id"] == _TASK_ID
    assert payload["run_id"] == _RUN_ID
    assert payload["accepted_tool_proposals"] is None
    assert payload["rejected_tool_proposals"] is None
    assert headers == {"Cache-Control": "no-store"}
    assert csrf.calls == 1
    assert administration.calls == [("run", ("reviewed", "checkout", "inspect the workspace"))]

    rejected_status, rejected_payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=TASK_CONTROL_PLANE_BASE_PATH,
        query={},
        headers=_headers(),
        body=_run_body(include_run_id=True),
        server_origin=_ORIGIN,
    )

    assert rejected_status is HTTPStatus.BAD_REQUEST
    assert rejected_payload == {"error": "invalid_task_request"}
    assert len(administration.calls) == 1


@pytest.mark.asyncio
async def test_task_http_status_is_read_only_and_does_not_require_csrf() -> None:
    csrf, administration, adapter = _adapter()

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="GET",
        path=f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["schema_version"] == 1
    assert payload["run_state"] == "running"
    assert headers == {"Cache-Control": "no-store"}
    assert csrf.calls == 0
    assert administration.calls == [("status", (_RUN_ID,))]


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["cancel", "resume"])
async def test_task_http_mutations_require_csrf(
    action: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    csrf, administration, adapter = _adapter()
    marker: object | None = None
    body = b""
    if action == "resume":
        marker = object()
        monkeypatch.setattr(
            task_http_module,
            "decode_task_resume_context_resupply",
            lambda encoded: marker,
        )
        body = b"canonical-resupply"

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}/{action}",
        query={},
        headers=_headers(),
        body=body,
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["run_id"] == _RUN_ID
    assert headers == {"Cache-Control": "no-store"}
    assert csrf.calls == 1
    assert administration.calls == [(action, (_RUN_ID,))]
    if action == "resume":
        assert administration.resume_context is marker


def test_task_http_resume_declares_only_route_specific_body_limit() -> None:
    _csrf, _administration, adapter = _adapter()
    resume_path = f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}/resume"

    assert adapter.body_limit(resume_path) == MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES
    assert adapter.body_limit(TASK_CONTROL_PLANE_BASE_PATH) is None
    assert adapter.body_limit(f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}/cancel") is None


@pytest.mark.asyncio
async def test_task_http_resume_requires_canonical_context_resupply_body() -> None:
    csrf, administration, adapter = _adapter()

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}/resume",
        query={},
        headers=_headers(),
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_task_request"}
    assert headers == {"Cache-Control": "no-store"}
    assert csrf.calls == 1
    assert administration.calls == []


def test_http_server_uses_resume_limit_without_widening_other_task_posts() -> None:
    csrf = _Csrf()
    server = _server(csrf)
    server.bind_task_http(_Administration())
    resume_path = f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}/resume"

    assert MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES > server._config.max_command_body_bytes
    assert server._body_limit("POST", resume_path) == MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES
    assert (
        server._body_limit("POST", TASK_CONTROL_PLANE_BASE_PATH)
        == server._config.max_command_body_bytes
    )


@pytest.mark.asyncio
async def test_task_http_rejects_invalid_csrf_without_calling_administration() -> None:
    csrf, administration, adapter = _adapter()
    csrf.reject = True

    status, payload, headers = await adapter.dispatch(
        authentication=_authentication(),
        method="POST",
        path=f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}/cancel",
        query={},
        headers=_headers(),
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert headers == {"Cache-Control": "no-store"}
    assert administration.calls == []


@pytest.mark.asyncio
async def test_task_http_rejects_wrong_method_query_and_unknown_routes() -> None:
    _csrf, administration, adapter = _adapter()

    method_status, method_payload, method_headers = await adapter.dispatch(
        authentication=_authentication(),
        method="GET",
        path=TASK_CONTROL_PLANE_BASE_PATH,
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert method_status is HTTPStatus.METHOD_NOT_ALLOWED
    assert method_payload == {"error": "method_not_allowed"}
    assert method_headers["Allow"] == "POST"

    query_status, query_payload, _ = await adapter.dispatch(
        authentication=_authentication(),
        method="GET",
        path=f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}",
        query={"x": ("1",)},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert query_status is HTTPStatus.BAD_REQUEST
    assert query_payload == {"error": "invalid_request"}

    assert adapter.handles(TASK_CONTROL_PLANE_BASE_PATH)
    assert adapter.handles(f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}")
    assert not adapter.handles(f"{TASK_CONTROL_PLANE_BASE_PATH}/not-a-run-id")
    assert not adapter.handles("/v1/control-plane/task")
    assert administration.calls == []


def _server(
    csrf: _Csrf,
) -> ControlPlaneHttpServer:
    return ControlPlaneHttpServer(
        cast(ControlPlaneReader, object()),
        None,
        durable_session_http=cast(ControlPlaneDurableSessionHttpBoundary, csrf),
    )


def test_http_server_binds_task_http_exactly_once() -> None:
    csrf = _Csrf()
    server = _server(csrf)
    administration = _Administration()

    adapter = server.bind_task_http(administration)

    assert server.task_http is adapter
    assert adapter.administration is administration
    with pytest.raises(ControlPlaneServerStateError, match="already bound"):
        server.bind_task_http(administration)


@pytest.mark.asyncio
async def test_http_server_routes_task_http_only_with_durable_authentication() -> None:
    csrf = _Csrf()
    server = _server(csrf)
    administration = _Administration()
    server.bind_task_http(administration)
    request = http_module._Request(
        method="POST",
        path=TASK_CONTROL_PLANE_BASE_PATH,
        query={},
        headers=_headers(),
        body=_run_body(),
    )
    authentication = _authentication()

    status, payload, headers = await server._dispatch_authenticated(
        request,
        principal=authentication.principal,
        durable_authentication=authentication,
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CREATED
    assert not isinstance(payload, bytes)
    assert payload["run_id"] == _RUN_ID
    assert headers == {"Cache-Control": "no-store"}
    assert administration.calls == [("run", ("reviewed", "checkout", "inspect the workspace"))]

    administration.calls.clear()
    read_request = http_module._Request(
        method="GET",
        path=f"{TASK_CONTROL_PLANE_BASE_PATH}/{_RUN_ID}",
        query={},
        headers={},
        body=b"",
    )
    status_without_session, payload_without_session, _ = await server._dispatch_authenticated(
        read_request,
        principal=authentication.principal,
        durable_authentication=None,
        server_origin=_ORIGIN,
    )

    assert status_without_session is HTTPStatus.NOT_FOUND
    assert payload_without_session == {"error": "not_found"}
    assert administration.calls == []
