from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.capabilities import CapabilityDescriptor, CapabilityRegistry
from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    AdminTokenAuthenticator,
    AuditSummary,
    CapabilityPage,
    ControlPlaneBrowserOrigin,
    ControlPlaneCommandAction,
    ControlPlaneCommandApi,
    ControlPlaneCommandAuthorizer,
    ControlPlaneCommandProtector,
    ControlPlaneConfirmationProof,
    ControlPlaneCsrfProtector,
    ControlPlaneHealth,
    ControlPlaneHttpServer,
    ControlPlaneJobCommandHandler,
    ControlPlanePrincipal,
    ControlPlaneSnapshot,
    InMemoryControlPlaneConfirmationService,
    InMemoryControlPlaneIdempotencyStore,
    JobPage,
    PageInfo,
    PageRequest,
    PluginPage,
    WorkflowPage,
    WorkflowSummary,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.jobs import InMemoryJobRepository, JobScheduler, JobSchedulerSnapshot
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState

_TOKEN = "command-http-token-000000000000001"
_NOW = datetime(2026, 7, 19, 10, 0, tzinfo=UTC)
_DEFAULT_PAGE = PageRequest()


class _Reader:
    async def snapshot(self) -> ControlPlaneSnapshot:
        return ControlPlaneSnapshot(
            generated_at=_NOW,
            health=ControlPlaneHealth.HEALTHY,
            runtime=RuntimeSnapshot(
                runtime_id=UUID(int=1),
                state=RuntimeState.RUNNING,
                components=(),
                active_components=(),
                in_flight_requests=0,
                created_at=_NOW,
                started_at=_NOW,
                stopped_at=None,
            ),
            jobs=JobSchedulerSnapshot(
                closed=False,
                jobs=0,
                scheduled=0,
                running=0,
                retrying=0,
                succeeded=0,
                cancelled=0,
                dead_letter=0,
                runs=0,
            ),
            workflows=WorkflowSummary(0, 0, 0, 0, 0, 0),
        )

    async def list_jobs(self, page: PageRequest = _DEFAULT_PAGE) -> JobPage:
        return JobPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_workflows(self, page: PageRequest = _DEFAULT_PAGE) -> WorkflowPage:
        return WorkflowPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_capabilities(self, page: PageRequest = _DEFAULT_PAGE) -> CapabilityPage:
        return CapabilityPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_plugins(self, page: PageRequest = _DEFAULT_PAGE) -> PluginPage:
        return PluginPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def audit_summary(self) -> AuditSummary | None:
        return None


async def _server(
    *,
    permissions: frozenset[str] | None = None,
) -> tuple[ControlPlaneHttpServer, JobScheduler, list[Event]]:
    events = EventBus()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    capabilities = CapabilityRegistry(events=events)
    await capabilities.register(CapabilityDescriptor("test.echo"), lambda invocation: {})
    scheduler = JobScheduler(InMemoryJobRepository(), capabilities)
    principal = ControlPlanePrincipal(
        "dashboard.operator",
        permissions
        or frozenset(
            {
                CONTROL_PLANE_READ_PERMISSION,
                *(action.permission for action in ControlPlaneCommandAction),
            }
        ),
    )
    csrf = ControlPlaneCsrfProtector(b"c" * 32, clock=lambda: _NOW)
    confirmations = InMemoryControlPlaneConfirmationService(b"d" * 32, clock=lambda: _NOW)
    idempotency = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    authorizer = ControlPlaneCommandAuthorizer()
    jobs = ControlPlaneJobCommandHandler(
        scheduler,
        capabilities,
        authorizer,
        ControlPlaneCommandProtector(csrf, confirmations),
        idempotency,
    )
    api = ControlPlaneCommandApi(
        csrf=csrf,
        confirmations=confirmations,
        idempotency=idempotency,
        authorizer=authorizer,
        events=events,
        jobs=jobs,
        clock=lambda: _NOW,
    )
    server = ControlPlaneHttpServer(
        _Reader(),
        AdminTokenAuthenticator(_TOKEN, principal=principal),
        command_api=api,
    )
    await server.start()
    return server, scheduler, captured


async def _request(
    server: ControlPlaneHttpServer,
    method: str,
    path: str,
    *,
    body: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
    authorize: bool = True,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    assert server.port is not None
    encoded = b"" if body is None else json.dumps(body).encode("utf-8")
    lines = [f"{method} {path} HTTP/1.1", f"Host: {server.host}:{server.port}"]
    if authorize:
        lines.append(f"Authorization: Bearer {_TOKEN}")
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    if encoded:
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(encoded)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + encoded
    reader, writer = await __import__("asyncio").open_connection(server.host, server.port)
    writer.write(raw)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, response_body = response.split(b"\r\n\r\n", 1)
    header_lines = head.decode("iso-8859-1").split("\r\n")
    status = int(header_lines[0].split(" ", 2)[1])
    response_headers = {
        name.lower(): value.strip()
        for name, value in (line.split(":", 1) for line in header_lines[1:])
    }
    return status, response_headers, json.loads(response_body)


def _origin(server: ControlPlaneHttpServer) -> str:
    assert server.port is not None
    return str(ControlPlaneBrowserOrigin(f"http://{server.host}:{server.port}"))


@pytest.mark.asyncio
async def test_command_routes_require_bearer_authentication() -> None:
    server, _, _ = await _server()
    try:
        status, _, body = await _request(
            server,
            "POST",
            "/v1/control-plane/csrf",
            headers={"Origin": _origin(server)},
            authorize=False,
        )
    finally:
        await server.stop()

    assert status == 401
    assert body == {"error": "unauthorized"}


@pytest.mark.asyncio
async def test_operations_expose_only_allowed_and_available_actions() -> None:
    permissions = frozenset(
        {
            CONTROL_PLANE_READ_PERMISSION,
            ControlPlaneCommandAction.CREATE_JOB.permission,
        }
    )
    server, _, _ = await _server(permissions=permissions)
    try:
        status, _, body = await _request(server, "GET", "/v1/control-plane/operations")
    finally:
        await server.stop()

    assert status == 200
    assert body["actions"] == {
        "job.cancel": False,
        "job.create": True,
        "job.retry-dead-letter": False,
        "workflow.cancel": False,
    }


@pytest.mark.asyncio
async def test_csrf_issuance_is_bound_to_exact_server_origin() -> None:
    server, _, _ = await _server()
    try:
        ok, _, payload = await _request(
            server,
            "POST",
            "/v1/control-plane/csrf",
            headers={"Origin": _origin(server)},
        )
        rejected, _, rejected_payload = await _request(
            server,
            "POST",
            "/v1/control-plane/csrf",
            headers={"Origin": "http://127.0.0.1:65535"},
        )
    finally:
        await server.stop()

    assert ok == 200
    assert payload["csrf_token"].startswith("v1.")
    assert rejected == 403
    assert rejected_payload == {"error": "request_rejected"}


@pytest.mark.asyncio
async def test_create_job_endpoint_executes_once_and_replays_receipt() -> None:
    server, scheduler, captured = await _server()
    origin = _origin(server)
    try:
        _, _, csrf_payload = await _request(
            server,
            "POST",
            "/v1/control-plane/csrf",
            headers={"Origin": origin},
        )
        headers = {
            "Origin": origin,
            "Idempotency-Key": "create-http-command-0001",
            "X-Phoenix-CSRF": csrf_payload["csrf_token"],
        }
        command: dict[str, object] = {
            "capability": "test.echo",
            "run_at": (_NOW + timedelta(minutes=5)).isoformat(),
            "arguments": {"message": "hello"},
        }
        first, _, first_payload = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/create",
            body=command,
            headers=headers,
        )
        second, _, second_payload = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/create",
            body=command,
            headers=headers,
        )
        scheduled = await scheduler.snapshot()
    finally:
        await server.stop()

    assert first == second == 200
    assert first_payload == second_payload
    assert first_payload["status"] == "succeeded"
    assert first_payload["result_code"] == "job.created"
    assert scheduled.jobs == 1
    assert any(event.name == "control-plane.command.succeeded" for event in captured)


@pytest.mark.asyncio
async def test_job_cancel_uses_one_time_confirmation_and_audits_result() -> None:
    server, scheduler, captured = await _server()
    origin = _origin(server)
    try:
        _, _, csrf_payload = await _request(
            server,
            "POST",
            "/v1/control-plane/csrf",
            headers={"Origin": origin},
        )
        csrf = csrf_payload["csrf_token"]
        create_headers = {
            "Origin": origin,
            "Idempotency-Key": "create-http-command-0002",
            "X-Phoenix-CSRF": csrf,
        }
        _, _, created = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/create",
            body={
                "capability": "test.echo",
                "run_at": (_NOW + timedelta(minutes=5)).isoformat(),
                "arguments": {},
            },
            headers=create_headers,
        )
        job_id = created["job_id"]
        cancel_key = "cancel-http-command-0001"
        confirmation_status, _, challenge = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/cancel/confirmation",
            body={"job_id": job_id},
            headers={
                "Origin": origin,
                "Idempotency-Key": cancel_key,
                "X-Phoenix-CSRF": csrf,
            },
        )
        cancel_headers = {
            "Origin": origin,
            "Idempotency-Key": cancel_key,
            "X-Phoenix-CSRF": csrf,
            "X-Phoenix-Confirmation": challenge["confirmation_proof"],
        }
        cancelled_status, _, cancelled = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/cancel",
            body={"job_id": job_id, "command_id": challenge["command_id"]},
            headers=cancel_headers,
        )
        replay_status, _, replay = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/cancel",
            body={"job_id": job_id, "command_id": challenge["command_id"]},
            headers=cancel_headers,
        )
        record = await scheduler.get(UUID(job_id))
    finally:
        await server.stop()

    assert confirmation_status == 200
    assert cancelled_status == 200
    assert cancelled["result_code"] == "job.cancelled"
    assert record is not None and record.status.value == "cancelled"
    assert replay_status == 403
    assert replay == {"error": "request_rejected"}
    assert any(event.name == "control-plane.command.confirmation-issued" for event in captured)
    assert any(event.name == "control-plane.command.succeeded" for event in captured)
    assert any(event.name == "control-plane.command.rejected" for event in captured)


@pytest.mark.asyncio
async def test_command_endpoint_rejects_invalid_json_and_missing_protection_headers() -> None:
    server, _, _ = await _server()
    try:
        status, _, body = await _request(
            server,
            "POST",
            "/v1/control-plane/commands/jobs/create",
            body={"capability": "test.echo", "run_at": _NOW.isoformat()},
            headers={"Origin": _origin(server)},
        )
    finally:
        await server.stop()

    assert status == 400
    assert body == {"error": "invalid_command"}


def test_confirmation_proof_is_never_present_in_safe_repr() -> None:
    proof = ControlPlaneConfirmationProof("v1.1." + ("A" * 43) + "." + ("B" * 43))
    assert proof.value not in repr(proof)
