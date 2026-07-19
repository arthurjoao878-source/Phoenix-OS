from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    AuditSummary,
    CapabilityPage,
    ControlPlaneHealth,
    ControlPlaneHttpConfig,
    ControlPlaneHttpServer,
    ControlPlaneHttpState,
    ControlPlaneServerStateError,
    ControlPlaneSnapshot,
    JobPage,
    PageInfo,
    PageRequest,
    PluginPage,
    WorkflowPage,
    WorkflowSummary,
)
from phoenix_os.jobs import JobSchedulerSnapshot
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState

_NOW = datetime(2026, 7, 18, 20, 0, tzinfo=UTC)
_TOKEN = "control-plane-test-token-00000001"
_DEFAULT_PAGE = PageRequest()


class _Reader:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    async def snapshot(self) -> ControlPlaneSnapshot:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return _snapshot()

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


class _DetailReader(_Reader):
    def __init__(self) -> None:
        super().__init__()
        self.pages: list[PageRequest] = []
        self.audit_calls = 0

    async def list_jobs(self, page: PageRequest = _DEFAULT_PAGE) -> JobPage:
        self.pages.append(page)
        return await super().list_jobs(page)

    async def list_workflows(self, page: PageRequest = _DEFAULT_PAGE) -> WorkflowPage:
        self.pages.append(page)
        return await super().list_workflows(page)

    async def list_capabilities(self, page: PageRequest = _DEFAULT_PAGE) -> CapabilityPage:
        self.pages.append(page)
        return await super().list_capabilities(page)

    async def list_plugins(self, page: PageRequest = _DEFAULT_PAGE) -> PluginPage:
        self.pages.append(page)
        return await super().list_plugins(page)

    async def audit_summary(self) -> AuditSummary | None:
        self.audit_calls += 1
        return AuditSummary(
            closed=False,
            records=2,
            head_sequence=2,
            signed_records=1,
            appended=2,
            reads=0,
            verifications=1,
            verification_failures=0,
            denied_operations=0,
        )


class _LargeReader(_Reader):
    async def snapshot(self) -> ControlPlaneSnapshot:
        snapshot = _snapshot()
        runtime = RuntimeSnapshot(
            runtime_id=snapshot.runtime.runtime_id,
            state=snapshot.runtime.state,
            components=("x" * 2048,),
            active_components=(),
            in_flight_requests=0,
            created_at=_NOW,
            started_at=_NOW,
            stopped_at=None,
        )
        return ControlPlaneSnapshot(
            generated_at=_NOW,
            health=ControlPlaneHealth.HEALTHY,
            runtime=runtime,
            jobs=snapshot.jobs,
            workflows=snapshot.workflows,
        )


def _snapshot() -> ControlPlaneSnapshot:
    return ControlPlaneSnapshot(
        generated_at=_NOW,
        health=ControlPlaneHealth.HEALTHY,
        runtime=RuntimeSnapshot(
            runtime_id=UUID("10000000-0000-0000-0000-000000000001"),
            state=RuntimeState.RUNNING,
            components=("jobs", "workflows"),
            active_components=("jobs", "workflows"),
            in_flight_requests=0,
            created_at=_NOW,
            started_at=_NOW,
            stopped_at=None,
        ),
        jobs=JobSchedulerSnapshot(
            closed=False,
            jobs=1,
            scheduled=0,
            running=0,
            retrying=0,
            succeeded=1,
            cancelled=0,
            dead_letter=0,
            runs=1,
        ),
        workflows=WorkflowSummary(
            total=1,
            pending=0,
            running=0,
            succeeded=1,
            failed=0,
            cancelled=0,
        ),
    )


def _server(
    reader: _Reader | _LargeReader | None = None,
    *,
    config: ControlPlaneHttpConfig | None = None,
) -> ControlPlaneHttpServer:
    return ControlPlaneHttpServer(
        reader or _Reader(),
        AdminTokenAuthenticator(_TOKEN),
        config=config,
    )


async def _request(
    server: ControlPlaneHttpServer,
    request: bytes,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    assert server.port is not None
    stream, writer = await __import__("asyncio").open_connection(server.host, server.port)
    writer.write(request)
    await writer.drain()
    response = await stream.read()
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {
        name.lower(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])
    }
    return status, headers, json.loads(body)


def _get(path: str, *, authorization: str | None = None) -> bytes:
    lines = [f"GET {path} HTTP/1.1", "Host: 127.0.0.1"]
    if authorization is not None:
        lines.append(f"Authorization: {authorization}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "localhost"])
def test_http_config_rejects_non_literal_or_non_loopback_hosts(host: str) -> None:
    with pytest.raises(ValueError, match="loopback"):
        ControlPlaneHttpConfig(host=host)


def test_http_config_accepts_ipv4_and_ipv6_loopback() -> None:
    assert ControlPlaneHttpConfig(host="127.0.0.1").host == "127.0.0.1"
    assert ControlPlaneHttpConfig(host="::1").host == "::1"


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"port": -1}, "port"),
        ({"request_timeout": 0}, "request_timeout"),
        ({"max_request_bytes": 512}, "max_request_bytes"),
        ({"max_response_bytes": 512}, "max_response_bytes"),
        ({"max_connections": 0}, "max_connections"),
    ],
)
def test_http_config_rejects_invalid_limits(
    kwargs: dict[str, int | float],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneHttpConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_http_server_has_one_shot_lifecycle_and_safe_snapshot() -> None:
    server = _server()

    await server.start()
    snapshot = await server.snapshot()
    assert snapshot.state is ControlPlaneHttpState.RUNNING
    assert snapshot.host == "127.0.0.1"
    assert snapshot.port == server.port
    assert snapshot.requests == 0
    assert snapshot.active_connections == 0

    with pytest.raises(ControlPlaneServerStateError, match="cannot start"):
        await server.start()

    await server.stop()
    assert server.state is ControlPlaneHttpState.STOPPED
    await server.stop()


@pytest.mark.asyncio
async def test_http_server_can_stop_before_start_but_cannot_then_start() -> None:
    server = _server()

    await server.stop()

    assert server.state is ControlPlaneHttpState.STOPPED
    with pytest.raises(ControlPlaneServerStateError, match="cannot start"):
        await server.start()


@pytest.mark.asyncio
async def test_public_liveness_does_not_invoke_control_plane_reader() -> None:
    reader = _Reader()
    server = _server(reader)
    await server.start()
    try:
        status, headers, body = await _request(server, _get("/health/live"))
    finally:
        await server.stop()

    assert status == 200
    assert body == {"status": "ok"}
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert reader.calls == 0


@pytest.mark.asyncio
async def test_protected_health_requires_bearer_token() -> None:
    reader = _Reader()
    server = _server(reader)
    await server.start()
    try:
        status, headers, body = await _request(
            server,
            _get("/v1/control-plane/health"),
        )
        snapshot = await server.snapshot()
    finally:
        await server.stop()

    assert status == 401
    assert body == {"error": "unauthorized"}
    assert headers["www-authenticate"] == 'Bearer realm="phoenix-control-plane"'
    assert reader.calls == 0
    assert snapshot.unauthorized == 1


@pytest.mark.asyncio
async def test_authenticated_health_returns_only_coarse_fields() -> None:
    reader = _Reader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get(
                "/v1/control-plane/health?ignored=true",
                authorization=f"Bearer {_TOKEN}",
            ),
        )
    finally:
        await server.stop()

    assert status == 200
    assert body == {
        "generated_at": _NOW.isoformat(),
        "health": "healthy",
        "schema_version": 1,
    }
    assert reader.calls == 1


@pytest.mark.asyncio
async def test_authenticated_snapshot_uses_safe_allowlist() -> None:
    reader = _Reader()
    server = _server(reader)
    await server.start()
    try:
        status, headers, body = await _request(
            server,
            _get(
                "/v1/control-plane/snapshot",
                authorization=f"Bearer {_TOKEN}",
            ),
        )
    finally:
        await server.stop()

    assert status == 200
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert body["health"] == "healthy"
    assert body["jobs"]["succeeded"] == 1
    assert body["workflows"]["succeeded"] == 1
    serialized = json.dumps(body)
    assert "token" not in serialized
    assert "arguments" not in serialized
    assert "output" not in serialized


@pytest.mark.asyncio
async def test_authenticated_unknown_route_returns_not_found_without_reader_call() -> None:
    reader = _Reader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get("/v1/unknown", authorization=f"Bearer {_TOKEN}"),
        )
    finally:
        await server.stop()

    assert status == 404
    assert body == {"error": "not_found"}
    assert reader.calls == 0


@pytest.mark.asyncio
async def test_http_server_rejects_unsupported_method() -> None:
    server = _server()
    await server.start()
    try:
        status, headers, body = await _request(
            server,
            b"POST /health/live HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
    finally:
        await server.stop()

    assert status == 405
    assert headers["allow"] == "GET"
    assert body == {"error": "method_not_allowed"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_request, expected_error",
    [
        (
            b"GET /v1/control-plane/health HTTP/1.1\r\nHost: x\r\n"
            + f"Authorization: Bearer {_TOKEN}\r\n".encode()
            + f"Authorization: Bearer {_TOKEN}\r\n\r\n".encode(),
            "duplicate_authorization",
        ),
        (
            b"GET /health/live HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n",
            "request_body_not_supported",
        ),
        (b"GET /health/live HTTP/1.1\r\n\r\n", "missing_host"),
    ],
)
async def test_http_server_rejects_malformed_or_body_requests(
    raw_request: bytes,
    expected_error: str,
) -> None:
    server = _server()
    await server.start()
    try:
        status, _, body = await _request(server, raw_request)
    finally:
        await server.stop()

    assert status == 400
    assert body == {"error": expected_error}


@pytest.mark.asyncio
async def test_http_server_rejects_oversized_request_headers() -> None:
    server = _server(config=ControlPlaneHttpConfig(max_request_bytes=1024))
    await server.start()
    request = (
        "GET /health/live HTTP/1.1\r\nHost: x\r\nX-Large: " + ("x" * 2000) + "\r\n\r\n"
    ).encode()
    try:
        status, _, body = await _request(server, request)
    finally:
        await server.stop()

    assert status == 431
    assert body == {"error": "request_too_large"}


@pytest.mark.asyncio
async def test_http_server_hides_reader_exception_details() -> None:
    reader = _Reader(error=RuntimeError("database password=secret"))
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get(
                "/v1/control-plane/snapshot",
                authorization=f"Bearer {_TOKEN}",
            ),
        )
        snapshot = await server.snapshot()
    finally:
        await server.stop()

    assert status == 503
    assert body == {"error": "service_unavailable"}
    assert "secret" not in json.dumps(body)
    assert snapshot.last_error == "RuntimeError"


@pytest.mark.asyncio
async def test_http_server_replaces_oversized_response_with_generic_error() -> None:
    server = _server(
        _LargeReader(),
        config=ControlPlaneHttpConfig(max_response_bytes=1024),
    )
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get(
                "/v1/control-plane/snapshot",
                authorization=f"Bearer {_TOKEN}",
            ),
        )
        snapshot = await server.snapshot()
    finally:
        await server.stop()

    assert status == 503
    assert body == {"error": "response_too_large"}
    assert snapshot.rejected == 1
    assert snapshot.last_error == "ResponseTooLarge"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/v1/control-plane/jobs",
        "/v1/control-plane/workflows",
        "/v1/control-plane/capabilities",
        "/v1/control-plane/plugins",
    ],
)
async def test_authenticated_detail_routes_accept_bounded_pagination(path: str) -> None:
    reader = _DetailReader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get(f"{path}?offset=3&limit=7", authorization=f"Bearer {_TOKEN}"),
        )
    finally:
        await server.stop()

    assert status == 200
    assert body == {
        "items": [],
        "page": {
            "limit": 7,
            "next_offset": None,
            "offset": 3,
            "returned": 0,
            "total": 0,
        },
    }
    assert reader.pages == [PageRequest(offset=3, limit=7)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query",
    [
        "offset=-1",
        "offset=abc",
        "offset=1.5",
        "limit=0",
        "limit=201",
        "limit=",
        "limit=1&limit=2",
        "cursor=10",
    ],
)
async def test_detail_routes_reject_invalid_pagination(query: str) -> None:
    reader = _DetailReader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get(
                f"/v1/control-plane/jobs?{query}",
                authorization=f"Bearer {_TOKEN}",
            ),
        )
    finally:
        await server.stop()

    assert status == 400
    assert body == {"error": "invalid_pagination"}
    assert reader.pages == []


@pytest.mark.asyncio
async def test_audit_route_returns_only_safe_summary_fields() -> None:
    reader = _DetailReader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get("/v1/control-plane/audit", authorization=f"Bearer {_TOKEN}"),
        )
    finally:
        await server.stop()

    assert status == 200
    assert body == {
        "appended": 2,
        "available": True,
        "closed": False,
        "denied_operations": 0,
        "head_sequence": 2,
        "reads": 0,
        "records": 2,
        "signed_records": 1,
        "verification_failures": 0,
        "verifications": 1,
    }
    assert "digest" not in repr(body)
    assert reader.audit_calls == 1


@pytest.mark.asyncio
async def test_audit_route_rejects_query_parameters() -> None:
    reader = _DetailReader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get(
                "/v1/control-plane/audit?limit=1",
                authorization=f"Bearer {_TOKEN}",
            ),
        )
    finally:
        await server.stop()

    assert status == 400
    assert body == {"error": "invalid_query"}
    assert reader.audit_calls == 0


@pytest.mark.asyncio
async def test_detail_routes_require_authentication_before_query_parsing() -> None:
    reader = _DetailReader()
    server = _server(reader)
    await server.start()
    try:
        status, _, body = await _request(
            server,
            _get("/v1/control-plane/jobs?limit=invalid"),
        )
    finally:
        await server.stop()

    assert status == 401
    assert body == {"error": "unauthorized"}
    assert reader.pages == []
