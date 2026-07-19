from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    InMemoryJobRepository,
    Kernel,
    MappingConfigSource,
    PhoenixRuntime,
    Router,
    RuntimeAssembler,
)
from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlaneEventStream,
    ControlPlaneEventStreamState,
    ControlPlaneHttpServer,
    ControlPlaneHttpState,
    ControlPlaneService,
    DashboardAsset,
    DashboardAssets,
    EventStreamRequest,
)

_TOKEN = "control-plane-dashboard-token-000001"


async def _raw_request(
    server: ControlPlaneHttpServer,
    path: str,
    *,
    authorization: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    assert server.port is not None
    reader, writer = await asyncio.open_connection(server.host, server.port)
    lines = [f"GET {path} HTTP/1.1", "Host: 127.0.0.1"]
    if authorization is not None:
        lines.append(f"Authorization: {authorization}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {
        name.lower(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])
    }
    return status, headers, body


def test_dashboard_asset_requires_allowlisted_shape() -> None:
    with pytest.raises(ValueError, match="rooted"):
        DashboardAsset("/index.html", "text/html", b"content")
    with pytest.raises(ValueError, match="content type"):
        DashboardAsset("/dashboard/index.html", " ", b"content")
    with pytest.raises(ValueError, match="empty"):
        DashboardAsset("/dashboard/index.html", "text/html", b"")


def test_packaged_dashboard_assets_are_exact_and_complete() -> None:
    assets = DashboardAssets()

    assert assets.paths() == (
        "/dashboard/",
        "/dashboard/app.css",
        "/dashboard/app.js",
        "/dashboard/favicon.svg",
    )
    assert all(assets.get(path) is not None for path in assets.paths())
    assert assets.get("/dashboard/../pyproject.toml") is None
    assert assets.get("/dashboard/app.js?token=hidden") is None
    assert assets.get("/dashboard/missing.js") is None


def test_dashboard_html_uses_only_packaged_scripts_and_styles() -> None:
    asset = DashboardAssets().get("/dashboard/")
    assert asset is not None
    html = asset.body.decode("utf-8")

    assert '<script src="/dashboard/app.js" defer></script>' in html
    assert '<link rel="stylesheet" href="/dashboard/app.css">' in html
    assert "<script>" not in html
    assert " style=" not in html
    assert "http://" not in html
    assert "https://" not in html


def test_dashboard_html_exposes_operator_management_and_history_filter() -> None:
    asset = DashboardAssets().get("/dashboard/")
    assert asset is not None
    html = asset.body.decode("utf-8")

    assert 'id="operators-panel"' in html
    assert 'id="create-operator-form"' in html
    assert 'id="history-operator"' in html
    assert 'id="sessions-panel"' in html
    assert 'id="sessions-status"' in html
    assert "HttpOnly" in html
    assert "Phoenix OS v0.21.0" in html
    assert "token_digest" not in html


def test_dashboard_javascript_uses_httponly_cookie_without_browser_token_storage() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")
    assert asset is not None
    javascript = asset.body.decode("utf-8")

    assert "sessionStorage" not in javascript
    assert "localStorage" not in javascript
    assert 'credentials: "same-origin"' in javascript
    assert "/v1/control-plane/operator/login" in javascript
    assert "/v1/control-plane/operator/step-up" in javascript
    assert "/v1/control-plane/operator-sessions" in javascript
    assert "/v1/control-plane/operators" in javascript
    assert "session_token" not in javascript
    assert "X-Phoenix-Step-Up" in javascript
    assert "innerHTML" not in javascript
    assert "eval(" not in javascript


@pytest.mark.asyncio
async def test_dashboard_routes_are_public_but_api_remains_authenticated() -> None:
    runtime = await _assembled_runtime()
    server = runtime.service("control_plane.http")
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()

    redirect_status, redirect_headers, redirect_body = await _raw_request(server, "/")
    html_status, html_headers, html_body = await _raw_request(server, "/dashboard/")
    api_status, _, api_body = await _raw_request(server, "/v1/control-plane/snapshot")

    assert redirect_status == 307
    assert redirect_headers["location"] == "/dashboard/"
    assert redirect_body == b""
    assert html_status == 200
    assert html_headers["content-type"] == "text/html; charset=utf-8"
    assert "default-src 'none'" in html_headers["content-security-policy"]
    assert html_headers["x-frame-options"] == "DENY"
    assert html_headers["referrer-policy"] == "no-referrer"
    assert b"Phoenix OS Control Plane" in html_body
    assert api_status == 401
    assert json.loads(api_body) == {"error": "unauthorized"}

    await runtime.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path, content_type",
    [
        ("/dashboard/app.css", "text/css; charset=utf-8"),
        ("/dashboard/app.js", "text/javascript; charset=utf-8"),
        ("/dashboard/favicon.svg", "image/svg+xml"),
    ],
)
async def test_dashboard_assets_have_strict_content_types_and_no_store(
    path: str,
    content_type: str,
) -> None:
    runtime = await _assembled_runtime()
    server = runtime.service("control_plane.http")
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()

    status, headers, body = await _raw_request(server, path)

    assert status == 200
    assert headers["content-type"] == content_type
    assert headers["cache-control"] == "no-store"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["x-content-type-options"] == "nosniff"
    assert body
    await runtime.stop()


@pytest.mark.asyncio
async def test_unknown_dashboard_path_never_reads_package_files() -> None:
    runtime = await _assembled_runtime()
    server = runtime.service("control_plane.http")
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()

    status, headers, body = await _raw_request(server, "/dashboard/../../pyproject.toml")

    assert status == 404
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert json.loads(body) == {"error": "not_found"}
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_orphan_control_plane_options() -> None:
    events = EventBus()
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    with pytest.raises(ValueError, match="require an authenticator"):
        RuntimeAssembler(
            kernel=Kernel(
                router=Router(),
                authorizer=AllowAllAuthorizer(),
                events=events,
            ),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=configuration,
            control_plane_job_records=InMemoryJobRepository(),
        )


@pytest.mark.asyncio
async def test_runtime_assembler_owns_control_plane_services_and_lifecycle() -> None:
    runtime = await _assembled_runtime()
    service = runtime.service("control_plane")
    events = runtime.service("control_plane.events")
    server = runtime.service("control_plane.http")

    assert isinstance(service, ControlPlaneService)
    assert isinstance(events, ControlPlaneEventStream)
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()

    assert events.state is ControlPlaneEventStreamState.RUNNING
    assert server.state is ControlPlaneHttpState.RUNNING
    snapshot = await service.snapshot()
    assert snapshot.runtime.state.value == "running"
    assert "control_plane.events" in snapshot.runtime.active_components
    assert "control_plane.http" in snapshot.runtime.active_components

    status, _, body = await _raw_request(
        server,
        "/v1/control-plane/snapshot",
        authorization=f"Bearer {_TOKEN}",
    )
    payload: dict[str, Any] = json.loads(body)
    assert status == 200
    assert payload["health"] == "healthy"
    assert payload["jobs"]["total"] == 0
    assert payload["workflows"]["total"] == 0

    batch = await events.read(EventStreamRequest(after=0, limit=50))
    assert any(item.name == "runtime.started" for item in batch.items)

    await runtime.stop()
    assert (await server.snapshot()).state is ControlPlaneHttpState.STOPPED
    assert (await events.snapshot()).state is ControlPlaneEventStreamState.STOPPED


async def _assembled_runtime() -> PhoenixRuntime:
    events = EventBus()
    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )
    capabilities = CapabilityRegistry(events=events)
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    return await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        control_plane_authenticator=AdminTokenAuthenticator(_TOKEN),
    ).assemble()
