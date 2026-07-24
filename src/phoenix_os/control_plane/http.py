"""Bounded loopback-only HTTP transport for the Phoenix control plane."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from phoenix_os.control_plane.assets import DashboardAssets
from phoenix_os.control_plane.auth import ControlPlaneAuthenticator, ControlPlanePrincipal
from phoenix_os.control_plane.command_api import ControlPlaneCommandApi
from phoenix_os.control_plane.command_http import ControlPlaneCommandHttpAdapter
from phoenix_os.control_plane.contracts import (
    DEFAULT_EVENT_BATCH_SIZE,
    ControlPlaneReader,
    EventStreamReader,
    EventStreamRequest,
    PageRequest,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_operator_http import (
    ControlPlaneDurableOperatorHttpAdapter,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionHttpBoundary,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneDurableSessionHttpRejectedError,
    ControlPlaneEventStreamBackpressureError,
    ControlPlaneEventStreamStateError,
    ControlPlaneServerStateError,
)
from phoenix_os.control_plane.journal_contracts import (
    DEFAULT_COMMAND_JOURNAL_PAGE_SIZE,
    ControlPlaneCommandJournalPageRequest,
)
from phoenix_os.control_plane.journal_history import ControlPlaneCommandHistoryReader
from phoenix_os.control_plane.operator_http import ControlPlaneOperatorHttpAdapter
from phoenix_os.control_plane.serialization import (
    audit_summary_to_dict,
    capability_page_to_dict,
    command_availability_to_dict,
    command_history_page_to_dict,
    event_batch_to_dict,
    job_page_to_dict,
    plugin_page_to_dict,
    snapshot_to_dict,
    workflow_page_to_dict,
)
from phoenix_os.control_plane.service_account_http import (
    ControlPlaneServiceAccountHttpAdapter,
)
from phoenix_os.control_plane.webhook_http import ControlPlaneWebhookHttpAdapter


class ControlPlaneHttpState(StrEnum):
    """One-shot lifecycle states for the local HTTP transport."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneHttpConfig:
    """Resource and network limits for the loopback HTTP server."""

    host: str = "127.0.0.1"
    port: int = 0
    request_timeout: float = 5.0
    max_request_bytes: int = 16 * 1024
    max_response_bytes: int = 1024 * 1024
    max_connections: int = 64
    max_event_wait: float = 4.0
    max_command_body_bytes: int = 64 * 1024
    max_command_concurrency: int = 8

    def __post_init__(self) -> None:
        host = self.host.strip()
        if not host:
            raise ValueError("control plane host must not be blank")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exception:
            raise ValueError("control plane host must be a literal loopback address") from exception
        if not address.is_loopback:
            raise ValueError("control plane host must be a loopback address")
        if self.port < 0 or self.port > 65535:
            raise ValueError("control plane port must be between 0 and 65535")
        if self.request_timeout <= 0:
            raise ValueError("control plane request_timeout must be positive")
        if self.max_request_bytes < 1024:
            raise ValueError("control plane max_request_bytes must be at least 1024")
        if self.max_response_bytes < 1024:
            raise ValueError("control plane max_response_bytes must be at least 1024")
        if self.max_connections <= 0:
            raise ValueError("control plane max_connections must be positive")
        if self.max_command_body_bytes <= 0 or self.max_command_body_bytes > 1024 * 1024:
            raise ValueError("control plane max_command_body_bytes must be between 1 and 1048576")
        if self.max_command_concurrency <= 0 or self.max_command_concurrency > 1024:
            raise ValueError("control plane max_command_concurrency must be between 1 and 1024")
        if self.max_event_wait <= 0 or self.max_event_wait >= self.request_timeout:
            raise ValueError(
                "control plane max_event_wait must be positive and below request_timeout"
            )
        object.__setattr__(self, "host", host)


@dataclass(frozen=True, slots=True)
class ControlPlaneHttpSnapshot:
    """Non-sensitive transport diagnostics for operators and tests."""

    state: ControlPlaneHttpState
    host: str
    port: int | None
    requests: int
    unauthorized: int
    rejected: int
    active_connections: int
    last_error: str | None = None

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("control plane snapshot host must not be blank")
        if self.port is not None and (self.port <= 0 or self.port > 65535):
            raise ValueError("control plane snapshot port must be valid")
        counters = (self.requests, self.unauthorized, self.rejected, self.active_connections)
        if any(value < 0 for value in counters):
            raise ValueError("control plane HTTP counters cannot be negative")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", ControlPlaneHttpState(self.state))
        object.__setattr__(self, "host", self.host.strip())
        object.__setattr__(self, "last_error", error)


@dataclass(frozen=True, slots=True)
class _Request:
    method: str
    path: str
    query: Mapping[str, tuple[str, ...]]
    headers: Mapping[str, tuple[str, ...]]
    body: bytes


class ControlPlaneHttpServer:
    """Expose safe control-plane reads through authenticated loopback HTTP."""

    def __init__(
        self,
        reader: ControlPlaneReader,
        authenticator: ControlPlaneAuthenticator | None,
        *,
        config: ControlPlaneHttpConfig | None = None,
        event_stream: EventStreamReader | None = None,
        dashboard_assets: DashboardAssets | None = None,
        command_api: ControlPlaneCommandApi | None = None,
        command_history: ControlPlaneCommandHistoryReader | None = None,
        operator_http: ControlPlaneOperatorHttpAdapter | None = None,
        durable_session_http: ControlPlaneDurableSessionHttpBoundary | None = None,
        durable_operator_http: ControlPlaneDurableOperatorHttpAdapter | None = None,
        service_account_http: ControlPlaneServiceAccountHttpAdapter | None = None,
        webhook_http: ControlPlaneWebhookHttpAdapter | None = None,
    ) -> None:
        if authenticator is None and durable_session_http is None:
            raise ValueError("control plane requires an authenticator or durable session boundary")
        if operator_http is not None and durable_operator_http is not None:
            raise ValueError("legacy and durable operator HTTP adapters are exclusive")
        if service_account_http is not None and durable_session_http is None:
            raise ValueError("service-account HTTP requires durable session authentication")
        if webhook_http is not None and durable_session_http is None:
            raise ValueError("webhook HTTP requires durable session authentication")
        self._reader = reader
        self._authenticator = authenticator
        self._config = config or ControlPlaneHttpConfig()
        self._event_stream = event_stream
        self._dashboard_assets = dashboard_assets or DashboardAssets()
        self._command_history = command_history
        self._operator_http = operator_http
        self._durable_session_http = durable_session_http
        self._durable_operator_http = durable_operator_http
        self._service_account_http = service_account_http
        self._webhook_http = webhook_http
        self._command_http = (
            None
            if command_api is None
            else ControlPlaneCommandHttpAdapter(
                command_api,
                max_concurrency=self._config.max_command_concurrency,
            )
        )
        self._state = ControlPlaneHttpState.CREATED
        self._server: asyncio.Server | None = None
        self._port: int | None = None
        self._requests = 0
        self._unauthorized = 0
        self._rejected = 0
        self._active_connections = 0
        self._last_error: str | None = None
        self._state_lock = asyncio.Lock()
        self._counter_lock = asyncio.Lock()
        self._connection_limit = asyncio.Semaphore(self._config.max_connections)

    @property
    def state(self) -> ControlPlaneHttpState:
        return self._state

    @property
    def host(self) -> str:
        return self._config.host

    @property
    def port(self) -> int | None:
        return self._port

    async def start(self, context: object = None) -> None:
        """Bind the loopback socket once and begin accepting bounded requests."""

        del context
        async with self._state_lock:
            if self._state is not ControlPlaneHttpState.CREATED:
                raise ControlPlaneServerStateError(
                    f"cannot start control plane HTTP server from state {self._state.value}"
                )
            server = await asyncio.start_server(
                self._handle_connection,
                host=self._config.host,
                port=self._config.port,
                limit=self._config.max_request_bytes + 1,
            )
            sockets = server.sockets or ()
            if len(sockets) != 1:
                server.close()
                await server.wait_closed()
                raise RuntimeError("control plane HTTP server requires exactly one bound socket")
            self._server = server
            self._port = int(sockets[0].getsockname()[1])
            self._state = ControlPlaneHttpState.RUNNING

    async def stop(self, context: object = None) -> None:
        """Stop accepting connections and close the one-shot transport."""

        del context
        async with self._state_lock:
            if self._state is ControlPlaneHttpState.STOPPED:
                return
            if self._state is ControlPlaneHttpState.CREATED:
                self._state = ControlPlaneHttpState.STOPPED
                return
            if self._state is not ControlPlaneHttpState.RUNNING:
                raise ControlPlaneServerStateError(
                    f"cannot stop control plane HTTP server from state {self._state.value}"
                )
            self._state = ControlPlaneHttpState.STOPPING
            server = self._server
            self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        async with self._state_lock:
            self._state = ControlPlaneHttpState.STOPPED

    async def snapshot(self) -> ControlPlaneHttpSnapshot:
        """Return transport counters without credentials or request content."""

        async with self._counter_lock:
            return ControlPlaneHttpSnapshot(
                state=self._state,
                host=self._config.host,
                port=self._port,
                requests=self._requests,
                unauthorized=self._unauthorized,
                rejected=self._rejected,
                active_connections=self._active_connections,
                last_error=self._last_error,
            )

    async def _handle_connection(
        self,
        stream: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._connection_limit:
            await self._change_active_connections(1)
            try:
                try:
                    async with asyncio.timeout(self._config.request_timeout):
                        request = await self._read_request(stream)
                        status, payload, headers = await self._dispatch(request)
                except TimeoutError:
                    await self._record_rejection("RequestTimeout")
                    status, payload, headers = (
                        HTTPStatus.REQUEST_TIMEOUT,
                        {"error": "request_timeout"},
                        {},
                    )
                except _HttpRequestError as exception:
                    await self._record_rejection(exception.code)
                    status, payload, headers = exception.status, {"error": exception.code}, {}
                except Exception as exception:
                    await self._record_error(type(exception).__name__)
                    status, payload, headers = (
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "service_unavailable"},
                        {},
                    )
                await self._write_response(writer, status, payload, headers)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, RuntimeError):
                    pass
                await self._change_active_connections(-1)

    async def _read_request(self, stream: asyncio.StreamReader) -> _Request:
        try:
            raw = await stream.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError as exception:
            raise _HttpRequestError(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request_too_large",
            ) from exception
        except asyncio.IncompleteReadError as exception:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_request") from exception
        if len(raw) > self._config.max_request_bytes:
            raise _HttpRequestError(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, "request_too_large")
        try:
            text = raw.decode("iso-8859-1")
        except UnicodeDecodeError as exception:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_request") from exception
        lines = text[:-4].split("\r\n")
        if not lines:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_request")
        request_line = lines[0].split(" ")
        if len(request_line) != 3:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_request")
        method, target, version = request_line
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise _HttpRequestError(
                HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                "unsupported_http_version",
            )
        parsed = urlsplit(target)
        if not parsed.path.startswith("/") or parsed.scheme or parsed.netloc or parsed.fragment:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "invalid_target")
        headers: dict[str, list[str]] = {}
        for line in lines[1:]:
            if not line or line[0].isspace() or ":" not in line:
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_headers")
            name, value = line.split(":", 1)
            normalized_name = name.strip().lower()
            if not normalized_name or any(character.isspace() for character in normalized_name):
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_headers")
            headers.setdefault(normalized_name, []).append(value.strip())
        if version == "HTTP/1.1" and "host" not in headers:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "missing_host")
        if len(headers.get("authorization", ())) > 1:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "duplicate_authorization")
        if "transfer-encoding" in headers:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "request_body_not_supported")
        content_lengths = headers.get("content-length", ())
        if len(content_lengths) > 1:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "invalid_content_length")
        content_length = 0
        if content_lengths:
            try:
                content_length = int(content_lengths[0])
            except ValueError as exception:
                raise _HttpRequestError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_content_length",
                ) from exception
            if content_length < 0 or content_length > self._config.max_command_body_bytes:
                raise _HttpRequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_body_too_large"
                )
            if content_length and method.upper() != "POST":
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "request_body_not_supported")
        body = b""
        if content_length:
            try:
                body = await stream.readexactly(content_length)
            except asyncio.IncompleteReadError as exception:
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "malformed_request") from exception
        try:
            query = parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError as exception:
            raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "invalid_query") from exception
        return _Request(
            method=method.upper(),
            path=parsed.path,
            query={name: tuple(values) for name, values in query.items()},
            headers={name: tuple(values) for name, values in headers.items()},
            body=body,
        )

    async def _dispatch(
        self,
        request: _Request,
    ) -> tuple[HTTPStatus, Mapping[str, object] | bytes, dict[str, str]]:
        async with self._counter_lock:
            self._requests += 1
        if request.method not in {"GET", "POST"}:
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
                {"Allow": "GET, POST"},
            )
        if request.path in {"/", "/dashboard"}:
            if request.method != "GET" or request.body:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET"},
                )
            return (
                HTTPStatus.TEMPORARY_REDIRECT,
                b"",
                {"Location": "/dashboard/", "Content-Type": "text/plain; charset=utf-8"},
            )
        asset = self._dashboard_assets.get(request.path)
        if asset is not None:
            if request.method != "GET" or request.body:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET"},
                )
            return (
                HTTPStatus.OK,
                asset.body,
                {
                    "Content-Type": asset.content_type,
                    "Content-Security-Policy": (
                        "default-src 'none'; script-src 'self'; style-src 'self'; "
                        "img-src 'self'; connect-src 'self'; base-uri 'none'; "
                        "form-action 'none'; frame-ancestors 'none'"
                    ),
                },
            )
        if request.path.startswith("/dashboard/"):
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}, {}
        if request.path == "/health/live":
            if request.method != "GET" or request.body:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET"},
                )
            return HTTPStatus.OK, {"status": "ok"}, {}

        authorization = _single_header(request.headers, "authorization")
        origin = self._server_origin()
        if self._durable_operator_http is not None and self._durable_operator_http.handles_public(
            request.path
        ):
            return await self._durable_operator_http.dispatch_public(
                method=request.method,
                authorization=authorization,
                headers=request.headers,
                body=request.body,
                query=request.query,
                server_origin=origin,
            )
        if self._operator_http is not None and self._operator_http.handles_public(request.path):
            return await self._operator_http.dispatch_public(
                method=request.method,
                authorization=authorization,
                body=request.body,
                query=request.query,
            )

        durable_authentication: ControlPlaneDurableSessionAuthentication | None = None
        rotation_headers: dict[str, str] = {}
        if self._durable_session_http is not None:
            try:
                durable_http = await self._durable_session_http.authenticate(
                    _single_header(request.headers, "cookie"),
                    origin=origin,
                )
            except (ControlPlaneDurableSessionHttpRejectedError, ValueError):
                principal = None
            else:
                durable_authentication = durable_http.authentication
                principal = durable_authentication.principal
                rotation_headers = dict(durable_http.response_headers)
        else:
            principal = await self._authenticate(authorization)

        if principal is None:
            async with self._counter_lock:
                self._unauthorized += 1
            headers = {"WWW-Authenticate": 'Bearer realm="phoenix-control-plane"'}
            if self._durable_session_http is not None:
                headers["Set-Cookie"] = self._durable_session_http.clear_cookie()
            return HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"}, headers
        if "control-plane.read" not in principal.permissions:
            async with self._counter_lock:
                self._unauthorized += 1
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, rotation_headers

        status, payload, headers = await self._dispatch_authenticated(
            request,
            principal=principal,
            durable_authentication=durable_authentication,
            server_origin=origin,
        )
        return status, payload, _merge_headers(headers, rotation_headers)

    async def _dispatch_authenticated(
        self,
        request: _Request,
        *,
        principal: ControlPlanePrincipal,
        durable_authentication: ControlPlaneDurableSessionAuthentication | None,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object] | bytes, dict[str, str]]:
        authorization = _single_header(request.headers, "authorization")
        if (
            durable_authentication is not None
            and self._durable_operator_http is not None
            and self._durable_operator_http.handles(request.path)
        ):
            return await self._durable_operator_http.dispatch(
                authentication=durable_authentication,
                method=request.method,
                path=request.path,
                query=request.query,
                headers=request.headers,
                body=request.body,
                server_origin=server_origin,
            )
        if (
            durable_authentication is not None
            and self._service_account_http is not None
            and self._service_account_http.handles(request.path)
        ):
            return await self._service_account_http.dispatch(
                authentication=durable_authentication,
                method=request.method,
                path=request.path,
                query=request.query,
                headers=request.headers,
                body=request.body,
                server_origin=server_origin,
            )
        if (
            durable_authentication is not None
            and self._webhook_http is not None
            and self._webhook_http.handles(request.path)
        ):
            return await self._webhook_http.dispatch(
                authentication=durable_authentication,
                method=request.method,
                path=request.path,
                query=request.query,
                headers=request.headers,
                body=request.body,
                server_origin=server_origin,
            )
        if self._operator_http is not None and self._operator_http.handles(request.path):
            return await self._operator_http.dispatch(
                principal=principal,
                authorization=authorization,
                method=request.method,
                path=request.path,
                query=request.query,
                headers=request.headers,
                body=request.body,
                server_origin=server_origin,
            )

        if self._command_http is not None and self._command_http.handles(request.path):
            if request.query:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_query"}, {}
            command_headers = request.headers
            if durable_authentication is not None and self._durable_session_http is not None:
                if request.path == "/v1/control-plane/csrf":
                    return HTTPStatus.GONE, {"error": "session_csrf_already_issued"}, {}
                try:
                    supplied_origin = _request_origin(request.headers, server_origin)
                    await self._durable_session_http.verify_csrf(
                        _single_header(request.headers, "x-phoenix-csrf"),
                        durable_authentication,
                        supplied_origin=supplied_origin,
                        expected_origin=server_origin,
                    )
                except (ControlPlaneDurableSessionCsrfRejectedError, ValueError):
                    return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, {}
                internal_csrf = self._command_http.api.issue_csrf(principal, server_origin)
                mutable_headers = dict(request.headers)
                mutable_headers["x-phoenix-csrf"] = (internal_csrf.value,)
                command_headers = mutable_headers
            return await self._command_http.dispatch(
                principal=principal,
                method=request.method,
                path=request.path,
                headers=command_headers,
                body=request.body,
                server_origin=server_origin,
            )
        if request.path == "/v1/control-plane/operations":
            if request.method != "GET" or request.body or request.query:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
            if self._command_http is None:
                return HTTPStatus.OK, {"schema_version": 1, "actions": {}}, {}
            return (
                HTTPStatus.OK,
                command_availability_to_dict(self._command_http.api.availability(principal)),
                {},
            )
        if request.path == "/v1/control-plane/commands/history":
            if request.method != "GET" or request.body:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET"},
                )
            if self._command_history is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "history_unavailable"}, {}
            try:
                history_request, operator_filter = _command_journal_page_request(request.query)
            except ValueError:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_pagination"}, {}
            return (
                HTTPStatus.OK,
                command_history_page_to_dict(
                    await self._command_history.list_history(
                        principal, history_request, operator=operator_filter
                    )
                ),
                {},
            )
        if request.method != "GET" or request.body:
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
                {"Allow": "GET"},
            )

        if request.path == "/v1/control-plane/health":
            snapshot = await self._reader.snapshot()
            return (
                HTTPStatus.OK,
                {
                    "schema_version": snapshot.schema_version,
                    "generated_at": snapshot.generated_at.isoformat(),
                    "health": snapshot.health.value,
                },
                {},
            )
        if request.path == "/v1/control-plane/snapshot":
            return HTTPStatus.OK, snapshot_to_dict(await self._reader.snapshot()), {}
        if request.path == "/v1/control-plane/audit":
            if request.query:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_query"}, {}
            return HTTPStatus.OK, audit_summary_to_dict(await self._reader.audit_summary()), {}
        if request.path == "/v1/control-plane/events":
            if self._event_stream is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "events_unavailable"}, {}
            try:
                event_request = _event_stream_request(
                    request.query,
                    max_wait=self._config.max_event_wait,
                )
            except ValueError:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_event_query"}, {}
            try:
                batch = await self._event_stream.read(event_request)
            except ControlPlaneEventStreamBackpressureError:
                await self._record_rejection("EventStreamBackpressure")
                return (
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "event_stream_busy"},
                    {"Retry-After": "1"},
                )
            except ControlPlaneEventStreamStateError:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "events_unavailable"}, {}
            except ValueError:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_event_query"}, {}
            return HTTPStatus.OK, event_batch_to_dict(batch), {}

        page_paths = {
            "/v1/control-plane/jobs",
            "/v1/control-plane/workflows",
            "/v1/control-plane/capabilities",
            "/v1/control-plane/plugins",
        }
        if request.path not in page_paths:
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}, {}
        try:
            page = _page_request(request.query)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_pagination"}, {}
        if request.path == "/v1/control-plane/jobs":
            return HTTPStatus.OK, job_page_to_dict(await self._reader.list_jobs(page)), {}
        if request.path == "/v1/control-plane/workflows":
            return (
                HTTPStatus.OK,
                workflow_page_to_dict(await self._reader.list_workflows(page)),
                {},
            )
        if request.path == "/v1/control-plane/capabilities":
            return (
                HTTPStatus.OK,
                capability_page_to_dict(await self._reader.list_capabilities(page)),
                {},
            )
        return HTTPStatus.OK, plugin_page_to_dict(await self._reader.list_plugins(page)), {}

    async def _authenticate(
        self,
        authorization: str | None,
    ) -> ControlPlanePrincipal | None:
        if self._authenticator is None:
            return None
        result = self._authenticator.authenticate(authorization)
        if inspect.isawaitable(result):
            return await result
        return result

    def _server_origin(self) -> ControlPlaneBrowserOrigin:
        if self._port is None:
            raise RuntimeError("control plane HTTP server is not bound")
        host = f"[{self._config.host}]" if ":" in self._config.host else self._config.host
        return ControlPlaneBrowserOrigin(f"http://{host}:{self._port}")

    async def _write_response(
        self,
        writer: asyncio.StreamWriter,
        status: HTTPStatus,
        payload: Mapping[str, object] | bytes,
        extra_headers: Mapping[str, str],
    ) -> None:
        response_headers = dict(extra_headers)
        if isinstance(payload, bytes):
            body = payload
            content_type = response_headers.pop("Content-Type", "application/octet-stream")
        else:
            body = json.dumps(
                dict(payload),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        if len(body) > self._config.max_response_bytes:
            status = HTTPStatus.SERVICE_UNAVAILABLE
            body = b'{"error":"response_too_large"}'
            content_type = "application/json; charset=utf-8"
            response_headers = {}
            await self._record_rejection("ResponseTooLarge")
        headers = {
            "Cache-Control": "no-store",
            "Connection": "close",
            "Content-Length": str(len(body)),
            "Content-Type": content_type,
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        headers.update(response_headers)
        head = [f"HTTP/1.1 {status.value} {status.phrase}"]
        head.extend(f"{name}: {value}" for name, value in headers.items())
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body)
        await writer.drain()

    async def _record_rejection(self, code: str) -> None:
        async with self._counter_lock:
            self._rejected += 1
            self._last_error = code

    async def _record_error(self, code: str) -> None:
        async with self._counter_lock:
            self._last_error = code

    async def _change_active_connections(self, delta: int) -> None:
        async with self._counter_lock:
            self._active_connections += delta


class _HttpRequestError(Exception):
    def __init__(self, status: HTTPStatus, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def _single_header(headers: Mapping[str, tuple[str, ...]], name: str) -> str | None:
    values = headers.get(name, ())
    return None if not values else values[0]


def _merge_headers(primary: Mapping[str, str], secondary: Mapping[str, str]) -> dict[str, str]:
    result = dict(primary)
    result.update(secondary)
    return result


def _request_origin(
    headers: Mapping[str, tuple[str, ...]],
    expected: ControlPlaneBrowserOrigin,
) -> ControlPlaneBrowserOrigin:
    raw = _single_header(headers, "origin")
    if raw is None:
        raise ValueError("origin is required")
    supplied = ControlPlaneBrowserOrigin(raw)
    if supplied != expected:
        raise ValueError("origin does not match control plane")
    return supplied


def _page_request(query: Mapping[str, tuple[str, ...]]) -> PageRequest:
    if set(query) - {"offset", "limit"}:
        raise ValueError("unsupported pagination parameter")
    values: dict[str, int] = {}
    for name in ("offset", "limit"):
        raw = query.get(name)
        if raw is None:
            continue
        if len(raw) != 1 or not raw[0] or not raw[0].isascii() or not raw[0].isdigit():
            raise ValueError(f"invalid {name}")
        values[name] = int(raw[0])
    return PageRequest(**values)


def _command_journal_page_request(
    query: Mapping[str, tuple[str, ...]],
) -> tuple[ControlPlaneCommandJournalPageRequest, str | None]:
    if set(query) - {"offset", "limit", "operator"}:
        raise ValueError("unsupported pagination parameter")
    offset = _single_unsigned_integer(query, "offset")
    limit = _single_unsigned_integer(query, "limit")
    operator_values = query.get("operator")
    operator = None
    if operator_values is not None:
        if len(operator_values) != 1 or not operator_values[0].strip():
            raise ValueError("invalid operator filter")
        operator = operator_values[0].strip().lower()
    return (
        ControlPlaneCommandJournalPageRequest(
            offset=0 if offset is None else offset,
            limit=DEFAULT_COMMAND_JOURNAL_PAGE_SIZE if limit is None else limit,
        ),
        operator,
    )


def _event_stream_request(
    query: Mapping[str, tuple[str, ...]],
    *,
    max_wait: float,
) -> EventStreamRequest:
    if set(query) - {"after", "limit", "wait"}:
        raise ValueError("unsupported event stream parameter")
    after = _single_unsigned_integer(query, "after")
    limit = _single_unsigned_integer(query, "limit")
    wait_values = query.get("wait")
    wait = 0.0
    if wait_values is not None:
        if len(wait_values) != 1 or not wait_values[0] or not wait_values[0].isascii():
            raise ValueError("invalid wait")
        try:
            wait = float(wait_values[0])
        except ValueError as exception:
            raise ValueError("invalid wait") from exception
        if not math.isfinite(wait) or wait < 0 or wait > max_wait:
            raise ValueError("invalid wait")
    return EventStreamRequest(
        after=0 if after is None else after,
        limit=DEFAULT_EVENT_BATCH_SIZE if limit is None else limit,
        wait=wait,
    )


def _single_unsigned_integer(
    query: Mapping[str, tuple[str, ...]],
    name: str,
) -> int | None:
    raw = query.get(name)
    if raw is None:
        return None
    if len(raw) != 1 or not raw[0] or not raw[0].isascii() or not raw[0].isdigit():
        raise ValueError(f"invalid {name}")
    return int(raw[0])
