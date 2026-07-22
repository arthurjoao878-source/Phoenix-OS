"""Policy-selected HTTP transport with native TLS and remote admission controls."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from http import HTTPStatus

from phoenix_os.control_plane.assets import DashboardAssets
from phoenix_os.control_plane.auth import ControlPlaneAuthenticator
from phoenix_os.control_plane.command_api import ControlPlaneCommandApi
from phoenix_os.control_plane.contracts import (
    ControlPlaneReader,
    EventStreamReader,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_operator_http import (
    ControlPlaneDurableOperatorHttpAdapter,
)
from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionHttpBoundary,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneNetworkGuardClosedError,
    ControlPlaneNetworkRejectedError,
    ControlPlaneRemoteLoginRejectedError,
    ControlPlaneServerStateError,
    ControlPlaneTlsListenerStateError,
)
from phoenix_os.control_plane.http import (
    ControlPlaneHttpConfig,
    ControlPlaneHttpServer,
    ControlPlaneHttpSnapshot,
    ControlPlaneHttpState,
    _HttpRequestError,
    _Request,
    _single_header,
)
from phoenix_os.control_plane.journal_history import (
    ControlPlaneCommandHistoryReader,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneNetworkPolicy,
    ControlPlaneNetworkPolicySnapshot,
)
from phoenix_os.control_plane.network_guard import (
    ControlPlaneClientConnectionLease,
    ControlPlaneClientRateLimitPolicy,
    ControlPlaneNetworkGuard,
    ControlPlaneNetworkGuardSnapshot,
    ControlPlaneNetworkRejectionReason,
    ControlPlaneNetworkRequestContext,
)
from phoenix_os.control_plane.operator_http import (
    ControlPlaneOperatorHttpAdapter,
)
from phoenix_os.control_plane.remote_security import (
    ControlPlaneRemoteAudit,
    ControlPlaneRemoteAuditSnapshot,
    ControlPlaneRemoteAuthenticationService,
    ControlPlaneRemoteLoginThrottle,
    ControlPlaneRemoteLoginThrottleSnapshot,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthenticationContext,
    ControlPlaneServiceAccountTransportContextError,
    control_plane_service_account_authentication_context,
)
from phoenix_os.control_plane.service_account_http import (
    ControlPlaneServiceAccountHttpAdapter,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
)
from phoenix_os.control_plane.tls_listener import (
    ControlPlaneTlsContextSnapshot,
    ControlPlaneTlsListener,
    ControlPlaneTlsListenerConfig,
    ControlPlaneTlsListenerSnapshot,
)


@dataclass(frozen=True, slots=True)
class ControlPlaneSecureHttpSnapshot:
    """Complete safe health snapshot for the selected exposure boundary."""

    transport: ControlPlaneHttpSnapshot
    network: ControlPlaneNetworkPolicySnapshot
    guard: ControlPlaneNetworkGuardSnapshot
    tls: ControlPlaneTlsListenerSnapshot | None
    remote_login: ControlPlaneRemoteLoginThrottleSnapshot | None
    remote_audit: ControlPlaneRemoteAuditSnapshot | None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported secure HTTP snapshot schema version")


class ControlPlaneSecureHttpServer(ControlPlaneHttpServer):
    """Run the existing HTTP application behind a reviewed network policy."""

    def __init__(
        self,
        reader: ControlPlaneReader,
        authenticator: ControlPlaneAuthenticator | None,
        *,
        network_policy: ControlPlaneNetworkPolicy,
        config: ControlPlaneHttpConfig | None = None,
        event_stream: EventStreamReader | None = None,
        dashboard_assets: DashboardAssets | None = None,
        command_api: ControlPlaneCommandApi | None = None,
        command_history: ControlPlaneCommandHistoryReader | None = None,
        operator_http: ControlPlaneOperatorHttpAdapter | None = None,
        durable_session_http: ControlPlaneDurableSessionHttpBoundary | None = None,
        durable_operator_http: ControlPlaneDurableOperatorHttpAdapter | None = None,
        service_account_http: ControlPlaneServiceAccountHttpAdapter | None = None,
        service_account_machine_http: ControlPlaneServiceAccountMachineHttpAdapter | None = None,
        client_rate_limit: ControlPlaneClientRateLimitPolicy | None = None,
        tls_config: ControlPlaneTlsListenerConfig | None = None,
        remote_authentication: ControlPlaneRemoteAuthenticationService | None = None,
        remote_login: ControlPlaneRemoteLoginThrottle | None = None,
        remote_audit: ControlPlaneRemoteAudit | None = None,
    ) -> None:
        if network_policy.port == 0:
            raise ValueError("explicit control-plane network policy requires a fixed nonzero port")
        if (remote_authentication is None) != (remote_login is None):
            raise ValueError(
                "remote authentication and remote login throttle must be configured together"
            )
        if remote_authentication is not None and remote_audit is None:
            raise ValueError("remote authentication requires remote audit")

        super().__init__(
            reader,
            authenticator,
            config=config,
            event_stream=event_stream,
            dashboard_assets=dashboard_assets,
            command_api=command_api,
            command_history=command_history,
            operator_http=operator_http,
            durable_session_http=durable_session_http,
            durable_operator_http=durable_operator_http,
            service_account_http=service_account_http,
        )
        self._service_account_machine_http = service_account_machine_http
        self._network_policy = network_policy
        self._network_guard = ControlPlaneNetworkGuard(
            network_policy,
            rate_limit=client_rate_limit,
        )
        self._remote_authentication = remote_authentication
        self._remote_login = remote_login
        self._remote_audit = remote_audit
        self._request_network_context: ContextVar[ControlPlaneNetworkRequestContext | None] = (
            ContextVar(
                f"phoenix_control_plane_network_context_{id(self)}",
                default=None,
            )
        )
        self._service_account_authentication_context: ContextVar[
            ControlPlaneServiceAccountAuthenticationContext | None
        ] = ContextVar(
            f"phoenix_service_account_transport_context_{id(self)}",
            default=None,
        )
        self._tls_listener = (
            None
            if not network_policy.tls.enabled
            else ControlPlaneTlsListener(
                network_policy,
                self._handle_connection,
                config=tls_config,
            )
        )

    @property
    def host(self) -> str:
        return self._network_policy.bind_host

    @property
    def network_policy(self) -> ControlPlaneNetworkPolicy:
        return self._network_policy

    @property
    def network_guard(self) -> ControlPlaneNetworkGuard:
        return self._network_guard

    @property
    def remote_login(self) -> ControlPlaneRemoteLoginThrottle | None:
        return self._remote_login

    @property
    def remote_audit(self) -> ControlPlaneRemoteAudit | None:
        return self._remote_audit

    @property
    def tls_listener(self) -> ControlPlaneTlsListener | None:
        return self._tls_listener

    async def start(self, context: object = None) -> None:
        """Start either the native TLS listener or the guarded plaintext listener."""

        del context
        async with self._state_lock:
            if self._state is not ControlPlaneHttpState.CREATED:
                raise ControlPlaneServerStateError(
                    f"cannot start control plane HTTP server from state {self._state.value}"
                )

        if self._tls_listener is not None:
            await self._tls_listener.start()
            bound_port = self._tls_listener.port
            server = None
        else:
            server = await asyncio.start_server(
                self._handle_connection,
                host=self._network_policy.bind_host,
                port=self._network_policy.port,
                limit=self._config.max_request_bytes + 1,
            )
            sockets = server.sockets or ()
            if len(sockets) != 1:
                server.close()
                await server.wait_closed()
                raise RuntimeError("control plane HTTP server requires exactly one bound socket")
            bound_port = int(sockets[0].getsockname()[1])

        if bound_port is None:
            if server is not None:
                server.close()
                await server.wait_closed()
            raise RuntimeError("control plane listener did not report a bound port")

        async with self._state_lock:
            self._server = server
            self._port = bound_port
            self._state = ControlPlaneHttpState.RUNNING

    async def stop(self, context: object = None) -> None:
        """Stop the listener before closing its admission state."""

        del context
        async with self._state_lock:
            if self._state is ControlPlaneHttpState.STOPPED:
                return
            if self._state is ControlPlaneHttpState.CREATED:
                self._state = ControlPlaneHttpState.STOPPING
                server = None
            elif self._state is ControlPlaneHttpState.RUNNING:
                self._state = ControlPlaneHttpState.STOPPING
                server = self._server
                self._server = None
            else:
                raise ControlPlaneServerStateError(
                    f"cannot stop control plane HTTP server from state {self._state.value}"
                )

        if self._tls_listener is not None:
            await self._tls_listener.stop()
        elif server is not None:
            server.close()
            await server.wait_closed()

        await self._network_guard.close()
        if self._remote_login is not None:
            await self._remote_login.close()

        async with self._state_lock:
            self._state = ControlPlaneHttpState.STOPPED

    async def snapshot(self) -> ControlPlaneHttpSnapshot:
        """Return transport state using the effective network-policy bind address."""

        current = await super().snapshot()
        return replace(current, host=self.host, port=self.port)

    async def secure_snapshot(self) -> ControlPlaneSecureHttpSnapshot:
        """Return network, guard, TLS, login, and audit health without secrets."""

        tls_snapshot = None if self._tls_listener is None else await self._tls_listener.snapshot()
        remote_login_snapshot = (
            None if self._remote_login is None else await self._remote_login.snapshot()
        )
        remote_audit_snapshot = (
            None if self._remote_audit is None else await self._remote_audit.snapshot()
        )
        return ControlPlaneSecureHttpSnapshot(
            transport=await self.snapshot(),
            network=self._network_policy.snapshot(),
            guard=await self._network_guard.snapshot(),
            tls=tls_snapshot,
            remote_login=remote_login_snapshot,
            remote_audit=remote_audit_snapshot,
        )

    async def reload_tls(self) -> ControlPlaneTlsContextSnapshot:
        """Reload certificate material for future handshakes without rebinding."""

        if self._tls_listener is None:
            raise ControlPlaneTlsListenerStateError("control plane native TLS is not configured")
        return await self._tls_listener.reload()

    def _machine_http_handles(
        self,
        path: str,
    ) -> bool:
        return (
            self._service_account_machine_http is not None
            and self._service_account_machine_http.handles(path)
        )

    def _requires_browser_origin(
        self,
        request: _Request,
    ) -> bool:
        return request.method == "POST" and not self._machine_http_handles(request.path)

    async def _handle_connection(
        self,
        stream: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._connection_limit:
            await self._change_active_connections(1)

            lease: ControlPlaneClientConnectionLease | None = None

            network_context: ControlPlaneNetworkRequestContext | None = None

            context_token: Token[ControlPlaneNetworkRequestContext | None] | None = None

            machine_context_token: (
                Token[ControlPlaneServiceAccountAuthenticationContext | None] | None
            ) = None

            connection_audited = False

            try:
                try:
                    async with asyncio.timeout(self._config.request_timeout):
                        request = await self._read_request(stream)

                        peer_address = _peer_address(writer)

                        network_context = await self._network_guard.authorize_request(
                            peer_address,
                            request.headers,
                            require_origin=(self._requires_browser_origin(request)),
                        )

                        lease = await self._network_guard.acquire_connection(
                            network_context.identity
                        )

                        if self._remote_audit is not None:
                            await self._remote_audit.connection_accepted(network_context.identity)

                            connection_audited = True

                        context_token = self._request_network_context.set(network_context)

                        if self._machine_http_handles(request.path):
                            machine_context = control_plane_service_account_authentication_context(
                                network_context,
                                writer,
                                tls_policy=(self._network_policy.tls),
                            )

                            machine_context_token = (
                                self._service_account_authentication_context.set(machine_context)
                            )

                        status, payload, headers = await self._dispatch(request)

                except TimeoutError:
                    await self._record_rejection("RequestTimeout")

                    status, payload, headers = (
                        HTTPStatus.REQUEST_TIMEOUT,
                        {
                            "error": "request_timeout",
                        },
                        {},
                    )

                except _HttpRequestError as exception:
                    await self._record_rejection(exception.code)

                    status, payload, headers = (
                        exception.status,
                        {
                            "error": exception.code,
                        },
                        {},
                    )

                except ControlPlaneServiceAccountTransportContextError:
                    await self._record_rejection("ServiceAccountTransportRejected")

                    status, payload, headers = (
                        HTTPStatus.FORBIDDEN,
                        {
                            "error": "request_rejected",
                        },
                        {},
                    )

                except (
                    ControlPlaneNetworkRejectedError,
                    ControlPlaneNetworkGuardClosedError,
                ):
                    guard_snapshot = await self._network_guard.snapshot()

                    reason = (
                        guard_snapshot.last_rejection or ControlPlaneNetworkRejectionReason.PROXY
                    )

                    if self._remote_audit is not None:
                        await self._remote_audit.network_rejected(
                            reason,
                            identity=(
                                None if network_context is None else network_context.identity
                            ),
                        )

                    limited = reason in {
                        ControlPlaneNetworkRejectionReason.RATE_LIMIT,
                        ControlPlaneNetworkRejectionReason.CONNECTION_LIMIT,
                    }

                    await self._record_rejection("NetworkRequestRejected")

                    status, payload, headers = (
                        (HTTPStatus.TOO_MANY_REQUESTS if limited else HTTPStatus.FORBIDDEN),
                        {
                            "error": "request_rejected",
                        },
                        (
                            {
                                "Retry-After": "1",
                            }
                            if limited
                            else {}
                        ),
                    )

                except Exception as exception:
                    await self._record_error(type(exception).__name__)

                    status, payload, headers = (
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {
                            "error": "service_unavailable",
                        },
                        {},
                    )

                await self._write_response(
                    writer,
                    status,
                    payload,
                    headers,
                )

            finally:
                if machine_context_token is not None:
                    self._service_account_authentication_context.reset(machine_context_token)

                if context_token is not None:
                    self._request_network_context.reset(context_token)

                if (
                    connection_audited
                    and self._remote_audit is not None
                    and network_context is not None
                ):
                    await self._remote_audit.connection_closed(network_context.identity)

                if lease is not None:
                    await lease.close()

                writer.close()

                try:
                    await writer.wait_closed()
                except (
                    ConnectionError,
                    RuntimeError,
                ):
                    pass

                await self._change_active_connections(-1)

    async def _dispatch(
        self,
        request: _Request,
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object] | bytes,
        dict[str, str],
    ]:
        if self._machine_http_handles(request.path):
            async with self._counter_lock:
                self._requests += 1

            machine_context = self._service_account_authentication_context.get()

            adapter = self._service_account_machine_http

            if machine_context is None or adapter is None:
                await self._record_rejection("ServiceAccountTransportUnavailable")

                return (
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        "error": "machine_api_unavailable",
                    },
                    {},
                )

            return await adapter.dispatch(
                context=machine_context,
                method=request.method,
                path=request.path,
                query=request.query,
                headers=request.headers,
                body=request.body,
            )

        if (
            request.path == "/v1/control-plane/operator/login"
            and self._remote_authentication is not None
        ):
            async with self._counter_lock:
                self._requests += 1
            if request.method != "POST" or request.body or request.query:
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
            context = self._request_network_context.get()
            if context is None:
                return (
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": "service_unavailable"},
                    {},
                )
            try:
                login = await self._remote_authentication.login(
                    _single_header(request.headers, "authorization"),
                    context,
                )
            except (ControlPlaneRemoteLoginRejectedError, ValueError):
                async with self._counter_lock:
                    self._unauthorized += 1
                return (
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "unauthorized"},
                    {"WWW-Authenticate": 'Bearer realm="phoenix-control-plane"'},
                )
            authentication = login.authentication
            return (
                HTTPStatus.OK,
                {
                    "schema_version": login.schema_version,
                    "session_id": str(authentication.session_id),
                    "operator_id": str(authentication.operator_id),
                    "username": authentication.principal.name,
                    "generation": authentication.generation,
                    "issued_at": authentication.authenticated_at.isoformat(),
                    "absolute_expires_at": (authentication.absolute_expires_at.isoformat()),
                    "idle_expires_at": authentication.idle_expires_at.isoformat(),
                },
                dict(login.response_headers),
            )
        return await super()._dispatch(request)

    def _server_origin(self) -> ControlPlaneBrowserOrigin:
        return ControlPlaneBrowserOrigin(str(self._network_policy.public_origin))


def _peer_address(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer and isinstance(peer[0], str) and peer[0]:
        return peer[0]
    raise ControlPlaneNetworkRejectedError("control-plane network request rejected")
