"""Runtime-owned composition for secure durable inbound events."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from types import MappingProxyType
from typing import Protocol

from phoenix_os.audit import AuditLedger
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
)
from phoenix_os.events import EventBus
from phoenix_os.inbound_events.admission import (
    InboundReplayIdempotencyService,
)
from phoenix_os.inbound_events.authentication import (
    InboundAuthenticationVerifier,
)
from phoenix_os.inbound_events.contracts import (
    DEFAULT_INBOUND_PAGE_REQUEST,
    MAX_INBOUND_PAGE_SIZE,
    InboundEventNormalizer,
    InboundEventRepository,
    InboundEventSource,
    InboundPageRequest,
    InboundReplayRepository,
    InboundSourceRepository,
)
from phoenix_os.inbound_events.gateway import (
    InboundEventGateway,
    PolicyEngineInboundAdmissionPolicy,
)
from phoenix_os.inbound_events.http import (
    InboundHttpAdapter,
    InboundHttpResponse,
    InboundHttpRoute,
    inbound_http_path,
)
from phoenix_os.inbound_events.limits import (
    InboundAdmissionLimiter,
    InboundAdmissionLimitPolicy,
)
from phoenix_os.inbound_events.manager import (
    InboundManager,
    InboundManagerConfig,
)
from phoenix_os.inbound_events.publisher import (
    DEFAULT_INBOUND_PUBLISHER_POLL_INTERVAL,
    InboundEventPublisher,
    InboundPublisherConfig,
    InboundPublisherWorker,
)
from phoenix_os.inbound_events.recovery import (
    DEFAULT_INBOUND_RECOVERY_BATCH_SIZE,
    DEFAULT_INBOUND_RECOVERY_POLL_INTERVAL,
    MAX_INBOUND_RECOVERY_BATCH_SIZE,
    InboundPublicationRecovery,
    InboundRecoveryWorker,
)
from phoenix_os.inbound_events.schema import InboundSchemaRegistry
from phoenix_os.observability import ObservabilityHub
from phoenix_os.policy import (
    PolicyEngine,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.secrets import SecretsManager

type InboundRuntimeCloseOperation = Awaitable[None]


class InboundRuntimeState(StrEnum):
    """One-shot lifecycle state for Runtime-owned inbound resources."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class InboundRuntimeStateError(RuntimeError):
    """Raised for invalid inbound runtime lifecycle transitions."""


class _ServiceAccountAuthentication(Protocol):
    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext,
    ) -> ControlPlaneServiceAccountAuthentication | None: ...


class _ServiceAccountReplay(Protocol):
    async def admit(
        self,
        authentication: ControlPlaneServiceAccountAuthentication,
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> None: ...


class _ServiceAccountPolicy(Protocol):
    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object: ...


class InboundServiceAccountSecurityBridge:
    """One-time late binding to the RFC-0023 Runtime security stack."""

    def __init__(self) -> None:
        self._authentication: _ServiceAccountAuthentication | None = None
        self._replay: _ServiceAccountReplay | None = None
        self._policy: _ServiceAccountPolicy | None = None

    @property
    def bound(self) -> bool:
        return self._authentication is not None

    def bind(
        self,
        *,
        authentication: _ServiceAccountAuthentication,
        replay: _ServiceAccountReplay,
        policy: _ServiceAccountPolicy,
    ) -> None:
        if self.bound:
            raise RuntimeError("inbound service-account security is already bound")
        if not callable(getattr(authentication, "authenticate", None)):
            raise TypeError("inbound service-account authentication is invalid")
        if not callable(getattr(replay, "admit", None)):
            raise TypeError("inbound service-account replay is invalid")
        if not callable(getattr(policy, "enforce", None)):
            raise TypeError("inbound service-account policy is invalid")
        self._authentication = authentication
        self._replay = replay
        self._policy = policy

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext | None = None,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        authentication = self._authentication
        if authentication is None or context is None:
            return None
        return await authentication.authenticate(
            authorization,
            context=context,
        )

    async def admit(
        self,
        authentication: ControlPlaneServiceAccountAuthentication,
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> None:
        replay = self._replay
        if replay is None:
            raise RuntimeError("inbound service-account replay is not bound")
        await replay.admit(authentication, request)

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object:
        policy = self._policy
        if policy is None:
            raise RuntimeError("inbound service-account policy is not bound")
        return await policy.enforce(
            context,
            action=action,
            resource=resource,
        )


class InboundRuntimeIngress:
    """Keep exact active-source ingress routes synchronized at Runtime."""

    def __init__(self, gateway: InboundEventGateway) -> None:
        if not isinstance(gateway, InboundEventGateway):
            raise TypeError("inbound runtime ingress requires InboundEventGateway")
        self._gateway = gateway
        self._routes: Mapping[str, InboundHttpRoute] = MappingProxyType({})
        self._adapter: InboundHttpAdapter | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def route_count(self) -> int:
        return len(self._routes)

    def handles(self, path: str) -> bool:
        return path in self._routes

    def body_limit(self, path: str) -> int:
        route = self._routes.get(path)
        if route is None:
            raise KeyError("inbound Runtime route is not registered")
        return route.source.max_body_bytes

    async def dispatch(
        self,
        *,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        transport_context: object | None,
    ) -> InboundHttpResponse:
        adapter = self._adapter
        if adapter is None or path not in self._routes:
            return (
                HTTPStatus.NOT_FOUND,
                {"error": "not_found"},
                {"Cache-Control": "no-store"},
            )
        return await adapter.dispatch(
            method=method,
            path=path,
            query=query,
            headers=headers,
            body=body,
            transport_context=transport_context,
        )

    async def load(
        self,
        sources: tuple[InboundEventSource, ...],
    ) -> None:
        async with self._lock:
            self._ensure_open()
            routes = {
                inbound_http_path(source): InboundHttpRoute(
                    source,
                    self._gateway,
                )
                for source in sources
                if source.accepting
            }
            if len(routes) != sum(source.accepting for source in sources):
                raise ValueError("inbound Runtime sources contain duplicate routes")
            self._publish(routes)

    async def source_changed(
        self,
        previous: InboundEventSource | None,
        current: InboundEventSource,
    ) -> None:
        if previous is not None and previous.id != current.id:
            raise ValueError("inbound Runtime route update changed source identity")
        async with self._lock:
            self._ensure_open()
            routes = dict(self._routes)
            if previous is not None:
                routes.pop(
                    inbound_http_path(previous),
                    None,
                )
            else:
                for path, route in tuple(routes.items()):
                    if route.source.id == current.id:
                        del routes[path]
            if current.accepting:
                path = inbound_http_path(current)
                existing = routes.get(path)
                if existing is not None and existing.source.id != current.id:
                    raise ValueError("inbound Runtime route name is already registered")
                routes[path] = InboundHttpRoute(
                    current,
                    self._gateway,
                )
            self._publish(routes)

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._routes = MappingProxyType({})
            self._adapter = None

    def _publish(
        self,
        routes: Mapping[str, InboundHttpRoute],
    ) -> None:
        ordered = {path: routes[path] for path in sorted(routes)}
        self._routes = MappingProxyType(ordered)
        self._adapter = None if not ordered else InboundHttpAdapter(tuple(ordered.values()))

    def _ensure_open(self) -> None:
        if self._closed:
            raise InboundRuntimeStateError("inbound Runtime ingress is closed")


@dataclass(frozen=True, slots=True)
class InboundRuntimeSnapshot:
    """Safe startup, recovery, routing, and lifecycle facts."""

    state: InboundRuntimeState
    registered_schemas: int
    loaded_sources: int
    active_routes: int
    recovered_events: int
    recovery_batches: int
    service_account_security_bound: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        values = (
            self.registered_schemas,
            self.loaded_sources,
            self.active_routes,
            self.recovered_events,
            self.recovery_batches,
        )
        if any(value < 0 for value in values):
            raise ValueError("inbound Runtime counters cannot be negative")
        if type(self.service_account_security_bound) is not bool:
            raise TypeError("inbound Runtime binding flag must be bool")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound Runtime snapshot version")
        object.__setattr__(
            self,
            "state",
            InboundRuntimeState(self.state),
        )


class InboundRuntimeOwner:
    """Register schemas, recover work, route sources, and own shutdown."""

    def __init__(
        self,
        *,
        normalizers: tuple[InboundEventNormalizer, ...],
        sources: InboundSourceRepository,
        events: InboundEventRepository,
        replay: InboundReplayRepository,
        schemas: InboundSchemaRegistry,
        ingress: InboundRuntimeIngress,
        limiter: InboundAdmissionLimiter,
        publisher: InboundEventPublisher,
        recovery: InboundPublicationRecovery,
        manager: InboundManager,
        service_account_security: InboundServiceAccountSecurityBridge,
        recovery_batch_size: int = DEFAULT_INBOUND_RECOVERY_BATCH_SIZE,
    ) -> None:
        if not normalizers:
            raise ValueError("inbound Runtime requires at least one normalizer")
        if not isinstance(schemas, InboundSchemaRegistry):
            raise TypeError("inbound Runtime owner requires InboundSchemaRegistry")
        if not isinstance(ingress, InboundRuntimeIngress):
            raise TypeError("inbound Runtime owner requires InboundRuntimeIngress")
        if not isinstance(limiter, InboundAdmissionLimiter):
            raise TypeError("inbound Runtime owner requires InboundAdmissionLimiter")
        if not isinstance(publisher, InboundEventPublisher):
            raise TypeError("inbound Runtime owner requires InboundEventPublisher")
        if not isinstance(recovery, InboundPublicationRecovery):
            raise TypeError("inbound Runtime owner requires InboundPublicationRecovery")
        if not isinstance(manager, InboundManager):
            raise TypeError("inbound Runtime owner requires InboundManager")
        if not isinstance(
            service_account_security,
            InboundServiceAccountSecurityBridge,
        ):
            raise TypeError("inbound Runtime owner requires service-account bridge")
        if not (1 <= recovery_batch_size <= MAX_INBOUND_RECOVERY_BATCH_SIZE):
            raise ValueError("inbound Runtime recovery batch size is outside bounds")
        self._normalizers = normalizers
        self._sources = sources
        self._events = events
        self._replay = replay
        self._schemas = schemas
        self._ingress = ingress
        self._limiter = limiter
        self._publisher = publisher
        self._recovery = recovery
        self._manager = manager
        self._service_account_security = service_account_security
        self._recovery_batch_size = recovery_batch_size
        self._state = InboundRuntimeState.CREATED
        self._registered_schemas = 0
        self._loaded_sources = 0
        self._recovered_events = 0
        self._recovery_batches = 0
        self._resources_closed = False
        self._state_lock = asyncio.Lock()

    @property
    def state(self) -> InboundRuntimeState:
        return self._state

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not InboundRuntimeState.CREATED:
                raise InboundRuntimeStateError(
                    f"cannot start inbound Runtime from {self._state.value}"
                )
            self._state = InboundRuntimeState.STARTING

        try:
            for normalizer in self._normalizers:
                self._schemas.register(normalizer)
                self._registered_schemas += 1

            sources = await _all_sources(self._sources)
            for source in sources:
                self._schemas.validate_source(source)
            await self._ingress.load(sources)
            self._loaded_sources = len(sources)

            while True:
                batch = await self._recovery.recover_publishing(limit=self._recovery_batch_size)
                self._recovery_batches += 1
                self._recovered_events += batch.considered
                if batch.considered < self._recovery_batch_size:
                    break
        except BaseException:
            try:
                await asyncio.shield(self._close_resources())
            except BaseException:
                pass
            async with self._state_lock:
                self._state = InboundRuntimeState.FAILED
            raise

        async with self._state_lock:
            self._state = InboundRuntimeState.RUNNING

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is InboundRuntimeState.STOPPED:
                return
            if self._state not in {
                InboundRuntimeState.CREATED,
                InboundRuntimeState.RUNNING,
                InboundRuntimeState.FAILED,
            }:
                raise InboundRuntimeStateError(
                    f"cannot stop inbound Runtime from {self._state.value}"
                )
            self._state = InboundRuntimeState.STOPPING

        try:
            await self._close_resources()
        except BaseException:
            async with self._state_lock:
                self._state = InboundRuntimeState.FAILED
            raise

        async with self._state_lock:
            self._state = InboundRuntimeState.STOPPED

    async def snapshot(self) -> InboundRuntimeSnapshot:
        async with self._state_lock:
            return InboundRuntimeSnapshot(
                state=self._state,
                registered_schemas=self._registered_schemas,
                loaded_sources=self._loaded_sources,
                active_routes=self._ingress.route_count,
                recovered_events=self._recovered_events,
                recovery_batches=self._recovery_batches,
                service_account_security_bound=(self._service_account_security.bound),
            )

    async def _close_resources(self) -> None:
        if self._resources_closed:
            return
        self._resources_closed = True
        first_error: Exception | None = None

        async def close(
            operation: InboundRuntimeCloseOperation,
        ) -> None:
            nonlocal first_error
            try:
                await operation
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                if first_error is None:
                    first_error = exception

        await close(self._ingress.close())
        await close(self._limiter.close())
        await close(self._publisher.close())
        await close(self._manager.close())
        await close(self._recovery.close())
        await close(self._events.close())
        await close(self._replay.close())
        await close(self._sources.close())

        if first_error is not None:
            raise RuntimeError("inbound Runtime resource shutdown failed") from first_error


@dataclass(frozen=True, slots=True)
class InboundRuntimeBundle:
    """All inbound services sharing one durable state boundary."""

    sources: InboundSourceRepository
    events: InboundEventRepository
    replay: InboundReplayRepository
    schemas: InboundSchemaRegistry
    service_account_security: InboundServiceAccountSecurityBridge
    authentication: InboundAuthenticationVerifier
    admission: InboundReplayIdempotencyService
    limiter: InboundAdmissionLimiter
    gateway: InboundEventGateway
    ingress: InboundRuntimeIngress
    publisher: InboundEventPublisher
    publisher_worker: InboundPublisherWorker
    recovery: InboundPublicationRecovery
    recovery_worker: InboundRecoveryWorker
    manager: InboundManager
    owner: InboundRuntimeOwner


def create_inbound_runtime(
    *,
    event_bus: EventBus,
    sources: InboundSourceRepository,
    events: InboundEventRepository,
    replay: InboundReplayRepository,
    secrets: SecretsManager,
    normalizers: tuple[InboundEventNormalizer, ...],
    policy_engine: PolicyEngine,
    hmac_context: SecurityContext | None = None,
    manager_config: InboundManagerConfig | None = None,
    publisher_config: InboundPublisherConfig | None = None,
    admission_policy: InboundAdmissionLimitPolicy | None = None,
    publisher_poll_interval: float = (DEFAULT_INBOUND_PUBLISHER_POLL_INTERVAL),
    recovery_poll_interval: float = (DEFAULT_INBOUND_RECOVERY_POLL_INTERVAL),
    recovery_batch_size: int = DEFAULT_INBOUND_RECOVERY_BATCH_SIZE,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> InboundRuntimeBundle:
    """Compose the optional inbound subsystem without starting it."""

    if not isinstance(event_bus, EventBus):
        raise TypeError("inbound Runtime requires EventBus")
    if not isinstance(secrets, SecretsManager):
        raise TypeError("inbound Runtime requires SecretsManager")
    if not isinstance(policy_engine, PolicyEngine):
        raise TypeError("inbound Runtime requires PolicyEngine")
    normalized_normalizers = tuple(normalizers)
    if not normalized_normalizers:
        raise ValueError("inbound Runtime requires at least one normalizer")
    if publisher_poll_interval <= 0:
        raise ValueError("inbound publisher poll interval must be positive")
    if recovery_poll_interval <= 0:
        raise ValueError("inbound recovery poll interval must be positive")

    security_context = hmac_context or SecurityContext(
        principal="phoenix.inbound",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset(
            {
                "secret.read",
                "secret.lease.revoke",
            }
        ),
        attributes={"component": "inbound-events"},
    )
    if not isinstance(security_context, SecurityContext):
        raise TypeError("inbound HMAC context must be SecurityContext")
    if not security_context.authenticated:
        raise ValueError("inbound HMAC context must be authenticated")

    schemas = InboundSchemaRegistry()
    service_account_security = InboundServiceAccountSecurityBridge()
    authentication = InboundAuthenticationVerifier(
        secrets=secrets,
        security_context=security_context,
        service_account_authenticator=service_account_security,
        service_account_replay=service_account_security,
        service_account_policy=service_account_security,
    )
    admission = InboundReplayIdempotencyService(
        events,
        replay,
    )
    limiter = InboundAdmissionLimiter(admission_policy)
    gateway = InboundEventGateway(
        sources=sources,
        authentication=authentication,
        schemas=schemas,
        admission=admission,
        policy=PolicyEngineInboundAdmissionPolicy(policy_engine),
        limits=limiter,
    )
    ingress = InboundRuntimeIngress(gateway)
    recovery = InboundPublicationRecovery(
        sources=sources,
        events=events,
        replay=replay,
        audit=audit,
        observability=observability,
    )
    publisher = InboundEventPublisher(
        sources=sources,
        events=events,
        event_bus=event_bus,
        config=publisher_config,
        audit=audit,
        observability=observability,
    )
    manager = InboundManager(
        sources=sources,
        events=events,
        replay=replay,
        recovery=recovery,
        schemas=schemas,
        config=manager_config,
        audit=audit,
        observability=observability,
        route_registry=ingress,
    )
    publisher_worker = InboundPublisherWorker(
        publisher,
        poll_interval=publisher_poll_interval,
    )
    recovery_worker = InboundRecoveryWorker(
        recovery,
        poll_interval=recovery_poll_interval,
    )
    owner = InboundRuntimeOwner(
        normalizers=normalized_normalizers,
        sources=sources,
        events=events,
        replay=replay,
        schemas=schemas,
        ingress=ingress,
        limiter=limiter,
        publisher=publisher,
        recovery=recovery,
        manager=manager,
        service_account_security=service_account_security,
        recovery_batch_size=recovery_batch_size,
    )
    return InboundRuntimeBundle(
        sources=sources,
        events=events,
        replay=replay,
        schemas=schemas,
        service_account_security=service_account_security,
        authentication=authentication,
        admission=admission,
        limiter=limiter,
        gateway=gateway,
        ingress=ingress,
        publisher=publisher,
        publisher_worker=publisher_worker,
        recovery=recovery,
        recovery_worker=recovery_worker,
        manager=manager,
        owner=owner,
    )


async def _all_sources(
    repository: InboundSourceRepository,
) -> tuple[InboundEventSource, ...]:
    sources: list[InboundEventSource] = []
    request = DEFAULT_INBOUND_PAGE_REQUEST
    while True:
        page = await repository.list(request)
        sources.extend(page.items)
        next_offset = page.page.next_offset
        if next_offset is None:
            return tuple(sources)
        request = InboundPageRequest(
            offset=next_offset,
            limit=MAX_INBOUND_PAGE_SIZE,
        )
