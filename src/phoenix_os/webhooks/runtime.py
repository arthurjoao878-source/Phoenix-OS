"""Phoenix Runtime ownership for durable signed webhooks."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from phoenix_os.audit import AuditLedger
from phoenix_os.events import EventBus
from phoenix_os.observability import ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretsManager
from phoenix_os.webhooks.contracts import (
    WebhookDeliveryRepository,
    WebhookEgressPolicy,
    WebhookPayloadSerializer,
    WebhookSubscriptionRepository,
)
from phoenix_os.webhooks.dispatcher import (
    WebhookDispatchBatch,
    WebhookDispatcher,
    WebhookDispatcherConfig,
)
from phoenix_os.webhooks.manager import WebhookManager
from phoenix_os.webhooks.recovery import (
    DEFAULT_WEBHOOK_RECOVERY_BATCH_SIZE,
    MAX_WEBHOOK_RECOVERY_BATCH_SIZE,
    WebhookDeliveryRecovery,
)
from phoenix_os.webhooks.registry import WebhookEventRegistry
from phoenix_os.webhooks.scheduling import (
    WebhookDeliveryScheduler,
    WebhookEventAdapter,
)
from phoenix_os.webhooks.signing import WebhookSigner
from phoenix_os.webhooks.transport import (
    WebhookTransport,
    WebhookTransportConfig,
)

DEFAULT_WEBHOOK_DISPATCH_POLL_INTERVAL = 1.0


class WebhookRuntimeState(StrEnum):
    """One-shot lifecycle state for Runtime-owned webhook resources."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class WebhookRuntimeStateError(RuntimeError):
    """Raised for invalid webhook runtime lifecycle transitions."""


@dataclass(frozen=True, slots=True)
class WebhookDispatcherWorkerSnapshot:
    """Safe bounded dispatcher-worker counters."""

    state: WebhookRuntimeState
    ticks: int
    considered: int
    failures: int
    last_error: str | None = None

    def __post_init__(self) -> None:
        counters = (
            self.ticks,
            self.considered,
            self.failures,
        )
        if any(value < 0 for value in counters):
            raise ValueError("webhook dispatcher worker counters cannot be negative")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", WebhookRuntimeState(self.state))
        object.__setattr__(self, "last_error", error)


class WebhookDispatcherWorker:
    """Run bounded due-delivery scans under the Phoenix Runtime lifecycle."""

    def __init__(
        self,
        dispatcher: WebhookDispatcher,
        *,
        poll_interval: float = DEFAULT_WEBHOOK_DISPATCH_POLL_INTERVAL,
    ) -> None:
        if not isinstance(dispatcher, WebhookDispatcher):
            raise TypeError("webhook dispatcher worker requires a WebhookDispatcher")
        if poll_interval <= 0:
            raise ValueError("webhook dispatch poll interval must be positive")
        self._dispatcher = dispatcher
        self._poll_interval = poll_interval
        self._state = WebhookRuntimeState.CREATED
        self._ticks = 0
        self._considered = 0
        self._failures = 0
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> WebhookRuntimeState:
        return self._state

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not WebhookRuntimeState.CREATED:
                raise WebhookRuntimeStateError(
                    f"cannot start webhook dispatcher worker from {self._state.value}"
                )
            if self._dispatcher.closed:
                raise WebhookRuntimeStateError("webhook dispatcher is already closed")
            self._state = WebhookRuntimeState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name="phoenix-webhook-dispatcher",
            )

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is WebhookRuntimeState.STOPPED:
                return
            if self._state not in {
                WebhookRuntimeState.CREATED,
                WebhookRuntimeState.RUNNING,
            }:
                raise WebhookRuntimeStateError(
                    f"cannot stop webhook dispatcher worker from {self._state.value}"
                )
            self._state = WebhookRuntimeState.STOPPING
            self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = WebhookRuntimeState.STOPPED

    async def run_once(self) -> WebhookDispatchBatch:
        if self._state is not WebhookRuntimeState.RUNNING:
            raise WebhookRuntimeStateError(
                f"cannot run webhook dispatcher from {self._state.value}"
            )
        async with self._tick_lock:
            self._ticks += 1
            try:
                batch = await self._dispatcher.dispatch_due()
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return WebhookDispatchBatch(())
            self._considered += batch.considered
            self._last_error = None
            return batch

    async def snapshot(self) -> WebhookDispatcherWorkerSnapshot:
        async with self._state_lock:
            return WebhookDispatcherWorkerSnapshot(
                state=self._state,
                ticks=self._ticks,
                considered=self._considered,
                failures=self._failures,
                last_error=self._last_error,
            )

    async def _run_loop(self) -> None:
        while not self._stop_requested.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    self._stop_requested.wait(),
                    timeout=self._poll_interval,
                )
            except TimeoutError:
                pass


@dataclass(frozen=True, slots=True)
class WebhookRuntimeSnapshot:
    """Safe Runtime-owned registration and recovery facts."""

    state: WebhookRuntimeState
    registered_events: int
    recovered_deliveries: int
    recovery_batches: int

    def __post_init__(self) -> None:
        counters = (
            self.registered_events,
            self.recovered_deliveries,
            self.recovery_batches,
        )
        if any(value < 0 for value in counters):
            raise ValueError("webhook runtime counters cannot be negative")
        object.__setattr__(self, "state", WebhookRuntimeState(self.state))


class WebhookRuntimeOwner:
    """Register serializers, recover interrupted work, and close shared resources."""

    def __init__(
        self,
        *,
        serializers: tuple[WebhookPayloadSerializer, ...],
        subscriptions: WebhookSubscriptionRepository,
        deliveries: WebhookDeliveryRepository,
        registry: WebhookEventRegistry,
        scheduler: WebhookDeliveryScheduler,
        dispatcher: WebhookDispatcher,
        recovery: WebhookDeliveryRecovery,
        manager: WebhookManager,
        transport: WebhookTransport,
        recovery_batch_size: int = DEFAULT_WEBHOOK_RECOVERY_BATCH_SIZE,
    ) -> None:
        if not serializers:
            raise ValueError("webhook runtime requires at least one serializer")
        if not isinstance(registry, WebhookEventRegistry):
            raise TypeError("webhook runtime owner requires a WebhookEventRegistry")
        if not isinstance(scheduler, WebhookDeliveryScheduler):
            raise TypeError("webhook runtime owner requires a WebhookDeliveryScheduler")
        if not isinstance(dispatcher, WebhookDispatcher):
            raise TypeError("webhook runtime owner requires a WebhookDispatcher")
        if not isinstance(recovery, WebhookDeliveryRecovery):
            raise TypeError("webhook runtime owner requires WebhookDeliveryRecovery")
        if not isinstance(manager, WebhookManager):
            raise TypeError("webhook runtime owner requires a WebhookManager")
        if not isinstance(transport, WebhookTransport):
            raise TypeError("webhook runtime owner requires a WebhookTransport")
        if not 1 <= recovery_batch_size <= MAX_WEBHOOK_RECOVERY_BATCH_SIZE:
            raise ValueError("webhook recovery batch size is outside supported bounds")
        self._serializers = serializers
        self._subscriptions = subscriptions
        self._deliveries = deliveries
        self._registry = registry
        self._scheduler = scheduler
        self._dispatcher = dispatcher
        self._recovery = recovery
        self._manager = manager
        self._transport = transport
        self._recovery_batch_size = recovery_batch_size
        self._state = WebhookRuntimeState.CREATED
        self._registered_events = 0
        self._recovered_deliveries = 0
        self._recovery_batches = 0
        self._resources_closed = False
        self._state_lock = asyncio.Lock()

    @property
    def state(self) -> WebhookRuntimeState:
        return self._state

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not WebhookRuntimeState.CREATED:
                raise WebhookRuntimeStateError(
                    f"cannot start webhook runtime owner from {self._state.value}"
                )
            self._state = WebhookRuntimeState.STARTING

        try:
            for serializer in self._serializers:
                await self._registry.register(serializer)
                self._registered_events += 1

            while True:
                batch = await self._recovery.recover_in_flight(limit=self._recovery_batch_size)
                self._recovery_batches += 1
                self._recovered_deliveries += batch.considered
                if batch.considered < self._recovery_batch_size:
                    break
        except BaseException:
            try:
                await asyncio.shield(self._close_resources())
            except BaseException:
                pass
            async with self._state_lock:
                self._state = WebhookRuntimeState.FAILED
            raise

        async with self._state_lock:
            self._state = WebhookRuntimeState.RUNNING

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is WebhookRuntimeState.STOPPED:
                return
            if self._state not in {
                WebhookRuntimeState.CREATED,
                WebhookRuntimeState.RUNNING,
                WebhookRuntimeState.FAILED,
            }:
                raise WebhookRuntimeStateError(
                    f"cannot stop webhook runtime owner from {self._state.value}"
                )
            self._state = WebhookRuntimeState.STOPPING

        try:
            await self._close_resources()
        except BaseException:
            async with self._state_lock:
                self._state = WebhookRuntimeState.FAILED
            raise

        async with self._state_lock:
            self._state = WebhookRuntimeState.STOPPED

    async def snapshot(self) -> WebhookRuntimeSnapshot:
        async with self._state_lock:
            return WebhookRuntimeSnapshot(
                state=self._state,
                registered_events=self._registered_events,
                recovered_deliveries=self._recovered_deliveries,
                recovery_batches=self._recovery_batches,
            )

    async def _close_resources(self) -> None:
        if self._resources_closed:
            return
        self._resources_closed = True
        first_error: Exception | None = None

        async def close_async(
            operation: Callable[[], Awaitable[None]],
        ) -> None:
            nonlocal first_error
            try:
                await operation()
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                if first_error is None:
                    first_error = exception

        await close_async(self._dispatcher.close)
        await close_async(self._manager.close)
        await close_async(self._recovery.close)
        await close_async(self._scheduler.close)
        await close_async(self._registry.close)

        try:
            self._transport.close()
        except Exception as exception:
            if first_error is None:
                first_error = exception

        await close_async(self._deliveries.close)
        await close_async(self._subscriptions.close)

        if first_error is not None:
            raise RuntimeError("webhook runtime resource shutdown failed") from first_error


@dataclass(frozen=True, slots=True)
class WebhookRuntimeBundle:
    """All webhook services sharing one durable state boundary."""

    subscriptions: WebhookSubscriptionRepository
    deliveries: WebhookDeliveryRepository
    registry: WebhookEventRegistry
    scheduler: WebhookDeliveryScheduler
    event_adapter: WebhookEventAdapter
    signer: WebhookSigner
    transport: WebhookTransport
    dispatcher: WebhookDispatcher
    dispatcher_worker: WebhookDispatcherWorker
    recovery: WebhookDeliveryRecovery
    manager: WebhookManager
    owner: WebhookRuntimeOwner


def create_webhook_runtime(
    *,
    events: EventBus,
    subscriptions: WebhookSubscriptionRepository,
    deliveries: WebhookDeliveryRepository,
    secrets: SecretsManager,
    serializers: tuple[WebhookPayloadSerializer, ...],
    egress_policies: Mapping[str, WebhookEgressPolicy],
    signing_context: SecurityContext | None = None,
    dispatcher_config: WebhookDispatcherConfig | None = None,
    transport_config: WebhookTransportConfig | None = None,
    dispatch_poll_interval: float = DEFAULT_WEBHOOK_DISPATCH_POLL_INTERVAL,
    recovery_batch_size: int = DEFAULT_WEBHOOK_RECOVERY_BATCH_SIZE,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> WebhookRuntimeBundle:
    """Compose the optional durable webhook subsystem without starting it."""

    if not isinstance(events, EventBus):
        raise TypeError("webhook runtime requires an EventBus")
    if not isinstance(secrets, SecretsManager):
        raise TypeError("webhook runtime requires a SecretsManager")
    normalized_serializers = tuple(serializers)
    if not normalized_serializers:
        raise ValueError("webhook runtime requires at least one serializer")
    normalized_policies = dict(egress_policies)
    if not normalized_policies:
        raise ValueError("webhook runtime requires at least one egress policy")

    resolved_context = signing_context or SecurityContext(
        principal="phoenix.webhooks",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset(
            {
                "secret.read",
                "secret.lease.revoke",
            }
        ),
        attributes={"component": "webhooks"},
    )
    if not isinstance(resolved_context, SecurityContext):
        raise TypeError("webhook signing context must be SecurityContext")
    if not resolved_context.authenticated:
        raise ValueError("webhook signing context must be authenticated")

    registry = WebhookEventRegistry()
    scheduler = WebhookDeliveryScheduler(
        registry=registry,
        subscriptions=subscriptions,
        deliveries=deliveries,
    )
    event_adapter = WebhookEventAdapter(
        events=events,
        scheduler=scheduler,
    )
    signer = WebhookSigner(
        secrets=secrets,
        context=resolved_context,
    )
    transport = WebhookTransport(config=transport_config)
    dispatcher = WebhookDispatcher(
        subscriptions=subscriptions,
        deliveries=deliveries,
        signer=signer,
        transport=transport,
        egress_policies=normalized_policies,
        config=dispatcher_config,
        audit=audit,
        observability=observability,
    )
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        audit=audit,
        observability=observability,
    )
    manager = WebhookManager(
        subscriptions=subscriptions,
        deliveries=deliveries,
        recovery=recovery,
        registry=registry,
        audit=audit,
        observability=observability,
    )
    dispatcher_worker = WebhookDispatcherWorker(
        dispatcher,
        poll_interval=dispatch_poll_interval,
    )
    owner = WebhookRuntimeOwner(
        serializers=normalized_serializers,
        subscriptions=subscriptions,
        deliveries=deliveries,
        registry=registry,
        scheduler=scheduler,
        dispatcher=dispatcher,
        recovery=recovery,
        manager=manager,
        transport=transport,
        recovery_batch_size=recovery_batch_size,
    )
    return WebhookRuntimeBundle(
        subscriptions=subscriptions,
        deliveries=deliveries,
        registry=registry,
        scheduler=scheduler,
        event_adapter=event_adapter,
        signer=signer,
        transport=transport,
        dispatcher=dispatcher,
        dispatcher_worker=dispatcher_worker,
        recovery=recovery,
        manager=manager,
        owner=owner,
    )
