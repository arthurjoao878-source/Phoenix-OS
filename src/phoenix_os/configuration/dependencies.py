"""Deterministic asynchronous dependency composition for Phoenix Runtime."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, cast
from uuid import uuid4

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.configuration.contracts import Configuration
from phoenix_os.configuration.errors import (
    DependencyCycleError,
    DuplicateServiceError,
    InvalidLifecycleServiceError,
    ServiceFactoryError,
    ServiceNotFoundError,
)
from phoenix_os.events import EventBus
from phoenix_os.kernel import Kernel
from phoenix_os.observability import EventObserver, ObservabilityHub
from phoenix_os.plugins import PluginManager
from phoenix_os.policy import PolicyEngine, SecurityContext
from phoenix_os.runtime import (
    ComponentSpec,
    LifecycleComponent,
    PhoenixRuntime,
    RuntimeContext,
    RuntimeState,
)
from phoenix_os.state import StateStore, StateStoreRegistry

if TYPE_CHECKING:
    from phoenix_os.agent import (
        AgentMemoryRuntimeConfiguration,
        AgentModelTurnAdapter,
        AgentServiceConfiguration,
        AgentWorkspaceCleanupRuntimeConfiguration,
        AgentWorkspaceRuntimeConfiguration,
        AgentWorkspaceTransferRuntimeConfiguration,
        CheckpointProtector,
        DurableAdministrationConfiguration,
        DurableApprovalRevalidator,
        DurableCompatibilityValidator,
        DurableLeaseManager,
        DurableMachineAdministrationGuard,
        DurableRecoveryWorkerConfiguration,
        DurableRetentionWorkerConfiguration,
        DurableRunStore,
        MemoryDerivedIndex,
        MemoryEmbeddingProvider,
        RetentionPolicy,
        ToolAdapter,
        ToolApprovalResolver,
        ToolApprovalService,
        ToolResourceResolver,
        WorkspaceBackingAdapter,
        WorkspaceTransferAdapter,
    )
    from phoenix_os.agent.durable_cleanup_administration import (
        DurableCleanupAdministration,
    )
    from phoenix_os.agent.durable_reconciliation_administration import (
        DurableReconciliationAdministration,
        DurableReconciliationStatusLookup,
    )
    from phoenix_os.agent.durable_runtime import DurableStorageLifecycle
    from phoenix_os.audit import AuditLedger
    from phoenix_os.control_plane import (
        AdminTokenAuthenticator,
        ControlPlaneClientRateLimitPolicy,
        ControlPlaneCommandJournalRepository,
        ControlPlaneCommandRetentionPolicy,
        ControlPlaneDurableAdministrationProtection,
        ControlPlaneDurableSessionCookiePolicy,
        ControlPlaneDurableSessionPolicy,
        ControlPlaneDurableSessionRepository,
        ControlPlaneDurableSessionRetentionPolicy,
        ControlPlaneEventStreamConfig,
        ControlPlaneHttpConfig,
        ControlPlaneNetworkPolicy,
        ControlPlaneOperatorRegistry,
        ControlPlaneOperatorToken,
        ControlPlaneRemoteLoginThrottlePolicy,
        ControlPlaneStepUpPolicy,
        ControlPlaneTlsListenerConfig,
        JobRecordSource,
    )
    from phoenix_os.control_plane.service_account_contracts import (
        ControlPlaneServiceAccountRepository,
    )
    from phoenix_os.control_plane.service_account_machine_http import (
        ControlPlaneServiceAccountMachineRoute,
    )
    from phoenix_os.host_automation import (
        HostAutomationAdapter,
        HostAutomationApprovalGate,
        HostAutomationObservabilityConfiguration,
        HostAutomationService,
    )
    from phoenix_os.identity import AuthenticationManager
    from phoenix_os.inbound_events import (
        InboundAdmissionLimitPolicy,
        InboundEventNormalizer,
        InboundEventRepository,
        InboundPublisherConfig,
        InboundReplayRepository,
        InboundSourceRepository,
    )
    from phoenix_os.inference.configuration import InferenceServiceConfiguration
    from phoenix_os.inference.contracts import ModelProvider
    from phoenix_os.jobs import JobScheduler
    from phoenix_os.secrets import SecretsManager
    from phoenix_os.webhooks import (
        WebhookDeliveryRepository,
        WebhookDispatcherConfig,
        WebhookEgressPolicy,
        WebhookPayloadSerializer,
        WebhookSubscriptionRepository,
        WebhookTransportConfig,
    )
    from phoenix_os.workflows import WorkflowOrchestrator

_RESERVED_DEFINITION_NAMES = frozenset(
    {
        "kernel",
        "events",
        "identity",
        "agent",
        "agent.administration",
        "agent.admission",
        "agent.approvals",
        "agent.executor",
        "agent.health",
        "agent.memory",
        "agent.memory.administration",
        "agent.memory.index",
        "agent.memory.owner",
        "agent.memory.retrieval",
        "agent.memory.store",
        "agent.registry",
        "agent.runtime",
        "agent.durable",
        "agent.durable.administration",
        "agent.durable.cleanup-administration",
        "agent.durable.compatibility",
        "agent.durable.leases",
        "agent.durable.observer",
        "agent.durable.protector",
        "agent.durable.recovery",
        "agent.durable.recovery-worker",
        "agent.durable.reconciliation-administration",
        "agent.durable.retention",
        "agent.durable.retention-worker",
        "agent.durable.storage",
        "inference",
        "inference.administration",
        "inference.health",
        "inference.registry",
        "inference.runtime",
        "jobs",
        "audit",
        "capabilities",
        "configuration",
        "control_plane",
        "control_plane.events",
        "control_plane.commands",
        "control_plane.durable-cleanup",
        "control_plane.durable-cleanup-http",
        "control_plane.durable-reconciliation",
        "control_plane.durable-reconciliation-http",
        "control_plane.command-journal",
        "control_plane.command-history",
        "control_plane.command-recovery",
        "control_plane.command-retention",
        "control_plane.operator-registry",
        "control_plane.operator-access",
        "control_plane.operator-sessions",
        "control_plane.operator-session-history",
        "control_plane.operator-session-recovery",
        "control_plane.operator-session-retention",
        "control_plane.operator-step-up",
        "control_plane.operators",
        "control_plane.http",
        "control_plane.network",
        "control_plane.network-guard",
        "control_plane.secure-http",
        "control_plane.remote-login",
        "control_plane.remote-audit",
        "control_plane.webhook-http",
        "control_plane.webhooks",
        "control_plane.inbound",
        "control_plane.inbound-http",
        "control_plane.inbound-management-http",
        "inbound",
        "inbound.admission",
        "inbound.authentication",
        "inbound.events",
        "inbound.gateway",
        "inbound.ingress",
        "inbound.limiter",
        "inbound.manager",
        "inbound.owner",
        "inbound.publisher",
        "inbound.publisher-worker",
        "inbound.recovery",
        "inbound.recovery-worker",
        "inbound.replay",
        "inbound.schemas",
        "inbound.service-account-security",
        "inbound.sources",
        "observability",
        "plugins",
        "policy",
        "state",
        "runtime",
        "secrets",
        "webhooks",
        "webhooks.deliveries",
        "webhooks.dispatcher",
        "webhooks.dispatcher-worker",
        "webhooks.events",
        "webhooks.manager",
        "webhooks.owner",
        "webhooks.recovery",
        "webhooks.registry",
        "webhooks.scheduler",
        "webhooks.signer",
        "webhooks.subscriptions",
        "webhooks.transport",
        "workflows",
    }
)

_HOST_AUTOMATION_DEFINITION_NAMES = frozenset(
    {
        "host",
        "host.administration",
        "host.health",
    }
)

_WORKSPACE_DEFINITION_NAMES = frozenset(
    {
        "agent.workspace",
        "agent.workspace.administration",
        "agent.workspace.backing",
        "agent.workspace.cleanup",
        "agent.workspace.owner",
        "agent.workspace.observer",
        "agent.workspace.service",
        "agent.workspace.store",
        "agent.workspace.transfer",
    }
)


class DependencyResolver(Protocol):
    """Read-only service lookup exposed to factories."""

    def service(self, name: str) -> object: ...


type ServiceFactory = Callable[[DependencyResolver, Configuration], object | Awaitable[object]]


def _normalize_service_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise ValueError("service name must not be blank")
    return normalized


@dataclass(frozen=True, slots=True)
class ServiceDefinition:
    """One named singleton service and its explicit dependencies."""

    name: str
    factory: ServiceFactory = field(repr=False)
    dependencies: tuple[str, ...] = ()
    lifecycle: bool = False

    def __post_init__(self) -> None:
        name = _normalize_service_name(self.name)
        if name in _RESERVED_DEFINITION_NAMES:
            raise ValueError(f"reserved service name cannot be registered: {name}")
        if not callable(self.factory):
            raise TypeError("service factory must be callable")

        dependencies = tuple(_normalize_service_name(item) for item in self.dependencies)
        if len(dependencies) != len(set(dependencies)):
            raise ValueError(f"duplicate dependencies for service: {name}")
        if name in dependencies:
            raise ValueError(f"service cannot depend on itself: {name}")

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "dependencies", dependencies)


class _MutableResolver:
    def __init__(self, services: dict[str, object]) -> None:
        self._services = services

    def service(self, name: str) -> object:
        normalized = _normalize_service_name(name)
        try:
            return self._services[normalized]
        except KeyError as exception:
            raise ServiceNotFoundError(normalized) from exception


@dataclass(frozen=True, slots=True)
class ServiceContainer:
    """Immutable result of dependency composition."""

    services: Mapping[str, object]
    components: tuple[ComponentSpec, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "services", MappingProxyType(dict(self.services)))

    def service(self, name: str) -> object:
        normalized = _normalize_service_name(name)
        try:
            return self.services[normalized]
        except KeyError as exception:
            raise ServiceNotFoundError(normalized) from exception


class ServiceComposer:
    """Build singleton services using deterministic dependency traversal."""

    def __init__(self, definitions: Iterable[ServiceDefinition] = ()) -> None:
        definitions_tuple = tuple(definitions)
        by_name: dict[str, ServiceDefinition] = {}
        for definition in definitions_tuple:
            if definition.name in by_name:
                raise DuplicateServiceError(f"duplicate service definition: {definition.name}")
            by_name[definition.name] = definition
        self._definitions = definitions_tuple
        self._by_name = MappingProxyType(by_name)

    async def compose(
        self,
        configuration: Configuration,
        *,
        base_services: Mapping[str, object] | None = None,
    ) -> ServiceContainer:
        services = {} if base_services is None else dict(base_services)
        conflicting = services.keys() & self._by_name.keys()
        if conflicting:
            names = ", ".join(sorted(conflicting))
            raise DuplicateServiceError(f"base services conflict with definitions: {names}")

        resolver = _MutableResolver(services)
        visiting: list[str] = []
        built: set[str] = set(services)
        components: list[ComponentSpec] = []

        async def build(name: str) -> None:
            if name in built:
                return
            if name in visiting:
                start = visiting.index(name)
                raise DependencyCycleError(tuple((*visiting[start:], name)))

            try:
                definition = self._by_name[name]
            except KeyError as exception:
                raise ServiceNotFoundError(name) from exception

            visiting.append(name)
            try:
                for dependency in definition.dependencies:
                    if dependency not in services and dependency not in self._by_name:
                        raise ServiceNotFoundError(dependency)
                    await build(dependency)

                try:
                    result = definition.factory(resolver, configuration)
                    service = await result if inspect.isawaitable(result) else result
                except (DependencyCycleError, ServiceNotFoundError):
                    raise
                except Exception as exception:
                    raise ServiceFactoryError(name, exception) from exception

                services[name] = service
                built.add(name)
                if definition.lifecycle:
                    start_hook = getattr(service, "start", None)
                    stop_hook = getattr(service, "stop", None)
                    if not callable(start_hook) or not callable(stop_hook):
                        raise InvalidLifecycleServiceError(
                            f"lifecycle service {name!r} must expose callable start and stop hooks"
                        )
                    components.append(ComponentSpec(name, cast(LifecycleComponent, service)))
            finally:
                visiting.pop()

        for definition in self._definitions:
            await build(definition.name)

        return ServiceContainer(services=services, components=tuple(components))


class _DurableReconciliationAdministrationLifecycle:
    """Own destructive confirmation admission above the fenced durable coordinator."""

    def __init__(
        self,
        *,
        protection: ControlPlaneDurableAdministrationProtection,
        coordinator: DurableReconciliationAdministration,
    ) -> None:
        self._protection = protection
        self._coordinator = coordinator
        self._http_close: Callable[[], Awaitable[None]] | None = None

    def bind_http_close(self, close: Callable[[], Awaitable[None]]) -> None:
        """Bind server-owned HTTP pending-confirmation cleanup exactly once."""

        if not callable(close):
            raise TypeError("durable reconciliation HTTP close must be callable")
        if self._http_close is not None:
            raise RuntimeError("durable reconciliation HTTP close is already bound")
        self._http_close = close

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._http_close is None:
            raise RuntimeError("durable reconciliation HTTP cleanup is not bound")
        if self._coordinator.closed:
            raise RuntimeError("durable reconciliation coordinator is closed")
        if (await self._protection.snapshot()).closed:
            raise RuntimeError("durable reconciliation confirmation protection is closed")

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        await _await_durable_administration_close(self._close_owned())

    async def _close_owned(self) -> None:
        failure: BaseException | None = None
        if self._http_close is not None:
            try:
                await self._http_close()
            except (Exception, asyncio.CancelledError) as exception:
                failure = exception

        try:
            await self._protection.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        try:
            await self._coordinator.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        if failure is not None:
            raise failure


async def _await_durable_administration_close(operation: Awaitable[None]) -> None:
    task = asyncio.ensure_future(operation)
    cancelled = False
    while True:
        try:
            await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            cancelled = True
            if task.done():
                break
    task.result()
    if cancelled:
        raise asyncio.CancelledError()


class _DurableReconciliationStorageLifecycle:
    """Guarantee reconciliation ownership closes before durable storage."""

    def __init__(
        self,
        *,
        storage: DurableStorageLifecycle,
        reconciliation: _DurableReconciliationAdministrationLifecycle,
    ) -> None:
        self._storage = storage
        self._reconciliation = reconciliation

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        try:
            await self._storage.start(context)
        except (Exception, asyncio.CancelledError):
            try:
                await self.close()
            except (Exception, asyncio.CancelledError):
                pass
            raise

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        await _await_durable_administration_close(self._close_owned())

    async def _close_owned(self) -> None:
        failure: BaseException | None = None
        try:
            await self._reconciliation.close()
        except (Exception, asyncio.CancelledError) as exception:
            failure = exception

        try:
            await self._storage.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        if failure is not None:
            raise failure


class _DurableCleanupAdministrationLifecycle:
    """Own cleanup confirmation admission above the bounded cleanup coordinator."""

    def __init__(
        self,
        *,
        protection: ControlPlaneDurableAdministrationProtection,
        coordinator: DurableCleanupAdministration,
    ) -> None:
        self._protection = protection
        self._coordinator = coordinator
        self._http_close: Callable[[], Awaitable[None]] | None = None

    def bind_http_close(self, close: Callable[[], Awaitable[None]]) -> None:
        """Bind server-owned HTTP pending-confirmation cleanup exactly once."""

        if not callable(close):
            raise TypeError("durable cleanup HTTP close must be callable")
        if self._http_close is not None:
            raise RuntimeError("durable cleanup HTTP close is already bound")
        self._http_close = close

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._http_close is None:
            raise RuntimeError("durable cleanup HTTP cleanup is not bound")
        if self._coordinator.closed:
            raise RuntimeError("durable cleanup coordinator is closed")
        if (await self._protection.snapshot()).closed:
            raise RuntimeError("durable cleanup confirmation protection is closed")

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        await _await_durable_administration_close(self._close_owned())

    async def _close_owned(self) -> None:
        failure: BaseException | None = None
        if self._http_close is not None:
            try:
                await self._http_close()
            except (Exception, asyncio.CancelledError) as exception:
                failure = exception

        try:
            await self._protection.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        try:
            await self._coordinator.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        if failure is not None:
            raise failure


class _DurableCleanupStorageLifecycle:
    """Guarantee cleanup confirmation and coordinator close before durable storage."""

    def __init__(
        self,
        *,
        storage: DurableStorageLifecycle | _DurableReconciliationStorageLifecycle,
        cleanup: _DurableCleanupAdministrationLifecycle,
    ) -> None:
        self._storage = storage
        self._cleanup = cleanup

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        try:
            await self._storage.start(context)
        except (Exception, asyncio.CancelledError):
            try:
                await self.close()
            except (Exception, asyncio.CancelledError):
                pass
            raise

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        await _await_durable_administration_close(self._close_owned())

    async def _close_owned(self) -> None:
        failure: BaseException | None = None
        try:
            await self._cleanup.close()
        except (Exception, asyncio.CancelledError) as exception:
            failure = exception

        try:
            await self._storage.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        if failure is not None:
            raise failure


class _HostAutomationLifecycle:
    """Bind one configured host service to the Phoenix Runtime lifecycle."""

    def __init__(self, service: HostAutomationService) -> None:
        self._service = service
        self._service._bind_runtime_lifecycle()

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        runtime = context.services.get("runtime")
        if not isinstance(runtime, PhoenixRuntime):
            raise RuntimeError("host automation lifecycle requires PhoenixRuntime")
        self._service._activate_runtime_lifecycle(lambda: runtime.state is RuntimeState.RUNNING)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self._service.close()


class RuntimeAssembler:
    """Compose configuration-backed services and create a Phoenix Runtime."""

    def __init__(
        self,
        *,
        kernel: Kernel,
        events: EventBus,
        capabilities: CapabilityRegistry,
        configuration: Configuration,
        definitions: Iterable[ServiceDefinition] = (),
        observability: ObservabilityHub | None = None,
        state: StateStore | StateStoreRegistry | None = None,
        plugins: PluginManager | None = None,
        policy: PolicyEngine | None = None,
        identity: AuthenticationManager | None = None,
        secrets: SecretsManager | None = None,
        audit: AuditLedger | None = None,
        jobs: JobScheduler | None = None,
        job_poll_interval: float = 1.0,
        job_lease_ttl: timedelta = timedelta(seconds=30),
        job_batch_size: int = 100,
        job_worker: str = "phoenix.scheduler",
        workflows: WorkflowOrchestrator | None = None,
        workflow_poll_interval: float = 1.0,
        workflow_worker: str = "phoenix.workflows",
        host_automation_adapter: HostAutomationAdapter | None = None,
        host_automation_approval_gate: HostAutomationApprovalGate | None = None,
        host_automation_require_application_close_approval: bool = False,
        host_automation_observability_configuration: (
            HostAutomationObservabilityConfiguration | None
        ) = None,
        inference_enabled: bool = False,
        inference_configuration: InferenceServiceConfiguration | None = None,
        inference_providers: tuple[ModelProvider, ...] = (),
        inference_service_account_administration_enabled: bool = False,
        agent_enabled: bool = False,
        agent_configuration: AgentServiceConfiguration | None = None,
        agent_model_adapter: AgentModelTurnAdapter | None = None,
        agent_tool_resolvers: tuple[ToolResourceResolver, ...] = (),
        agent_tool_adapters: tuple[ToolAdapter, ...] = (),
        agent_approval_service: ToolApprovalService | None = None,
        agent_approval_resolver: ToolApprovalResolver | None = None,
        agent_memory_configuration: AgentMemoryRuntimeConfiguration | None = None,
        agent_memory_embedding_provider: MemoryEmbeddingProvider | None = None,
        agent_memory_index: MemoryDerivedIndex | None = None,
        agent_workspace_configuration: AgentWorkspaceRuntimeConfiguration | None = None,
        agent_workspace_backing: WorkspaceBackingAdapter | None = None,
        agent_workspace_transfer_adapter: WorkspaceTransferAdapter | None = None,
        agent_workspace_transfer_configuration: (
            AgentWorkspaceTransferRuntimeConfiguration | None
        ) = None,
        agent_workspace_cleanup_configuration: (
            AgentWorkspaceCleanupRuntimeConfiguration | None
        ) = None,
        agent_durable_enabled: bool = False,
        agent_durable_store: DurableRunStore | None = None,
        agent_durable_lease_manager: DurableLeaseManager | None = None,
        agent_durable_compatibility_validator: DurableCompatibilityValidator | None = None,
        agent_durable_recovery_configuration: DurableRecoveryWorkerConfiguration | None = None,
        agent_durable_approval_revalidator: DurableApprovalRevalidator | None = None,
        agent_durable_administration_configuration: (
            DurableAdministrationConfiguration | None
        ) = None,
        agent_durable_machine_administration_guard: (
            DurableMachineAdministrationGuard | None
        ) = None,
        agent_durable_reconciliation_administration_enabled: bool = False,
        agent_durable_cleanup_administration_enabled: bool = False,
        agent_durable_reconciliation_status_lookup: (
            DurableReconciliationStatusLookup | None
        ) = None,
        agent_checkpoint_protector: CheckpointProtector | None = None,
        agent_durable_retention_policy: RetentionPolicy | None = None,
        agent_durable_retention_configuration: DurableRetentionWorkerConfiguration | None = None,
        webhooks_enabled: bool = False,
        webhook_service_account_administration_enabled: bool = False,
        webhook_subscription_repository: WebhookSubscriptionRepository | None = None,
        webhook_delivery_repository: WebhookDeliveryRepository | None = None,
        webhook_event_serializers: tuple[WebhookPayloadSerializer, ...] = (),
        webhook_egress_policies: Mapping[str, WebhookEgressPolicy] | None = None,
        webhook_dispatcher_config: WebhookDispatcherConfig | None = None,
        webhook_transport_config: WebhookTransportConfig | None = None,
        webhook_dispatch_poll_interval: float = 1.0,
        webhook_recovery_batch_size: int = 50,
        webhook_subscription_capacity: int = 256,
        webhook_delivery_capacity: int = 4096,
        webhook_signing_context: SecurityContext | None = None,
        inbound_events_enabled: bool = False,
        inbound_service_account_administration_enabled: bool = False,
        inbound_source_repository: InboundSourceRepository | None = None,
        inbound_event_repository: InboundEventRepository | None = None,
        inbound_replay_repository: InboundReplayRepository | None = None,
        inbound_event_normalizers: tuple[InboundEventNormalizer, ...] = (),
        inbound_publisher_config: InboundPublisherConfig | None = None,
        inbound_admission_policy: InboundAdmissionLimitPolicy | None = None,
        inbound_publisher_poll_interval: float = 1.0,
        inbound_recovery_poll_interval: float = 60.0,
        inbound_recovery_batch_size: int = 50,
        inbound_source_capacity: int = 256,
        inbound_event_capacity: int = 4096,
        inbound_replay_capacity: int = 16_384,
        inbound_hmac_context: SecurityContext | None = None,
        control_plane_authenticator: AdminTokenAuthenticator | None = None,
        control_plane_operator_registry: ControlPlaneOperatorRegistry | None = None,
        control_plane_operator_token: ControlPlaneOperatorToken | None = None,
        control_plane_operator_username: str = "phoenix-maintainer",
        control_plane_operator_display_name: str = "Phoenix Maintainer",
        control_plane_operator_role: str = "maintainer",
        control_plane_operator_capacity: int = 10_000,
        control_plane_durable_session_repository: ControlPlaneDurableSessionRepository
        | None = None,
        control_plane_durable_session_policy: ControlPlaneDurableSessionPolicy | None = None,
        control_plane_durable_session_capacity: int = 4096,
        control_plane_durable_session_cookie_policy: ControlPlaneDurableSessionCookiePolicy
        | None = None,
        control_plane_durable_session_recovery_poll_interval: float = 30.0,
        control_plane_durable_session_recovery_batch_size: int = 100,
        control_plane_durable_session_retention_policy: ControlPlaneDurableSessionRetentionPolicy
        | None = None,
        control_plane_durable_session_retention_poll_interval: float = 3600.0,
        control_plane_step_up_policy: ControlPlaneStepUpPolicy | None = None,
        control_plane_service_accounts_enabled: bool = False,
        control_plane_service_account_repository: (
            ControlPlaneServiceAccountRepository | None
        ) = None,
        control_plane_service_account_machine_routes: tuple[
            ControlPlaneServiceAccountMachineRoute,
            ...,
        ] = (),
        control_plane_service_account_audit_secret: (bytes | bytearray | memoryview | None) = None,
        control_plane_service_account_replay_secret: (bytes | bytearray | memoryview | None) = None,
        control_plane_http_config: ControlPlaneHttpConfig | None = None,
        control_plane_network_policy: ControlPlaneNetworkPolicy | None = None,
        control_plane_client_rate_limit: ControlPlaneClientRateLimitPolicy | None = None,
        control_plane_tls_listener_config: ControlPlaneTlsListenerConfig | None = None,
        control_plane_remote_login_policy: ControlPlaneRemoteLoginThrottlePolicy | None = None,
        control_plane_remote_address_secret: bytes | bytearray | memoryview | None = None,
        control_plane_event_config: ControlPlaneEventStreamConfig | None = None,
        control_plane_job_records: JobRecordSource | None = None,
        control_plane_command_journal: ControlPlaneCommandJournalRepository | None = None,
        control_plane_command_journal_capacity: int = 4096,
        control_plane_command_recovery_poll_interval: float = 1.0,
        control_plane_command_recovery_batch_size: int = 100,
        control_plane_command_retention_policy: ControlPlaneCommandRetentionPolicy | None = None,
        control_plane_command_retention_poll_interval: float = 3600.0,
        observe_events: bool = True,
        journal_events: bool = True,
        metadata: Mapping[str, str] | None = None,
        source: str = "phoenix.runtime",
    ) -> None:
        self._kernel = kernel
        self._events = events
        self._capabilities = capabilities
        self._configuration = configuration
        self._observability = observability
        self._state = state
        self._plugins = plugins
        self._policy = policy
        self._identity = identity
        self._secrets = secrets
        self._audit = audit
        self._jobs = jobs
        self._job_poll_interval = job_poll_interval
        self._job_lease_ttl = job_lease_ttl
        self._job_batch_size = job_batch_size
        self._job_worker = job_worker
        self._workflows = workflows
        self._workflow_poll_interval = workflow_poll_interval
        self._workflow_worker = workflow_worker
        self._host_automation_adapter = host_automation_adapter
        self._host_automation_approval_gate = host_automation_approval_gate
        self._host_automation_require_application_close_approval = (
            host_automation_require_application_close_approval
        )
        self._host_automation_observability_configuration = (
            host_automation_observability_configuration
        )
        self._inference_enabled = inference_enabled
        self._inference_configuration = inference_configuration
        self._inference_providers = tuple(inference_providers)
        self._inference_service_account_administration_enabled = (
            inference_service_account_administration_enabled
        )
        self._agent_enabled = agent_enabled
        self._agent_configuration = agent_configuration
        self._agent_model_adapter = agent_model_adapter
        self._agent_tool_resolvers = tuple(agent_tool_resolvers)
        self._agent_tool_adapters = tuple(agent_tool_adapters)
        self._agent_approval_service = agent_approval_service
        self._agent_approval_resolver = agent_approval_resolver
        self._agent_memory_configuration = agent_memory_configuration
        self._agent_memory_embedding_provider = agent_memory_embedding_provider
        self._agent_memory_index = agent_memory_index
        self._agent_workspace_configuration = agent_workspace_configuration
        self._agent_workspace_backing = agent_workspace_backing
        self._agent_workspace_transfer_adapter = agent_workspace_transfer_adapter
        self._agent_workspace_transfer_configuration = agent_workspace_transfer_configuration
        self._agent_workspace_cleanup_configuration = agent_workspace_cleanup_configuration
        self._agent_durable_enabled = agent_durable_enabled
        self._agent_durable_store = agent_durable_store
        self._agent_durable_lease_manager = agent_durable_lease_manager
        self._agent_durable_compatibility_validator = agent_durable_compatibility_validator
        self._agent_durable_recovery_configuration = agent_durable_recovery_configuration
        self._agent_durable_approval_revalidator = agent_durable_approval_revalidator
        self._agent_durable_administration_configuration = (
            agent_durable_administration_configuration
        )
        self._agent_durable_machine_administration_guard = (
            agent_durable_machine_administration_guard
        )
        self._agent_durable_reconciliation_administration_enabled = (
            agent_durable_reconciliation_administration_enabled
        )
        self._agent_durable_cleanup_administration_enabled = (
            agent_durable_cleanup_administration_enabled
        )
        self._agent_durable_reconciliation_status_lookup = (
            agent_durable_reconciliation_status_lookup
        )
        self._agent_checkpoint_protector = agent_checkpoint_protector
        self._agent_durable_retention_policy = agent_durable_retention_policy
        self._agent_durable_retention_configuration = agent_durable_retention_configuration
        self._webhooks_enabled = webhooks_enabled
        self._webhook_service_account_administration_enabled = (
            webhook_service_account_administration_enabled
        )
        self._webhook_subscription_repository = webhook_subscription_repository
        self._webhook_delivery_repository = webhook_delivery_repository
        self._webhook_event_serializers = tuple(webhook_event_serializers)
        self._webhook_egress_policies = (
            None if webhook_egress_policies is None else dict(webhook_egress_policies)
        )
        self._webhook_dispatcher_config = webhook_dispatcher_config
        self._webhook_transport_config = webhook_transport_config
        self._webhook_dispatch_poll_interval = webhook_dispatch_poll_interval
        self._webhook_recovery_batch_size = webhook_recovery_batch_size
        self._webhook_subscription_capacity = webhook_subscription_capacity
        self._webhook_delivery_capacity = webhook_delivery_capacity
        self._webhook_signing_context = webhook_signing_context
        self._inbound_events_enabled = inbound_events_enabled
        self._inbound_service_account_administration_enabled = (
            inbound_service_account_administration_enabled
        )
        self._inbound_source_repository = inbound_source_repository
        self._inbound_event_repository = inbound_event_repository
        self._inbound_replay_repository = inbound_replay_repository
        self._inbound_event_normalizers = tuple(inbound_event_normalizers)
        self._inbound_publisher_config = inbound_publisher_config
        self._inbound_admission_policy = inbound_admission_policy
        self._inbound_publisher_poll_interval = inbound_publisher_poll_interval
        self._inbound_recovery_poll_interval = inbound_recovery_poll_interval
        self._inbound_recovery_batch_size = inbound_recovery_batch_size
        self._inbound_source_capacity = inbound_source_capacity
        self._inbound_event_capacity = inbound_event_capacity
        self._inbound_replay_capacity = inbound_replay_capacity
        self._inbound_hmac_context = inbound_hmac_context
        self._control_plane_authenticator = control_plane_authenticator
        self._control_plane_operator_registry = control_plane_operator_registry
        self._control_plane_operator_token = control_plane_operator_token
        self._control_plane_operator_username = control_plane_operator_username
        self._control_plane_operator_display_name = control_plane_operator_display_name
        self._control_plane_operator_role = control_plane_operator_role
        self._control_plane_operator_capacity = control_plane_operator_capacity
        self._control_plane_durable_session_repository = control_plane_durable_session_repository
        self._control_plane_durable_session_policy = control_plane_durable_session_policy
        self._control_plane_durable_session_capacity = control_plane_durable_session_capacity
        self._control_plane_durable_session_cookie_policy = (
            control_plane_durable_session_cookie_policy
        )
        self._control_plane_durable_session_recovery_poll_interval = (
            control_plane_durable_session_recovery_poll_interval
        )
        self._control_plane_durable_session_recovery_batch_size = (
            control_plane_durable_session_recovery_batch_size
        )
        self._control_plane_durable_session_retention_policy = (
            control_plane_durable_session_retention_policy
        )
        self._control_plane_durable_session_retention_poll_interval = (
            control_plane_durable_session_retention_poll_interval
        )
        self._control_plane_step_up_policy = control_plane_step_up_policy
        self._control_plane_service_account_repository = control_plane_service_account_repository
        self._control_plane_service_account_machine_routes = tuple(
            control_plane_service_account_machine_routes
        )
        self._control_plane_service_account_audit_secret = (
            control_plane_service_account_audit_secret
        )
        self._control_plane_service_account_replay_secret = (
            control_plane_service_account_replay_secret
        )
        self._control_plane_http_config = control_plane_http_config
        self._control_plane_network_policy = control_plane_network_policy
        self._control_plane_client_rate_limit = control_plane_client_rate_limit
        self._control_plane_tls_listener_config = control_plane_tls_listener_config
        self._control_plane_remote_login_policy = control_plane_remote_login_policy
        self._control_plane_remote_address_secret = control_plane_remote_address_secret
        self._control_plane_event_config = control_plane_event_config
        self._control_plane_job_records = control_plane_job_records
        self._control_plane_command_journal = control_plane_command_journal
        self._control_plane_command_journal_capacity = control_plane_command_journal_capacity
        self._control_plane_command_recovery_poll_interval = (
            control_plane_command_recovery_poll_interval
        )
        self._control_plane_command_recovery_batch_size = control_plane_command_recovery_batch_size
        self._control_plane_command_retention_policy = control_plane_command_retention_policy
        self._control_plane_command_retention_poll_interval = (
            control_plane_command_retention_poll_interval
        )
        if workflows is not None and jobs is None:
            raise ValueError("workflow orchestration requires a Runtime-owned job scheduler")
        if not isinstance(host_automation_require_application_close_approval, bool):
            raise TypeError("host automation close approval flag must be bool")
        host_automation_options_supplied = any(
            (
                host_automation_approval_gate is not None,
                host_automation_require_application_close_approval,
                host_automation_observability_configuration is not None,
            )
        )
        if host_automation_options_supplied and host_automation_adapter is None:
            raise ValueError("host automation options require an adapter")
        if host_automation_adapter is not None:
            from phoenix_os.host_automation import (
                HostAutomationAdapter as RuntimeHostAutomationAdapter,
            )
            from phoenix_os.host_automation import (
                HostAutomationApprovalGate as RuntimeHostAutomationApprovalGate,
            )
            from phoenix_os.host_automation import (
                HostAutomationObservabilityConfiguration as RuntimeHostObservabilityConfiguration,
            )

            if not isinstance(host_automation_adapter, RuntimeHostAutomationAdapter):
                raise TypeError("host automation adapter has an invalid type")
            if policy is None:
                raise ValueError("configured host automation requires a PolicyEngine")
            if host_automation_approval_gate is not None and not isinstance(
                host_automation_approval_gate,
                RuntimeHostAutomationApprovalGate,
            ):
                raise TypeError("host automation approval gate has an invalid type")
            if (
                host_automation_require_application_close_approval
                and host_automation_approval_gate is None
            ):
                raise ValueError("host application close approval requires an approval gate")
            if host_automation_observability_configuration is not None and not isinstance(
                host_automation_observability_configuration,
                RuntimeHostObservabilityConfiguration,
            ):
                raise TypeError("host automation observability configuration has an invalid type")
        if not isinstance(inference_enabled, bool):
            raise TypeError("inference enabled flag must be bool")
        if not isinstance(
            inference_service_account_administration_enabled,
            bool,
        ):
            raise TypeError("inference service-account administration enabled flag must be bool")
        inference_options_supplied = any(
            (
                inference_configuration is not None,
                bool(self._inference_providers),
                inference_service_account_administration_enabled,
            )
        )
        if inference_options_supplied and not inference_enabled:
            raise ValueError("inference options require inference_enabled")
        if inference_enabled:
            if policy is None:
                raise ValueError("enabled inference requires a PolicyEngine")
            if inference_configuration is None:
                raise ValueError("enabled inference requires configuration")
            if not self._inference_providers:
                raise ValueError("enabled inference requires at least one provider")
        if not isinstance(agent_enabled, bool):
            raise TypeError("agent enabled flag must be bool")
        agent_options_supplied = any(
            (
                agent_configuration is not None,
                agent_model_adapter is not None,
                bool(self._agent_tool_resolvers),
                bool(self._agent_tool_adapters),
                agent_approval_service is not None,
                agent_approval_resolver is not None,
            )
        )
        if agent_options_supplied and not agent_enabled:
            raise ValueError("agent options require agent_enabled")
        if agent_enabled:
            if policy is None:
                raise ValueError("enabled agent requires a PolicyEngine")
            if agent_configuration is None:
                raise ValueError("enabled agent requires configuration")
            if agent_model_adapter is None:
                raise ValueError("enabled agent requires a model adapter")

        memory_options_supplied = any(
            (
                agent_memory_configuration is not None,
                agent_memory_embedding_provider is not None,
                agent_memory_index is not None,
            )
        )
        if memory_options_supplied and agent_memory_configuration is None:
            raise ValueError("agent memory options require memory configuration")
        if agent_memory_configuration is not None:
            from phoenix_os.agent.memory_runtime import (
                AgentMemoryRuntimeConfiguration as RuntimeAgentMemoryRuntimeConfiguration,
            )
            from phoenix_os.agent.memory_runtime import (
                MemoryDerivedIndex as RuntimeMemoryDerivedIndex,
            )
            from phoenix_os.agent.memory_runtime import (
                MemoryEmbeddingProvider as RuntimeMemoryEmbeddingProvider,
            )

            if not isinstance(
                agent_memory_configuration,
                RuntimeAgentMemoryRuntimeConfiguration,
            ):
                raise TypeError("agent memory configuration has an invalid type")
            if not agent_enabled:
                raise ValueError("agent memory configuration requires agent_enabled")
            if agent_memory_configuration.semantic_enabled:
                if agent_memory_embedding_provider is None:
                    raise ValueError("semantic agent memory requires an embedding provider")
                if not isinstance(
                    agent_memory_embedding_provider,
                    RuntimeMemoryEmbeddingProvider,
                ):
                    raise TypeError("agent memory embedding provider has an invalid type")
                if agent_memory_index is not None and not isinstance(
                    agent_memory_index,
                    RuntimeMemoryDerivedIndex,
                ):
                    raise TypeError("agent memory index has an invalid type")
            elif agent_memory_embedding_provider is not None or agent_memory_index is not None:
                raise ValueError("agent memory semantic provider/index require semantic_enabled")
        workspace_options_supplied = any(
            (
                agent_workspace_configuration is not None,
                agent_workspace_backing is not None,
                agent_workspace_transfer_adapter is not None,
                agent_workspace_transfer_configuration is not None,
                agent_workspace_cleanup_configuration is not None,
            )
        )
        if workspace_options_supplied and agent_workspace_configuration is None:
            raise ValueError("agent workspace options require workspace configuration")
        if agent_workspace_configuration is not None:
            from phoenix_os.agent.workspace_backing import (
                WorkspaceBackingAdapter as RuntimeWorkspaceBackingAdapter,
            )
            from phoenix_os.agent.workspace_cleanup_runtime import (
                AgentWorkspaceCleanupRuntimeConfiguration as RuntimeWorkspaceCleanupConfiguration,
            )
            from phoenix_os.agent.workspace_runtime import (
                AgentWorkspaceRuntimeConfiguration as RuntimeWorkspaceConfiguration,
            )
            from phoenix_os.agent.workspace_transfer import (
                WorkspaceTransferAdapter as RuntimeWorkspaceTransferAdapter,
            )
            from phoenix_os.agent.workspace_transfer_runtime import (
                AgentWorkspaceTransferRuntimeConfiguration as RuntimeWorkspaceTransferConfiguration,
            )

            if not isinstance(
                agent_workspace_configuration,
                RuntimeWorkspaceConfiguration,
            ):
                raise TypeError("agent workspace configuration has an invalid type")
            if not agent_enabled:
                raise ValueError("agent workspace configuration requires agent_enabled")
            if agent_workspace_backing is not None and not isinstance(
                agent_workspace_backing,
                RuntimeWorkspaceBackingAdapter,
            ):
                raise TypeError("agent workspace backing has an invalid type")
            if agent_workspace_transfer_adapter is not None and not isinstance(
                agent_workspace_transfer_adapter,
                RuntimeWorkspaceTransferAdapter,
            ):
                raise TypeError("agent workspace transfer adapter has an invalid type")
            if agent_workspace_transfer_configuration is not None:
                if not isinstance(
                    agent_workspace_transfer_configuration,
                    RuntimeWorkspaceTransferConfiguration,
                ):
                    raise TypeError("agent workspace transfer configuration has an invalid type")
                if agent_workspace_transfer_adapter is None:
                    raise ValueError(
                        "agent workspace transfer configuration requires transfer adapter"
                    )
            if agent_workspace_cleanup_configuration is not None and not isinstance(
                agent_workspace_cleanup_configuration,
                RuntimeWorkspaceCleanupConfiguration,
            ):
                raise TypeError("agent workspace cleanup configuration has an invalid type")

        if not isinstance(agent_durable_enabled, bool):
            raise TypeError("agent durable enabled flag must be bool")
        if not isinstance(agent_durable_reconciliation_administration_enabled, bool):
            raise TypeError("agent durable reconciliation administration enabled flag must be bool")
        if not isinstance(agent_durable_cleanup_administration_enabled, bool):
            raise TypeError("agent durable cleanup administration enabled flag must be bool")
        durable_options_supplied = any(
            (
                agent_durable_store is not None,
                agent_durable_lease_manager is not None,
                agent_durable_compatibility_validator is not None,
                agent_durable_recovery_configuration is not None,
                agent_durable_approval_revalidator is not None,
                agent_durable_administration_configuration is not None,
                agent_durable_machine_administration_guard is not None,
                agent_durable_reconciliation_administration_enabled,
                agent_durable_cleanup_administration_enabled,
                agent_durable_reconciliation_status_lookup is not None,
                agent_checkpoint_protector is not None,
                agent_durable_retention_policy is not None,
                agent_durable_retention_configuration is not None,
            )
        )
        if durable_options_supplied and not agent_durable_enabled:
            raise ValueError("durable agent options require agent_durable_enabled")
        if agent_durable_enabled:
            if not agent_enabled:
                raise ValueError("enabled durable agent requires agent_enabled")
            if agent_durable_store is None:
                raise ValueError("enabled durable agent requires a DurableRunStore")
            if agent_durable_lease_manager is None:
                raise ValueError("enabled durable agent requires a DurableLeaseManager")
            if agent_durable_compatibility_validator is None:
                raise ValueError("enabled durable agent requires a DurableCompatibilityValidator")
            if (
                agent_durable_administration_configuration is not None
                or agent_durable_machine_administration_guard is not None
            ):
                from phoenix_os.agent.durable_administration import (
                    DurableAdministrationConfiguration as RuntimeDurableAdministrationConfiguration,
                )
                from phoenix_os.agent.durable_administration import (
                    DurableMachineAdministrationGuard as RuntimeDurableMachineAdministrationGuard,
                )

                if agent_durable_administration_configuration is not None and not isinstance(
                    agent_durable_administration_configuration,
                    RuntimeDurableAdministrationConfiguration,
                ):
                    raise TypeError(
                        "agent durable administration configuration has an invalid type"
                    )
                if agent_durable_machine_administration_guard is not None and not isinstance(
                    agent_durable_machine_administration_guard,
                    RuntimeDurableMachineAdministrationGuard,
                ):
                    raise TypeError(
                        "agent durable machine administration guard has an invalid type"
                    )
                if (
                    agent_durable_administration_configuration is not None
                    and agent_durable_administration_configuration.machine_administration_enabled
                    and agent_durable_machine_administration_guard is None
                ):
                    raise ValueError(
                        "enabled durable machine administration requires a machine guard"
                    )

            if agent_durable_reconciliation_status_lookup is not None:
                from phoenix_os.agent.durable_reconciliation_administration import (
                    DurableReconciliationStatusLookup as RuntimeDurableReconciliationStatusLookup,
                )

                if not isinstance(
                    agent_durable_reconciliation_status_lookup,
                    RuntimeDurableReconciliationStatusLookup,
                ):
                    raise TypeError(
                        "agent durable reconciliation status lookup has an invalid type"
                    )
                if not agent_durable_reconciliation_administration_enabled:
                    raise ValueError(
                        "durable reconciliation status lookup requires enabled "
                        "reconciliation administration"
                    )

            if agent_durable_reconciliation_administration_enabled:
                if audit is None:
                    raise ValueError(
                        "enabled durable reconciliation administration requires AuditLedger"
                    )
                if control_plane_operator_registry is None and control_plane_operator_token is None:
                    raise ValueError(
                        "enabled durable reconciliation administration requires "
                        "durable operator mode"
                    )
            if agent_durable_cleanup_administration_enabled:
                if audit is None:
                    raise ValueError("enabled durable cleanup administration requires AuditLedger")
                if agent_durable_retention_policy is None:
                    raise ValueError(
                        "enabled durable cleanup administration requires retention policy"
                    )
                if control_plane_operator_registry is None and control_plane_operator_token is None:
                    raise ValueError(
                        "enabled durable cleanup administration requires durable operator mode"
                    )
        if not isinstance(webhooks_enabled, bool):
            raise TypeError("webhooks enabled flag must be bool")
        if not isinstance(webhook_service_account_administration_enabled, bool):
            raise TypeError("webhook service-account administration enabled flag must be bool")
        webhook_options_supplied = any(
            (
                webhook_subscription_repository is not None,
                webhook_delivery_repository is not None,
                bool(self._webhook_event_serializers),
                self._webhook_egress_policies is not None,
                webhook_dispatcher_config is not None,
                webhook_transport_config is not None,
                webhook_signing_context is not None,
                webhook_service_account_administration_enabled,
            )
        )
        if webhook_options_supplied and not webhooks_enabled:
            raise ValueError("webhook options require webhooks_enabled")
        if webhooks_enabled:
            if secrets is None:
                raise ValueError("enabled webhooks require a SecretsManager")
            if not self._webhook_event_serializers:
                raise ValueError("enabled webhooks require at least one event serializer")
            if not self._webhook_egress_policies:
                raise ValueError("enabled webhooks require at least one egress policy")
            if webhook_dispatch_poll_interval <= 0:
                raise ValueError("webhook dispatch poll interval must be positive")
            if not 1 <= webhook_recovery_batch_size <= 200:
                raise ValueError("webhook recovery batch size is outside supported bounds")
            if not 1 <= webhook_subscription_capacity <= 10_000:
                raise ValueError("webhook subscription capacity is outside supported bounds")
            if not 1 <= webhook_delivery_capacity <= 1_000_000:
                raise ValueError("webhook delivery capacity is outside supported bounds")
            if webhook_signing_context is not None and not webhook_signing_context.authenticated:
                raise ValueError("webhook signing context must be authenticated")
        if not isinstance(inbound_events_enabled, bool):
            raise TypeError("inbound events enabled flag must be bool")
        if not isinstance(
            inbound_service_account_administration_enabled,
            bool,
        ):
            raise TypeError("inbound service-account administration enabled flag must be bool")
        inbound_options_supplied = any(
            (
                inbound_source_repository is not None,
                inbound_event_repository is not None,
                inbound_replay_repository is not None,
                bool(self._inbound_event_normalizers),
                inbound_publisher_config is not None,
                inbound_admission_policy is not None,
                inbound_hmac_context is not None,
                inbound_service_account_administration_enabled,
            )
        )
        if inbound_options_supplied and not inbound_events_enabled:
            raise ValueError("inbound options require inbound_events_enabled")
        repository_count = sum(
            repository is not None
            for repository in (
                inbound_source_repository,
                inbound_event_repository,
                inbound_replay_repository,
            )
        )
        if repository_count not in {0, 3}:
            raise ValueError("custom inbound composition requires all three repositories")
        if inbound_events_enabled:
            if secrets is None:
                raise ValueError("enabled inbound events require a SecretsManager")
            if policy is None:
                raise ValueError("enabled inbound events require a PolicyEngine")
            if not self._inbound_event_normalizers:
                raise ValueError("enabled inbound events require at least one normalizer")
            if inbound_publisher_poll_interval <= 0:
                raise ValueError("inbound publisher poll interval must be positive")
            if inbound_recovery_poll_interval <= 0:
                raise ValueError("inbound recovery poll interval must be positive")
            if not 1 <= inbound_recovery_batch_size <= 200:
                raise ValueError("inbound recovery batch size is outside supported bounds")
            if not 1 <= inbound_source_capacity <= 10_000:
                raise ValueError("inbound source capacity is outside supported bounds")
            if not 1 <= inbound_event_capacity <= 100_000:
                raise ValueError("inbound event capacity is outside supported bounds")
            if not 1 <= inbound_replay_capacity <= 500_000:
                raise ValueError("inbound replay capacity is outside supported bounds")
            if inbound_hmac_context is not None and not inbound_hmac_context.authenticated:
                raise ValueError("inbound HMAC context must be authenticated")
        operator_mode = (
            control_plane_operator_registry is not None or control_plane_operator_token is not None
        )

        if not isinstance(
            control_plane_service_accounts_enabled,
            bool,
        ):
            raise TypeError("service-account enabled flag must be bool")

        service_accounts_enabled = (
            control_plane_service_accounts_enabled
            or control_plane_service_account_repository is not None
            or bool(self._control_plane_service_account_machine_routes)
        )

        security_secrets_supplied = any(
            secret is not None
            for secret in (
                control_plane_service_account_audit_secret,
                control_plane_service_account_replay_secret,
            )
        )

        if security_secrets_supplied and not service_accounts_enabled:
            raise ValueError("service-account security secrets require service accounts")

        if service_accounts_enabled and not operator_mode:
            raise ValueError("service accounts require durable operator mode")
        if inference_service_account_administration_enabled and not service_accounts_enabled:
            raise ValueError("inference machine administration requires service accounts")
        if (
            inference_service_account_administration_enabled
            and control_plane_network_policy is None
        ):
            raise ValueError("inference machine administration requires a secure network policy")
        if inference_service_account_administration_enabled and policy is None:
            raise ValueError("inference machine administration requires a PolicyEngine")
        if webhook_service_account_administration_enabled and not service_accounts_enabled:
            raise ValueError("webhook machine administration requires service accounts")
        if inbound_service_account_administration_enabled and not service_accounts_enabled:
            raise ValueError("inbound machine administration requires service accounts")
        if inbound_service_account_administration_enabled and control_plane_network_policy is None:
            raise ValueError("inbound machine administration requires a secure network policy")
        if inbound_service_account_administration_enabled and policy is None:
            raise ValueError("inbound machine administration requires a PolicyEngine")
        if webhook_service_account_administration_enabled and control_plane_network_policy is None:
            raise ValueError("webhook machine administration requires a secure network policy")
        if webhook_service_account_administration_enabled and policy is None:
            raise ValueError("webhook machine administration requires a PolicyEngine")
        if (
            self._control_plane_service_account_machine_routes
            and control_plane_network_policy is None
        ):
            raise ValueError("machine routes require a secure network policy")

        if self._control_plane_service_account_machine_routes and policy is None:
            raise ValueError("machine routes require a PolicyEngine")

        self._control_plane_service_accounts_enabled = service_accounts_enabled

        if control_plane_authenticator is not None and operator_mode:
            raise ValueError("legacy and operator control-plane authentication are exclusive")
        control_plane_enabled = control_plane_authenticator is not None or operator_mode
        if inbound_events_enabled and not control_plane_enabled:
            raise ValueError("enabled inbound events require a control-plane listener")
        if not control_plane_enabled and any(
            item is not None
            for item in (
                control_plane_http_config,
                control_plane_network_policy,
                control_plane_client_rate_limit,
                control_plane_tls_listener_config,
                control_plane_remote_login_policy,
                control_plane_remote_address_secret,
                control_plane_event_config,
                control_plane_job_records,
                control_plane_command_journal,
                control_plane_command_retention_policy,
                control_plane_durable_session_repository,
                control_plane_durable_session_policy,
                control_plane_durable_session_cookie_policy,
                control_plane_durable_session_retention_policy,
                control_plane_step_up_policy,
            )
        ):
            raise ValueError("control plane options require an authenticator or operator registry")
        if control_plane_network_policy is not None:
            from phoenix_os.control_plane.network_contracts import (
                ControlPlaneExposureMode,
            )

            if control_plane_network_policy.port == 0:
                raise ValueError(
                    "explicit control-plane network policy requires a fixed nonzero port"
                )
            if control_plane_http_config is not None and (
                control_plane_http_config.host != "127.0.0.1" or control_plane_http_config.port != 0
            ):
                raise ValueError("HTTP host and port must come only from the network policy")
            if (
                control_plane_network_policy.exposure is ControlPlaneExposureMode.REMOTE
                and not operator_mode
            ):
                raise ValueError("remote control-plane exposure requires durable operator mode")
            if control_plane_network_policy.exposure is not ControlPlaneExposureMode.REMOTE and any(
                item is not None
                for item in (
                    control_plane_remote_login_policy,
                    control_plane_remote_address_secret,
                )
            ):
                raise ValueError("remote login options require remote exposure")
        elif any(
            item is not None
            for item in (
                control_plane_client_rate_limit,
                control_plane_tls_listener_config,
                control_plane_remote_login_policy,
                control_plane_remote_address_secret,
            )
        ):
            raise ValueError("network admission options require a control-plane network policy")

        if control_plane_operator_capacity <= 0 or control_plane_operator_capacity > 10_000:
            raise ValueError("control-plane operator capacity is outside supported bounds")
        if (
            control_plane_durable_session_capacity <= 0
            or control_plane_durable_session_capacity > 100_000
        ):
            raise ValueError("control-plane durable session capacity is outside supported bounds")
        if control_plane_durable_session_recovery_poll_interval <= 0:
            raise ValueError("durable session recovery poll interval must be positive")
        if (
            control_plane_durable_session_recovery_batch_size <= 0
            or control_plane_durable_session_recovery_batch_size > 200
        ):
            raise ValueError("durable session recovery batch size is outside supported bounds")
        if control_plane_durable_session_retention_poll_interval <= 0:
            raise ValueError("durable session retention poll interval must be positive")
        self._observe_events = observe_events
        self._journal_events = journal_events
        definitions_tuple = tuple(definitions)
        if host_automation_adapter is not None:
            host_conflicts = sorted(
                definition.name
                for definition in definitions_tuple
                if definition.name in _HOST_AUTOMATION_DEFINITION_NAMES
            )
            if host_conflicts:
                names = ", ".join(host_conflicts)
                raise ValueError(f"host automation services conflict with definitions: {names}")
        if agent_workspace_configuration is not None:
            workspace_conflicts = sorted(
                definition.name
                for definition in definitions_tuple
                if definition.name in _WORKSPACE_DEFINITION_NAMES
            )
            if workspace_conflicts:
                names = ", ".join(workspace_conflicts)
                raise ValueError(f"agent workspace services conflict with definitions: {names}")
        self._composer = ServiceComposer(definitions_tuple)
        self._metadata = {} if metadata is None else dict(metadata)
        self._source = source

    async def assemble(self) -> PhoenixRuntime:
        base_services: dict[str, object] = {
            "kernel": self._kernel,
            "events": self._events,
            "capabilities": self._capabilities,
            "configuration": self._configuration,
        }
        if self._observability is not None:
            base_services["observability"] = self._observability
        if self._audit is not None:
            base_services["audit"] = self._audit
        if self._policy is not None:
            base_services["policy"] = self._policy
        if self._identity is not None:
            base_services["identity"] = self._identity
        if self._state is not None:
            base_services["state"] = self._state
        if self._secrets is not None:
            base_services["secrets"] = self._secrets
        if self._plugins is not None:
            base_services["plugins"] = self._plugins
        if self._jobs is not None:
            base_services["jobs"] = self._jobs
        if self._workflows is not None:
            base_services["workflows"] = self._workflows
        container = await self._composer.compose(
            self._configuration,
            base_services=base_services,
        )
        if self._plugins is not None:
            self._plugins.bind_services(container.services)
            await self._plugins.prepare()
        custom_services = {
            name: service
            for name, service in container.services.items()
            if name not in {"kernel", "events", "capabilities"}
        }
        components: list[ComponentSpec] = []
        if self._observability is not None:
            components.append(ComponentSpec("observability", self._observability))
            if self._observe_events:
                components.append(
                    ComponentSpec(
                        "observability.events",
                        EventObserver(
                            events=self._events,
                            observability=self._observability,
                        ),
                    )
                )
        if self._audit is not None:
            components.append(ComponentSpec("audit", self._audit))
            if self._journal_events:
                from phoenix_os.audit import SecurityJournal

                components.append(
                    ComponentSpec(
                        "audit.events",
                        SecurityJournal(events=self._events, ledger=self._audit),
                    )
                )
        if self._policy is not None:
            components.append(ComponentSpec("policy", self._policy))
        if self._state is not None:
            components.append(ComponentSpec("state", cast(LifecycleComponent, self._state)))
        if self._identity is not None:
            components.append(ComponentSpec("identity", self._identity))
        if self._secrets is not None:
            components.append(ComponentSpec("secrets", self._secrets))
        components.extend(container.components)
        if self._plugins is not None:
            components.append(ComponentSpec("plugins", self._plugins))

        state_store: StateStore | None
        if isinstance(self._state, StateStoreRegistry):
            state_store = None if self._state.default_name is None else self._state.store()
        else:
            state_store = self._state

        host_automation_service = None
        if self._host_automation_adapter is not None:
            from phoenix_os.host_automation import (
                ContentFreeHostAutomationObserver,
                HostAutomationAdministration,
                HostAutomationObservabilityConfiguration,
                HostAutomationService,
                PolicyEngineHostAutomationAuthorizer,
            )

            assert self._policy is not None
            host_observability_configuration = self._host_automation_observability_configuration
            if host_observability_configuration is None:
                host_observability_configuration = HostAutomationObservabilityConfiguration()
            host_observer = ContentFreeHostAutomationObserver(
                self._host_automation_adapter.host_id,
                host_observability_configuration,
                events=self._events,
                audit=self._audit,
                observability=self._observability,
            )
            host_automation_service = HostAutomationService(
                adapter=self._host_automation_adapter,
                authorizer=PolicyEngineHostAutomationAuthorizer(self._policy),
                approval_gate=self._host_automation_approval_gate,
                require_application_close_approval=(
                    self._host_automation_require_application_close_approval
                ),
                observer=host_observer,
            )
            host_automation_administration = HostAutomationAdministration(host_automation_service)
            custom_services["host"] = host_automation_service
            custom_services["host.health"] = host_automation_administration
            custom_services["host.administration"] = host_automation_administration
            components.append(
                ComponentSpec(
                    "host",
                    _HostAutomationLifecycle(host_automation_service),
                )
            )

        inference_stack = None
        if self._inference_enabled:
            from phoenix_os.inference import create_inference_runtime_stack

            assert self._inference_configuration is not None
            assert self._policy is not None
            inference_stack = create_inference_runtime_stack(
                configuration=self._inference_configuration,
                providers=self._inference_providers,
                policy=self._policy,
                events=self._events,
                secrets=self._secrets,
                audit=self._audit,
                observability=self._observability,
            )
            custom_services["inference"] = inference_stack.service
            custom_services["inference.health"] = inference_stack.service
            custom_services["inference.runtime"] = inference_stack.runtime
            custom_services["inference.registry"] = inference_stack.registry
            custom_services["inference.administration"] = inference_stack.administration
            components.append(ComponentSpec("inference", inference_stack.service))

        agent_workspace_stack = None
        if self._agent_workspace_configuration is not None:
            from phoenix_os.agent import create_agent_workspace_runtime_stack

            assert self._policy is not None
            agent_workspace_stack = create_agent_workspace_runtime_stack(
                configuration=self._agent_workspace_configuration,
                policy=self._policy,
                events=self._events,
                audit=self._audit,
                observability=self._observability,
                state_store=state_store,
                backing=self._agent_workspace_backing,
                transfer_adapter=self._agent_workspace_transfer_adapter,
                transfer_configuration=self._agent_workspace_transfer_configuration,
                cleanup_configuration=self._agent_workspace_cleanup_configuration,
            )
            custom_services["agent.workspace"] = agent_workspace_stack.service
            custom_services["agent.workspace.administration"] = agent_workspace_stack.administration
            custom_services["agent.workspace.owner"] = agent_workspace_stack.owner
            custom_services["agent.workspace.observer"] = agent_workspace_stack.observer
            custom_services["agent.workspace.store"] = agent_workspace_stack.store
            custom_services["agent.workspace.backing"] = agent_workspace_stack.backing
            custom_services["agent.workspace.cleanup"] = agent_workspace_stack.cleanup
            if agent_workspace_stack.transfer is not None:
                custom_services["agent.workspace.transfer"] = agent_workspace_stack.transfer
            components.extend(agent_workspace_stack.components)

        agent_memory_stack = None
        if self._agent_memory_configuration is not None:
            from phoenix_os.agent import create_agent_memory_runtime_stack

            assert self._policy is not None
            agent_memory_stack = create_agent_memory_runtime_stack(
                configuration=self._agent_memory_configuration,
                policy=self._policy,
                state_store=state_store,
                embedding_provider=self._agent_memory_embedding_provider,
                index=self._agent_memory_index,
                events=self._events,
            )
            custom_services["agent.memory"] = agent_memory_stack.service
            custom_services["agent.memory.owner"] = agent_memory_stack.owner
            custom_services["agent.memory.store"] = agent_memory_stack.store
            custom_services["agent.memory.retrieval"] = agent_memory_stack.retrieval
            custom_services["agent.memory.administration"] = agent_memory_stack.administration
            if agent_memory_stack.index is not None:
                custom_services["agent.memory.index"] = agent_memory_stack.index
            components.append(ComponentSpec("agent.memory", agent_memory_stack.owner))

        agent_stack = None
        if self._agent_enabled:
            from phoenix_os.agent import create_agent_runtime_stack

            assert self._agent_configuration is not None
            assert self._agent_model_adapter is not None
            assert self._policy is not None
            agent_stack = create_agent_runtime_stack(
                configuration=self._agent_configuration,
                model_adapter=self._agent_model_adapter,
                tool_resolvers=self._agent_tool_resolvers,
                tool_adapters=self._agent_tool_adapters,
                policy=self._policy,
                session_freshness_source=self._identity,
                events=self._events,
                approval_service=self._agent_approval_service,
                approval_resolver=self._agent_approval_resolver,
                memory_context=(None if agent_memory_stack is None else agent_memory_stack.context),
                audit=self._audit,
                observability=self._observability,
            )
            custom_services["agent"] = agent_stack.service
            custom_services["agent.health"] = agent_stack.service
            custom_services["agent.runtime"] = agent_stack.runtime
            custom_services["agent.registry"] = agent_stack.registry
            custom_services["agent.admission"] = agent_stack.admission
            custom_services["agent.executor"] = agent_stack.executor
            custom_services["agent.administration"] = agent_stack.administration
            if agent_stack.approval_service is not None:
                custom_services["agent.approvals"] = agent_stack.approval_service
            components.append(ComponentSpec("agent", agent_stack.service))

        inbound_runtime = None
        if self._inbound_events_enabled:
            from phoenix_os.inbound_events import (
                InboundManagerConfig,
                StateInboundEventRepository,
                StateInboundReplayRepository,
                StateInboundSourceRepository,
                create_in_memory_inbound_repositories,
                create_inbound_runtime,
            )

            inbound_sources = self._inbound_source_repository
            inbound_events = self._inbound_event_repository
            inbound_replay = self._inbound_replay_repository

            if inbound_sources is None:
                if state_store is None:
                    repositories = create_in_memory_inbound_repositories(
                        source_capacity=self._inbound_source_capacity,
                        event_capacity=self._inbound_event_capacity,
                        replay_capacity=self._inbound_replay_capacity,
                    )
                    inbound_sources = repositories.sources
                    inbound_events = repositories.events
                    inbound_replay = repositories.replay
                else:
                    inbound_sources = StateInboundSourceRepository(
                        state_store,
                        capacity=self._inbound_source_capacity,
                    )
                    inbound_events = StateInboundEventRepository(
                        state_store,
                        capacity=self._inbound_event_capacity,
                        replay_capacity=self._inbound_replay_capacity,
                    )
                    inbound_replay = StateInboundReplayRepository(
                        state_store,
                        capacity=self._inbound_replay_capacity,
                    )

            assert inbound_events is not None
            assert inbound_replay is not None
            assert self._secrets is not None
            assert self._policy is not None

            inbound_runtime = create_inbound_runtime(
                event_bus=self._events,
                sources=inbound_sources,
                events=inbound_events,
                replay=inbound_replay,
                secrets=self._secrets,
                normalizers=self._inbound_event_normalizers,
                policy_engine=self._policy,
                hmac_context=self._inbound_hmac_context,
                manager_config=InboundManagerConfig(
                    machine_administration_enabled=(
                        self._inbound_service_account_administration_enabled
                    )
                ),
                publisher_config=self._inbound_publisher_config,
                admission_policy=self._inbound_admission_policy,
                publisher_poll_interval=(self._inbound_publisher_poll_interval),
                recovery_poll_interval=(self._inbound_recovery_poll_interval),
                recovery_batch_size=self._inbound_recovery_batch_size,
                audit=self._audit,
                observability=self._observability,
            )
            custom_services["inbound"] = inbound_runtime
            custom_services["inbound.sources"] = inbound_runtime.sources
            custom_services["inbound.events"] = inbound_runtime.events
            custom_services["inbound.replay"] = inbound_runtime.replay
            custom_services["inbound.schemas"] = inbound_runtime.schemas
            custom_services["inbound.service-account-security"] = (
                inbound_runtime.service_account_security
            )
            custom_services["inbound.authentication"] = inbound_runtime.authentication
            custom_services["inbound.admission"] = inbound_runtime.admission
            custom_services["inbound.limiter"] = inbound_runtime.limiter
            custom_services["inbound.gateway"] = inbound_runtime.gateway
            custom_services["inbound.ingress"] = inbound_runtime.ingress
            custom_services["inbound.publisher"] = inbound_runtime.publisher
            custom_services["inbound.publisher-worker"] = inbound_runtime.publisher_worker
            custom_services["inbound.recovery"] = inbound_runtime.recovery
            custom_services["inbound.recovery-worker"] = inbound_runtime.recovery_worker
            custom_services["inbound.manager"] = inbound_runtime.manager
            custom_services["inbound.owner"] = inbound_runtime.owner

        webhook_runtime = None
        if self._webhooks_enabled:
            from phoenix_os.webhooks import (
                InMemoryWebhookDeliveryRepository,
                InMemoryWebhookSubscriptionRepository,
                StateWebhookDeliveryRepository,
                StateWebhookSubscriptionRepository,
                create_webhook_runtime,
            )

            webhook_subscriptions = self._webhook_subscription_repository
            if webhook_subscriptions is None:
                webhook_subscriptions = (
                    InMemoryWebhookSubscriptionRepository(
                        capacity=self._webhook_subscription_capacity
                    )
                    if state_store is None
                    else StateWebhookSubscriptionRepository(
                        state_store,
                        capacity=self._webhook_subscription_capacity,
                    )
                )

            webhook_deliveries = self._webhook_delivery_repository
            if webhook_deliveries is None:
                webhook_deliveries = (
                    InMemoryWebhookDeliveryRepository(capacity=self._webhook_delivery_capacity)
                    if state_store is None
                    else StateWebhookDeliveryRepository(
                        state_store,
                        capacity=self._webhook_delivery_capacity,
                    )
                )

            assert self._secrets is not None
            assert self._webhook_egress_policies is not None
            webhook_runtime = create_webhook_runtime(
                events=self._events,
                subscriptions=webhook_subscriptions,
                deliveries=webhook_deliveries,
                secrets=self._secrets,
                serializers=self._webhook_event_serializers,
                egress_policies=self._webhook_egress_policies,
                signing_context=self._webhook_signing_context,
                dispatcher_config=self._webhook_dispatcher_config,
                transport_config=self._webhook_transport_config,
                dispatch_poll_interval=self._webhook_dispatch_poll_interval,
                recovery_batch_size=self._webhook_recovery_batch_size,
                audit=self._audit,
                observability=self._observability,
            )
            custom_services["webhooks"] = webhook_runtime
            custom_services["webhooks.subscriptions"] = webhook_runtime.subscriptions
            custom_services["webhooks.deliveries"] = webhook_runtime.deliveries
            custom_services["webhooks.registry"] = webhook_runtime.registry
            custom_services["webhooks.scheduler"] = webhook_runtime.scheduler
            custom_services["webhooks.events"] = webhook_runtime.event_adapter
            custom_services["webhooks.signer"] = webhook_runtime.signer
            custom_services["webhooks.transport"] = webhook_runtime.transport
            custom_services["webhooks.dispatcher"] = webhook_runtime.dispatcher
            custom_services["webhooks.dispatcher-worker"] = webhook_runtime.dispatcher_worker
            custom_services["webhooks.recovery"] = webhook_runtime.recovery
            custom_services["webhooks.manager"] = webhook_runtime.manager
            custom_services["webhooks.owner"] = webhook_runtime.owner

        job_worker_service = None
        if self._jobs is not None:
            from phoenix_os.jobs import JobWorker

            job_worker_service = JobWorker(
                self._jobs,
                poll_interval=self._job_poll_interval,
                lease_ttl=self._job_lease_ttl,
                batch_size=self._job_batch_size,
                worker=self._job_worker,
            )

        workflow_worker_service = None
        if self._workflows is not None:
            from phoenix_os.workflows import WorkflowWorker

            workflow_worker_service = WorkflowWorker(
                self._workflows,
                poll_interval=self._workflow_poll_interval,
                worker=self._workflow_worker,
            )

        control_plane_stack = None
        operator_mode = (
            self._control_plane_operator_registry is not None
            or self._control_plane_operator_token is not None
        )
        if self._control_plane_authenticator is not None or operator_mode:
            from phoenix_os.control_plane.durable_session_contracts import (
                ControlPlaneDurableSessionPolicy,
            )
            from phoenix_os.control_plane.durable_session_memory import (
                InMemoryControlPlaneDurableSessionRepository,
            )
            from phoenix_os.control_plane.durable_session_state import (
                StateControlPlaneDurableSessionRepository,
            )
            from phoenix_os.control_plane.journal_memory import (
                InMemoryControlPlaneCommandJournalRepository,
            )
            from phoenix_os.control_plane.journal_state import (
                StateControlPlaneCommandJournalRepository,
            )
            from phoenix_os.control_plane.operator_contracts import (
                ControlPlaneOperatorRecord,
                ControlPlaneOperatorRole,
            )
            from phoenix_os.control_plane.operator_memory import (
                InMemoryControlPlaneOperatorRegistry,
            )
            from phoenix_os.control_plane.operator_state import (
                StateControlPlaneOperatorRegistry,
            )
            from phoenix_os.control_plane.runtime import ControlPlaneRuntimeStack

            service_account_repository = self._control_plane_service_account_repository

            if self._control_plane_service_accounts_enabled and service_account_repository is None:
                from phoenix_os.control_plane.service_account_memory import (
                    InMemoryControlPlaneServiceAccountRepository,
                )
                from phoenix_os.control_plane.service_account_state import (
                    StateControlPlaneServiceAccountRepository,
                )

                service_account_repository = (
                    InMemoryControlPlaneServiceAccountRepository()
                    if state_store is None
                    else StateControlPlaneServiceAccountRepository(state_store)
                )

            command_journal = self._control_plane_command_journal
            if command_journal is None:
                command_journal = (
                    InMemoryControlPlaneCommandJournalRepository(
                        capacity=self._control_plane_command_journal_capacity
                    )
                    if state_store is None
                    else StateControlPlaneCommandJournalRepository(
                        state_store,
                        capacity=self._control_plane_command_journal_capacity,
                    )
                )

            operator_registry = self._control_plane_operator_registry
            bootstrap_operator = None
            durable_session_repository = self._control_plane_durable_session_repository
            durable_session_policy = (
                self._control_plane_durable_session_policy or ControlPlaneDurableSessionPolicy()
            )
            if operator_mode:
                if operator_registry is None:
                    operator_registry = (
                        InMemoryControlPlaneOperatorRegistry(
                            capacity=self._control_plane_operator_capacity
                        )
                        if state_store is None
                        else StateControlPlaneOperatorRegistry(
                            state_store,
                            capacity=self._control_plane_operator_capacity,
                        )
                    )
                if durable_session_repository is None:
                    durable_session_repository = (
                        InMemoryControlPlaneDurableSessionRepository(
                            capacity=self._control_plane_durable_session_capacity,
                            max_sessions_per_operator=(
                                durable_session_policy.max_sessions_per_operator
                            ),
                        )
                        if state_store is None
                        else StateControlPlaneDurableSessionRepository(
                            state_store,
                            capacity=self._control_plane_durable_session_capacity,
                            max_sessions_per_operator=(
                                durable_session_policy.max_sessions_per_operator
                            ),
                        )
                    )
                if self._control_plane_operator_token is not None:
                    now = datetime.now(UTC)
                    bootstrap_operator = ControlPlaneOperatorRecord(
                        id=uuid4(),
                        username=self._control_plane_operator_username,
                        display_name=self._control_plane_operator_display_name,
                        role=ControlPlaneOperatorRole(self._control_plane_operator_role),
                        token_digest=self._control_plane_operator_token.digest,
                        created_at=now,
                        updated_at=now,
                    )

            machine_routes = self._control_plane_service_account_machine_routes
            if (
                inference_stack is not None
                and self._inference_service_account_administration_enabled
            ):
                from phoenix_os.control_plane.inference_machine_http import (
                    control_plane_inference_machine_routes,
                )

                machine_routes = (
                    *machine_routes,
                    *control_plane_inference_machine_routes(inference_stack.administration),
                )
            if inbound_runtime is not None and self._inbound_service_account_administration_enabled:
                from phoenix_os.control_plane.inbound_machine_http import (
                    control_plane_inbound_machine_routes,
                )

                machine_routes = (
                    *machine_routes,
                    *control_plane_inbound_machine_routes(inbound_runtime.manager),
                )
            if webhook_runtime is not None and self._webhook_service_account_administration_enabled:
                from phoenix_os.control_plane.webhook_machine_http import (
                    control_plane_webhook_machine_routes,
                )

                machine_routes = (
                    *machine_routes,
                    *control_plane_webhook_machine_routes(webhook_runtime.manager),
                )

            control_plane_stack = ControlPlaneRuntimeStack.create(
                event_bus=self._events,
                capabilities=self._capabilities,
                authenticator=self._control_plane_authenticator,
                operator_registry=operator_registry,
                bootstrap_operator=bootstrap_operator,
                durable_session_repository=durable_session_repository,
                durable_session_policy=durable_session_policy,
                durable_session_cookie_policy=(self._control_plane_durable_session_cookie_policy),
                durable_session_recovery_poll_interval=(
                    self._control_plane_durable_session_recovery_poll_interval
                ),
                durable_session_recovery_batch_size=(
                    self._control_plane_durable_session_recovery_batch_size
                ),
                durable_session_retention_policy=(
                    self._control_plane_durable_session_retention_policy
                ),
                durable_session_retention_poll_interval=(
                    self._control_plane_durable_session_retention_poll_interval
                ),
                step_up_policy=self._control_plane_step_up_policy,
                service_account_repository=(service_account_repository),
                service_account_machine_routes=machine_routes,
                service_account_audit_secret=(self._control_plane_service_account_audit_secret),
                service_account_replay_secret=(self._control_plane_service_account_replay_secret),
                inference_administration=(
                    None
                    if inference_stack is None or not operator_mode
                    else inference_stack.administration
                ),
                inbound_manager=(
                    None
                    if inbound_runtime is None or not operator_mode
                    else inbound_runtime.manager
                ),
                inbound_http=(None if inbound_runtime is None else inbound_runtime.ingress),
                webhook_manager=(
                    None
                    if webhook_runtime is None or not operator_mode
                    else webhook_runtime.manager
                ),
                policy_engine=self._policy,
                jobs=self._jobs,
                job_records=self._control_plane_job_records,
                workflows=self._workflows,
                plugins=self._plugins,
                audit=self._audit,
                job_worker=job_worker_service,
                workflow_worker=workflow_worker_service,
                http_config=self._control_plane_http_config,
                network_policy=self._control_plane_network_policy,
                client_rate_limit=self._control_plane_client_rate_limit,
                tls_listener_config=self._control_plane_tls_listener_config,
                remote_login_policy=self._control_plane_remote_login_policy,
                remote_address_secret=self._control_plane_remote_address_secret,
                event_config=self._control_plane_event_config,
                job_commands=self._jobs,
                workflow_commands=self._workflows,
                command_journal=command_journal,
                command_recovery_poll_interval=(self._control_plane_command_recovery_poll_interval),
                command_recovery_batch_size=self._control_plane_command_recovery_batch_size,
                command_retention_policy=self._control_plane_command_retention_policy,
                command_retention_poll_interval=(
                    self._control_plane_command_retention_poll_interval
                ),
            )
            if inbound_runtime is not None and control_plane_stack.service_accounts is not None:
                service_account_policy = control_plane_stack.service_accounts.policy
                if service_account_policy is None:
                    raise AssertionError("inbound service-account binding lost policy")
                inbound_runtime.service_account_security.bind(
                    authentication=(control_plane_stack.service_accounts.authentication),
                    replay=control_plane_stack.service_accounts.replay,
                    policy=service_account_policy,
                )

            custom_services["control_plane"] = control_plane_stack.service
            custom_services["control_plane.command-journal"] = control_plane_stack.journal
            custom_services["control_plane.command-history"] = control_plane_stack.history
            custom_services["control_plane.command-recovery"] = control_plane_stack.recovery
            custom_services["control_plane.command-retention"] = control_plane_stack.retention
            custom_services["control_plane.events"] = control_plane_stack.events
            custom_services["control_plane.commands"] = control_plane_stack.commands
            custom_services["control_plane.http"] = control_plane_stack.http
            if control_plane_stack.secure_http is not None:
                custom_services["control_plane.secure-http"] = control_plane_stack.secure_http
                custom_services["control_plane.network"] = (
                    control_plane_stack.secure_http.network_policy
                )
                custom_services["control_plane.network-guard"] = (
                    control_plane_stack.secure_http.network_guard
                )
                if control_plane_stack.secure_http.remote_login is not None:
                    custom_services["control_plane.remote-login"] = (
                        control_plane_stack.secure_http.remote_login
                    )
                if control_plane_stack.secure_http.remote_audit is not None:
                    custom_services["control_plane.remote-audit"] = (
                        control_plane_stack.secure_http.remote_audit
                    )
            if control_plane_stack.operator_registry is not None:
                custom_services["control_plane.operator-registry"] = (
                    control_plane_stack.operator_registry
                )
            if control_plane_stack.operator_access is not None:
                custom_services["control_plane.operator-access"] = (
                    control_plane_stack.operator_access
                )
            if control_plane_stack.operator_api is not None:
                custom_services["control_plane.operators"] = control_plane_stack.operator_api
            if control_plane_stack.durable_sessions is not None:
                custom_services["control_plane.operator-sessions"] = (
                    control_plane_stack.durable_sessions
                )
            if control_plane_stack.durable_session_history is not None:
                custom_services["control_plane.operator-session-history"] = (
                    control_plane_stack.durable_session_history
                )
            if control_plane_stack.durable_session_recovery is not None:
                custom_services["control_plane.operator-session-recovery"] = (
                    control_plane_stack.durable_session_recovery
                )
            if control_plane_stack.durable_session_retention is not None:
                custom_services["control_plane.operator-session-retention"] = (
                    control_plane_stack.durable_session_retention
                )
            if control_plane_stack.operator_step_up is not None:
                custom_services["control_plane.operator-step-up"] = (
                    control_plane_stack.operator_step_up
                )

            if control_plane_stack.inbound is not None:
                custom_services["control_plane.inbound"] = control_plane_stack.inbound
            if control_plane_stack.inbound_http is not None:
                custom_services["control_plane.inbound-http"] = control_plane_stack.inbound_http
            if control_plane_stack.inbound_management_http is not None:
                custom_services["control_plane.inbound-management-http"] = (
                    control_plane_stack.inbound_management_http
                )

            if control_plane_stack.webhooks is not None:
                custom_services["control_plane.webhooks"] = control_plane_stack.webhooks
            if control_plane_stack.webhook_http is not None:
                custom_services["control_plane.webhook-http"] = control_plane_stack.webhook_http

            if control_plane_stack.service_accounts is not None:
                service_accounts = control_plane_stack.service_accounts

                custom_services["control_plane.service-accounts"] = service_accounts.administration

                custom_services["control_plane.service-account-repository"] = (
                    service_accounts.repository
                )

                custom_services["control_plane.service-account-lifecycle"] = (
                    service_accounts.lifecycle
                )

                custom_services["control_plane.service-account-audit"] = service_accounts.audit

                custom_services["control_plane.service-account-http"] = service_accounts.http

                custom_services["control_plane.service-account-authentication"] = (
                    service_accounts.authentication
                )

                custom_services["control_plane.service-account-request-security"] = (
                    service_accounts.request_security
                )

                if service_accounts.machine_http is not None:
                    custom_services["control_plane.service-account-machine-http"] = (
                        service_accounts.machine_http
                    )

            if control_plane_stack.operator_registry_owner is not None:
                components.append(
                    ComponentSpec(
                        "control_plane.operator-registry",
                        control_plane_stack.operator_registry_owner,
                    )
                )
            if control_plane_stack.durable_sessions_owner is not None:
                components.append(
                    ComponentSpec(
                        "control_plane.operator-sessions",
                        control_plane_stack.durable_sessions_owner,
                    )
                )
            if control_plane_stack.operator_access is not None:
                components.append(
                    ComponentSpec(
                        "control_plane.operator-access",
                        control_plane_stack.operator_access,
                    )
                )
            if control_plane_stack.durable_session_recovery is not None:
                components.append(
                    ComponentSpec(
                        "control_plane.operator-session-recovery",
                        control_plane_stack.durable_session_recovery,
                    )
                )
            if control_plane_stack.durable_session_retention is not None:
                components.append(
                    ComponentSpec(
                        "control_plane.operator-session-retention",
                        control_plane_stack.durable_session_retention,
                    )
                )
            if control_plane_stack.service_accounts_owner is not None:
                components.append(
                    ComponentSpec(
                        "control_plane.service-accounts",
                        control_plane_stack.service_accounts_owner,
                    )
                )

            components.append(
                ComponentSpec("control_plane.command-journal", control_plane_stack.journal_owner)
            )
            components.append(
                ComponentSpec("control_plane.command-recovery", control_plane_stack.recovery)
            )
            components.append(
                ComponentSpec("control_plane.command-retention", control_plane_stack.retention)
            )
            components.append(ComponentSpec("control_plane.events", control_plane_stack.events))
            components.append(ComponentSpec("control_plane.commands", control_plane_stack.commands))

        if inbound_runtime is not None:
            components.append(ComponentSpec("inbound", inbound_runtime.owner))
            components.append(
                ComponentSpec(
                    "inbound.publisher",
                    inbound_runtime.publisher_worker,
                )
            )
            components.append(
                ComponentSpec(
                    "inbound.recovery",
                    inbound_runtime.recovery_worker,
                )
            )

        if webhook_runtime is not None:
            components.append(ComponentSpec("webhooks", webhook_runtime.owner))
            components.append(
                ComponentSpec(
                    "webhooks.dispatcher",
                    webhook_runtime.dispatcher_worker,
                )
            )
            components.append(
                ComponentSpec(
                    "webhooks.events",
                    webhook_runtime.event_adapter,
                )
            )

        if job_worker_service is not None:
            components.append(ComponentSpec("jobs", job_worker_service))
        if workflow_worker_service is not None:
            components.append(ComponentSpec("workflows", workflow_worker_service))
        if control_plane_stack is not None:
            components.append(ComponentSpec("control_plane.http", control_plane_stack.http))

        durable_agent_stack = None
        durable_reconciliation_lifecycle = None
        durable_reconciliation_storage_lifecycle = None
        durable_cleanup_lifecycle = None
        durable_cleanup_storage_lifecycle = None
        try:
            if self._agent_durable_enabled:
                from phoenix_os.agent import (
                    ContentFreeDurableRunObserver,
                    ToolApprovalDurableRevalidator,
                    ToolApprovalStateService,
                    create_durable_agent_runtime_stack,
                )
                from phoenix_os.agent.durable_authorization import (
                    PolicyEngineDurableReconciliationAuthorizer,
                )

                assert self._agent_configuration is not None
                assert self._agent_durable_store is not None
                assert self._agent_durable_lease_manager is not None
                assert self._agent_durable_compatibility_validator is not None

                approval_revalidator = self._agent_durable_approval_revalidator
                if approval_revalidator is None and isinstance(
                    self._agent_approval_service,
                    ToolApprovalStateService,
                ):
                    approval_revalidator = ToolApprovalDurableRevalidator(
                        self._agent_approval_service
                    )

                durable_observer = ContentFreeDurableRunObserver(
                    self._agent_configuration,
                    events=self._events,
                    audit=self._audit,
                    observability=self._observability,
                )

                reconciliation_authorizer = None
                if self._agent_durable_reconciliation_administration_enabled:
                    assert self._policy is not None
                    reconciliation_authorizer = PolicyEngineDurableReconciliationAuthorizer(
                        self._policy
                    )

                durable_agent_stack = create_durable_agent_runtime_stack(
                    store=self._agent_durable_store,
                    lease_manager=self._agent_durable_lease_manager,
                    compatibility_validator=self._agent_durable_compatibility_validator,
                    recovery_configuration=self._agent_durable_recovery_configuration,
                    approval_revalidator=approval_revalidator,
                    observer=durable_observer,
                    administration_configuration=(self._agent_durable_administration_configuration),
                    machine_guard=self._agent_durable_machine_administration_guard,
                    reconciliation_authorizer=reconciliation_authorizer,
                    reconciliation_audit=(
                        self._audit
                        if self._agent_durable_reconciliation_administration_enabled
                        else None
                    ),
                    reconciliation_status_lookup=(self._agent_durable_reconciliation_status_lookup),
                    protector=self._agent_checkpoint_protector,
                    retention_policy=self._agent_durable_retention_policy,
                    retention_configuration=(self._agent_durable_retention_configuration),
                    cleanup_audit=(
                        self._audit if self._agent_durable_cleanup_administration_enabled else None
                    ),
                )
                custom_services["agent.durable"] = durable_agent_stack
                custom_services["agent.durable.administration"] = durable_agent_stack.administration
                custom_services["agent.durable.observer"] = durable_agent_stack.observer
                if durable_agent_stack.reconciliation_administration is not None:
                    custom_services["agent.durable.reconciliation-administration"] = (
                        durable_agent_stack.reconciliation_administration
                    )
                if durable_agent_stack.cleanup_administration is not None:
                    custom_services["agent.durable.cleanup-administration"] = (
                        durable_agent_stack.cleanup_administration
                    )
                custom_services["agent.durable.storage"] = durable_agent_stack.store
                custom_services["agent.durable.leases"] = durable_agent_stack.lease_manager
                custom_services["agent.durable.compatibility"] = (
                    durable_agent_stack.compatibility_validator
                )
                custom_services["agent.durable.recovery"] = durable_agent_stack.recovery_coordinator
                custom_services["agent.durable.recovery-worker"] = (
                    durable_agent_stack.recovery_worker
                )
                if durable_agent_stack.retention_policy is not None:
                    custom_services["agent.durable.retention"] = (
                        durable_agent_stack.retention_policy
                    )
                if durable_agent_stack.retention_worker is not None:
                    custom_services["agent.durable.retention-worker"] = (
                        durable_agent_stack.retention_worker
                    )
                if durable_agent_stack.protector is not None:
                    custom_services["agent.durable.protector"] = durable_agent_stack.protector

                reconciliation_coordinator = durable_agent_stack.reconciliation_administration
                if reconciliation_coordinator is not None:
                    if control_plane_stack is None or control_plane_stack.operator_step_up is None:
                        raise AssertionError(
                            "durable reconciliation composition lost operator step-up"
                        )
                    from phoenix_os.control_plane.durable_administration_protection import (
                        ControlPlaneDurableAdministrationProtection,
                    )
                    from phoenix_os.control_plane.durable_reconciliation_administration import (
                        ControlPlaneDurableReconciliationAdministration,
                    )

                    reconciliation_protection = ControlPlaneDurableAdministrationProtection(
                        step_up=control_plane_stack.operator_step_up,
                    )
                    control_plane_reconciliation = ControlPlaneDurableReconciliationAdministration(
                        coordinator=reconciliation_coordinator,
                        protection=reconciliation_protection,
                    )
                    durable_reconciliation_lifecycle = (
                        _DurableReconciliationAdministrationLifecycle(
                            protection=reconciliation_protection,
                            coordinator=reconciliation_coordinator,
                        )
                    )
                    control_plane_reconciliation_http = (
                        control_plane_stack.http.bind_durable_reconciliation_http(
                            control_plane_reconciliation
                        )
                    )
                    durable_reconciliation_lifecycle.bind_http_close(
                        control_plane_reconciliation_http.close
                    )
                    durable_reconciliation_storage_lifecycle = (
                        _DurableReconciliationStorageLifecycle(
                            storage=durable_agent_stack.storage_lifecycle,
                            reconciliation=durable_reconciliation_lifecycle,
                        )
                    )
                    custom_services["control_plane.durable-reconciliation"] = (
                        control_plane_reconciliation
                    )
                    custom_services["control_plane.durable-reconciliation-http"] = (
                        control_plane_reconciliation_http
                    )

                cleanup_coordinator = durable_agent_stack.cleanup_administration
                if cleanup_coordinator is not None:
                    if control_plane_stack is None or control_plane_stack.operator_step_up is None:
                        raise AssertionError("durable cleanup composition lost operator step-up")
                    from phoenix_os.control_plane.durable_administration_protection import (
                        ControlPlaneDurableAdministrationProtection,
                    )
                    from phoenix_os.control_plane.durable_cleanup_administration import (
                        ControlPlaneDurableCleanupAdministration,
                    )

                    cleanup_protection = ControlPlaneDurableAdministrationProtection(
                        step_up=control_plane_stack.operator_step_up,
                    )
                    control_plane_cleanup = ControlPlaneDurableCleanupAdministration(
                        coordinator=cleanup_coordinator,
                        protection=cleanup_protection,
                    )
                    durable_cleanup_lifecycle = _DurableCleanupAdministrationLifecycle(
                        protection=cleanup_protection,
                        coordinator=cleanup_coordinator,
                    )
                    control_plane_cleanup_http = control_plane_stack.http.bind_durable_cleanup_http(
                        control_plane_cleanup
                    )
                    durable_cleanup_lifecycle.bind_http_close(control_plane_cleanup_http.close)
                    durable_cleanup_storage_lifecycle = _DurableCleanupStorageLifecycle(
                        storage=(
                            durable_agent_stack.storage_lifecycle
                            if durable_reconciliation_storage_lifecycle is None
                            else durable_reconciliation_storage_lifecycle
                        ),
                        cleanup=durable_cleanup_lifecycle,
                    )
                    custom_services["control_plane.durable-cleanup"] = control_plane_cleanup
                    custom_services["control_plane.durable-cleanup-http"] = (
                        control_plane_cleanup_http
                    )

                agent_component_index = next(
                    index for index, component in enumerate(components) if component.name == "agent"
                )
                components.insert(
                    agent_component_index,
                    ComponentSpec(
                        "agent.durable.storage",
                        (
                            durable_cleanup_storage_lifecycle
                            if durable_cleanup_storage_lifecycle is not None
                            else (
                                durable_agent_stack.storage_lifecycle
                                if durable_reconciliation_storage_lifecycle is None
                                else durable_reconciliation_storage_lifecycle
                            )
                        ),
                    ),
                )
                components.insert(
                    agent_component_index + 2,
                    ComponentSpec(
                        "agent.durable.recovery",
                        durable_agent_stack.recovery_lifecycle,
                    ),
                )
                if durable_agent_stack.retention_lifecycle is not None:
                    components.insert(
                        agent_component_index + 3,
                        ComponentSpec(
                            "agent.durable.retention",
                            durable_agent_stack.retention_lifecycle,
                        ),
                    )

                if durable_reconciliation_lifecycle is not None:
                    control_plane_http_index = next(
                        index
                        for index, component in enumerate(components)
                        if component.name == "control_plane.http"
                    )
                    components.insert(
                        control_plane_http_index,
                        ComponentSpec(
                            "control_plane.durable-reconciliation",
                            durable_reconciliation_lifecycle,
                        ),
                    )

                if durable_cleanup_lifecycle is not None:
                    control_plane_http_index = next(
                        index
                        for index, component in enumerate(components)
                        if component.name == "control_plane.http"
                    )
                    components.insert(
                        control_plane_http_index,
                        ComponentSpec(
                            "control_plane.durable-cleanup",
                            durable_cleanup_lifecycle,
                        ),
                    )

            runtime = PhoenixRuntime(
                kernel=self._kernel,
                events=self._events,
                capabilities=self._capabilities,
                components=components,
                services=custom_services,
                metadata=self._metadata,
                source=self._source,
            )
            if control_plane_stack is not None:
                control_plane_stack.bind_runtime(runtime)
            return runtime
        except (Exception, asyncio.CancelledError) as exception:
            rollback_failure: BaseException | None = None
            if durable_cleanup_lifecycle is not None:
                try:
                    await durable_cleanup_lifecycle.close()
                except (Exception, asyncio.CancelledError) as rollback_exception:
                    rollback_failure = rollback_exception

            if durable_reconciliation_lifecycle is not None:
                try:
                    await durable_reconciliation_lifecycle.close()
                except (Exception, asyncio.CancelledError) as rollback_exception:
                    if rollback_failure is None:
                        rollback_failure = rollback_exception

            if durable_agent_stack is not None:
                try:
                    await durable_agent_stack.close()
                except (Exception, asyncio.CancelledError) as rollback_exception:
                    if rollback_failure is None:
                        rollback_failure = rollback_exception

            if rollback_failure is not None:
                raise exception from rollback_failure
            raise
