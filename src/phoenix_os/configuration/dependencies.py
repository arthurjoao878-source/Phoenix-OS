"""Deterministic asynchronous dependency composition for Phoenix Runtime."""

from __future__ import annotations

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
from phoenix_os.runtime import ComponentSpec, LifecycleComponent, PhoenixRuntime
from phoenix_os.state import StateStore, StateStoreRegistry

if TYPE_CHECKING:
    from phoenix_os.audit import AuditLedger
    from phoenix_os.control_plane import (
        AdminTokenAuthenticator,
        ControlPlaneClientRateLimitPolicy,
        ControlPlaneCommandJournalRepository,
        ControlPlaneCommandRetentionPolicy,
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
    from phoenix_os.identity import AuthenticationManager
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
        "jobs",
        "audit",
        "capabilities",
        "configuration",
        "control_plane",
        "control_plane.events",
        "control_plane.commands",
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
        if webhook_service_account_administration_enabled and not service_accounts_enabled:
            raise ValueError("webhook machine administration requires service accounts")
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
        self._composer = ServiceComposer(definitions)
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
