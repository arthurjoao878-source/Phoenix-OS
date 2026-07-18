"""Deterministic asynchronous dependency composition for Phoenix Runtime."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, cast

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
from phoenix_os.policy import PolicyEngine
from phoenix_os.runtime import ComponentSpec, LifecycleComponent, PhoenixRuntime
from phoenix_os.state import StateStore, StateStoreRegistry

if TYPE_CHECKING:
    from phoenix_os.identity import AuthenticationManager
    from phoenix_os.secrets import SecretsManager

_RESERVED_DEFINITION_NAMES = frozenset(
    {
        "kernel",
        "events",
        "identity",
        "capabilities",
        "configuration",
        "observability",
        "plugins",
        "policy",
        "state",
        "runtime",
        "secrets",
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
        observe_events: bool = True,
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
        self._observe_events = observe_events
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
        return PhoenixRuntime(
            kernel=self._kernel,
            events=self._events,
            capabilities=self._capabilities,
            components=components,
            services=custom_services,
            metadata=self._metadata,
            source=self._source,
        )
