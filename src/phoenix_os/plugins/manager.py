"""Deterministic plugin registration, dependency resolution, and lifecycle ownership."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.plugins.contracts import (
    PHOENIX_VERSION,
    PLUGIN_API_VERSION,
    Plugin,
    PluginContext,
    PluginFailure,
    PluginFailurePhase,
    PluginManagerState,
    PluginManifest,
    PluginPermission,
    PluginRegistration,
    PluginSnapshot,
    PluginStatus,
    SemanticVersion,
    new_plugin_registration,
)
from phoenix_os.plugins.errors import (
    PluginAlreadyRegisteredError,
    PluginCompatibilityError,
    PluginDependencyCycleError,
    PluginDependencyError,
    PluginExportError,
    PluginNotFoundError,
    PluginPermissionDeniedError,
    PluginSetupError,
    PluginStartError,
    PluginStateError,
    PluginStopError,
)
from phoenix_os.plugins.sdk import PluginRegistrar
from phoenix_os.state import StateStoreRegistry


@dataclass(slots=True)
class _RegisteredPlugin:
    registration: PluginRegistration
    plugin: Plugin
    manifest: PluginManifest
    sequence: int
    status: PluginStatus = PluginStatus.REGISTERED
    registrar: PluginRegistrar | None = None
    context: PluginContext | None = None


class PluginManager:
    """Secure host boundary for plugins and their deterministic lifecycle."""

    def __init__(
        self,
        plugins: Iterable[Plugin] = (),
        *,
        capabilities: CapabilityRegistry,
        events: EventBus,
        state: StateStoreRegistry | None = None,
        observability: ObservabilityHub | None = None,
        allowed_permissions: frozenset[PluginPermission] = frozenset(),
        host_services: Mapping[str, object] | None = None,
        core_version: SemanticVersion | str = PHOENIX_VERSION,
        api_version: int = PLUGIN_API_VERSION,
        source: str = "phoenix.plugins",
    ) -> None:
        if api_version <= 0:
            raise ValueError("api_version must be greater than zero")
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")

        self._capabilities = capabilities
        self._events = events
        self._state_registry = state
        self._observability = observability
        self._allowed_permissions = frozenset(
            PluginPermission(item) for item in allowed_permissions
        )
        self._core_version = SemanticVersion.parse(core_version)
        self._api_version = api_version
        self._source = normalized_source
        self._registered: dict[str, _RegisteredPlugin] = {}
        self._by_registration: dict[object, str] = {}
        self._resolved: tuple[_RegisteredPlugin, ...] = ()
        self._active: list[_RegisteredPlugin] = []
        self._services: dict[str, tuple[str, object]] = {}
        self._host_services: dict[str, object] = {
            "capabilities": capabilities,
            "events": events,
        }
        if state is not None:
            self._host_services["state"] = state
        if observability is not None:
            self._host_services["observability"] = observability
        if host_services is not None:
            self._merge_host_services(host_services)
        self._host_services["plugins"] = self
        self._state = PluginManagerState.CREATED
        self._failures: list[PluginFailure] = []
        self._sequence = 0
        self._lock = asyncio.Lock()

        for plugin in plugins:
            self._register_initial(plugin)

    @property
    def state(self) -> PluginManagerState:
        return self._state

    @property
    def core_version(self) -> SemanticVersion:
        return self._core_version

    @property
    def api_version(self) -> int:
        return self._api_version

    def bind_services(self, services: Mapping[str, object]) -> None:
        """Bind composed runtime services before plugin preparation."""

        if self._state is not PluginManagerState.CREATED:
            raise PluginStateError("host services can only be bound before preparation")
        self._merge_host_services(services)
        self._host_services["plugins"] = self

    async def register(self, plugin: Plugin) -> PluginRegistration:
        async with self._lock:
            self._require_state(PluginManagerState.CREATED)
            return self._register_initial(plugin).registration

    async def unregister(self, registration: PluginRegistration) -> bool:
        async with self._lock:
            self._require_state(PluginManagerState.CREATED)
            plugin_id = self._by_registration.get(registration.id)
            if plugin_id is None or plugin_id != registration.plugin_id:
                return False
            registered = self._registered.get(plugin_id)
            if registered is None or registered.registration != registration:
                return False
            del self._registered[plugin_id]
            del self._by_registration[registration.id]
            return True

    async def list_manifests(self) -> tuple[PluginManifest, ...]:
        async with self._lock:
            return tuple(
                item.manifest
                for item in sorted(self._registered.values(), key=lambda item: item.sequence)
            )

    def service(self, name: str) -> object:
        normalized = name.strip()
        if not normalized:
            raise ValueError("service name must not be blank")
        contribution = self._services.get(normalized)
        if contribution is not None:
            return contribution[1]
        try:
            return self._host_services[normalized]
        except KeyError as exception:
            raise PluginNotFoundError(f"plugin service not found: {normalized}") from exception

    async def prepare(self) -> None:
        async with self._lock:
            if self._state is PluginManagerState.PREPARED:
                return
            self._require_state(PluginManagerState.CREATED)
            self._state = PluginManagerState.PREPARING
            prepared: list[_RegisteredPlugin] = []
            current: _RegisteredPlugin | None = None
            try:
                self._validate_manifests()
                self._resolved = self._resolve_dependencies()
                for current in self._resolved:
                    registrar = self._new_registrar(current.manifest)
                    context = PluginContext(
                        manifest=current.manifest,
                        registrar=registrar,
                        host_services=self._host_services,
                    )
                    current.registrar = registrar
                    current.context = context
                    await self._invoke_plugin_hook(current, "setup", PluginFailurePhase.SETUP)
                    current.status = PluginStatus.PREPARED
                    prepared.append(current)
                    await self._signal("plugin.prepared", current.manifest)
                self._state = PluginManagerState.PREPARED
                await self._metric("plugins.prepared", len(prepared))
            except asyncio.CancelledError:
                await self._cleanup_plugins(tuple((*prepared, *((current,) if current else ()))))
                self._state = PluginManagerState.FAILED
                raise
            except Exception as exception:
                plugin_id = "manager" if current is None else current.manifest.plugin_id
                self._record_failure(plugin_id, PluginFailurePhase.SETUP, exception)
                if current is not None:
                    current.status = PluginStatus.FAILED
                await self._cleanup_plugins(tuple((*prepared, *((current,) if current else ()))))
                self._state = PluginManagerState.FAILED
                await self._signal("plugin.setup.failed", None, {"plugin_id": plugin_id})
                if isinstance(
                    exception,
                    (
                        PluginCompatibilityError,
                        PluginDependencyError,
                        PluginPermissionDeniedError,
                    ),
                ):
                    raise
                raise PluginSetupError(plugin_id, exception) from exception

    async def start(self, context: object) -> None:
        del context
        if self._state is PluginManagerState.CREATED:
            await self.prepare()
        async with self._lock:
            if self._state is PluginManagerState.RUNNING:
                return
            self._require_state(PluginManagerState.PREPARED)
            self._state = PluginManagerState.STARTING
            started: list[_RegisteredPlugin] = []
            current: _RegisteredPlugin | None = None
            try:
                for current in self._resolved:
                    await self._invoke_plugin_hook(current, "start", PluginFailurePhase.START)
                    current.status = PluginStatus.ACTIVE
                    started.append(current)
                    self._active.append(current)
                    await self._signal("plugin.started", current.manifest)
                self._state = PluginManagerState.RUNNING
                await self._metric("plugins.active", len(self._active))
            except asyncio.CancelledError:
                await self._rollback_started(started)
                await self._cleanup_plugins(self._resolved)
                self._state = PluginManagerState.FAILED
                raise
            except Exception as exception:
                plugin_id = "manager" if current is None else current.manifest.plugin_id
                self._record_failure(plugin_id, PluginFailurePhase.START, exception)
                if current is not None:
                    current.status = PluginStatus.FAILED
                await self._rollback_started(started)
                await self._cleanup_plugins(self._resolved)
                self._state = PluginManagerState.FAILED
                await self._signal("plugin.start.failed", None, {"plugin_id": plugin_id})
                raise PluginStartError(plugin_id, exception) from exception

    async def stop(self, context: object) -> None:
        del context
        async with self._lock:
            if self._state is PluginManagerState.STOPPED:
                return
            if self._state is PluginManagerState.CREATED:
                self._state = PluginManagerState.STOPPED
                return
            if self._state not in {
                PluginManagerState.PREPARED,
                PluginManagerState.RUNNING,
                PluginManagerState.FAILED,
            }:
                raise PluginStateError(f"cannot stop plugin manager from state {self._state.value}")

            self._state = PluginManagerState.STOPPING
            shutdown_failures: list[PluginFailure] = []
            for registered in reversed(self._active):
                try:
                    await self._invoke_plugin_hook(registered, "stop", PluginFailurePhase.STOP)
                    registered.status = PluginStatus.STOPPED
                    await self._signal("plugin.stopped", registered.manifest)
                except asyncio.CancelledError:
                    raise
                except Exception as exception:
                    failure = PluginFailure(
                        registered.manifest.plugin_id,
                        PluginFailurePhase.STOP,
                        exception,
                    )
                    shutdown_failures.append(failure)
                    self._failures.append(failure)
                    registered.status = PluginStatus.FAILED
            self._active.clear()

            cleanup_failures = await self._cleanup_plugins(self._resolved)
            shutdown_failures.extend(cleanup_failures)
            self._state = PluginManagerState.STOPPED
            await self._metric("plugins.active", 0)
            if shutdown_failures:
                raise PluginStopError(tuple(shutdown_failures))

    async def close(self) -> None:
        await self.stop(object())

    async def snapshot(self) -> PluginSnapshot:
        async with self._lock:
            registered = sorted(self._registered.values(), key=lambda item: item.sequence)
            return PluginSnapshot(
                state=self._state,
                registered=tuple(item.manifest.plugin_id for item in registered),
                resolved_order=tuple(item.manifest.plugin_id for item in self._resolved),
                prepared=tuple(
                    item.manifest.plugin_id
                    for item in self._resolved
                    if item.status in {PluginStatus.PREPARED, PluginStatus.ACTIVE}
                ),
                active=tuple(item.manifest.plugin_id for item in self._active),
                services=tuple(self._services),
                failures=tuple(self._failures),
            )

    def _register_initial(self, plugin: Plugin) -> _RegisteredPlugin:
        manifest = self._manifest_of(plugin)
        if manifest.plugin_id in self._registered:
            raise PluginAlreadyRegisteredError(f"plugin already registered: {manifest.plugin_id}")
        registration = new_plugin_registration(manifest.plugin_id)
        registered = _RegisteredPlugin(registration, plugin, manifest, self._sequence)
        self._sequence += 1
        self._registered[manifest.plugin_id] = registered
        self._by_registration[registration.id] = manifest.plugin_id
        return registered

    @staticmethod
    def _manifest_of(plugin: Plugin) -> PluginManifest:
        manifest = getattr(plugin, "manifest", None)
        if not isinstance(manifest, PluginManifest):
            raise TypeError("plugin must expose a PluginManifest as manifest")
        if not callable(getattr(plugin, "setup", None)):
            raise TypeError("plugin must expose a callable setup hook")
        return manifest

    def _validate_manifests(self) -> None:
        for registered in sorted(self._registered.values(), key=lambda item: item.sequence):
            manifest = registered.manifest
            if manifest.api_version != self._api_version:
                raise PluginCompatibilityError(
                    f"plugin {manifest.plugin_id!r} requires API {manifest.api_version}; "
                    f"host provides {self._api_version}"
                )
            if not manifest.phoenix_versions.accepts(self._core_version):
                raise PluginCompatibilityError(
                    f"plugin {manifest.plugin_id!r} does not support Phoenix {self._core_version}"
                )
            denied = manifest.permissions - self._allowed_permissions
            if denied:
                names = ", ".join(sorted(item.value for item in denied))
                raise PluginPermissionDeniedError(
                    f"plugin {manifest.plugin_id!r} requested denied permissions: {names}"
                )

    def _resolve_dependencies(self) -> tuple[_RegisteredPlugin, ...]:
        ordered = sorted(self._registered.values(), key=lambda item: item.sequence)
        visiting: list[str] = []
        visited: set[str] = set()
        resolved: list[_RegisteredPlugin] = []

        def visit(registered: _RegisteredPlugin) -> None:
            plugin_id = registered.manifest.plugin_id
            if plugin_id in visited:
                return
            if plugin_id in visiting:
                start = visiting.index(plugin_id)
                raise PluginDependencyCycleError(tuple((*visiting[start:], plugin_id)))
            visiting.append(plugin_id)
            try:
                for dependency in registered.manifest.dependencies:
                    target = self._registered.get(dependency.plugin_id)
                    if target is None:
                        if dependency.optional:
                            continue
                        raise PluginDependencyError(
                            f"plugin {plugin_id!r} requires missing plugin {dependency.plugin_id!r}"
                        )
                    if not dependency.versions.accepts(target.manifest.version):
                        raise PluginDependencyError(
                            f"plugin {plugin_id!r} requires {dependency.plugin_id!r} "
                            f"at {dependency.versions}; found {target.manifest.version}"
                        )
                    visit(target)
                visited.add(plugin_id)
                resolved.append(registered)
            finally:
                visiting.pop()

        for registered in ordered:
            visit(registered)
        return tuple(resolved)

    def _new_registrar(self, manifest: PluginManifest) -> PluginRegistrar:
        plugin_id = manifest.plugin_id
        return PluginRegistrar(
            manifest=manifest,
            capabilities=self._capabilities,
            state=self._state_registry,
            publish_service=lambda name, service: self._publish_service(plugin_id, name, service),
            remove_service=lambda name: self._remove_service(plugin_id, name),
            resolve_service=self.service,
        )

    def _publish_service(self, plugin_id: str, name: str, service: object) -> None:
        if name in self._host_services or name in self._services:
            raise PluginExportError(f"plugin service already exists: {name}")
        self._services[name] = (plugin_id, service)

    def _remove_service(self, plugin_id: str, name: str) -> None:
        current = self._services.get(name)
        if current is None:
            return
        if current[0] != plugin_id:
            raise PluginExportError(
                f"plugin {plugin_id!r} cannot remove service owned by {current[0]!r}"
            )
        del self._services[name]

    def _merge_host_services(self, services: Mapping[str, object]) -> None:
        for name, service in services.items():
            normalized = name.strip()
            if not normalized:
                raise ValueError("host service names must not be blank")
            current = self._host_services.get(normalized)
            if current is not None and current is not service:
                raise PluginExportError(f"conflicting host service: {normalized}")
            self._host_services[normalized] = service

    async def _invoke_plugin_hook(
        self,
        registered: _RegisteredPlugin,
        hook_name: str,
        phase: PluginFailurePhase,
    ) -> None:
        context = registered.context
        if context is None:
            raise PluginStateError("plugin context has not been prepared")
        hook = getattr(registered.plugin, hook_name, None)
        if hook is None:
            return
        if not callable(hook):
            raise TypeError(f"plugin {hook_name} hook must be callable")

        async def invoke() -> None:
            result = hook(context)
            if inspect.isawaitable(result):
                await result

        if self._observability is None:
            await invoke()
        else:
            async with self._observability.span(
                f"plugin.{phase.value}",
                source=self._source,
                attributes={"plugin_id": registered.manifest.plugin_id},
            ):
                await invoke()

    async def _rollback_started(self, started: list[_RegisteredPlugin]) -> None:
        for registered in reversed(started):
            try:
                await self._invoke_plugin_hook(registered, "stop", PluginFailurePhase.STOP)
                registered.status = PluginStatus.STOPPED
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._record_failure(
                    registered.manifest.plugin_id,
                    PluginFailurePhase.STOP,
                    exception,
                )
        self._active.clear()

    async def _cleanup_plugins(
        self,
        plugins: tuple[_RegisteredPlugin, ...],
    ) -> list[PluginFailure]:
        failures: list[PluginFailure] = []
        seen: set[str] = set()
        for registered in reversed(plugins):
            plugin_id = registered.manifest.plugin_id
            if plugin_id in seen:
                continue
            seen.add(plugin_id)
            registrar = registered.registrar
            if registrar is None:
                continue
            try:
                await registrar.cleanup()
                if registered.status is not PluginStatus.FAILED:
                    registered.status = PluginStatus.STOPPED
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                failure = PluginFailure(plugin_id, PluginFailurePhase.CLEANUP, exception)
                failures.append(failure)
                self._failures.append(failure)
        return failures

    def _record_failure(
        self,
        plugin_id: str,
        phase: PluginFailurePhase,
        exception: Exception,
    ) -> None:
        self._failures.append(PluginFailure(plugin_id, phase, exception))

    async def _signal(
        self,
        name: str,
        manifest: PluginManifest | None,
        payload: Mapping[str, object] | None = None,
    ) -> None:
        data = {} if payload is None else dict(payload)
        if manifest is not None:
            data.update(
                {
                    "plugin_id": manifest.plugin_id,
                    "plugin_version": str(manifest.version),
                }
            )
        try:
            await self._events.emit(name, source=self._source, payload=data)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        if self._observability is not None:
            try:
                await self._observability.log(
                    name,
                    source=self._source,
                    message=name,
                    severity=Severity.INFO if not name.endswith("failed") else Severity.ERROR,
                    attributes=data,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    async def _metric(self, name: str, value: int) -> None:
        if self._observability is None:
            return
        try:
            await self._observability.metric(
                name,
                value,
                source=self._source,
                kind=MetricKind.GAUGE,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    def _require_state(self, expected: PluginManagerState) -> None:
        if self._state is not expected:
            raise PluginStateError(
                f"expected plugin manager state {expected.value}; found {self._state.value}"
            )
