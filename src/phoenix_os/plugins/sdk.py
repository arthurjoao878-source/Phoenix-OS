"""Restricted Plugin SDK and hook adapters."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping

from phoenix_os.capabilities import (
    CapabilityDescriptor,
    CapabilityProvider,
    CapabilityRegistration,
    CapabilityRegistry,
)
from phoenix_os.plugins.contracts import (
    PluginContext,
    PluginHook,
    PluginManifest,
    PluginPermission,
)
from phoenix_os.plugins.errors import PluginExportError, PluginPermissionDeniedError
from phoenix_os.state import StateStore, StateStoreRegistry

type ServicePublisher = Callable[[str, object], None]
type ServiceRemover = Callable[[str], None]
type ServiceResolver = Callable[[str], object]


def _normalize_contribution_name(name: str, label: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise ValueError(f"{label} must not be blank")
    return normalized


class PluginRegistrar:
    """Host-owned registrar that enforces manifest permissions and exports."""

    def __init__(
        self,
        *,
        manifest: PluginManifest,
        capabilities: CapabilityRegistry,
        state: StateStoreRegistry | None,
        publish_service: ServicePublisher,
        remove_service: ServiceRemover,
        resolve_service: ServiceResolver,
    ) -> None:
        self._manifest = manifest
        self._capabilities = capabilities
        self._state = state
        self._publish_service = publish_service
        self._remove_service = remove_service
        self._resolve_service = resolve_service
        self._capability_registrations: list[CapabilityRegistration] = []
        self._state_stores: list[str] = []
        self._services: list[str] = []
        self._cleaned = False

    @property
    def manifest(self) -> PluginManifest:
        return self._manifest

    @property
    def contribution_counts(self) -> tuple[int, int, int]:
        return (
            len(self._capability_registrations),
            len(self._state_stores),
            len(self._services),
        )

    async def register_capability(
        self,
        descriptor: CapabilityDescriptor,
        provider: CapabilityProvider,
    ) -> None:
        self._ensure_active()
        self._require_permission(PluginPermission.REGISTER_CAPABILITIES)
        self._require_export(descriptor.name, self._manifest.exports.capabilities, "capability")
        registration = await self._capabilities.register(descriptor, provider)
        self._capability_registrations.append(registration)

    async def register_state_store(
        self,
        name: str,
        store: StateStore,
        *,
        make_default: bool = False,
    ) -> None:
        self._ensure_active()
        self._require_permission(PluginPermission.REGISTER_STATE_STORES)
        normalized = _normalize_contribution_name(name, "state store name").lower()
        self._require_export(normalized, self._manifest.exports.state_stores, "state store")
        if self._state is None:
            raise PluginExportError("host does not expose a state-store registry")
        await self._state.register(normalized, store, make_default=make_default)
        self._state_stores.append(normalized)

    async def publish_service(self, name: str, service: object) -> None:
        self._ensure_active()
        self._require_permission(PluginPermission.PUBLISH_SERVICES)
        normalized = _normalize_contribution_name(name, "service name")
        self._require_export(normalized, self._manifest.exports.services, "service")
        self._publish_service(normalized, service)
        self._services.append(normalized)

    def service(self, name: str) -> object:
        return self._resolve_service(_normalize_contribution_name(name, "service name"))

    async def cleanup(self) -> None:
        """Remove all contributions in strict reverse registration order."""

        if self._cleaned:
            return
        failures: list[Exception] = []
        for name in reversed(self._services):
            try:
                self._remove_service(name)
            except Exception as exception:
                failures.append(exception)
        self._services.clear()

        if self._state is not None and not self._state.started:
            for name in reversed(self._state_stores):
                try:
                    await self._state.remove(name)
                except Exception as exception:
                    failures.append(exception)
        self._state_stores.clear()

        for registration in reversed(self._capability_registrations):
            try:
                await self._capabilities.unregister(registration)
            except Exception as exception:
                failures.append(exception)
        self._capability_registrations.clear()
        self._cleaned = True
        if failures:
            raise ExceptionGroup("plugin contribution cleanup failed", failures)

    def _require_permission(self, permission: PluginPermission) -> None:
        if permission not in self._manifest.permissions:
            raise PluginPermissionDeniedError(
                f"plugin {self._manifest.plugin_id!r} did not request permission "
                f"{permission.value!r}"
            )

    def _require_export(self, name: str, allowed: frozenset[str], kind: str) -> None:
        if name not in allowed:
            raise PluginExportError(
                f"plugin {self._manifest.plugin_id!r} did not declare {kind} export {name!r}"
            )

    def _ensure_active(self) -> None:
        if self._cleaned:
            raise PluginExportError("plugin registrar is already cleaned up")


class HookPlugin:
    """Adapt ordinary synchronous or asynchronous callbacks to a plugin."""

    def __init__(
        self,
        manifest: PluginManifest,
        *,
        setup: PluginHook | None = None,
        start: PluginHook | None = None,
        stop: PluginHook | None = None,
    ) -> None:
        for name, hook in (("setup", setup), ("start", start), ("stop", stop)):
            if hook is not None and not callable(hook):
                raise TypeError(f"{name} hook must be callable")
        self.manifest = manifest
        self._setup = setup
        self._start = start
        self._stop = stop

    async def setup(self, context: PluginContext) -> None:
        await _run_hook(self._setup, context)

    async def start(self, context: PluginContext) -> None:
        await _run_hook(self._start, context)

    async def stop(self, context: PluginContext) -> None:
        await _run_hook(self._stop, context)


async def _run_hook(hook: PluginHook | None, context: PluginContext) -> None:
    if hook is None:
        return
    result = hook(context)
    if inspect.isawaitable(result):
        await result


def plugin_services(context: PluginContext) -> Mapping[str, object]:
    """Return the immutable host-service snapshot supplied to a plugin."""

    return context.host_services
