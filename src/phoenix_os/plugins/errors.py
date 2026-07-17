"""Errors exposed by the Phoenix plugin system."""

from __future__ import annotations

from phoenix_os.plugins.contracts import PluginFailure


class PhoenixPluginError(Exception):
    """Base class for plugin subsystem failures."""


class PluginAlreadyRegisteredError(PhoenixPluginError):
    pass


class PluginNotFoundError(PhoenixPluginError):
    pass


class PluginCompatibilityError(PhoenixPluginError):
    pass


class PluginDependencyError(PhoenixPluginError):
    pass


class PluginDependencyCycleError(PluginDependencyError):
    def __init__(self, cycle: tuple[str, ...]) -> None:
        self.cycle = cycle
        super().__init__("plugin dependency cycle: " + " -> ".join(cycle))


class PluginPermissionDeniedError(PhoenixPluginError):
    pass


class PluginExportError(PhoenixPluginError):
    pass


class PluginSetupError(PhoenixPluginError):
    def __init__(self, plugin_id: str, exception: Exception) -> None:
        self.plugin_id = plugin_id
        self.exception = exception
        super().__init__(f"plugin setup failed: {plugin_id}")


class PluginStartError(PhoenixPluginError):
    def __init__(self, plugin_id: str, exception: Exception) -> None:
        self.plugin_id = plugin_id
        self.exception = exception
        super().__init__(f"plugin start failed: {plugin_id}")


class PluginStopError(PhoenixPluginError):
    def __init__(self, failures: tuple[PluginFailure, ...]) -> None:
        self.failures = failures
        super().__init__(f"plugin shutdown failed with {len(failures)} failure(s)")


class PluginStateError(PhoenixPluginError):
    pass


class PluginDiscoveryError(PhoenixPluginError):
    pass
