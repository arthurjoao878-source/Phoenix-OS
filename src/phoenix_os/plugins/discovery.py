"""Explicit, allowlisted plugin discovery through Python entry points."""

from __future__ import annotations

import inspect
from importlib import metadata
from typing import cast

from phoenix_os.plugins.contracts import Plugin, PluginReference
from phoenix_os.plugins.errors import PluginDiscoveryError, PluginPermissionDeniedError


class EntryPointPluginDiscovery:
    """Discover metadata without importing plugin code, then load by explicit allowlist."""

    def __init__(self, group: str = "phoenix_os.plugins") -> None:
        normalized = group.strip()
        if not normalized:
            raise ValueError("entry point group must not be blank")
        self._group = normalized

    @property
    def group(self) -> str:
        return self._group

    def discover(self) -> tuple[PluginReference, ...]:
        references = [
            PluginReference(entry.name, entry.value, entry.group)
            for entry in metadata.entry_points().select(group=self._group)
        ]
        references.sort(key=lambda item: (item.name, item.value))
        return tuple(references)

    async def load(
        self,
        reference: PluginReference,
        *,
        allowed_names: frozenset[str],
    ) -> Plugin:
        if reference.group != self._group:
            raise PluginDiscoveryError("plugin reference belongs to a different entry point group")
        if reference.name not in allowed_names:
            raise PluginPermissionDeniedError(f"entry point is not allowlisted: {reference.name}")

        candidates = [
            entry
            for entry in metadata.entry_points().select(group=self._group, name=reference.name)
            if entry.value == reference.value
        ]
        if len(candidates) != 1:
            raise PluginDiscoveryError(
                f"expected exactly one matching entry point for {reference.name!r}"
            )

        try:
            loaded = candidates[0].load()
            if inspect.isclass(loaded):
                loaded = loaded()
            elif callable(loaded) and not hasattr(loaded, "manifest"):
                loaded = loaded()
            if inspect.isawaitable(loaded):
                loaded = await loaded
        except Exception as exception:
            raise PluginDiscoveryError(f"failed to load plugin {reference.name!r}") from exception

        if not hasattr(loaded, "manifest") or not callable(getattr(loaded, "setup", None)):
            raise PluginDiscoveryError("entry point did not produce a valid plugin")
        return cast(Plugin, loaded)
