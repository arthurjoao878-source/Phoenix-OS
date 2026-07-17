from __future__ import annotations

from collections.abc import Callable

import pytest

from phoenix_os import (
    EntryPointPluginDiscovery,
    HookPlugin,
    PluginDiscoveryError,
    PluginManifest,
    PluginPermissionDeniedError,
    PluginReference,
)


class FakeEntryPoint:
    def __init__(
        self,
        name: str,
        value: str,
        group: str,
        loader: Callable[[], object],
    ) -> None:
        self.name = name
        self.value = value
        self.group = group
        self._loader = loader

    def load(self) -> object:
        return self._loader()


class FakeEntryPoints(list[FakeEntryPoint]):
    def select(self, **filters: str) -> FakeEntryPoints:
        return FakeEntryPoints(
            entry
            for entry in self
            if all(getattr(entry, key) == value for key, value in filters.items())
        )


def install_entries(monkeypatch: pytest.MonkeyPatch, *entries: FakeEntryPoint) -> None:
    monkeypatch.setattr(
        "phoenix_os.plugins.discovery.metadata.entry_points",
        lambda: FakeEntryPoints(entries),
    )


def test_discovery_returns_sorted_metadata_without_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded: list[str] = []
    install_entries(
        monkeypatch,
        FakeEntryPoint("zeta", "pkg:zeta", "phoenix_os.plugins", lambda: loaded.append("z")),
        FakeEntryPoint("alpha", "pkg:alpha", "phoenix_os.plugins", lambda: loaded.append("a")),
        FakeEntryPoint("other", "pkg:other", "other.group", lambda: loaded.append("o")),
    )

    references = EntryPointPluginDiscovery().discover()

    assert [reference.name for reference in references] == ["alpha", "zeta"]
    assert loaded == []


@pytest.mark.asyncio
async def test_load_requires_explicit_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    demo = HookPlugin(PluginManifest("demo", "Demo", "1.0.0"))
    entry = FakeEntryPoint("demo", "pkg:demo", "phoenix_os.plugins", lambda: demo)
    install_entries(monkeypatch, entry)
    discovery = EntryPointPluginDiscovery()
    reference = discovery.discover()[0]

    with pytest.raises(PluginPermissionDeniedError, match="allowlisted"):
        await discovery.load(reference, allowed_names=frozenset())
    assert await discovery.load(reference, allowed_names=frozenset({"demo"})) is demo


@pytest.mark.asyncio
async def test_load_supports_classes_factories_and_async_factories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DemoPlugin(HookPlugin):
        def __init__(self) -> None:
            super().__init__(PluginManifest("class-demo", "Class Demo", "1.0.0"))

    async def async_factory() -> HookPlugin:
        return HookPlugin(PluginManifest("async-demo", "Async Demo", "1.0.0"))

    install_entries(
        monkeypatch,
        FakeEntryPoint("class-demo", "pkg:Class", "phoenix_os.plugins", lambda: DemoPlugin),
        FakeEntryPoint("async-demo", "pkg:async", "phoenix_os.plugins", lambda: async_factory),
    )
    discovery = EntryPointPluginDiscovery()
    references = discovery.discover()

    first = await discovery.load(references[0], allowed_names=frozenset({"async-demo"}))
    second = await discovery.load(references[1], allowed_names=frozenset({"class-demo"}))

    assert first.manifest.plugin_id == "async-demo"
    assert second.manifest.plugin_id == "class-demo"


@pytest.mark.asyncio
async def test_load_rejects_wrong_group_missing_duplicate_and_invalid_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = EntryPointPluginDiscovery()
    wrong = PluginReference("demo", "pkg:demo", "other")
    with pytest.raises(PluginDiscoveryError, match="different"):
        await discovery.load(wrong, allowed_names=frozenset({"demo"}))

    install_entries(monkeypatch)
    reference = PluginReference("demo", "pkg:demo", "phoenix_os.plugins")
    with pytest.raises(PluginDiscoveryError, match="exactly one"):
        await discovery.load(reference, allowed_names=frozenset({"demo"}))

    install_entries(
        monkeypatch,
        FakeEntryPoint("demo", "pkg:demo", "phoenix_os.plugins", lambda: object()),
    )
    with pytest.raises(PluginDiscoveryError, match="valid plugin"):
        await discovery.load(reference, allowed_names=frozenset({"demo"}))


@pytest.mark.asyncio
async def test_load_wraps_import_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> object:
        raise ImportError("broken package")

    install_entries(
        monkeypatch,
        FakeEntryPoint("demo", "pkg:demo", "phoenix_os.plugins", fail),
    )
    discovery = EntryPointPluginDiscovery()
    reference = discovery.discover()[0]
    with pytest.raises(PluginDiscoveryError, match="failed to load"):
        await discovery.load(reference, allowed_names=frozenset({"demo"}))
