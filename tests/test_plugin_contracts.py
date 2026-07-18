from types import MappingProxyType

import pytest

from phoenix_os import (
    PHOENIX_VERSION,
    PLUGIN_API_VERSION,
    HookPlugin,
    PluginContext,
    PluginDependency,
    PluginExports,
    PluginManifest,
    PluginPermission,
    SemanticVersion,
    VersionRange,
    normalize_plugin_id,
)


class Resolver:
    async def register_capability(self, descriptor: object, provider: object) -> None:
        del descriptor, provider

    async def register_state_store(
        self, name: str, store: object, *, make_default: bool = False
    ) -> None:
        del name, store, make_default

    async def publish_service(self, name: str, service: object) -> None:
        del name, service

    def service(self, name: str) -> object:
        return {"answer": 42}[name]


def test_semantic_version_parse_order_and_string() -> None:
    assert SemanticVersion.parse("1.2.3") == SemanticVersion(1, 2, 3)
    assert SemanticVersion.parse(SemanticVersion(1, 2, 3)) == SemanticVersion(1, 2, 3)
    assert SemanticVersion(1, 2, 3) < SemanticVersion(1, 3, 0)
    assert str(SemanticVersion(10, 20, 30)) == "10.20.30"


@pytest.mark.parametrize("value", ["", "1", "1.2", "01.2.3", "1.2.-1", "v1.2.3"])
def test_semantic_version_rejects_invalid_text(value: str) -> None:
    with pytest.raises(ValueError, match="semantic version"):
        SemanticVersion.parse(value)


def test_semantic_version_rejects_negative_parts() -> None:
    with pytest.raises(ValueError, match="negative"):
        SemanticVersion(-1, 0, 0)


def test_version_range_supports_inclusive_and_exclusive_bounds() -> None:
    versions = VersionRange("1.0.0", "2.0.0")
    assert versions.accepts("1.0.0")
    assert versions.accepts("1.9.9")
    assert not versions.accepts("2.0.0")
    assert str(versions) == ">=1.0.0,<2.0.0"


def test_version_range_can_be_unbounded_and_include_maximum() -> None:
    assert VersionRange().accepts("999.0.0")
    versions = VersionRange(maximum="1.0.0", include_maximum=True)
    assert versions.accepts("1.0.0")
    assert not versions.accepts("1.0.1")


def test_version_range_rejects_empty_or_reversed_bounds() -> None:
    with pytest.raises(ValueError, match="lower"):
        VersionRange("2.0.0", "1.0.0")
    with pytest.raises(ValueError, match="empty"):
        VersionRange("1.0.0", "1.0.0")


def test_plugin_id_normalization_and_validation() -> None:
    assert normalize_plugin_id("  Nova.Tools  ") == "nova.tools"
    for value in ("", "bad id", ".bad", "bad.", "áudio"):
        with pytest.raises(ValueError):
            normalize_plugin_id(value)


def test_manifest_normalizes_and_freezes_public_data() -> None:
    manifest = PluginManifest(
        "Nova.Tools",
        " Nova Tools ",
        "1.2.3",
        permissions=frozenset({PluginPermission.PUBLISH_SERVICES}),
        exports=PluginExports(services=frozenset({"nova.clock"})),
        metadata={"author": "Arthur"},
    )

    assert manifest.plugin_id == "nova.tools"
    assert manifest.name == "Nova Tools"
    assert manifest.version == SemanticVersion(1, 2, 3)
    assert manifest.api_version == PLUGIN_API_VERSION
    assert PHOENIX_VERSION == "0.11.0"
    assert isinstance(manifest.metadata, MappingProxyType)
    with pytest.raises(TypeError):
        manifest.metadata["author"] = "other"  # type: ignore[index]


def test_manifest_rejects_duplicate_and_self_dependencies() -> None:
    dependency = PluginDependency("base")
    with pytest.raises(ValueError, match="unique"):
        PluginManifest("demo", "Demo", "1.0.0", dependencies=(dependency, dependency))
    with pytest.raises(ValueError, match="itself"):
        PluginManifest("demo", "Demo", "1.0.0", dependencies=(PluginDependency("demo"),))


def test_exports_reject_blank_names() -> None:
    with pytest.raises(ValueError, match="blank"):
        PluginExports(services=frozenset({""}))


def test_plugin_context_resolves_services_through_registrar() -> None:
    manifest = PluginManifest("demo", "Demo", "1.0.0")
    context = PluginContext(manifest, Resolver(), {"host": object()})
    assert context.service("answer") == 42
    assert isinstance(context.host_services, MappingProxyType)


@pytest.mark.asyncio
async def test_hook_plugin_supports_sync_and_async_callbacks() -> None:
    calls: list[str] = []
    manifest = PluginManifest("demo", "Demo", "1.0.0")

    def setup(context: PluginContext) -> None:
        assert context.manifest is manifest
        calls.append("setup")

    async def start(context: PluginContext) -> None:
        assert context.manifest is manifest
        calls.append("start")

    plugin = HookPlugin(manifest, setup=setup, start=start, stop=lambda _: calls.append("stop"))
    context = PluginContext(manifest, Resolver())

    await plugin.setup(context)
    await plugin.start(context)
    await plugin.stop(context)

    assert calls == ["setup", "start", "stop"]
