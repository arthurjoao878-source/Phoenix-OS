from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from phoenix_os import (
    AllowAllPermissionPolicy,
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    EventBus,
    HookPlugin,
    InMemorySink,
    MemoryStateStore,
    ObservabilityHub,
    PluginAlreadyRegisteredError,
    PluginCompatibilityError,
    PluginDependency,
    PluginDependencyCycleError,
    PluginDependencyError,
    PluginExportError,
    PluginExports,
    PluginManager,
    PluginManagerState,
    PluginManifest,
    PluginNotFoundError,
    PluginPermission,
    PluginPermissionDeniedError,
    PluginSetupError,
    PluginStartError,
    PluginStateError,
    PluginStopError,
    SemanticVersion,
    StateStoreRegistry,
    VersionRange,
)
from phoenix_os.plugins import PluginContext


def manifest(
    plugin_id: str,
    *,
    version: str = "1.0.0",
    dependencies: tuple[PluginDependency, ...] = (),
    permissions: frozenset[PluginPermission] = frozenset(),
    exports: PluginExports | None = None,
    api_version: int = 1,
    phoenix_versions: VersionRange | None = None,
) -> PluginManifest:
    return PluginManifest(
        plugin_id,
        plugin_id,
        version,
        dependencies=dependencies,
        permissions=permissions,
        exports=PluginExports() if exports is None else exports,
        api_version=api_version,
        phoenix_versions=VersionRange() if phoenix_versions is None else phoenix_versions,
    )


def plugin(
    plugin_id: str,
    calls: list[str] | None = None,
    *,
    setup: Callable[[PluginContext], Awaitable[None] | None] | None = None,
    start: Callable[[PluginContext], Awaitable[None] | None] | None = None,
    stop: Callable[[PluginContext], Awaitable[None] | None] | None = None,
    **manifest_kwargs: object,
) -> HookPlugin:
    calls = [] if calls is None else calls

    def default_setup(context: PluginContext) -> None:
        calls.append(f"setup:{context.manifest.plugin_id}")

    def default_start(context: PluginContext) -> None:
        calls.append(f"start:{context.manifest.plugin_id}")

    def default_stop(context: PluginContext) -> None:
        calls.append(f"stop:{context.manifest.plugin_id}")

    return HookPlugin(
        manifest(plugin_id, **manifest_kwargs),  # type: ignore[arg-type]
        setup=default_setup if setup is None else setup,
        start=default_start if start is None else start,
        stop=default_stop if stop is None else stop,
    )


def manager_for(
    *plugins: HookPlugin,
    permissions: frozenset[PluginPermission] = frozenset(),
    state: StateStoreRegistry | None = None,
    observability: ObservabilityHub | None = None,
    events: EventBus | None = None,
) -> PluginManager:
    bus = EventBus() if events is None else events
    capabilities = CapabilityRegistry(
        permission_policy=AllowAllPermissionPolicy(),
        events=bus,
    )
    return PluginManager(
        plugins,
        capabilities=capabilities,
        events=bus,
        state=state,
        observability=observability,
        allowed_permissions=permissions,
    )


@pytest.mark.asyncio
async def test_registration_listing_unregistration_and_duplicates() -> None:
    first = plugin("first")
    manager = manager_for(first)

    assert [item.plugin_id for item in await manager.list_manifests()] == ["first"]
    with pytest.raises(PluginAlreadyRegisteredError):
        await manager.register(plugin("first"))

    registration = await manager.register(plugin("second"))
    assert await manager.unregister(registration)
    assert not await manager.unregister(registration)
    assert [item.plugin_id for item in await manager.list_manifests()] == ["first"]


@pytest.mark.asyncio
async def test_manager_rejects_mutation_after_preparation() -> None:
    manager = manager_for(plugin("first"))
    await manager.prepare()
    with pytest.raises(PluginStateError):
        await manager.register(plugin("second"))


@pytest.mark.asyncio
async def test_dependencies_are_prepared_started_and_stopped_deterministically() -> None:
    calls: list[str] = []
    dependent = plugin(
        "dependent",
        calls,
        dependencies=(PluginDependency("base"),),
    )
    base = plugin("base", calls)
    manager = manager_for(dependent, base)

    await manager.prepare()
    await manager.start(object())
    await manager.stop(object())

    assert calls == [
        "setup:base",
        "setup:dependent",
        "start:base",
        "start:dependent",
        "stop:dependent",
        "stop:base",
    ]
    snapshot = await manager.snapshot()
    assert snapshot.resolved_order == ("base", "dependent")
    assert snapshot.state is PluginManagerState.STOPPED


@pytest.mark.asyncio
async def test_missing_dependency_is_rejected_but_optional_dependency_is_allowed() -> None:
    required = manager_for(plugin("dependent", dependencies=(PluginDependency("missing"),)))
    with pytest.raises(PluginDependencyError, match="missing"):
        await required.prepare()

    optional = manager_for(
        plugin("dependent", dependencies=(PluginDependency("missing", optional=True),))
    )
    await optional.prepare()
    assert (await optional.snapshot()).resolved_order == ("dependent",)


@pytest.mark.asyncio
async def test_dependency_version_and_cycles_are_rejected() -> None:
    versioned = manager_for(
        plugin(
            "dependent",
            dependencies=(PluginDependency("base", VersionRange("2.0.0", "3.0.0")),),
        ),
        plugin("base", version="1.0.0"),
    )
    with pytest.raises(PluginDependencyError, match=r"found 1\.0\.0"):
        await versioned.prepare()

    cycle = manager_for(
        plugin("a", dependencies=(PluginDependency("b"),)),
        plugin("b", dependencies=(PluginDependency("a"),)),
    )
    with pytest.raises(PluginDependencyCycleError) as captured:
        await cycle.prepare()
    assert captured.value.cycle == ("a", "b", "a")


@pytest.mark.asyncio
async def test_api_core_compatibility_and_permissions_are_enforced() -> None:
    incompatible_api = manager_for(plugin("demo", api_version=2))
    with pytest.raises(PluginCompatibilityError, match="API"):
        await incompatible_api.prepare()

    incompatible_core = manager_for(plugin("demo", phoenix_versions=VersionRange("1.0.0", "2.0.0")))
    with pytest.raises(PluginCompatibilityError, match="Phoenix"):
        await incompatible_core.prepare()

    denied = manager_for(plugin("demo", permissions=frozenset({PluginPermission.PUBLISH_SERVICES})))
    with pytest.raises(PluginPermissionDeniedError, match="denied"):
        await denied.prepare()


@pytest.mark.asyncio
async def test_capability_contribution_is_available_and_removed_on_stop() -> None:
    events = EventBus()
    capabilities = CapabilityRegistry(
        permission_policy=AllowAllPermissionPolicy(),
        events=events,
    )

    async def setup(context: PluginContext) -> None:
        async def provider(invocation: CapabilityInvocation) -> dict[str, object]:
            del invocation
            return {"value": 42}

        await context.registrar.register_capability(
            CapabilityDescriptor("demo.answer"),
            provider,
        )

    demo = HookPlugin(
        manifest(
            "demo",
            permissions=frozenset({PluginPermission.REGISTER_CAPABILITIES}),
            exports=PluginExports(capabilities=frozenset({"demo.answer"})),
        ),
        setup=setup,
    )
    manager = PluginManager(
        (demo,),
        capabilities=capabilities,
        events=events,
        allowed_permissions=frozenset({PluginPermission.REGISTER_CAPABILITIES}),
    )

    await manager.prepare()
    result = await capabilities.invoke("demo.answer", context=CapabilityContext())
    assert result.output == {"value": 42}
    await manager.stop(object())
    assert await capabilities.list_descriptors() == ()


@pytest.mark.asyncio
async def test_undeclared_export_fails_setup_and_rolls_back_previous_contributions() -> None:
    async def good_setup(context: PluginContext) -> None:
        await context.registrar.publish_service("good.service", object())

    async def bad_setup(context: PluginContext) -> None:
        await context.registrar.publish_service("not.declared", object())

    permissions = frozenset({PluginPermission.PUBLISH_SERVICES})
    manager = manager_for(
        HookPlugin(
            manifest(
                "good",
                permissions=permissions,
                exports=PluginExports(services=frozenset({"good.service"})),
            ),
            setup=good_setup,
        ),
        HookPlugin(manifest("bad", permissions=permissions), setup=bad_setup),
        permissions=permissions,
    )

    with pytest.raises(PluginSetupError) as captured:
        await manager.prepare()
    assert isinstance(captured.value.exception, PluginExportError)
    with pytest.raises(PluginNotFoundError):
        manager.service("good.service")
    assert manager.state is PluginManagerState.FAILED


@pytest.mark.asyncio
async def test_state_store_and_service_contributions_are_resolved_and_cleaned() -> None:
    registry = StateStoreRegistry()
    permissions = frozenset(
        {PluginPermission.REGISTER_STATE_STORES, PluginPermission.PUBLISH_SERVICES}
    )

    async def setup(context: PluginContext) -> None:
        await context.registrar.register_state_store("demo-store", MemoryStateStore())
        service = object()
        await context.registrar.publish_service("demo.service", service)
        assert context.service("demo.service") is service

    demo = HookPlugin(
        manifest(
            "demo",
            permissions=permissions,
            exports=PluginExports(
                state_stores=frozenset({"demo-store"}),
                services=frozenset({"demo.service"}),
            ),
        ),
        setup=setup,
    )
    manager = manager_for(demo, permissions=permissions, state=registry)

    await manager.prepare()
    assert registry.names() == ("demo-store",)
    assert manager.service("demo.service")
    await manager.stop(object())
    assert registry.names() == ()
    with pytest.raises(PluginNotFoundError):
        manager.service("demo.service")


@pytest.mark.asyncio
async def test_dependent_plugin_can_resolve_service_published_by_dependency() -> None:
    value = object()

    async def base_setup(context: PluginContext) -> None:
        await context.registrar.publish_service("base.service", value)

    async def dependent_setup(context: PluginContext) -> None:
        assert context.service("base.service") is value

    permission = frozenset({PluginPermission.PUBLISH_SERVICES})
    manager = manager_for(
        HookPlugin(
            manifest(
                "base",
                permissions=permission,
                exports=PluginExports(services=frozenset({"base.service"})),
            ),
            setup=base_setup,
        ),
        HookPlugin(
            manifest("dependent", dependencies=(PluginDependency("base"),)),
            setup=dependent_setup,
        ),
        permissions=permission,
    )
    await manager.prepare()
    assert manager.service("base.service") is value


@pytest.mark.asyncio
async def test_start_failure_rolls_back_started_plugins_and_contributions() -> None:
    calls: list[str] = []

    async def setup(context: PluginContext) -> None:
        await context.registrar.publish_service("base.service", object())

    async def fail(_: PluginContext) -> None:
        raise RuntimeError("boom")

    permission = frozenset({PluginPermission.PUBLISH_SERVICES})
    base = HookPlugin(
        manifest(
            "base",
            permissions=permission,
            exports=PluginExports(services=frozenset({"base.service"})),
        ),
        setup=setup,
        start=lambda _: calls.append("start:base"),
        stop=lambda _: calls.append("stop:base"),
    )
    broken = HookPlugin(
        manifest("broken", dependencies=(PluginDependency("base"),)),
        start=fail,
    )
    manager = manager_for(base, broken, permissions=permission)
    await manager.prepare()

    with pytest.raises(PluginStartError, match="broken"):
        await manager.start(object())
    assert calls == ["start:base", "stop:base"]
    with pytest.raises(PluginNotFoundError):
        manager.service("base.service")
    assert manager.state is PluginManagerState.FAILED


@pytest.mark.asyncio
async def test_stop_collects_failures_and_continues_reverse_shutdown() -> None:
    calls: list[str] = []

    async def bad_stop(_: PluginContext) -> None:
        calls.append("stop:bad")
        raise RuntimeError("stop failed")

    manager = manager_for(
        plugin("good", calls),
        plugin("bad", calls, stop=bad_stop),
    )
    await manager.start(object())

    with pytest.raises(PluginStopError) as captured:
        await manager.stop(object())
    assert calls[-2:] == ["stop:bad", "stop:good"]
    assert len(captured.value.failures) == 1
    assert manager.state is PluginManagerState.STOPPED


@pytest.mark.asyncio
async def test_snapshot_events_and_observability_capture_lifecycle() -> None:
    events = EventBus()
    observed_events: list[str] = []
    await events.subscribe("*", lambda event: observed_events.append(event.name))
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    manager = manager_for(
        plugin("demo"),
        events=events,
        observability=observability,
    )

    await manager.start(object())
    running = await manager.snapshot()
    assert running.active == ("demo",)
    await manager.stop(object())

    assert "plugin.prepared" in observed_events
    assert "plugin.started" in observed_events
    assert "plugin.stopped" in observed_events
    records = (await sink.snapshot()).records
    names = [record.name for record in records]
    assert "plugin.setup" in names
    assert "plugin.start" in names
    assert "plugins.active" in names


@pytest.mark.asyncio
async def test_binding_services_is_only_allowed_before_prepare_and_conflicts_are_rejected() -> None:
    manager = manager_for(plugin("demo"))
    service = object()
    manager.bind_services({"custom": service})
    assert manager.service("custom") is service
    with pytest.raises(PluginExportError, match="conflicting"):
        manager.bind_services({"custom": object()})
    await manager.prepare()
    with pytest.raises(PluginStateError):
        manager.bind_services({"late": object()})


def test_manager_exposes_core_version() -> None:
    manager = manager_for()
    assert manager.core_version == SemanticVersion(0, 16, 0)
    assert manager.api_version == 1
