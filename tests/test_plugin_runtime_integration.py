from __future__ import annotations

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    AllowAllPermissionPolicy,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    HookPlugin,
    Kernel,
    MappingConfigSource,
    MemoryStateStore,
    PluginContext,
    PluginExports,
    PluginManager,
    PluginManagerState,
    PluginManifest,
    PluginPermission,
    Request,
    Response,
    Router,
    RuntimeAssembler,
    RuntimeState,
    ServiceDefinition,
    StateStoreRegistry,
)
from phoenix_os.configuration import Configuration


async def echo(request: Request) -> Response:
    return Response(200, {"action": request.action})


class Worker:
    pass


class RecordingStateStore(MemoryStateStore):
    def __init__(self, calls: list[str]) -> None:
        super().__init__()
        self._calls = calls

    async def start(self, context: object) -> None:
        del context
        self._calls.append("state:start")

    async def stop(self, context: object) -> None:
        del context
        self._calls.append("state:stop")
        await self.close()


@pytest.mark.asyncio
async def test_runtime_assembler_prepares_plugins_and_owns_lifecycle() -> None:
    calls: list[str] = []
    events = EventBus()
    capabilities = CapabilityRegistry(
        permission_policy=AllowAllPermissionPolicy(),
        events=events,
    )
    state = StateStoreRegistry()
    worker = Worker()

    async def setup(context: PluginContext) -> None:
        assert context.service("worker") is worker
        await context.registrar.register_state_store("plugin-state", RecordingStateStore(calls))
        await context.registrar.publish_service("plugin.service", object())
        calls.append("plugin:setup")

    plugin = HookPlugin(
        PluginManifest(
            "demo",
            "Demo",
            "1.0.0",
            permissions=frozenset(
                {PluginPermission.REGISTER_STATE_STORES, PluginPermission.PUBLISH_SERVICES}
            ),
            exports=PluginExports(
                state_stores=frozenset({"plugin-state"}),
                services=frozenset({"plugin.service"}),
            ),
        ),
        setup=setup,
        start=lambda _: calls.append("plugin:start"),
        stop=lambda _: calls.append("plugin:stop"),
    )
    plugins = PluginManager(
        (plugin,),
        capabilities=capabilities,
        events=events,
        state=state,
        allowed_permissions=frozenset(
            {PluginPermission.REGISTER_STATE_STORES, PluginPermission.PUBLISH_SERVICES}
        ),
    )
    router = Router()
    router.add("system.echo", echo)
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()

    def worker_factory(resolver: object, config: Configuration) -> object:
        del resolver, config
        return worker

    runtime = await RuntimeAssembler(
        kernel=Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        definitions=(ServiceDefinition("worker", worker_factory),),
        state=state,
        plugins=plugins,
    ).assemble()

    assert state.names() == ("plugin-state",)
    assert runtime.service("plugins") is plugins
    assert plugins.service("plugin.service")

    await runtime.start()
    assert (await runtime.handle(Request("system.echo"))).status == 200
    await runtime.stop()

    assert calls == [
        "plugin:setup",
        "state:start",
        "plugin:start",
        "plugin:stop",
        "state:stop",
    ]
    assert runtime.state is RuntimeState.STOPPED
    assert plugins.state is PluginManagerState.STOPPED


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_plugin_service_name_conflicts() -> None:
    events = EventBus()
    capabilities = CapabilityRegistry(events=events)
    plugins = PluginManager((), capabilities=capabilities, events=events)
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    router = Router()
    router.add("system.echo", echo)

    def conflicting_factory(resolver: object, config: Configuration) -> object:
        del resolver, config
        return object()

    runtime = await RuntimeAssembler(
        kernel=Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        definitions=(ServiceDefinition("worker", conflicting_factory),),
        plugins=plugins,
    ).assemble()

    assert plugins.service("worker") is runtime.service("worker")
