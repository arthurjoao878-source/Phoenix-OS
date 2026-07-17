"""Register a restricted plugin and run it through Phoenix Runtime."""

from __future__ import annotations

import asyncio

from phoenix_os import (
    AllowAllAuthorizer,
    AllowAllPermissionPolicy,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    HookPlugin,
    Kernel,
    MappingConfigSource,
    PluginContext,
    PluginExports,
    PluginManager,
    PluginManifest,
    PluginPermission,
    Router,
    RuntimeAssembler,
)


async def main() -> None:
    events = EventBus()
    capabilities = CapabilityRegistry(
        permission_policy=AllowAllPermissionPolicy(),
        events=events,
    )

    async def setup(context: PluginContext) -> None:
        async def answer(invocation: CapabilityInvocation) -> dict[str, object]:
            del invocation
            return {"answer": 42}

        await context.registrar.register_capability(
            CapabilityDescriptor("example.answer"),
            answer,
        )
        await context.registrar.publish_service("example.greeting", "hello from plugin")

    plugin = HookPlugin(
        PluginManifest(
            "example.plugin",
            "Example Plugin",
            "1.0.0",
            permissions=frozenset(
                {
                    PluginPermission.REGISTER_CAPABILITIES,
                    PluginPermission.PUBLISH_SERVICES,
                }
            ),
            exports=PluginExports(
                capabilities=frozenset({"example.answer"}),
                services=frozenset({"example.greeting"}),
            ),
        ),
        setup=setup,
    )
    plugins = PluginManager(
        (plugin,),
        capabilities=capabilities,
        events=events,
        allowed_permissions=frozenset(
            {
                PluginPermission.REGISTER_CAPABILITIES,
                PluginPermission.PUBLISH_SERVICES,
            }
        ),
    )
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    runtime = await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        plugins=plugins,
    ).assemble()

    async with runtime:
        result = await capabilities.invoke("example.answer")
        print(result.output["answer"])
        print(plugins.service("example.greeting"))


if __name__ == "__main__":
    asyncio.run(main())
