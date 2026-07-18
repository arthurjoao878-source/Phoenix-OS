import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
    SecretsManager,
)


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_and_closes_secrets_manager() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    manager = SecretsManager(events=events)
    runtime = await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        configuration=configuration,
        secrets=manager,
    ).assemble()

    assert runtime.service("secrets") is manager
    await runtime.start()
    assert not manager.closed
    await runtime.stop()
    assert manager.closed
