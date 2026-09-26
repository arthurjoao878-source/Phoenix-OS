from pathlib import Path

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    MemoryStateStore,
    Router,
    RuntimeAssembler,
    RuntimeState,
    SQLiteStateStore,
    StateKey,
    StateStoreRegistration,
    StateStoreRegistry,
)


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_and_owns_state_store() -> None:
    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    store = MemoryStateStore(events=events)
    state = StateStoreRegistry((StateStoreRegistration("primary", store),))

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        state=state,
    ).assemble()

    assert runtime.service("state") is state
    await runtime.start()
    assert runtime.state.value == RuntimeState.RUNNING.value
    await state.store().put(StateKey("runtime", "ready", bool), True)
    await runtime.stop()

    assert state.closed
    assert store.closed
    assert runtime.state.value == RuntimeState.STOPPED.value


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_and_owns_direct_sqlite_state_store(tmp_path: Path) -> None:
    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    store = SQLiteStateStore(tmp_path / "durable.sqlite3", events=events)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        state=store,
    ).assemble()

    assert runtime.service("state") is store
    await runtime.start()
    await store.put(StateKey("runtime", "persistent", bool), True)
    await runtime.stop()

    assert store.closed
    assert runtime.state.value == RuntimeState.STOPPED.value
