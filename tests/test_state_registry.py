import pytest

from phoenix_os import (
    DuplicateStateStoreError,
    MemoryStateStore,
    StateKey,
    StateStoreClosedError,
    StateStoreNotFoundError,
    StateStoreRegistration,
    StateStoreRegistry,
)


class RecordingStore(MemoryStateStore):
    def __init__(self, name: str, calls: list[str]) -> None:
        super().__init__()
        self.name = name
        self.calls = calls

    async def start(self, context: object) -> None:
        del context
        self.calls.append(f"start:{self.name}")

    async def stop(self, context: object) -> None:
        del context
        self.calls.append(f"stop:{self.name}")
        await self.close()


def test_registry_resolves_single_default_store() -> None:
    store = MemoryStateStore()
    registry = StateStoreRegistry((StateStoreRegistration("Primary", store),))

    assert registry.default_name == "primary"
    assert registry.store() is store
    assert registry.store("PRIMARY") is store
    assert registry.names() == ("primary",)


def test_registry_requires_explicit_default_for_multiple_stores() -> None:
    first = MemoryStateStore()
    second = MemoryStateStore()
    registry = StateStoreRegistry(
        (
            StateStoreRegistration("first", first),
            StateStoreRegistration("second", second),
        )
    )

    with pytest.raises(StateStoreNotFoundError, match="default"):
        registry.store()
    assert registry.store("second") is second


def test_registry_rejects_duplicates_and_unknown_default() -> None:
    store = MemoryStateStore()
    registration = StateStoreRegistration("primary", store)
    with pytest.raises(DuplicateStateStoreError):
        StateStoreRegistry((registration, registration))
    with pytest.raises(StateStoreNotFoundError, match="default"):
        StateStoreRegistry((registration,), default="missing")


@pytest.mark.asyncio
async def test_registry_registration_and_removal_before_start() -> None:
    registry = StateStoreRegistry()
    first = MemoryStateStore()
    second = MemoryStateStore()

    await registry.register("first", first)
    await registry.register("second", second, make_default=True)
    assert registry.store() is second
    assert await registry.remove("first")
    assert not await registry.remove("missing")
    assert registry.names() == ("second",)


@pytest.mark.asyncio
async def test_registry_owns_deterministic_lifecycle() -> None:
    calls: list[str] = []
    first = RecordingStore("first", calls)
    second = RecordingStore("second", calls)
    registry = StateStoreRegistry(
        (
            StateStoreRegistration("first", first),
            StateStoreRegistration("second", second),
        ),
        default="first",
    )

    await registry.start(object())
    assert calls == ["start:first", "start:second"]
    await registry.stop(object())
    assert calls == ["start:first", "start:second", "stop:second", "stop:first"]
    assert registry.closed
    with pytest.raises(StateStoreClosedError):
        registry.store()


@pytest.mark.asyncio
async def test_registry_disallows_mutation_after_start() -> None:
    registry = StateStoreRegistry((StateStoreRegistration("primary", MemoryStateStore()),))
    await registry.start(object())

    with pytest.raises(StateStoreClosedError, match="after registry startup"):
        await registry.register("other", MemoryStateStore())
    with pytest.raises(StateStoreClosedError, match="after registry startup"):
        await registry.remove("primary")
    await registry.stop(object())


@pytest.mark.asyncio
async def test_named_stores_keep_state_isolated() -> None:
    first = MemoryStateStore()
    second = MemoryStateStore()
    registry = StateStoreRegistry(
        (
            StateStoreRegistration("first", first),
            StateStoreRegistration("second", second),
        ),
        default="first",
    )
    key = StateKey("profile", "arthur", int)

    await registry.store().put(key, 1)
    await registry.store("second").put(key, 2)

    assert (await registry.store("first").get(key)).value == 1  # type: ignore[union-attr]
    assert (await registry.store("second").get(key)).value == 2  # type: ignore[union-attr]
