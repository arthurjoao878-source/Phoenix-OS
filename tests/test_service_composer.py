import pytest

from phoenix_os.configuration import (
    ConfigOrigin,
    Configuration,
    DependencyCycleError,
    DuplicateServiceError,
    InvalidLifecycleServiceError,
    ServiceComposer,
    ServiceDefinition,
    ServiceFactoryError,
    ServiceNotFoundError,
)
from phoenix_os.runtime import RuntimeContext


def configuration() -> Configuration:
    return Configuration(
        values={"database.url": "sqlite://"},
        origins={"database.url": ConfigOrigin("test", "database.url")},
    )


@pytest.mark.asyncio
async def test_composer_builds_dependencies_once_in_dependency_order() -> None:
    calls: list[str] = []

    def database(resolver: object, config: Configuration) -> object:
        del resolver
        calls.append("database")
        return {"url": config.value("database.url", str)}

    def repository(resolver: object, config: Configuration) -> object:
        del config
        calls.append("repository")
        service = resolver.service("database")  # type: ignore[attr-defined]
        return {"database": service}

    composer = ServiceComposer(
        (
            ServiceDefinition("repository", repository, dependencies=("database",)),
            ServiceDefinition("database", database),
        )
    )

    container = await composer.compose(configuration())

    assert calls == ["database", "repository"]
    assert container.service("repository") == {"database": container.service("database")}
    assert tuple(container.services) == ("database", "repository")


@pytest.mark.asyncio
async def test_composer_supports_async_factories_and_base_services() -> None:
    async def factory(resolver: object, config: Configuration) -> object:
        del config
        return {"events": resolver.service("events")}  # type: ignore[attr-defined]

    events = object()
    container = await ServiceComposer(
        (ServiceDefinition("observer", factory, dependencies=("events",)),)
    ).compose(configuration(), base_services={"events": events})

    assert container.service("observer") == {"events": events}


@pytest.mark.asyncio
async def test_composer_detects_missing_dependencies_and_cycles() -> None:
    missing = ServiceComposer(
        (ServiceDefinition("repository", lambda resolver, config: object(), ("database",)),)
    )
    with pytest.raises(ServiceNotFoundError) as captured:
        await missing.compose(configuration())
    assert captured.value.name == "database"

    cyclic = ServiceComposer(
        (
            ServiceDefinition("a", lambda resolver, config: object(), ("b",)),
            ServiceDefinition("b", lambda resolver, config: object(), ("a",)),
        )
    )
    with pytest.raises(DependencyCycleError) as cycle:
        await cyclic.compose(configuration())
    assert cycle.value.cycle == ("a", "b", "a")


def test_composer_rejects_duplicate_and_reserved_definitions() -> None:
    definition = ServiceDefinition("cache", lambda resolver, config: object())
    with pytest.raises(DuplicateServiceError):
        ServiceComposer((definition, definition))
    with pytest.raises(ValueError, match="reserved"):
        ServiceDefinition("kernel", lambda resolver, config: object())


@pytest.mark.asyncio
async def test_composer_wraps_factory_failures() -> None:
    def failing(resolver: object, config: Configuration) -> object:
        del resolver, config
        raise OSError("internal path should not leak through the public message")

    with pytest.raises(ServiceFactoryError) as captured:
        await ServiceComposer((ServiceDefinition("cache", failing),)).compose(configuration())
    assert captured.value.name == "cache"
    assert "internal path" not in str(captured.value)
    assert isinstance(captured.value.exception, OSError)


class LifecycleService:
    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    async def start(self, context: RuntimeContext) -> None:
        del context
        self._calls.append("start")

    async def stop(self, context: RuntimeContext) -> None:
        del context
        self._calls.append("stop")


@pytest.mark.asyncio
async def test_lifecycle_services_become_runtime_components() -> None:
    calls: list[str] = []
    container = await ServiceComposer(
        (
            ServiceDefinition(
                "worker",
                lambda resolver, config: LifecycleService(calls),
                lifecycle=True,
            ),
        )
    ).compose(configuration())

    assert tuple(component.name for component in container.components) == ("worker",)


@pytest.mark.asyncio
async def test_lifecycle_service_requires_start_and_stop_hooks() -> None:
    with pytest.raises(InvalidLifecycleServiceError):
        await ServiceComposer(
            (
                ServiceDefinition(
                    "bad",
                    lambda resolver, config: object(),
                    lifecycle=True,
                ),
            )
        ).compose(configuration())


def test_service_definition_normalizes_and_validates_dependencies() -> None:
    definition = ServiceDefinition(
        " cache ",
        lambda resolver, config: object(),
        dependencies=(" database ",),
    )
    assert definition.name == "cache"
    assert definition.dependencies == ("database",)

    with pytest.raises(ValueError, match="duplicate"):
        ServiceDefinition(
            "cache",
            lambda resolver, config: object(),
            dependencies=("db", " db "),
        )
    with pytest.raises(ValueError, match="itself"):
        ServiceDefinition("cache", lambda resolver, config: object(), dependencies=("cache",))


@pytest.mark.asyncio
async def test_service_container_is_immutable() -> None:
    container = await ServiceComposer(
        (ServiceDefinition("cache", lambda resolver, config: object()),)
    ).compose(configuration())

    with pytest.raises(TypeError):
        container.services["other"] = object()  # type: ignore[index]
    with pytest.raises(ServiceNotFoundError):
        container.service("missing")
