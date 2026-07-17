import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    Configuration,
    EventBus,
    EventObserver,
    InMemorySink,
    Kernel,
    LogRecord,
    ObservabilityHub,
    Router,
    RuntimeAssembler,
    RuntimeState,
    Severity,
    default_event_severity,
)
from phoenix_os.events import Event
from phoenix_os.runtime import RuntimeContext


@pytest.mark.asyncio
async def test_event_observer_exports_event_with_redacted_payload() -> None:
    events = EventBus()
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    observer = EventObserver(events=events, observability=observability)
    context = RuntimeContext(services={})

    await observer.start(context)
    await events.emit(
        "capability.invocation.failed",
        source="phoenix.capabilities",
        payload={"token": "unsafe", "code": "execution_error"},
        correlation_id="corr",
    )
    await observer.stop(context)

    record = (await sink.snapshot()).records[0]
    assert isinstance(record, LogRecord)
    assert record.name == "capability.invocation.failed"
    assert record.severity is Severity.ERROR
    assert record.correlation_id == "corr"
    payload = record.attributes["event.payload"]
    assert payload["token"] == "***"  # type: ignore[index]
    assert payload["code"] == "execution_error"  # type: ignore[index]


@pytest.mark.asyncio
async def test_event_observer_start_is_idempotent_and_stop_unsubscribes() -> None:
    events = EventBus()
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    observer = EventObserver(events=events, observability=observability)
    context = RuntimeContext(services={})

    await observer.start(context)
    await observer.start(context)
    assert observer.active
    await events.emit("system.ready", source="test")
    await observer.stop(context)
    await observer.stop(context)
    assert not observer.active
    await events.emit("system.after", source="test")

    assert len((await sink.snapshot()).records) == 1


def test_default_event_severity_mapping() -> None:
    assert default_event_severity(Event("runtime.started", "test")) is Severity.INFO
    assert default_event_severity(Event("permission.denied", "test")) is Severity.WARNING
    assert default_event_severity(Event("runtime.start.failed", "test")) is Severity.ERROR


@pytest.mark.asyncio
async def test_custom_severity_mapper_is_used() -> None:
    events = EventBus()
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    observer = EventObserver(
        events=events,
        observability=observability,
        severity_mapper=lambda event: Severity.CRITICAL,
    )
    context = RuntimeContext(services={})

    await observer.start(context)
    await events.emit("anything", source="test")
    await observer.stop(context)

    record = (await sink.snapshot()).records[0]
    assert isinstance(record, LogRecord)
    assert record.severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_runtime_assembler_integrates_observability_lifecycle() -> None:
    configuration = Configuration(values={}, origins={})
    events = EventBus()
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    router = Router()
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        observability=observability,
    ).assemble()

    assert runtime.service("observability") is observability
    await runtime.start()
    await events.emit("custom.ready", source="test")
    await runtime.stop()

    assert runtime.state is RuntimeState.STOPPED
    assert observability.closed
    names = [record.name for record in (await sink.snapshot()).records]
    assert "runtime.component.started" in names
    assert "runtime.started" in names
    assert "custom.ready" in names
    assert "runtime.stopping" in names


@pytest.mark.asyncio
async def test_runtime_assembler_can_disable_event_bridge() -> None:
    configuration = Configuration(values={}, origins={})
    events = EventBus()
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    router = Router()
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        observability=observability,
        observe_events=False,
    ).assemble()
    await runtime.start()
    await events.emit("custom.ready", source="test")
    await runtime.stop()

    assert (await sink.snapshot()).records == ()
