import asyncio
from collections.abc import Mapping

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ComponentSpec,
    Event,
    EventBus,
    HookComponent,
    Kernel,
    PhoenixRuntime,
    Request,
    Response,
    Router,
    RuntimeDeadlineExceededError,
    RuntimeNotRunningError,
    RuntimePhase,
    RuntimeServiceNotFoundError,
    RuntimeStartError,
    RuntimeState,
    RuntimeStateError,
    RuntimeStopError,
)
from phoenix_os.runtime import RuntimeContext


async def echo_handler(request: Request) -> Response:
    return Response(status=200, body={"action": request.action})


def make_runtime(
    *,
    components: tuple[ComponentSpec, ...] = (),
    services: Mapping[str, object] | None = None,
    events: EventBus | None = None,
) -> tuple[PhoenixRuntime, EventBus, CapabilityRegistry]:
    event_bus = EventBus() if events is None else events
    router = Router()
    router.add("system.echo", echo_handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=event_bus)
    capabilities = CapabilityRegistry(events=event_bus)
    runtime = PhoenixRuntime(
        kernel=kernel,
        events=event_bus,
        capabilities=capabilities,
        components=components,
        services=services,
    )
    return runtime, event_bus, capabilities


@pytest.mark.asyncio
async def test_runtime_starts_in_order_and_stops_in_reverse_order() -> None:
    calls: list[str] = []

    def component(name: str) -> ComponentSpec:
        return ComponentSpec(
            name,
            HookComponent(
                start=lambda context: calls.append(f"start:{name}"),
                stop=lambda context: calls.append(f"stop:{name}"),
            ),
        )

    runtime, events, capabilities = make_runtime(
        components=(component("database"), component("adapters"), component("interface"))
    )

    await runtime.start()
    assert runtime.state is RuntimeState.RUNNING
    await runtime.stop()

    assert calls == [
        "start:database",
        "start:adapters",
        "start:interface",
        "stop:interface",
        "stop:adapters",
        "stop:database",
    ]
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED
    assert events.closed is True
    assert capabilities.closed is True


@pytest.mark.asyncio
async def test_start_and_stop_are_idempotent_after_success() -> None:
    calls: list[str] = []
    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec(
                "service",
                HookComponent(
                    start=lambda context: calls.append("start"),
                    stop=lambda context: calls.append("stop"),
                ),
            ),
        )
    )

    await asyncio.gather(runtime.start(), runtime.start())
    await runtime.start()
    await asyncio.gather(runtime.stop(), runtime.stop())
    await runtime.stop()

    assert calls == ["start", "stop"]


@pytest.mark.asyncio
async def test_runtime_exposes_frozen_composed_services() -> None:
    cache = object()
    runtime, events, capabilities = make_runtime(services={"cache": cache})

    assert runtime.service("cache") is cache
    assert runtime.service("events") is events
    assert runtime.service("capabilities") is capabilities
    assert runtime.service("runtime") is runtime
    with pytest.raises(RuntimeServiceNotFoundError):
        runtime.service("missing")
    with pytest.raises(ValueError, match="blank"):
        runtime.service(" ")
    with pytest.raises(TypeError):
        runtime.services["other"] = object()  # type: ignore[index]


@pytest.mark.asyncio
async def test_reserved_services_and_duplicate_components_are_rejected() -> None:
    runtime, events, capabilities = make_runtime()
    kernel = runtime.service("kernel")
    assert isinstance(kernel, Kernel)

    with pytest.raises(ValueError, match="reserved"):
        PhoenixRuntime(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            services={" runtime ": object()},
        )

    duplicated = ComponentSpec("same", HookComponent())
    with pytest.raises(ValueError, match="unique"):
        PhoenixRuntime(
            kernel=kernel,
            events=EventBus(),
            capabilities=CapabilityRegistry(),
            components=(duplicated, duplicated),
        )

    await runtime.stop()


@pytest.mark.asyncio
async def test_components_receive_the_same_runtime_context() -> None:
    contexts: list[RuntimeContext] = []
    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec(
                "capture",
                HookComponent(
                    start=lambda context: contexts.append(context),
                    stop=lambda context: contexts.append(context),
                ),
            ),
        )
    )

    await runtime.start()
    await runtime.stop()

    assert contexts == [runtime.context, runtime.context]


@pytest.mark.asyncio
async def test_runtime_emits_correlated_lifecycle_events() -> None:
    events = EventBus()
    observed: list[Event] = []
    await events.subscribe("*", lambda event: observed.append(event))
    runtime, _, _ = make_runtime(
        events=events,
        components=(ComponentSpec("service", HookComponent()),),
    )

    await runtime.start()
    await runtime.stop()

    assert [event.name for event in observed] == [
        "runtime.starting",
        "runtime.component.starting",
        "runtime.component.started",
        "runtime.started",
        "runtime.stopping",
        "runtime.component.stopping",
        "runtime.component.stopped",
        "runtime.stopped",
    ]
    assert {event.correlation_id for event in observed} == {str(runtime.context.id)}
    assert {event.causation_id for event in observed} == {runtime.context.id}


@pytest.mark.asyncio
async def test_handle_requires_running_runtime_and_delegates_to_kernel() -> None:
    runtime, _, _ = make_runtime()

    with pytest.raises(RuntimeNotRunningError):
        await runtime.handle(Request("system.echo"))

    await runtime.start()
    response = await runtime.handle(Request("system.echo"))
    assert response.status == 200
    assert response.body == {"action": "system.echo"}

    await runtime.stop()
    with pytest.raises(RuntimeNotRunningError):
        await runtime.handle(Request("system.echo"))


@pytest.mark.asyncio
async def test_shutdown_drains_in_flight_requests_and_rejects_new_work() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    events = EventBus()
    router = Router()

    async def blocking_handler(request: Request) -> Response:
        del request
        entered.set()
        await release.wait()
        return Response(status=200)

    router.add("system.block", blocking_handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    runtime = PhoenixRuntime(kernel=kernel, events=events, capabilities=capabilities)
    await runtime.start()

    request_task = asyncio.create_task(runtime.handle(Request("system.block")))
    await entered.wait()
    stop_task = asyncio.create_task(runtime.stop())
    await asyncio.sleep(0)

    assert runtime.state is RuntimeState.STOPPING
    with pytest.raises(RuntimeNotRunningError):
        await runtime.handle(Request("system.block"))
    assert stop_task.done() is False

    release.set()
    assert (await request_task).status == 200
    await stop_task
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_snapshot_reports_active_components_and_in_flight_requests() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    events = EventBus()
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        entered.set()
        await release.wait()
        return Response(status=200)

    router.add("wait", handler)
    runtime = PhoenixRuntime(
        kernel=Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        components=(ComponentSpec("component", HookComponent()),),
    )

    initial = await runtime.snapshot()
    assert initial.state is RuntimeState.CREATED
    assert initial.active_components == ()
    await runtime.start()

    task = asyncio.create_task(runtime.handle(Request("wait")))
    await entered.wait()
    running = await runtime.snapshot()
    assert running.active_components == ("component",)
    assert running.in_flight_requests == 1
    assert running.started_at is not None

    release.set()
    await task
    await runtime.stop()
    stopped = await runtime.snapshot()
    assert stopped.in_flight_requests == 0
    assert stopped.stopped_at is not None


@pytest.mark.asyncio
async def test_start_failure_rolls_back_started_components() -> None:
    calls: list[str] = []

    async def fail(context: RuntimeContext) -> None:
        del context
        calls.append("start:second")
        raise RuntimeError("private startup detail")

    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec(
                "first",
                HookComponent(
                    start=lambda context: calls.append("start:first"),
                    stop=lambda context: calls.append("stop:first"),
                ),
            ),
            ComponentSpec("second", HookComponent(start=fail)),
        )
    )

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert calls == ["start:first", "start:second", "stop:first"]
    assert captured.value.failure.component == "second"
    assert captured.value.failure.phase is RuntimePhase.START
    assert captured.value.rollback_failures == ()
    assert str(captured.value) == "runtime startup failed in component 'second'"
    assert runtime.state is RuntimeState.FAILED
    await runtime.stop()


@pytest.mark.asyncio
async def test_rollback_failure_is_reported_and_can_be_retried_by_stop() -> None:
    stop_attempts = 0

    async def flaky_stop(context: RuntimeContext) -> None:
        nonlocal stop_attempts
        del context
        stop_attempts += 1
        if stop_attempts == 1:
            raise RuntimeError("rollback failed")

    async def fail(context: RuntimeContext) -> None:
        del context
        raise RuntimeError("startup failed")

    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec("first", HookComponent(stop=flaky_stop)),
            ComponentSpec("second", HookComponent(start=fail)),
        )
    )

    with pytest.raises(RuntimeStartError) as captured:
        await runtime.start()

    assert len(captured.value.rollback_failures) == 1
    assert captured.value.rollback_failures[0].component == "first"
    assert (await runtime.snapshot()).active_components == ("first",)

    await runtime.stop()
    assert stop_attempts == 2
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_stop_attempts_every_component_and_supports_retry() -> None:
    calls: list[str] = []
    fail_once = True

    async def first_stop(context: RuntimeContext) -> None:
        del context
        calls.append("stop:first")

    async def second_stop(context: RuntimeContext) -> None:
        nonlocal fail_once
        del context
        calls.append("stop:second")
        if fail_once:
            fail_once = False
            raise RuntimeError("temporary stop failure")

    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec("first", HookComponent(stop=first_stop)),
            ComponentSpec("second", HookComponent(stop=second_stop)),
        )
    )
    await runtime.start()

    with pytest.raises(RuntimeStopError) as captured:
        await runtime.stop()

    assert calls == ["stop:second", "stop:first"]
    assert len(captured.value.failures) == 1
    assert captured.value.failures[0].component == "second"
    assert runtime.state is RuntimeState.FAILED
    assert (await runtime.snapshot()).active_components == ("second",)

    await runtime.stop()
    assert calls == ["stop:second", "stop:first", "stop:second"]
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_start_deadline_rolls_back_and_becomes_domain_error() -> None:
    calls: list[str] = []

    async def slow_start(context: RuntimeContext) -> None:
        del context
        await asyncio.sleep(1)

    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec("first", HookComponent(stop=lambda context: calls.append("rollback"))),
            ComponentSpec("slow", HookComponent(start=slow_start)),
        )
    )

    with pytest.raises(RuntimeDeadlineExceededError) as captured:
        await runtime.start(deadline=0.001)

    assert captured.value.phase is RuntimePhase.START
    assert calls == ["rollback"]
    assert runtime.state is RuntimeState.FAILED
    await runtime.stop()


@pytest.mark.asyncio
async def test_stop_deadline_while_draining_can_be_retried() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    events = EventBus()
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        entered.set()
        await release.wait()
        return Response(status=200)

    router.add("wait", handler)
    runtime = PhoenixRuntime(
        kernel=Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
    )
    await runtime.start()
    task = asyncio.create_task(runtime.handle(Request("wait")))
    await entered.wait()

    with pytest.raises(RuntimeDeadlineExceededError) as captured:
        await runtime.stop(deadline=0.001)

    assert captured.value.phase is RuntimePhase.STOP
    assert runtime.state is RuntimeState.FAILED
    release.set()
    await task
    await runtime.stop()
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_non_positive_lifecycle_deadlines_are_rejected() -> None:
    runtime, _, _ = make_runtime()

    with pytest.raises(ValueError, match="deadline"):
        await runtime.start(deadline=0)
    with pytest.raises(ValueError, match="deadline"):
        await runtime.stop(deadline=-1)

    await runtime.stop()


@pytest.mark.asyncio
async def test_start_cancellation_rolls_back_and_propagates() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls: list[str] = []

    async def blocking_start(context: RuntimeContext) -> None:
        del context
        entered.set()
        await release.wait()

    runtime, _, _ = make_runtime(
        components=(
            ComponentSpec("first", HookComponent(stop=lambda context: calls.append("rollback"))),
            ComponentSpec("blocking", HookComponent(start=blocking_start)),
        )
    )

    task = asyncio.create_task(runtime.start())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert calls == ["rollback"]
    assert runtime.state is RuntimeState.FAILED
    await runtime.stop()


@pytest.mark.asyncio
async def test_stop_cancellation_propagates_and_cleanup_can_be_retried() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocking_stop(context: RuntimeContext) -> None:
        del context
        entered.set()
        await release.wait()

    runtime, _, _ = make_runtime(
        components=(ComponentSpec("blocking", HookComponent(stop=blocking_stop)),)
    )
    await runtime.start()

    task = asyncio.create_task(runtime.stop())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert runtime.state is RuntimeState.FAILED
    release.set()
    await runtime.stop()
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_async_context_manager_starts_and_stops_runtime() -> None:
    runtime, events, capabilities = make_runtime()

    async with runtime as active:
        assert active is runtime
        assert runtime.state is RuntimeState.RUNNING

    assert (await runtime.snapshot()).state is RuntimeState.STOPPED
    assert events.closed is True
    assert capabilities.closed is True


@pytest.mark.asyncio
async def test_context_manager_preserves_body_exception_after_cleanup() -> None:
    runtime, _, _ = make_runtime()

    with pytest.raises(ValueError, match="body failure"):
        async with runtime:
            raise ValueError("body failure")

    assert (await runtime.snapshot()).state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_context_manager_cleans_up_after_start_failure() -> None:
    async def fail(context: RuntimeContext) -> None:
        del context
        raise RuntimeError("failed")

    runtime, events, capabilities = make_runtime(
        components=(ComponentSpec("broken", HookComponent(start=fail)),)
    )

    with pytest.raises(RuntimeStartError):
        async with runtime:
            pass

    assert (await runtime.snapshot()).state is RuntimeState.STOPPED
    assert events.closed is True
    assert capabilities.closed is True


@pytest.mark.asyncio
async def test_stop_from_created_closes_owned_core_services() -> None:
    runtime, events, capabilities = make_runtime()

    await runtime.stop()

    assert (await runtime.snapshot()).state is RuntimeState.STOPPED
    assert events.closed is True
    assert capabilities.closed is True
    with pytest.raises(RuntimeStateError):
        await runtime.start()
