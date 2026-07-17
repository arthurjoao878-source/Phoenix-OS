import asyncio
from collections.abc import Awaitable, Callable

import pytest

from phoenix_os.events import (
    BusClosedError,
    ErrorPolicy,
    Event,
    EventBus,
    EventDispatchError,
)


@pytest.mark.asyncio
async def test_publish_delivers_exact_subscription() -> None:
    bus = EventBus()
    received: list[str] = []

    async def handler(event: Event) -> None:
        received.append(event.name)

    await bus.subscribe("alpha", handler)
    report = await bus.emit("alpha", source="test")

    assert received == ["alpha"]
    assert report.matched == 1
    assert report.delivered == 1
    assert report.succeeded


@pytest.mark.asyncio
async def test_non_matching_subscription_is_not_called() -> None:
    bus = EventBus()
    called = False

    async def handler(event: Event) -> None:
        nonlocal called
        del event
        called = True

    await bus.subscribe("alpha", handler)
    report = await bus.emit("beta", source="test")

    assert called is False
    assert report.matched == 0


@pytest.mark.asyncio
async def test_wildcard_receives_all_events() -> None:
    bus = EventBus()
    received: list[str] = []

    async def handler(event: Event) -> None:
        received.append(event.name)

    await bus.subscribe("*", handler)
    await bus.emit("alpha", source="test")
    await bus.emit("beta", source="test")

    assert received == ["alpha", "beta"]


@pytest.mark.asyncio
async def test_priority_then_registration_order_is_deterministic() -> None:
    bus = EventBus()
    calls: list[str] = []

    def build(name: str) -> Callable[[Event], Awaitable[None]]:
        async def handler(event: Event) -> None:
            del event
            calls.append(name)

        return handler

    await bus.subscribe("alpha", build("normal-first"))
    await bus.subscribe("alpha", build("high-first"), priority=10)
    await bus.subscribe("alpha", build("high-second"), priority=10)
    await bus.subscribe("alpha", build("low"), priority=-5)

    await bus.emit("alpha", source="test")

    assert calls == ["high-first", "high-second", "normal-first", "low"]


@pytest.mark.asyncio
async def test_synchronous_handler_is_supported() -> None:
    bus = EventBus()
    received: list[str] = []

    def handler(event: Event) -> None:
        received.append(event.name)

    await bus.subscribe("alpha", handler)
    report = await bus.emit("alpha", source="test")

    assert received == ["alpha"]
    assert report.delivered == 1


@pytest.mark.asyncio
async def test_unsubscribe_returns_whether_subscription_existed() -> None:
    bus = EventBus()

    async def handler(event: Event) -> None:
        del event

    subscription = await bus.subscribe("alpha", handler)

    assert await bus.unsubscribe(subscription) is True
    assert await bus.unsubscribe(subscription) is False


@pytest.mark.asyncio
async def test_once_subscription_is_removed_before_invocation() -> None:
    bus = EventBus()
    calls = 0

    async def handler(event: Event) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            await bus.publish(event)

    await bus.subscribe("alpha", handler, once=True)
    await bus.emit("alpha", source="test")

    assert calls == 1


@pytest.mark.asyncio
async def test_handler_added_during_dispatch_starts_next_event() -> None:
    bus = EventBus()
    calls: list[str] = []

    async def late(event: Event) -> None:
        del event
        calls.append("late")

    async def first(event: Event) -> None:
        del event
        calls.append("first")
        await bus.subscribe("alpha", late)

    await bus.subscribe("alpha", first)
    await bus.emit("alpha", source="test")
    assert calls == ["first"]

    await bus.emit("alpha", source="test")
    assert calls == ["first", "first", "late"]


@pytest.mark.asyncio
async def test_unsubscribe_during_dispatch_does_not_change_snapshot() -> None:
    bus = EventBus()
    calls: list[str] = []

    async def second(event: Event) -> None:
        del event
        calls.append("second")

    second_subscription = await bus.subscribe("alpha", second)

    async def first(event: Event) -> None:
        del event
        calls.append("first")
        await bus.unsubscribe(second_subscription)

    await bus.subscribe("alpha", first, priority=10)
    await bus.emit("alpha", source="test")
    assert calls == ["first", "second"]

    calls.clear()
    await bus.emit("alpha", source="test")
    assert calls == ["first"]


@pytest.mark.asyncio
async def test_failure_is_collected_and_later_handler_runs() -> None:
    bus = EventBus()
    calls: list[str] = []

    async def failing(event: Event) -> None:
        del event
        calls.append("failing")
        raise ValueError("boom")

    async def healthy(event: Event) -> None:
        del event
        calls.append("healthy")

    failed_subscription = await bus.subscribe("alpha", failing)
    await bus.subscribe("alpha", healthy)
    report = await bus.emit("alpha", source="test")

    assert calls == ["failing", "healthy"]
    assert report.matched == 2
    assert report.delivered == 1
    assert len(report.failures) == 1
    assert report.failures[0].subscription == failed_subscription
    assert isinstance(report.failures[0].exception, ValueError)


@pytest.mark.asyncio
async def test_raise_policy_raises_after_all_handlers_run() -> None:
    bus = EventBus()
    calls: list[str] = []

    async def failing(event: Event) -> None:
        del event
        calls.append("failing")
        raise ValueError("boom")

    async def healthy(event: Event) -> None:
        del event
        calls.append("healthy")

    await bus.subscribe("alpha", failing)
    await bus.subscribe("alpha", healthy)

    with pytest.raises(EventDispatchError) as captured:
        await bus.emit("alpha", source="test", error_policy=ErrorPolicy.RAISE)

    assert calls == ["failing", "healthy"]
    assert captured.value.report.delivered == 1
    assert len(captured.value.report.failures) == 1


@pytest.mark.asyncio
async def test_handler_cancellation_propagates() -> None:
    bus = EventBus()

    async def cancelled(event: Event) -> None:
        del event
        raise asyncio.CancelledError

    await bus.subscribe("alpha", cancelled)

    with pytest.raises(asyncio.CancelledError):
        await bus.emit("alpha", source="test")


@pytest.mark.asyncio
async def test_emit_builds_event_with_requested_fields() -> None:
    bus = EventBus()
    captured: list[Event] = []

    async def handler(event: Event) -> None:
        captured.append(event)

    await bus.subscribe("alpha", handler)
    report = await bus.emit(
        "alpha",
        source="unit-test",
        payload={"value": 7},
        metadata={"kind": "demo"},
        correlation_id="corr-7",
    )

    assert report.event is captured[0]
    assert report.event.source == "unit-test"
    assert report.event.payload == {"value": 7}
    assert report.event.metadata == {"kind": "demo"}
    assert report.event.correlation_id == "corr-7"


@pytest.mark.asyncio
async def test_close_clears_handlers_and_rejects_future_operations() -> None:
    bus = EventBus()

    async def handler(event: Event) -> None:
        del event

    await bus.subscribe("alpha", handler)
    await bus.close()

    assert bus.closed is True
    with pytest.raises(BusClosedError):
        await bus.emit("alpha", source="test")
    with pytest.raises(BusClosedError):
        await bus.subscribe("alpha", handler)


@pytest.mark.asyncio
async def test_close_is_idempotent() -> None:
    bus = EventBus()
    await bus.close()
    await bus.close()
    assert bus.closed


@pytest.mark.asyncio
async def test_blank_subscription_name_is_rejected() -> None:
    bus = EventBus()

    async def handler(event: Event) -> None:
        del event

    with pytest.raises(ValueError, match="event_name"):
        await bus.subscribe("  ", handler)
