from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    AuditSummary,
    CapabilityPage,
    ControlPlaneEventStream,
    ControlPlaneEventStreamBackpressureError,
    ControlPlaneEventStreamConfig,
    ControlPlaneEventStreamState,
    ControlPlaneEventStreamStateError,
    ControlPlaneHealth,
    ControlPlaneHttpConfig,
    ControlPlaneHttpServer,
    ControlPlaneSnapshot,
    EventBatch,
    EventStreamRequest,
    EventView,
    JobPage,
    PageInfo,
    PageRequest,
    PluginPage,
    WorkflowPage,
    WorkflowSummary,
    event_batch_to_dict,
)
from phoenix_os.events import EventBus
from phoenix_os.jobs import JobSchedulerSnapshot
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState

_NOW = datetime(2026, 7, 18, 22, 0, tzinfo=UTC)
_TOKEN = "control-plane-event-token-00000001"
_DEFAULT_PAGE = PageRequest()
_DEFAULT_EVENT_REQUEST = EventStreamRequest()


def _event(sequence: int, *, name: str = "job.succeeded") -> EventView:
    return EventView(
        sequence=sequence,
        id=UUID(f"10000000-0000-0000-0000-{sequence:012d}"),
        name=name,
        source="phoenix.tests",
        occurred_at=_NOW,
        correlation_id=f"correlation-{sequence}",
        causation_id=None,
    )


def _batch(*items: EventView, cursor: int | None = None) -> EventBatch:
    latest = items[-1].sequence if items else None
    oldest = items[0].sequence if items else None
    return EventBatch(
        items=tuple(items),
        cursor=(latest if cursor is None and latest is not None else cursor or 0),
        oldest_cursor=oldest,
        latest_cursor=latest,
        gap=False,
        dropped=0,
        timed_out=False,
    )


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"retention": 0}, "retention"),
        ({"retention": 100_001}, "retention"),
        ({"max_waiters": 0}, "max_waiters"),
        ({"max_waiters": 10_001}, "max_waiters"),
        ({"max_wait": 0}, "max_wait"),
        ({"max_wait": 61}, "max_wait"),
    ],
)
def test_event_stream_config_rejects_invalid_limits(
    kwargs: dict[str, int | float],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneEventStreamConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"after": -1}, "cursor"),
        ({"limit": 0}, "limit"),
        ({"limit": 201}, "limit"),
        ({"wait": -0.1}, "wait"),
    ],
)
def test_event_stream_request_rejects_invalid_values(
    kwargs: dict[str, int | float],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        EventStreamRequest(**kwargs)  # type: ignore[arg-type]


def test_event_view_requires_safe_identity_and_aware_time() -> None:
    with pytest.raises(ValueError, match="positive"):
        EventView(0, UUID(int=1), "event", "source", _NOW, None, None)
    with pytest.raises(ValueError, match="blank"):
        EventView(1, UUID(int=1), " ", "source", _NOW, None, None)
    with pytest.raises(ValueError, match="timezone-aware"):
        EventView(1, UUID(int=1), "event", "source", _NOW.replace(tzinfo=None), None, None)


def test_event_batch_validates_cursor_order_and_gap() -> None:
    with pytest.raises(ValueError, match="strictly increasing"):
        EventBatch((_event(2), _event(1)), 1, 1, 2, False, 0, False)
    with pytest.raises(ValueError, match="final item"):
        EventBatch((_event(1),), 2, 1, 1, False, 0, False)
    with pytest.raises(ValueError, match="gap"):
        EventBatch((), 0, None, None, True, 0, False)


@pytest.mark.asyncio
async def test_event_stream_has_one_shot_lifecycle() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(bus)

    await stream.start()
    assert stream.state is ControlPlaneEventStreamState.RUNNING
    with pytest.raises(ControlPlaneEventStreamStateError, match="cannot start"):
        await stream.start()

    await stream.stop()
    assert stream.state.value == ControlPlaneEventStreamState.STOPPED.value
    await stream.stop()
    with pytest.raises(ControlPlaneEventStreamStateError, match="cannot read"):
        await stream.read()


@pytest.mark.asyncio
async def test_event_stream_discards_payload_and_metadata() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(bus)
    await stream.start()

    await bus.emit(
        "workflow.started",
        source="phoenix.workflows",
        payload={"password": "secret-value", "arguments": {"token": "hidden"}},
        metadata={"authorization": "Bearer hidden"},
        correlation_id="workflow-1",
    )
    payload = event_batch_to_dict(await stream.read())

    assert payload["items"][0]["name"] == "workflow.started"  # type: ignore[index]
    assert "secret-value" not in repr(payload)
    assert "hidden" not in repr(payload)
    assert "payload" not in repr(payload)
    assert "metadata" not in repr(payload)
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_retention_reports_cursor_gap_for_slow_clients() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(retention=2),
    )
    await stream.start()

    for index in range(3):
        await bus.emit(f"event.{index}", source="phoenix.tests")

    batch = await stream.read(EventStreamRequest(after=0, limit=10))
    assert [item.sequence for item in batch.items] == [2, 3]
    assert batch.oldest_cursor == 2
    assert batch.latest_cursor == 3
    assert batch.cursor == 3
    assert batch.gap is True
    assert batch.dropped == 1
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_cursor_batches_are_deterministic() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(bus)
    await stream.start()
    for index in range(5):
        await bus.emit(f"event.{index}", source="phoenix.tests")

    first = await stream.read(EventStreamRequest(limit=2))
    second = await stream.read(EventStreamRequest(after=first.cursor, limit=2))
    third = await stream.read(EventStreamRequest(after=second.cursor, limit=2))

    assert [item.sequence for item in first.items] == [1, 2]
    assert [item.sequence for item in second.items] == [3, 4]
    assert [item.sequence for item in third.items] == [5]
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_immediate_empty_read_is_not_timeout() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(bus)
    await stream.start()

    batch = await stream.read()

    assert batch.items == ()
    assert batch.cursor == 0
    assert batch.timed_out is False
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_long_poll_wakes_on_new_event() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(max_wait=1.0),
    )
    await stream.start()

    task = asyncio.create_task(stream.read(EventStreamRequest(wait=0.5)))
    await asyncio.sleep(0)
    await bus.emit("runtime.started", source="phoenix.runtime")
    batch = await task

    assert [item.name for item in batch.items] == ["runtime.started"]
    assert batch.timed_out is False
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_long_poll_returns_bounded_timeout() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(max_wait=1.0),
    )
    await stream.start()

    batch = await stream.read(EventStreamRequest(wait=0.01))

    assert batch.items == ()
    assert batch.timed_out is True
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_rejects_wait_above_configured_maximum() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(max_wait=0.1),
    )
    await stream.start()

    with pytest.raises(ValueError, match="maximum"):
        await stream.read(EventStreamRequest(wait=0.2))
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_bounds_waiters_and_records_backpressure() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(max_waiters=1, max_wait=1.0),
    )
    await stream.start()

    first = asyncio.create_task(stream.read(EventStreamRequest(wait=0.05)))
    for _ in range(20):
        if (await stream.snapshot()).waiters == 1:
            break
        await asyncio.sleep(0)

    with pytest.raises(ControlPlaneEventStreamBackpressureError, match="capacity"):
        await stream.read(EventStreamRequest(wait=0.05))
    await first
    snapshot = await stream.snapshot()
    assert snapshot.rejected_waiters == 1
    assert snapshot.waiters == 0
    await stream.stop()


@pytest.mark.asyncio
async def test_event_stream_stop_wakes_waiters_with_state_error() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(max_wait=1.0),
    )
    await stream.start()
    task = asyncio.create_task(stream.read(EventStreamRequest(wait=0.5)))
    for _ in range(20):
        if (await stream.snapshot()).waiters == 1:
            break
        await asyncio.sleep(0)

    await stream.stop()

    with pytest.raises(ControlPlaneEventStreamStateError, match="cannot read"):
        await task


@pytest.mark.asyncio
async def test_event_stream_snapshot_reports_retention_counters() -> None:
    bus = EventBus()
    stream = ControlPlaneEventStream(
        bus,
        config=ControlPlaneEventStreamConfig(retention=2),
    )
    await stream.start()
    for index in range(3):
        await bus.emit(f"event.{index}", source="phoenix.tests")

    snapshot = await stream.snapshot()

    assert snapshot.retention == 2
    assert snapshot.retained == 2
    assert snapshot.published == 3
    assert snapshot.evicted == 1
    assert snapshot.oldest_cursor == 2
    assert snapshot.latest_cursor == 3
    await stream.stop()


class _Reader:
    async def snapshot(self) -> ControlPlaneSnapshot:
        return ControlPlaneSnapshot(
            generated_at=_NOW,
            health=ControlPlaneHealth.HEALTHY,
            runtime=RuntimeSnapshot(
                runtime_id=UUID(int=1),
                state=RuntimeState.RUNNING,
                components=(),
                active_components=(),
                in_flight_requests=0,
                created_at=_NOW,
                started_at=_NOW,
                stopped_at=None,
            ),
            jobs=JobSchedulerSnapshot(False, 0, 0, 0, 0, 0, 0, 0, 0),
            workflows=WorkflowSummary(0, 0, 0, 0, 0, 0),
        )

    async def list_jobs(self, page: PageRequest = _DEFAULT_PAGE) -> JobPage:
        return JobPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_workflows(self, page: PageRequest = _DEFAULT_PAGE) -> WorkflowPage:
        return WorkflowPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_capabilities(self, page: PageRequest = _DEFAULT_PAGE) -> CapabilityPage:
        return CapabilityPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_plugins(self, page: PageRequest = _DEFAULT_PAGE) -> PluginPage:
        return PluginPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def audit_summary(self) -> AuditSummary | None:
        return None


class _StaticStream:
    def __init__(self, batch: EventBatch) -> None:
        self.batch = batch
        self.requests: list[EventStreamRequest] = []

    async def read(self, request: EventStreamRequest = _DEFAULT_EVENT_REQUEST) -> EventBatch:
        self.requests.append(request)
        return self.batch


class _BusyStream:
    async def read(self, request: EventStreamRequest = _DEFAULT_EVENT_REQUEST) -> EventBatch:
        del request
        raise ControlPlaneEventStreamBackpressureError("busy")


class _StoppedStream:
    async def read(self, request: EventStreamRequest = _DEFAULT_EVENT_REQUEST) -> EventBatch:
        del request
        raise ControlPlaneEventStreamStateError("stopped")


def _server(event_stream: Any = None) -> ControlPlaneHttpServer:
    return ControlPlaneHttpServer(
        _Reader(),
        AdminTokenAuthenticator(_TOKEN),
        config=ControlPlaneHttpConfig(request_timeout=0.5, max_event_wait=0.2),
        event_stream=event_stream,
    )


async def _request(
    server: ControlPlaneHttpServer,
    path: str,
    *,
    authorized: bool = True,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    assert server.port is not None
    reader, writer = await asyncio.open_connection(server.host, server.port)
    headers = [f"GET {path} HTTP/1.1", "Host: 127.0.0.1"]
    if authorized:
        headers.append(f"Authorization: Bearer {_TOKEN}")
    writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    response_headers = {
        name.lower(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])
    }
    return status, response_headers, json.loads(body)


@pytest.mark.asyncio
async def test_http_event_feed_requires_authentication() -> None:
    server = _server(_StaticStream(_batch()))
    await server.start()

    status, _, payload = await _request(
        server,
        "/v1/control-plane/events",
        authorized=False,
    )

    assert status == 401
    assert payload == {"error": "unauthorized"}
    await server.stop()


@pytest.mark.asyncio
async def test_http_event_feed_reports_unavailable_stream() -> None:
    server = _server()
    await server.start()

    status, _, payload = await _request(server, "/v1/control-plane/events")

    assert status == 503
    assert payload == {"error": "events_unavailable"}
    await server.stop()


@pytest.mark.asyncio
async def test_http_event_feed_serializes_safe_batch_and_forwards_query() -> None:
    stream = _StaticStream(_batch(_event(7), cursor=7))
    server = _server(stream)
    await server.start()

    status, headers, payload = await _request(
        server,
        "/v1/control-plane/events?after=6&limit=10&wait=0.1",
    )

    assert status == 200
    assert headers["cache-control"] == "no-store"
    assert payload["cursor"] == 7
    assert payload["items"][0]["name"] == "job.succeeded"
    assert stream.requests == [EventStreamRequest(after=6, limit=10, wait=0.1)]
    await server.stop()


@pytest.mark.parametrize(
    "query",
    [
        "unknown=1",
        "after=-1",
        "after=",
        "after=1&after=2",
        "limit=0",
        "limit=201",
        "wait=-1",
        "wait=nan",
        "wait=0.3",
        "wait=1&wait=2",
    ],
)
@pytest.mark.asyncio
async def test_http_event_feed_rejects_invalid_queries(query: str) -> None:
    server = _server(_StaticStream(_batch()))
    await server.start()

    status, _, payload = await _request(server, f"/v1/control-plane/events?{query}")

    assert status == 400
    assert payload == {"error": "invalid_event_query"}
    await server.stop()


@pytest.mark.asyncio
async def test_http_event_feed_maps_waiter_backpressure_to_429() -> None:
    server = _server(_BusyStream())
    await server.start()

    status, headers, payload = await _request(server, "/v1/control-plane/events")

    assert status == 429
    assert headers["retry-after"] == "1"
    assert payload == {"error": "event_stream_busy"}
    assert (await server.snapshot()).rejected == 1
    await server.stop()


@pytest.mark.asyncio
async def test_http_event_feed_maps_stopped_stream_to_503() -> None:
    server = _server(_StoppedStream())
    await server.start()

    status, _, payload = await _request(server, "/v1/control-plane/events")

    assert status == 503
    assert payload == {"error": "events_unavailable"}
    await server.stop()
