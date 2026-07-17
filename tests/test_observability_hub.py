import asyncio

import pytest

from phoenix_os import (
    ExportErrorPolicy,
    InMemorySink,
    LogRecord,
    MetricKind,
    MetricRecord,
    ObservabilityClosedError,
    ObservabilityHub,
    Observation,
    ObservationExportError,
    Severity,
)


class RecordingSink:
    def __init__(self, name: str, calls: list[str]) -> None:
        self.name = name
        self.calls = calls
        self.records: list[Observation] = []

    async def emit(self, observation: Observation) -> None:
        self.calls.append(self.name)
        self.records.append(observation)


@pytest.mark.asyncio
async def test_sinks_run_by_priority_then_registration_order() -> None:
    calls: list[str] = []
    hub = ObservabilityHub()
    await hub.add_sink(RecordingSink("normal", calls))
    await hub.add_sink(RecordingSink("high-first", calls), priority=10)
    await hub.add_sink(RecordingSink("high-second", calls), priority=10)
    await hub.add_sink(RecordingSink("low", calls), priority=-5)

    report = await hub.log("ready", source="test", message="ready")

    assert calls == ["high-first", "high-second", "normal", "low"]
    assert report.matched == 4
    assert report.exported == 4
    assert report.succeeded


@pytest.mark.asyncio
async def test_synchronous_sink_is_supported() -> None:
    records: list[Observation] = []

    class SyncSink:
        def emit(self, observation: Observation) -> None:
            records.append(observation)

    hub = ObservabilityHub((SyncSink(),))
    report = await hub.log("ready", source="test", message="ready")

    assert report.exported == 1
    assert records == [report.observation]


@pytest.mark.asyncio
async def test_remove_sink_returns_whether_registration_existed() -> None:
    hub = ObservabilityHub()
    registration = await hub.add_sink(InMemorySink())

    assert await hub.remove_sink(registration) is True
    assert await hub.remove_sink(registration) is False


@pytest.mark.asyncio
async def test_failures_are_collected_and_later_sinks_run() -> None:
    calls: list[str] = []

    class FailingSink:
        async def emit(self, observation: Observation) -> None:
            del observation
            calls.append("failing")
            raise ValueError("boom")

    hub = ObservabilityHub()
    failed = await hub.add_sink(FailingSink())
    healthy = RecordingSink("healthy", calls)
    await hub.add_sink(healthy)

    report = await hub.log("ready", source="test", message="ready")

    assert calls == ["failing", "healthy"]
    assert report.exported == 1
    assert len(report.failures) == 1
    assert report.failures[0].registration == failed
    assert isinstance(report.failures[0].exception, ValueError)

    snapshot = await hub.snapshot()
    assert snapshot.observations == 1
    assert snapshot.export_failures == 1


@pytest.mark.asyncio
async def test_raise_policy_raises_after_all_sinks_run() -> None:
    calls: list[str] = []

    class FailingSink:
        async def emit(self, observation: Observation) -> None:
            del observation
            calls.append("failing")
            raise ValueError("boom")

    hub = ObservabilityHub((FailingSink(), RecordingSink("healthy", calls)))

    with pytest.raises(ObservationExportError) as captured:
        await hub.log(
            "ready",
            source="test",
            message="ready",
            error_policy=ExportErrorPolicy.RAISE,
        )

    assert calls == ["failing", "healthy"]
    assert captured.value.report.exported == 1


@pytest.mark.asyncio
async def test_sink_cancellation_propagates() -> None:
    class CancelledSink:
        async def emit(self, observation: Observation) -> None:
            del observation
            raise asyncio.CancelledError

    hub = ObservabilityHub((CancelledSink(),))
    with pytest.raises(asyncio.CancelledError):
        await hub.log("ready", source="test", message="ready")


@pytest.mark.asyncio
async def test_log_and_metric_helpers_build_expected_records() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    log_report = await hub.log(
        "system.ready",
        source="test",
        message="ready",
        severity=Severity.WARNING,
        attributes={"value": 7},
        correlation_id="corr",
    )
    metric_report = await hub.metric(
        "requests.total",
        3,
        source="test",
        kind=MetricKind.COUNTER,
        unit="request",
    )

    assert isinstance(log_report.observation, LogRecord)
    assert log_report.observation.severity is Severity.WARNING
    assert log_report.observation.correlation_id == "corr"
    assert isinstance(metric_report.observation, MetricRecord)
    assert metric_report.observation.kind is MetricKind.COUNTER


@pytest.mark.asyncio
async def test_direct_emit_is_redacted_before_export() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    report = await hub.emit(
        LogRecord(
            "auth",
            "test",
            "authentication attempted",
            attributes={"password": "unsafe", "safe": "ok"},
        )
    )

    assert report.observation.attributes == {"password": "***", "safe": "ok"}


@pytest.mark.asyncio
async def test_close_rejects_new_operations_and_is_idempotent() -> None:
    hub = ObservabilityHub((InMemorySink(),))
    await hub.close()
    await hub.close()

    assert hub.closed
    with pytest.raises(ObservabilityClosedError):
        await hub.log("ready", source="test", message="ready")
    with pytest.raises(ObservabilityClosedError):
        await hub.add_sink(InMemorySink())


@pytest.mark.asyncio
async def test_lifecycle_hooks_close_hub() -> None:
    hub = ObservabilityHub()
    await hub.start(object())
    await hub.stop(object())
    assert hub.closed


def test_constructor_and_add_sink_validate_sink_contract() -> None:
    with pytest.raises(TypeError, match="emit"):
        ObservabilityHub((object(),))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_add_sink_validates_sink_contract() -> None:
    hub = ObservabilityHub()
    with pytest.raises(TypeError, match="emit"):
        await hub.add_sink(object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_in_memory_sink_is_bounded_and_reports_drops() -> None:
    sink = InMemorySink(capacity=2)
    hub = ObservabilityHub((sink,))
    for index in range(3):
        await hub.log(f"record.{index}", source="test", message="record")

    snapshot = await sink.snapshot()
    assert [record.name for record in snapshot.records] == ["record.1", "record.2"]
    assert snapshot.dropped == 1


@pytest.mark.asyncio
async def test_in_memory_sink_clear_and_close() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))
    await hub.log("ready", source="test", message="ready")
    await sink.clear()
    assert (await sink.snapshot()).records == ()

    await sink.close()
    assert (await sink.snapshot()).closed
    with pytest.raises(Exception, match="closed"):
        await sink.emit(LogRecord("name", "test", "message"))
