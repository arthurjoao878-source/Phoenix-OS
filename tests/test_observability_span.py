import asyncio

import pytest

from phoenix_os import (
    ExportErrorPolicy,
    InMemorySink,
    LogRecord,
    ObservabilityHub,
    Observation,
    ObservationExportError,
    SpanRecord,
    SpanStateError,
    SpanStatus,
    current_span_context,
)


@pytest.mark.asyncio
async def test_successful_span_exports_record_and_resets_context() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    async with hub.span("request", source="test", attributes={"route": "echo"}) as span:
        assert current_span_context() == span.context

    assert current_span_context() is None
    records = (await sink.snapshot()).records
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, SpanRecord)
    assert record.status is SpanStatus.OK
    assert record.attributes == {"route": "echo"}
    assert record.duration_seconds >= 0


@pytest.mark.asyncio
async def test_nested_spans_share_trace_and_set_parent() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    async with hub.span("parent", source="test") as parent:
        async with hub.span("child", source="test") as child:
            assert child.context.trace_id == parent.context.trace_id
            assert child.context.parent_span_id == parent.context.span_id
            assert child.context.correlation_id == parent.context.correlation_id

    records = (await sink.snapshot()).records
    child_record = records[0]
    parent_record = records[1]
    assert isinstance(child_record, SpanRecord)
    assert isinstance(parent_record, SpanRecord)
    assert child_record.context.parent_span_id == parent_record.context.span_id


@pytest.mark.asyncio
async def test_error_span_records_exception_type_and_preserves_exception() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    with pytest.raises(ValueError, match="boom"):
        async with hub.span("request", source="test"):
            raise ValueError("boom")

    record = (await sink.snapshot()).records[0]
    assert isinstance(record, SpanRecord)
    assert record.status is SpanStatus.ERROR
    assert record.exception_type == "ValueError"


@pytest.mark.asyncio
async def test_cancelled_span_records_cancelled_and_propagates() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    with pytest.raises(asyncio.CancelledError):
        async with hub.span("request", source="test"):
            raise asyncio.CancelledError

    record = (await sink.snapshot()).records[0]
    assert isinstance(record, SpanRecord)
    assert record.status is SpanStatus.CANCELLED
    assert record.exception_type == "CancelledError"


@pytest.mark.asyncio
async def test_logs_inside_span_inherit_correlation_and_causation() -> None:
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))

    async with hub.span("request", source="test") as span:
        report = await hub.log("inside", source="test", message="inside")
        log = report.observation
        assert isinstance(log, LogRecord)
        assert log.correlation_id == span.context.correlation_id
        assert log.causation_id == span.context.span_id


@pytest.mark.asyncio
async def test_span_instance_cannot_be_reentered() -> None:
    hub = ObservabilityHub((InMemorySink(),))
    span = hub.span("request", source="test")

    with pytest.raises(SpanStateError, match="available"):
        _ = span.context

    async with span:
        pass

    with pytest.raises(SpanStateError, match="more than once"):
        async with span:
            pass


@pytest.mark.asyncio
async def test_sink_failure_does_not_mask_body_exception() -> None:
    class FailingSink:
        async def emit(self, observation: Observation) -> None:
            del observation
            raise RuntimeError("export failed")

    hub = ObservabilityHub((FailingSink(),))
    with pytest.raises(ValueError, match="body failed"):
        async with hub.span(
            "request",
            source="test",
            error_policy=ExportErrorPolicy.RAISE,
        ):
            raise ValueError("body failed")


@pytest.mark.asyncio
async def test_raise_policy_applies_when_successful_span_export_fails() -> None:
    class FailingSink:
        async def emit(self, observation: Observation) -> None:
            del observation
            raise RuntimeError("export failed")

    hub = ObservabilityHub((FailingSink(),))
    with pytest.raises(ObservationExportError):
        async with hub.span(
            "request",
            source="test",
            error_policy=ExportErrorPolicy.RAISE,
        ):
            pass
