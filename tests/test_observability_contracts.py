from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import uuid4

import pytest

from phoenix_os import (
    LogRecord,
    MetricKind,
    MetricRecord,
    Severity,
    SpanContext,
    SpanRecord,
    SpanStatus,
)


def test_log_record_normalizes_and_freezes_attributes() -> None:
    record = LogRecord(
        " system.ready ",
        " phoenix.test ",
        " ready ",
        severity=Severity.INFO,
        attributes={"nested": {"values": [1, 2]}},
        correlation_id=" corr-1 ",
    )

    assert record.name == "system.ready"
    assert record.source == "phoenix.test"
    assert record.message == "ready"
    assert record.correlation_id == "corr-1"
    assert isinstance(record.attributes, MappingProxyType)
    nested = record.attributes["nested"]
    assert isinstance(nested, MappingProxyType)
    assert nested["values"] == (1, 2)

    with pytest.raises(TypeError):
        record.attributes["new"] = 1  # type: ignore[index]


def test_log_record_rejects_blank_fields_and_naive_time() -> None:
    with pytest.raises(ValueError, match="log name"):
        LogRecord(" ", "source", "message")
    with pytest.raises(ValueError, match="log source"):
        LogRecord("name", " ", "message")
    with pytest.raises(ValueError, match="log message"):
        LogRecord("name", "source", " ")
    with pytest.raises(ValueError, match="timezone-aware"):
        LogRecord("name", "source", "message", occurred_at=datetime.now())


def test_observation_attributes_reject_sets_as_nondeterministic() -> None:
    with pytest.raises(TypeError, match="set values"):
        LogRecord("name", "source", "message", attributes={"bad": {1, 2}})


def test_metric_record_validates_numeric_semantics() -> None:
    metric = MetricRecord(
        "requests.total",
        "phoenix.test",
        2,
        kind=MetricKind.COUNTER,
        unit=" request ",
    )
    assert metric.value == 2
    assert metric.unit == "request"

    with pytest.raises(TypeError, match="integer or float"):
        MetricRecord("bad", "test", True)
    with pytest.raises(ValueError, match="finite"):
        MetricRecord("bad", "test", float("inf"))
    with pytest.raises(ValueError, match="must not be negative"):
        MetricRecord("bad", "test", -1, kind=MetricKind.COUNTER)


def test_span_context_normalizes_correlation_id() -> None:
    context = SpanContext(correlation_id=" corr ")
    assert context.correlation_id == "corr"

    with pytest.raises(ValueError, match="correlation_id"):
        SpanContext(correlation_id=" ")


def test_span_record_exposes_duration_and_relationships() -> None:
    started = datetime.now(UTC)
    parent = uuid4()
    context = SpanContext(parent_span_id=parent, correlation_id="corr")
    record = SpanRecord(
        "request",
        "phoenix.test",
        context,
        SpanStatus.OK,
        started,
        started + timedelta(milliseconds=250),
    )

    assert record.duration_seconds == pytest.approx(0.25)
    assert record.correlation_id == "corr"
    assert record.causation_id == parent


def test_span_record_rejects_invalid_times() -> None:
    started = datetime.now(UTC)
    context = SpanContext()

    with pytest.raises(ValueError, match="ended_at"):
        SpanRecord(
            "request",
            "test",
            context,
            SpanStatus.OK,
            started,
            started - timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        SpanRecord(
            "request",
            "test",
            context,
            SpanStatus.OK,
            datetime.now(),
            started,
        )
