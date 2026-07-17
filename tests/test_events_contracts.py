from datetime import UTC, datetime
from uuid import uuid4

import pytest

from phoenix_os.events import DispatchReport, Event


def test_event_copies_and_freezes_payload() -> None:
    payload: dict[str, object] = {"count": 1}
    event = Event(name="sample", source="test", payload=payload)
    payload["count"] = 2

    assert event.payload["count"] == 1
    with pytest.raises(TypeError):
        event.payload["count"] = 3  # type: ignore[index]


def test_event_copies_and_freezes_metadata() -> None:
    metadata = {"tenant": "alpha"}
    event = Event(name="sample", source="test", metadata=metadata)
    metadata["tenant"] = "beta"

    assert event.metadata["tenant"] == "alpha"
    with pytest.raises(TypeError):
        event.metadata["tenant"] = "gamma"  # type: ignore[index]


@pytest.mark.parametrize("name", ["", "   "])
def test_event_rejects_blank_name(name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        Event(name=name, source="test")


@pytest.mark.parametrize("source", ["", "   "])
def test_event_rejects_blank_source(source: str) -> None:
    with pytest.raises(ValueError, match="source"):
        Event(name="sample", source=source)


def test_event_requires_timezone_aware_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Event(name="sample", source="test", occurred_at=datetime(2026, 7, 17))


def test_event_preserves_correlation_and_causation() -> None:
    cause = uuid4()
    event = Event(
        name="sample",
        source="test",
        correlation_id="corr-1",
        causation_id=cause,
        occurred_at=datetime(2026, 7, 17, tzinfo=UTC),
    )

    assert event.correlation_id == "corr-1"
    assert event.causation_id == cause


def test_dispatch_report_succeeded_property() -> None:
    event = Event(name="sample", source="test")
    report = DispatchReport(event=event, matched=0, delivered=0, failures=())

    assert report.succeeded is True
