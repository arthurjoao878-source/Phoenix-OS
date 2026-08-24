from uuid import uuid4

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.network_egress import (
    ContentFreeNetworkEgressObserver,
    NetworkEgressObservabilityConfiguration,
    NetworkEgressOperationObservation,
    NetworkEgressOperationOutcome,
)
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-network-observer",
    )


@pytest.mark.asyncio
async def test_network_observer_emits_only_fixed_content_free_signals() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("network.http.request."):
            captured.append(event)

    await events.subscribe("*", capture)
    store = InMemoryAuditStore()
    audit = AuditLedger(store)
    sink = InMemorySink(capacity=100)
    observability = ObservabilityHub((sink,))
    observer = ContentFreeNetworkEgressObserver(
        NetworkEgressObservabilityConfiguration(),
        events=events,
        audit=audit,
        observability=observability,
    )
    request_id = uuid4()

    await observer.record(
        NetworkEgressOperationObservation(
            request_id=request_id,
            outcome=NetworkEgressOperationOutcome.STARTED,
            request_started=False,
        ),
        _context(),
    )
    await observer.record(
        NetworkEgressOperationObservation(
            request_id=request_id,
            outcome=NetworkEgressOperationOutcome.SUCCEEDED,
            request_started=True,
            duration_ms=7,
        ),
        _context(),
    )

    assert [event.name for event in captured] == [
        "network.http.request.started",
        "network.http.request.succeeded",
    ]
    assert all(event.payload == {} for event in captured)
    allowed_metadata = {
        "request_id",
        "action",
        "outcome",
        "request_started",
        "duration_ms",
    }
    assert all(set(event.metadata) <= allowed_metadata for event in captured)

    records = await store.read(AuditQuery(limit=100))
    observations = (await sink.snapshot()).records
    serialized = repr((captured, records, observations)).lower()
    for forbidden in (
        "api.example.com",
        "/v1/private",
        "10.0.0.7",
        "authorization",
        "set-cookie",
        "top-secret-credential",
        "top-secret-body",
    ):
        assert forbidden not in serialized


def test_network_observation_contract_rejects_content_like_extra_fields() -> None:
    request_id = uuid4()
    with pytest.raises(TypeError):
        NetworkEgressOperationObservation(  # type: ignore[call-arg]
            request_id=request_id,
            outcome=NetworkEgressOperationOutcome.SUCCEEDED,
            request_started=True,
            duration_ms=1,
            host="api.example.com",
        )

    with pytest.raises(ValueError, match="successful"):
        NetworkEgressOperationObservation(
            request_id=request_id,
            outcome=NetworkEgressOperationOutcome.SUCCEEDED,
            request_started=False,
            duration_ms=1,
        )
