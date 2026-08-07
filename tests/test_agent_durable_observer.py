from dataclasses import fields
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointId,
    CheckpointPayloadProfile,
    CheckpointSequence,
    DurableAgentRunId,
    DurableRunStatus,
    FencingGeneration,
)
from phoenix_os.agent.durable_observer import (
    ContentFreeDurableRunObserver,
    DurableRunObservation,
    DurableRunObservationOutcome,
    DurableRunObserver,
    DurableRunOperation,
    NullDurableRunObserver,
)
from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.observability import InMemorySink, MetricRecord, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 7, 12, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
CHECKPOINT_ID = CheckpointId(UUID("20000000-0000-0000-0000-000000000002"))


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
    )


def _context(
    *,
    secret: str | None = None,
    correlation_id: str = "corr-durable-observer",
    causation_id: UUID | None = None,
) -> SecurityContext:
    attributes: dict[str, str] = {}
    if secret is not None:
        attributes["untrusted-content"] = secret

    return SecurityContext(
        principal="service:durable-worker",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id=correlation_id,
        causation_id=causation_id,
        attributes=attributes,
    )


def _observation() -> DurableRunObservation:
    return DurableRunObservation(
        operation=DurableRunOperation.CHECKPOINT,
        outcome=DurableRunObservationOutcome.SUCCEEDED,
        run_id=DURABLE_RUN_ID,
        status=DurableRunStatus.ACTIVE,
        checkpoint_id=CHECKPOINT_ID,
        sequence=CheckpointSequence(2),
        fencing_generation=FencingGeneration(3),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
        checkpoint_digest=CheckpointDigest("a" * 64),
        duration_ms=17,
        category="safe-boundary",
        error_code="checkpoint.accepted",
    )


def test_durable_observation_contract_is_typed_content_free_and_runtime_checkable() -> None:
    observation = _observation()

    assert observation.name == "agent.durable.checkpoint.succeeded"
    assert observation.metadata() == {
        "run_id": str(DURABLE_RUN_ID),
        "operation": "checkpoint",
        "outcome": "succeeded",
        "status": "active",
        "checkpoint_id": str(CHECKPOINT_ID),
        "sequence": 2,
        "fencing_generation": 3,
        "payload_profile": "metadata_only",
        "checkpoint_digest": "a" * 64,
        "duration_ms": 17,
        "category": "safe-boundary",
        "error_code": "checkpoint.accepted",
    }

    forbidden_fields = {
        "prompt",
        "response",
        "arguments",
        "result",
        "protected_payload",
        "plaintext",
        "ciphertext",
        "credential",
        "secret",
        "secret_reference",
        "approval_token",
        "endpoint",
        "external_response",
        "evidence",
        "exception",
    }
    contract_fields = {item.name for item in fields(DurableRunObservation)}

    assert forbidden_fields.isdisjoint(contract_fields)
    assert isinstance(NullDurableRunObserver(), DurableRunObserver)

    with pytest.raises(ValueError, match="safe bounded identifier"):
        DurableRunObservation(
            operation=DurableRunOperation.CHECKPOINT,
            outcome=DurableRunObservationOutcome.REJECTED,
            run_id=DURABLE_RUN_ID,
            category="TOP SECRET CONTENT",
        )


@pytest.mark.asyncio
async def test_content_free_durable_observer_emits_empty_payload_without_sensitive_content() -> (
    None
):
    secret = "TOP-SECRET-DURABLE-CONTENT-4E"
    configuration = _configuration()
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.durable."):
            captured.append(event)

    await events.subscribe("*", capture)

    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)

    sink = InMemorySink(capacity=100)
    observability = ObservabilityHub((sink,))

    observer = ContentFreeDurableRunObserver(
        configuration,
        events=events,
        audit=audit,
        observability=observability,
    )

    assert isinstance(observer, DurableRunObserver)

    caller_causation_id = UUID("30000000-0000-0000-0000-000000000003")

    await observer.record(
        _observation(),
        _context(
            secret=secret,
            correlation_id=secret,
            causation_id=caller_causation_id,
        ),
    )

    assert len(captured) == 1
    assert captured[0].name == "agent.durable.checkpoint.succeeded"
    assert captured[0].payload == {}
    assert captured[0].metadata["run_id"] == str(DURABLE_RUN_ID)

    audit_records = await audit_store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records

    assert captured[0].correlation_id == str(DURABLE_RUN_ID)
    assert captured[0].causation_id == CHECKPOINT_ID.value

    assert len(audit_records) == 1
    assert audit_records[0].event.correlation_id == str(DURABLE_RUN_ID)
    assert audit_records[0].event.causation_id == CHECKPOINT_ID.value

    for record in observations:
        assert record.correlation_id == str(DURABLE_RUN_ID)
        assert record.causation_id == CHECKPOINT_ID.value

    serialized = repr(
        (
            captured,
            audit_records,
            observations,
        )
    )

    assert secret not in serialized
    assert "TOP SECRET CONTENT" not in serialized

    metrics = tuple(record for record in observations if isinstance(record, MetricRecord))

    assert metrics
    for metric in metrics:
        assert "run_id" not in metric.attributes
        assert "checkpoint_id" not in metric.attributes
        assert "checkpoint_digest" not in metric.attributes


class _FailingObservationSink:
    def emit(self, observation: object) -> None:
        del observation
        raise RuntimeError("synthetic durable observability exporter failure")


@pytest.mark.asyncio
async def test_durable_observer_is_best_effort_and_reports_content_free_health() -> None:
    secret = "TOP-SECRET-DURABLE-HEALTH-4E"

    events = EventBus()

    async def fail_event(event: Event) -> None:
        del event
        raise RuntimeError("synthetic durable event handler failure")

    await events.subscribe("*", fail_event)

    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)
    await audit.close()

    observability = ObservabilityHub((_FailingObservationSink(),))

    observer = ContentFreeDurableRunObserver(
        _configuration(),
        events=events,
        audit=audit,
        observability=observability,
    )

    # Delivery failures are diagnostic only and must never change
    # the authoritative durable operation outcome.
    await observer.record(
        _observation(),
        _context(secret=secret),
    )

    snapshot = await observer.snapshot()

    assert snapshot.observations == 1
    assert snapshot.event_failures == 1
    assert snapshot.audit_failures == 1
    assert snapshot.observability_failures == 1
    assert snapshot.degraded is True
    assert secret not in repr(snapshot)


@pytest.mark.asyncio
async def test_null_durable_observer_reports_empty_healthy_snapshot() -> None:
    observer = NullDurableRunObserver()

    snapshot = await observer.snapshot()

    assert snapshot.observations == 0
    assert snapshot.event_failures == 0
    assert snapshot.audit_failures == 0
    assert snapshot.observability_failures == 0
    assert snapshot.degraded is False
