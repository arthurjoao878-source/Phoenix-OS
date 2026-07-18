from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from phoenix_os import (
    AUDIT_GENESIS_DIGEST,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditRecord,
    AuditSeal,
    AuditSeverity,
    AuditStoreSnapshot,
    AuditVerification,
    KeyRef,
    SecretValue,
    canonical_audit_bytes,
    compute_audit_digest,
)


def event(**overrides: object) -> AuditEvent:
    values: dict[str, object] = {
        "name": "policy.evaluated",
        "source": "phoenix.policy",
        "category": AuditCategory.AUTHORIZATION,
        "action": "state.read",
        "resource": "state:profile/arthur",
        "actor": "arthur",
        "details": {"safe": 1},
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    values.update(overrides)
    return AuditEvent(**values)  # type: ignore[arg-type]


def test_audit_event_normalizes_and_redacts_details() -> None:
    audit_event = event(
        name=" Policy.Evaluated ",
        source=" Phoenix.Policy ",
        action=" STATE.READ ",
        details={
            "password": "never-store",
            "nested": {"api_token": "never-store-too"},
            "value": SecretValue("hidden"),
        },
    )

    assert audit_event.name == "policy.evaluated"
    assert audit_event.source == "phoenix.policy"
    assert audit_event.action == "state.read"
    assert audit_event.details["password"] == "***"
    assert audit_event.details["value"] == "***"
    nested = audit_event.details["nested"]
    assert nested["api_token"] == "***"  # type: ignore[index]
    assert "never-store" not in repr(audit_event)


def test_audit_event_is_immutable_and_validates_fields() -> None:
    audit_event = event()
    with pytest.raises(FrozenInstanceError):
        audit_event.actor = "other"  # type: ignore[misc]
    with pytest.raises(ValueError, match="event name"):
        event(name="not valid!")
    with pytest.raises(ValueError, match="timezone-aware"):
        event(occurred_at=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="audit actor"):
        event(actor=" ")


def test_audit_seal_hides_signature_and_validates_it() -> None:
    seal = AuditSeal(KeyRef("audit", "kms", 2), " Ed25519 ", b"signature")
    assert seal.algorithm == "ed25519"
    assert seal.signature == b"signature"
    assert "signature" not in repr(seal)
    with pytest.raises(ValueError, match="must not be empty"):
        AuditSeal(KeyRef("audit"), "external", b"")


def test_canonical_digest_is_stable_and_sensitive_to_chain_fields() -> None:
    audit_event = event(details={"b": 2, "a": 1})
    recorded_at = datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)
    first = compute_audit_digest(
        audit_event,
        sequence=1,
        recorded_at=recorded_at,
        previous_digest=AUDIT_GENESIS_DIGEST,
    )
    second = compute_audit_digest(
        audit_event,
        sequence=1,
        recorded_at=recorded_at,
        previous_digest=AUDIT_GENESIS_DIGEST,
    )
    changed = compute_audit_digest(
        audit_event,
        sequence=2,
        recorded_at=recorded_at,
        previous_digest=AUDIT_GENESIS_DIGEST,
    )

    assert first == second
    assert first != changed
    assert len(first) == 64
    canonical = canonical_audit_bytes(
        audit_event,
        sequence=1,
        recorded_at=recorded_at,
        previous_digest=AUDIT_GENESIS_DIGEST,
    )
    assert canonical.index(b'"a":1') < canonical.index(b'"b":2')


def test_audit_record_validates_sequence_timestamp_and_digests() -> None:
    audit_event = event()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    digest = compute_audit_digest(
        audit_event,
        sequence=1,
        recorded_at=now,
        previous_digest=AUDIT_GENESIS_DIGEST,
    )
    record = AuditRecord(audit_event, 1, now, AUDIT_GENESIS_DIGEST, digest)
    assert record.sequence == 1
    with pytest.raises(ValueError, match="positive"):
        AuditRecord(audit_event, 0, now, AUDIT_GENESIS_DIGEST, digest)
    with pytest.raises(ValueError, match="timezone-aware"):
        AuditRecord(audit_event, 1, datetime(2026, 1, 1), AUDIT_GENESIS_DIGEST, digest)
    with pytest.raises(ValueError, match="SHA-256"):
        AuditRecord(audit_event, 1, now, "bad", digest)


def test_audit_query_filters_exact_values_and_validates_bounds() -> None:
    audit_event = event(outcome=AuditOutcome.DENIED)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    digest = compute_audit_digest(
        audit_event,
        sequence=4,
        recorded_at=now,
        previous_digest=AUDIT_GENESIS_DIGEST,
    )
    record = AuditRecord(audit_event, 4, now, AUDIT_GENESIS_DIGEST, digest)
    query = AuditQuery(
        start_sequence=3,
        end_sequence=5,
        categories=frozenset({AuditCategory.AUTHORIZATION}),
        outcomes=frozenset({AuditOutcome.DENIED}),
        sources=frozenset({"PHOENIX.POLICY"}),
        actors=frozenset({"arthur"}),
        actions=frozenset({"STATE.READ"}),
    )
    assert query.matches(record)
    assert not AuditQuery(start_sequence=5).matches(record)
    with pytest.raises(ValueError, match="start_sequence"):
        AuditQuery(start_sequence=0)
    with pytest.raises(ValueError, match="end_sequence"):
        AuditQuery(start_sequence=5, end_sequence=4)
    with pytest.raises(ValueError, match="between 1 and 1000"):
        AuditQuery(limit=1001)


def test_verification_and_store_snapshot_validate_invariants() -> None:
    valid = AuditVerification(True, 0, AUDIT_GENESIS_DIGEST)
    assert valid.valid
    invalid = AuditVerification(
        False,
        1,
        AUDIT_GENESIS_DIGEST,
        first_sequence=1,
        last_sequence=1,
        failure_sequence=1,
        reason="broken",
    )
    assert invalid.reason == "broken"
    with pytest.raises(ValueError, match="failure details"):
        AuditVerification(
            True,
            1,
            AUDIT_GENESIS_DIGEST,
            first_sequence=1,
            last_sequence=1,
            failure_sequence=1,
        )
    snapshot = AuditStoreSnapshot(False, 0, None, AUDIT_GENESIS_DIGEST, 0)
    assert snapshot.records == 0
    with pytest.raises(ValueError, match="head sequence"):
        AuditStoreSnapshot(False, 0, 1, AUDIT_GENESIS_DIGEST, 0)


def test_audit_event_preserves_correlation_and_causation() -> None:
    cause = uuid4()
    audit_event = event(correlation_id=" corr-1 ", causation_id=cause)
    assert audit_event.correlation_id == "corr-1"
    assert audit_event.causation_id == cause
    assert audit_event.severity is AuditSeverity.INFO
