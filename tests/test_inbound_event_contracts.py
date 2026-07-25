from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.inbound_events import (
    MAX_INBOUND_REPLAY_RETENTION,
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundAuthenticationMode,
    InboundCorruptionError,
    InboundEventReceipt,
    InboundEventSchema,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundPersistenceError,
    InboundPublicationOutcome,
    InboundPublicationRetryPolicy,
    InboundPublicationStatus,
    InboundReplayKind,
    InboundReplayReservation,
    InboundRequestEvidence,
    InboundSchemaError,
    InboundServiceAccountPolicy,
    PhoenixInboundEventError,
    canonical_inbound_json_bytes,
    inbound_evidence_digest,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000026")
_RECEIPT_ID = UUID("00000000-0000-4000-8000-000000000027")


def _hmac_policy() -> InboundHmacPolicy:
    return InboundHmacPolicy(SecretRef("inbound-key", "integrations", 2))


def _source() -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=_hmac_policy(),
        event_types=frozenset({"build.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:arthur",
    )


def _event() -> InboundAcceptedEvent:
    payload = {"build_id": "build-25", "successful": True, "labels": ["release"]}
    digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    return InboundAcceptedEvent(
        id=_EVENT_ID,
        receipt_id=_RECEIPT_ID,
        source_id=_SOURCE_ID,
        source_event_id="external-event-25",
        external_event_type="build.completed",
        external_schema_version=1,
        internal_event_type="external.build.completed",
        occurred_at=_NOW,
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=payload,
        normalized_payload_sha256=digest,
        next_attempt_at=_NOW,
    )


def _receipt() -> InboundEventReceipt:
    return InboundEventReceipt(
        id=_RECEIPT_ID,
        accepted_event_id=_EVENT_ID,
        source_id=_SOURCE_ID,
        source_event_id="external-event-25",
        external_event_type="build.completed",
        external_schema_version=1,
        accepted_at=_NOW,
    )


def _reservations() -> tuple[InboundReplayReservation, ...]:
    event = _event()
    return tuple(
        InboundReplayReservation(
            source_id=_SOURCE_ID,
            kind=kind,
            evidence_digest=inbound_evidence_digest(
                _SOURCE_ID,
                kind,
                {
                    InboundReplayKind.REQUEST_ID: "request-25",
                    InboundReplayKind.NONCE: "nonce-25",
                    InboundReplayKind.SOURCE_EVENT_ID: "external-event-25",
                }[kind],
            ),
            accepted_event_id=_EVENT_ID,
            created_at=_NOW,
            expires_at=_NOW + timedelta(hours=1),
            normalized_payload_sha256=(
                event.normalized_payload_sha256
                if kind is InboundReplayKind.SOURCE_EVENT_ID
                else None
            ),
        )
        for kind in InboundReplayKind
    )


def test_source_status_exposes_acceptance_eligibility() -> None:
    assert InboundEventSourceStatus.ACTIVE.accepting is True
    assert InboundEventSourceStatus.DISABLED.accepting is False
    assert InboundEventSourceStatus.REVOKED.accepting is False


def test_publication_status_exposes_terminal_and_schedulable_states() -> None:
    assert InboundPublicationStatus.PENDING.schedulable is True
    assert InboundPublicationStatus.RETRYING.schedulable is True
    assert InboundPublicationStatus.PUBLISHING.schedulable is False
    assert InboundPublicationStatus.PUBLISHED.terminal is True
    assert InboundPublicationStatus.DEAD_LETTER.terminal is True
    assert InboundPublicationStatus.DISCARDED.terminal is True


def test_hmac_policy_requires_exact_versioned_secret_reference() -> None:
    with pytest.raises(ValueError, match="exact version"):
        InboundHmacPolicy(SecretRef("inbound-key", "integrations"))

    policy = _hmac_policy()

    assert policy.mode is InboundAuthenticationMode.HMAC_SHA256
    assert policy.key_version == 2


def test_hmac_policy_validates_bounded_predecessor_overlap() -> None:
    current = SecretRef("inbound-key", "integrations", 3)
    predecessor = SecretRef("inbound-key", "integrations", 2)
    policy = InboundHmacPolicy(
        current,
        predecessor_secret_ref=predecessor,
        predecessor_valid_until=_NOW + timedelta(minutes=5),
    )

    assert policy.predecessor_secret_ref == predecessor

    with pytest.raises(ValueError, match="another version"):
        InboundHmacPolicy(
            current,
            predecessor_secret_ref=current,
            predecessor_valid_until=_NOW + timedelta(minutes=5),
        )


def test_service_account_policy_is_exact_and_deny_by_default() -> None:
    policy = InboundServiceAccountPolicy("inbound-source:release.events")

    assert policy.mode is InboundAuthenticationMode.SERVICE_ACCOUNT
    assert policy.required_action == "inbound_event.submit"
    assert policy.resource == "inbound-source:release.events"

    with pytest.raises(ValueError, match=r"must be inbound_event\.submit"):
        InboundServiceAccountPolicy(
            "inbound-source:release.events",
            required_action="inbound_event.admin",
        )


def test_source_normalizes_names_and_preserves_bounded_configuration() -> None:
    source = InboundEventSource(
        id=_SOURCE_ID,
        name=" Release.Events ",
        display_name="  Release   Events  ",
        authentication=_hmac_policy(),
        event_types=frozenset({" Build.Completed "}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by=" maintainer:arthur ",
    )

    assert source.name == "release.events"
    assert source.display_name == "Release Events"
    assert source.event_types == frozenset({"build.completed"})
    assert source.accepting is True


def test_source_lifecycle_rejects_inconsistent_timestamps() -> None:
    with pytest.raises(ValueError, match="requires only disabled_at"):
        InboundEventSource(
            id=_SOURCE_ID,
            name="release.events",
            display_name="Release Events",
            authentication=_hmac_policy(),
            event_types=frozenset({"build.completed"}),
            created_at=_NOW,
            updated_at=_NOW,
            created_by="maintainer:arthur",
            status=InboundEventSourceStatus.DISABLED,
        )


def test_event_schema_normalizes_allowlisted_fields() -> None:
    schema = InboundEventSchema(
        event_type=" Build.Completed ",
        event_schema_version=2,
        internal_event_type=" External.Build.Completed ",
        required_fields=frozenset({" Build_ID "}),
        optional_fields=frozenset({" Labels "}),
    )

    assert schema.event_type == "build.completed"
    assert schema.internal_event_type == "external.build.completed"
    assert schema.allowed_fields == frozenset({"build_id", "labels"})


def test_event_schema_rejects_overlapping_or_unbounded_fields() -> None:
    with pytest.raises(ValueError, match="disjoint"):
        InboundEventSchema(
            event_type="build.completed",
            event_schema_version=1,
            internal_event_type="external.build.completed",
            required_fields=frozenset({"build_id"}),
            optional_fields=frozenset({"build_id"}),
        )

    with pytest.raises(ValueError, match="max_json_depth"):
        InboundEventSchema(
            event_type="build.completed",
            event_schema_version=1,
            internal_event_type="external.build.completed",
            max_json_depth=0,
        )


def test_retry_policy_is_deterministic_and_bounded() -> None:
    policy = InboundPublicationRetryPolicy(
        max_attempts=5,
        initial_delay=timedelta(seconds=2),
        multiplier=3,
        max_delay=timedelta(seconds=10),
    )

    assert policy.delay_after(1) == timedelta(seconds=2)
    assert policy.delay_after(2) == timedelta(seconds=6)
    assert policy.delay_after(3) == timedelta(seconds=10)
    assert policy.delay_after(4) == timedelta(seconds=10)

    with pytest.raises(ValueError):
        InboundPublicationRetryPolicy(multiplier=math.inf)


def test_request_evidence_redacts_nonce_and_request_identifier() -> None:
    evidence = InboundRequestEvidence(
        source_id=_SOURCE_ID,
        request_id="request-secret",
        source_event_id="external-event-25",
        nonce="nonce-secret",
        timestamp=_NOW,
        body_sha256="a" * 64,
    )

    rendered = repr(evidence)
    assert "request-secret" not in rendered
    assert "nonce-secret" not in rendered
    assert rendered.count("<redacted>") == 2


def test_accepted_event_payload_is_deeply_immutable_and_redacted() -> None:
    original: dict[str, object] = {
        "build_id": "build-25",
        "metadata": {"labels": ["release", "stable"]},
    }
    digest = hashlib.sha256(canonical_inbound_json_bytes(original)).hexdigest()
    event = InboundAcceptedEvent(
        id=_EVENT_ID,
        receipt_id=_RECEIPT_ID,
        source_id=_SOURCE_ID,
        source_event_id="external-event-25",
        external_event_type="build.completed",
        external_schema_version=1,
        internal_event_type="external.build.completed",
        occurred_at=_NOW,
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=original,
        normalized_payload_sha256=digest,
        next_attempt_at=_NOW,
    )

    original["build_id"] = "changed"
    metadata = cast(MappingProxyType[str, object], event.normalized_payload["metadata"])

    assert isinstance(event.normalized_payload, MappingProxyType)
    assert event.normalized_payload["build_id"] == "build-25"
    assert metadata["labels"] == ("release", "stable")
    assert "release" not in repr(event)

    mutable = cast(Any, event.normalized_payload)
    with pytest.raises(TypeError):
        mutable["new"] = "value"


def test_accepted_event_rejects_digest_mismatch_and_nonfinite_payload() -> None:
    with pytest.raises(ValueError, match="does not match"):
        InboundAcceptedEvent(
            id=_EVENT_ID,
            receipt_id=_RECEIPT_ID,
            source_id=_SOURCE_ID,
            source_event_id="external-event-25",
            external_event_type="build.completed",
            external_schema_version=1,
            internal_event_type="external.build.completed",
            occurred_at=_NOW,
            accepted_at=_NOW,
            updated_at=_NOW,
            normalized_payload={"build_id": "build-25"},
            normalized_payload_sha256="0" * 64,
            next_attempt_at=_NOW,
        )

    with pytest.raises(ValueError, match="non-finite"):
        canonical_inbound_json_bytes({"value": math.inf})


def test_replay_reservation_persists_only_source_scoped_digests() -> None:
    digest = inbound_evidence_digest(_SOURCE_ID, InboundReplayKind.NONCE, "nonce-secret")
    reservation = InboundReplayReservation(
        source_id=_SOURCE_ID,
        kind=InboundReplayKind.NONCE,
        evidence_digest=digest,
        accepted_event_id=_EVENT_ID,
        created_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )

    assert reservation.evidence_digest != "nonce-secret"
    assert len(reservation.evidence_digest) == 64

    with pytest.raises(ValueError, match="retention"):
        InboundReplayReservation(
            source_id=_SOURCE_ID,
            kind=InboundReplayKind.NONCE,
            evidence_digest=digest,
            accepted_event_id=_EVENT_ID,
            created_at=_NOW,
            expires_at=_NOW + MAX_INBOUND_REPLAY_RETENTION + timedelta(seconds=1),
        )


def test_atomic_acceptance_requires_all_three_replay_kinds() -> None:
    acceptance = InboundAcceptance(
        event=_event(),
        receipt=_receipt(),
        replay_reservations=_reservations(),
    )

    assert {item.kind for item in acceptance.replay_reservations} == set(InboundReplayKind)

    with pytest.raises(ValueError, match="requires request, nonce, and source-event"):
        InboundAcceptance(
            event=_event(),
            receipt=_receipt(),
            replay_reservations=_reservations()[:2],
        )


def test_error_hierarchy_preserves_persistence_context() -> None:
    assert issubclass(InboundPersistenceError, PhoenixInboundEventError)
    assert issubclass(InboundCorruptionError, InboundPersistenceError)
    assert issubclass(InboundSchemaError, InboundCorruptionError)
    assert InboundPublicationOutcome.SUCCEEDED.value == "succeeded"
