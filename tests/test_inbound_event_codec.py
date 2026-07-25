from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.inbound_events import (
    InboundAcceptedEvent,
    InboundCorruptionError,
    InboundEventReceipt,
    InboundEventSchema,
    InboundEventSource,
    InboundHmacPolicy,
    InboundReplayKind,
    InboundReplayReservation,
    InboundSchemaError,
    InboundServiceAccountPolicy,
    canonical_inbound_accepted_event_record_bytes,
    canonical_inbound_event_schema_record_bytes,
    canonical_inbound_json_bytes,
    canonical_inbound_receipt_record_bytes,
    canonical_inbound_replay_record_bytes,
    canonical_inbound_source_record_bytes,
    decode_inbound_accepted_event,
    decode_inbound_event_schema,
    decode_inbound_receipt,
    decode_inbound_replay,
    decode_inbound_source,
    encode_inbound_accepted_event,
    encode_inbound_event_schema,
    encode_inbound_receipt,
    encode_inbound_replay,
    encode_inbound_source,
    inbound_accepted_event_digest,
    inbound_event_schema_digest,
    inbound_evidence_digest,
    inbound_receipt_digest,
    inbound_replay_digest,
    inbound_source_digest,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000026")
_RECEIPT_ID = UUID("00000000-0000-4000-8000-000000000027")


def _source(*, service_account: bool = False) -> InboundEventSource:
    authentication = (
        InboundServiceAccountPolicy("inbound-source:release.events")
        if service_account
        else InboundHmacPolicy(
            SecretRef("inbound-key", "integrations", 3),
            predecessor_secret_ref=SecretRef("inbound-key", "integrations", 2),
            predecessor_valid_until=_NOW + timedelta(minutes=5),
        )
    )
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=authentication,
        event_types=frozenset({"build.completed", "build.failed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:arthur",
    )


def _schema() -> InboundEventSchema:
    return InboundEventSchema(
        event_type="build.completed",
        event_schema_version=2,
        internal_event_type="external.build.completed",
        required_fields=frozenset({"build_id", "successful"}),
        optional_fields=frozenset({"labels"}),
    )


def _event() -> InboundAcceptedEvent:
    payload = {
        "build_id": "build-25",
        "successful": True,
        "labels": ["release", "stable"],
    }
    digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    return InboundAcceptedEvent(
        id=_EVENT_ID,
        receipt_id=_RECEIPT_ID,
        source_id=_SOURCE_ID,
        source_event_id="external-event-25",
        external_event_type="build.completed",
        external_schema_version=2,
        internal_event_type="external.build.completed",
        occurred_at=_NOW,
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=payload,
        normalized_payload_sha256=digest,
        correlation_id="release-25",
        next_attempt_at=_NOW,
    )


def _receipt() -> InboundEventReceipt:
    return InboundEventReceipt(
        id=_RECEIPT_ID,
        accepted_event_id=_EVENT_ID,
        source_id=_SOURCE_ID,
        source_event_id="external-event-25",
        external_event_type="build.completed",
        external_schema_version=2,
        accepted_at=_NOW,
        correlation_id="release-25",
    )


def _replay() -> InboundReplayReservation:
    event = _event()
    return InboundReplayReservation(
        source_id=_SOURCE_ID,
        kind=InboundReplayKind.SOURCE_EVENT_ID,
        evidence_digest=inbound_evidence_digest(
            _SOURCE_ID,
            InboundReplayKind.SOURCE_EVENT_ID,
            "external-event-25",
        ),
        accepted_event_id=_EVENT_ID,
        created_at=_NOW,
        expires_at=_NOW + timedelta(days=1),
        normalized_payload_sha256=event.normalized_payload_sha256,
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _mutate_record(
    encoded: bytes,
    mutation: Callable[[dict[str, object]], None],
) -> bytes:
    envelope = json.loads(encoded.decode("utf-8"))
    record = envelope["record"]
    mutation(record)
    envelope["record_digest"] = hashlib.sha256(_canonical(record)).hexdigest()
    return _canonical(envelope)


@pytest.mark.parametrize("service_account", [False, True])
def test_source_codec_round_trip_is_deterministic(service_account: bool) -> None:
    source = _source(service_account=service_account)
    encoded = encode_inbound_source(source)

    assert decode_inbound_source(encoded) == source
    assert encode_inbound_source(decode_inbound_source(encoded)) == encoded
    assert (
        inbound_source_digest(source)
        == hashlib.sha256(canonical_inbound_source_record_bytes(source)).hexdigest()
    )


def test_event_schema_codec_round_trip_is_deterministic() -> None:
    schema = _schema()
    encoded = encode_inbound_event_schema(schema)

    assert decode_inbound_event_schema(encoded) == schema
    assert (
        inbound_event_schema_digest(schema)
        == hashlib.sha256(canonical_inbound_event_schema_record_bytes(schema)).hexdigest()
    )


def test_accepted_event_codec_round_trip_is_deterministic() -> None:
    event = _event()
    encoded = encode_inbound_accepted_event(event)

    decoded = decode_inbound_accepted_event(encoded)

    assert decoded == event
    assert encode_inbound_accepted_event(decoded) == encoded
    assert (
        inbound_accepted_event_digest(event)
        == hashlib.sha256(canonical_inbound_accepted_event_record_bytes(event)).hexdigest()
    )
    assert b"Authorization" not in encoded
    assert b"nonce" not in encoded
    assert b"signature" not in encoded


def test_receipt_codec_round_trip_is_deterministic() -> None:
    receipt = _receipt()
    encoded = encode_inbound_receipt(receipt)

    assert decode_inbound_receipt(encoded) == receipt
    assert (
        inbound_receipt_digest(receipt)
        == hashlib.sha256(canonical_inbound_receipt_record_bytes(receipt)).hexdigest()
    )


def test_replay_codec_round_trip_persists_only_digest_evidence() -> None:
    replay = _replay()
    encoded = encode_inbound_replay(replay)

    assert decode_inbound_replay(encoded) == replay
    assert (
        inbound_replay_digest(replay)
        == hashlib.sha256(canonical_inbound_replay_record_bytes(replay)).hexdigest()
    )
    assert b"external-event-25" not in encoded


@pytest.mark.parametrize(
    ("encoder", "decoder", "value"),
    [
        (encode_inbound_source, decode_inbound_source, _source()),
        (encode_inbound_event_schema, decode_inbound_event_schema, _schema()),
        (encode_inbound_accepted_event, decode_inbound_accepted_event, _event()),
        (encode_inbound_receipt, decode_inbound_receipt, _receipt()),
        (encode_inbound_replay, decode_inbound_replay, _replay()),
    ],
)
def test_codecs_reject_tampered_record_digests(
    encoder: Callable[[Any], bytes],
    decoder: Callable[[bytes], Any],
    value: Any,
) -> None:
    encoded = encoder(value)
    envelope = json.loads(encoded.decode("utf-8"))
    envelope["record_digest"] = "0" * 64

    with pytest.raises(InboundCorruptionError, match="digest"):
        decoder(_canonical(envelope))


def test_source_codec_rejects_unknown_fields_even_with_valid_digest() -> None:
    encoded = _mutate_record(
        encode_inbound_source(_source()),
        lambda record: record.__setitem__("plaintext_secret", "forbidden"),
    )

    with pytest.raises(InboundCorruptionError, match="fields"):
        decode_inbound_source(encoded)


def test_codec_rejects_unsupported_envelope_schema() -> None:
    envelope = json.loads(encode_inbound_receipt(_receipt()).decode("utf-8"))
    envelope["schema_version"] = 2

    with pytest.raises(InboundSchemaError, match="unsupported"):
        decode_inbound_receipt(_canonical(envelope))


def test_codec_rejects_noncanonical_json() -> None:
    encoded = encode_inbound_replay(_replay())
    decoded = json.loads(encoded.decode("utf-8"))
    pretty = json.dumps(decoded, indent=2).encode("utf-8")

    with pytest.raises(InboundCorruptionError, match="not canonical"):
        decode_inbound_replay(pretty)


def test_source_codec_contains_only_secret_reference_metadata() -> None:
    encoded = encode_inbound_source(_source())

    assert b"inbound-key" in encoded
    assert b"integrations" in encoded
    assert b"plaintext" not in encoded
    assert b"secret-value" not in encoded
