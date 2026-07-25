"""Strict schema-v1 codecs for durable inbound-event records."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from phoenix_os.inbound_events.contracts import (
    InboundAcceptedEvent,
    InboundEventReceipt,
    InboundEventSchema,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundHmacScheme,
    InboundPublicationAttempt,
    InboundPublicationOutcome,
    InboundPublicationRetryPolicy,
    InboundPublicationStatus,
    InboundReplayKind,
    InboundReplayReservation,
    InboundServiceAccountPolicy,
)
from phoenix_os.inbound_events.errors import InboundCorruptionError, InboundSchemaError
from phoenix_os.secrets import SecretRef

_SCHEMA_VERSION = 1
_SOURCE_KIND = "phoenix.inbound.source.record"
_EVENT_SCHEMA_KIND = "phoenix.inbound.event-schema.record"
_ACCEPTED_EVENT_KIND = "phoenix.inbound.accepted-event.record"
_RECEIPT_KIND = "phoenix.inbound.receipt.record"
_REPLAY_KIND = "phoenix.inbound.replay-reservation.record"

_MAX_SOURCE_DOCUMENT_BYTES = 262_144
_MAX_EVENT_SCHEMA_DOCUMENT_BYTES = 262_144
_MAX_ACCEPTED_EVENT_DOCUMENT_BYTES = 2_097_152
_MAX_RECEIPT_DOCUMENT_BYTES = 131_072
_MAX_REPLAY_DOCUMENT_BYTES = 131_072

_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record", "record_digest"})
_SOURCE_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "display_name",
        "authentication",
        "event_types",
        "created_at",
        "updated_at",
        "created_by",
        "max_body_bytes",
        "max_header_bytes",
        "timestamp_skew_microseconds",
        "replay_retention_microseconds",
        "max_concurrency",
        "requests_per_minute",
        "retry",
        "status",
        "disabled_at",
        "revoked_at",
        "revision",
    }
)
_AUTH_HMAC_FIELDS = frozenset(
    {
        "mode",
        "secret_ref",
        "scheme",
        "lease_ttl_microseconds",
        "predecessor_secret_ref",
        "predecessor_valid_until",
    }
)
_AUTH_SERVICE_ACCOUNT_FIELDS = frozenset({"mode", "required_action", "resource"})
_SECRET_REF_FIELDS = frozenset({"name", "namespace", "version"})
_RETRY_FIELDS = frozenset(
    {
        "max_attempts",
        "initial_delay_microseconds",
        "multiplier_hex",
        "max_delay_microseconds",
    }
)
_EVENT_SCHEMA_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "event_schema_version",
        "internal_event_type",
        "required_fields",
        "optional_fields",
        "max_raw_body_bytes",
        "max_normalized_payload_bytes",
        "max_json_depth",
        "max_mapping_items",
        "max_sequence_items",
        "max_string_length",
        "reject_unknown_fields",
    }
)
_ACCEPTED_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "receipt_id",
        "source_id",
        "source_event_id",
        "external_event_type",
        "external_schema_version",
        "internal_event_type",
        "occurred_at",
        "accepted_at",
        "updated_at",
        "normalized_payload",
        "normalized_payload_sha256",
        "status",
        "correlation_id",
        "attempts",
        "current_attempt",
        "publishing_at",
        "next_attempt_at",
        "terminal_at",
        "revision",
    }
)
_ATTEMPT_FIELDS = frozenset(
    {
        "schema_version",
        "accepted_event_id",
        "number",
        "scheduled_at",
        "started_at",
        "finished_at",
        "outcome",
        "retry_scheduled",
        "next_attempt_at",
        "error_category",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "accepted_event_id",
        "source_id",
        "source_event_id",
        "external_event_type",
        "external_schema_version",
        "accepted_at",
        "correlation_id",
    }
)
_REPLAY_FIELDS = frozenset(
    {
        "schema_version",
        "source_id",
        "kind",
        "evidence_digest",
        "accepted_event_id",
        "created_at",
        "expires_at",
        "normalized_payload_sha256",
    }
)


def canonical_inbound_source_record_bytes(source: InboundEventSource) -> bytes:
    """Return deterministic schema-v1 bytes for one source record."""

    if not isinstance(source, InboundEventSource):
        raise TypeError("source must be InboundEventSource")
    return _canonical_json_bytes(_source_record(source))


def inbound_source_digest(source: InboundEventSource) -> str:
    return hashlib.sha256(canonical_inbound_source_record_bytes(source)).hexdigest()


def encode_inbound_source(source: InboundEventSource) -> bytes:
    return _encode_envelope(_SOURCE_KIND, _source_record(source))


def decode_inbound_source(encoded: bytes) -> InboundEventSource:
    record = _decode_envelope(
        encoded,
        expected_kind=_SOURCE_KIND,
        maximum_bytes=_MAX_SOURCE_DOCUMENT_BYTES,
        label="source",
    )
    _require_exact_fields(record, _SOURCE_FIELDS, label="source record")
    _require_schema(record, label="source record")
    try:
        source = InboundEventSource(
            id=_uuid(record, "id"),
            name=_string(record, "name"),
            display_name=_string(record, "display_name"),
            authentication=_decode_authentication(
                _mapping(record.get("authentication"), label="source authentication")
            ),
            event_types=frozenset(
                _string_list(record.get("event_types"), label="source event types")
            ),
            created_at=_datetime(record, "created_at"),
            updated_at=_datetime(record, "updated_at"),
            created_by=_string(record, "created_by"),
            max_body_bytes=_integer(record, "max_body_bytes"),
            max_header_bytes=_integer(record, "max_header_bytes"),
            timestamp_skew=_timedelta(record, "timestamp_skew_microseconds"),
            replay_retention=_timedelta(record, "replay_retention_microseconds"),
            max_concurrency=_integer(record, "max_concurrency"),
            requests_per_minute=_integer(record, "requests_per_minute"),
            retry=_decode_retry(_mapping(record.get("retry"), label="source retry policy")),
            status=InboundEventSourceStatus(_string(record, "status")),
            disabled_at=_optional_datetime(record, "disabled_at"),
            revoked_at=_optional_datetime(record, "revoked_at"),
            revision=_integer(record, "revision"),
            schema_version=_integer(record, "schema_version"),
        )
    except (InboundCorruptionError, InboundSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InboundCorruptionError("persisted inbound source is invalid") from exception
    if _source_record(source) != record:
        raise InboundCorruptionError("persisted inbound source is not canonical")
    return source


def canonical_inbound_event_schema_record_bytes(schema: InboundEventSchema) -> bytes:
    if not isinstance(schema, InboundEventSchema):
        raise TypeError("schema must be InboundEventSchema")
    return _canonical_json_bytes(_event_schema_record(schema))


def inbound_event_schema_digest(schema: InboundEventSchema) -> str:
    return hashlib.sha256(canonical_inbound_event_schema_record_bytes(schema)).hexdigest()


def encode_inbound_event_schema(schema: InboundEventSchema) -> bytes:
    return _encode_envelope(_EVENT_SCHEMA_KIND, _event_schema_record(schema))


def decode_inbound_event_schema(encoded: bytes) -> InboundEventSchema:
    record = _decode_envelope(
        encoded,
        expected_kind=_EVENT_SCHEMA_KIND,
        maximum_bytes=_MAX_EVENT_SCHEMA_DOCUMENT_BYTES,
        label="event schema",
    )
    _require_exact_fields(record, _EVENT_SCHEMA_FIELDS, label="event schema record")
    _require_schema(record, label="event schema record")
    try:
        schema = InboundEventSchema(
            event_type=_string(record, "event_type"),
            event_schema_version=_integer(record, "event_schema_version"),
            internal_event_type=_string(record, "internal_event_type"),
            required_fields=frozenset(
                _string_list(record.get("required_fields"), label="required fields")
            ),
            optional_fields=frozenset(
                _string_list(record.get("optional_fields"), label="optional fields")
            ),
            max_raw_body_bytes=_integer(record, "max_raw_body_bytes"),
            max_normalized_payload_bytes=_integer(record, "max_normalized_payload_bytes"),
            max_json_depth=_integer(record, "max_json_depth"),
            max_mapping_items=_integer(record, "max_mapping_items"),
            max_sequence_items=_integer(record, "max_sequence_items"),
            max_string_length=_integer(record, "max_string_length"),
            reject_unknown_fields=_boolean(record, "reject_unknown_fields"),
            schema_version=_integer(record, "schema_version"),
        )
    except (InboundCorruptionError, InboundSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InboundCorruptionError("persisted inbound event schema is invalid") from exception
    if _event_schema_record(schema) != record:
        raise InboundCorruptionError("persisted inbound event schema is not canonical")
    return schema


def canonical_inbound_accepted_event_record_bytes(event: InboundAcceptedEvent) -> bytes:
    if not isinstance(event, InboundAcceptedEvent):
        raise TypeError("event must be InboundAcceptedEvent")
    return _canonical_json_bytes(_accepted_event_record(event))


def inbound_accepted_event_digest(event: InboundAcceptedEvent) -> str:
    return hashlib.sha256(canonical_inbound_accepted_event_record_bytes(event)).hexdigest()


def encode_inbound_accepted_event(event: InboundAcceptedEvent) -> bytes:
    return _encode_envelope(_ACCEPTED_EVENT_KIND, _accepted_event_record(event))


def decode_inbound_accepted_event(encoded: bytes) -> InboundAcceptedEvent:
    record = _decode_envelope(
        encoded,
        expected_kind=_ACCEPTED_EVENT_KIND,
        maximum_bytes=_MAX_ACCEPTED_EVENT_DOCUMENT_BYTES,
        label="accepted event",
    )
    _require_exact_fields(record, _ACCEPTED_EVENT_FIELDS, label="accepted event record")
    _require_schema(record, label="accepted event record")
    try:
        attempts = tuple(
            _decode_attempt(_mapping(item, label="publication attempt"))
            for item in _list(record.get("attempts"), label="publication attempts")
        )
        payload = _mapping(record.get("normalized_payload"), label="normalized payload")
        event = InboundAcceptedEvent(
            id=_uuid(record, "id"),
            receipt_id=_uuid(record, "receipt_id"),
            source_id=_uuid(record, "source_id"),
            source_event_id=_string(record, "source_event_id"),
            external_event_type=_string(record, "external_event_type"),
            external_schema_version=_integer(record, "external_schema_version"),
            internal_event_type=_string(record, "internal_event_type"),
            occurred_at=_datetime(record, "occurred_at"),
            accepted_at=_datetime(record, "accepted_at"),
            updated_at=_datetime(record, "updated_at"),
            normalized_payload=payload,
            normalized_payload_sha256=_string(record, "normalized_payload_sha256"),
            status=InboundPublicationStatus(_string(record, "status")),
            correlation_id=_optional_string(record, "correlation_id"),
            attempts=attempts,
            current_attempt=_optional_integer(record, "current_attempt"),
            publishing_at=_optional_datetime(record, "publishing_at"),
            next_attempt_at=_optional_datetime(record, "next_attempt_at"),
            terminal_at=_optional_datetime(record, "terminal_at"),
            revision=_integer(record, "revision"),
            schema_version=_integer(record, "schema_version"),
        )
    except (InboundCorruptionError, InboundSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InboundCorruptionError("persisted inbound accepted event is invalid") from exception
    if _accepted_event_record(event) != record:
        raise InboundCorruptionError("persisted inbound accepted event is not canonical")
    return event


def canonical_inbound_receipt_record_bytes(receipt: InboundEventReceipt) -> bytes:
    if not isinstance(receipt, InboundEventReceipt):
        raise TypeError("receipt must be InboundEventReceipt")
    return _canonical_json_bytes(_receipt_record(receipt))


def inbound_receipt_digest(receipt: InboundEventReceipt) -> str:
    return hashlib.sha256(canonical_inbound_receipt_record_bytes(receipt)).hexdigest()


def encode_inbound_receipt(receipt: InboundEventReceipt) -> bytes:
    return _encode_envelope(_RECEIPT_KIND, _receipt_record(receipt))


def decode_inbound_receipt(encoded: bytes) -> InboundEventReceipt:
    record = _decode_envelope(
        encoded,
        expected_kind=_RECEIPT_KIND,
        maximum_bytes=_MAX_RECEIPT_DOCUMENT_BYTES,
        label="receipt",
    )
    _require_exact_fields(record, _RECEIPT_FIELDS, label="receipt record")
    _require_schema(record, label="receipt record")
    try:
        receipt = InboundEventReceipt(
            id=_uuid(record, "id"),
            accepted_event_id=_uuid(record, "accepted_event_id"),
            source_id=_uuid(record, "source_id"),
            source_event_id=_string(record, "source_event_id"),
            external_event_type=_string(record, "external_event_type"),
            external_schema_version=_integer(record, "external_schema_version"),
            accepted_at=_datetime(record, "accepted_at"),
            correlation_id=_optional_string(record, "correlation_id"),
            schema_version=_integer(record, "schema_version"),
        )
    except (InboundCorruptionError, InboundSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InboundCorruptionError("persisted inbound receipt is invalid") from exception
    if _receipt_record(receipt) != record:
        raise InboundCorruptionError("persisted inbound receipt is not canonical")
    return receipt


def canonical_inbound_replay_record_bytes(reservation: InboundReplayReservation) -> bytes:
    if not isinstance(reservation, InboundReplayReservation):
        raise TypeError("reservation must be InboundReplayReservation")
    return _canonical_json_bytes(_replay_record(reservation))


def inbound_replay_digest(reservation: InboundReplayReservation) -> str:
    return hashlib.sha256(canonical_inbound_replay_record_bytes(reservation)).hexdigest()


def encode_inbound_replay(reservation: InboundReplayReservation) -> bytes:
    return _encode_envelope(_REPLAY_KIND, _replay_record(reservation))


def decode_inbound_replay(encoded: bytes) -> InboundReplayReservation:
    record = _decode_envelope(
        encoded,
        expected_kind=_REPLAY_KIND,
        maximum_bytes=_MAX_REPLAY_DOCUMENT_BYTES,
        label="replay reservation",
    )
    _require_exact_fields(record, _REPLAY_FIELDS, label="replay reservation record")
    _require_schema(record, label="replay reservation record")
    try:
        reservation = InboundReplayReservation(
            source_id=_uuid(record, "source_id"),
            kind=InboundReplayKind(_string(record, "kind")),
            evidence_digest=_string(record, "evidence_digest"),
            accepted_event_id=_uuid(record, "accepted_event_id"),
            created_at=_datetime(record, "created_at"),
            expires_at=_datetime(record, "expires_at"),
            normalized_payload_sha256=_optional_string(
                record,
                "normalized_payload_sha256",
            ),
            schema_version=_integer(record, "schema_version"),
        )
    except (InboundCorruptionError, InboundSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InboundCorruptionError(
            "persisted inbound replay reservation is invalid"
        ) from exception
    if _replay_record(reservation) != record:
        raise InboundCorruptionError("persisted inbound replay reservation is not canonical")
    return reservation


def _source_record(source: InboundEventSource) -> dict[str, object]:
    return {
        "schema_version": source.schema_version,
        "id": str(source.id),
        "name": source.name,
        "display_name": source.display_name,
        "authentication": _authentication_record(source.authentication),
        "event_types": sorted(source.event_types),
        "created_at": _format_datetime(source.created_at),
        "updated_at": _format_datetime(source.updated_at),
        "created_by": source.created_by,
        "max_body_bytes": source.max_body_bytes,
        "max_header_bytes": source.max_header_bytes,
        "timestamp_skew_microseconds": _timedelta_microseconds(source.timestamp_skew),
        "replay_retention_microseconds": _timedelta_microseconds(source.replay_retention),
        "max_concurrency": source.max_concurrency,
        "requests_per_minute": source.requests_per_minute,
        "retry": _retry_record(source.retry),
        "status": source.status.value,
        "disabled_at": _format_optional_datetime(source.disabled_at),
        "revoked_at": _format_optional_datetime(source.revoked_at),
        "revision": source.revision,
    }


def _authentication_record(
    policy: InboundHmacPolicy | InboundServiceAccountPolicy,
) -> dict[str, object]:
    if isinstance(policy, InboundHmacPolicy):
        return {
            "mode": policy.mode.value,
            "secret_ref": _secret_ref_record(policy.secret_ref),
            "scheme": policy.scheme.value,
            "lease_ttl_microseconds": _timedelta_microseconds(policy.lease_ttl),
            "predecessor_secret_ref": (
                None
                if policy.predecessor_secret_ref is None
                else _secret_ref_record(policy.predecessor_secret_ref)
            ),
            "predecessor_valid_until": _format_optional_datetime(policy.predecessor_valid_until),
        }
    return {
        "mode": policy.mode.value,
        "required_action": policy.required_action,
        "resource": policy.resource,
    }


def _decode_authentication(
    value: Mapping[str, object],
) -> InboundHmacPolicy | InboundServiceAccountPolicy:
    mode = _string(value, "mode")
    if mode == "hmac_sha256":
        _require_exact_fields(value, _AUTH_HMAC_FIELDS, label="HMAC authentication policy")
        predecessor_value = value.get("predecessor_secret_ref")
        predecessor = (
            None
            if predecessor_value is None
            else _decode_secret_ref(
                _mapping(predecessor_value, label="predecessor secret reference")
            )
        )
        return InboundHmacPolicy(
            secret_ref=_decode_secret_ref(
                _mapping(value.get("secret_ref"), label="secret reference")
            ),
            scheme=InboundHmacScheme(_string(value, "scheme")),
            lease_ttl=_timedelta(value, "lease_ttl_microseconds"),
            predecessor_secret_ref=predecessor,
            predecessor_valid_until=_optional_datetime(value, "predecessor_valid_until"),
        )
    if mode == "service_account":
        _require_exact_fields(
            value,
            _AUTH_SERVICE_ACCOUNT_FIELDS,
            label="service-account authentication policy",
        )
        return InboundServiceAccountPolicy(
            required_action=_string(value, "required_action"),
            resource=_string(value, "resource"),
        )
    raise InboundCorruptionError("persisted inbound authentication mode is unsupported")


def _secret_ref_record(reference: SecretRef) -> dict[str, object]:
    return {
        "name": reference.name,
        "namespace": reference.namespace,
        "version": reference.version,
    }


def _decode_secret_ref(value: Mapping[str, object]) -> SecretRef:
    _require_exact_fields(value, _SECRET_REF_FIELDS, label="secret reference")
    return SecretRef(
        name=_string(value, "name"),
        namespace=_string(value, "namespace"),
        version=_integer(value, "version"),
    )


def _retry_record(policy: InboundPublicationRetryPolicy) -> dict[str, object]:
    return {
        "max_attempts": policy.max_attempts,
        "initial_delay_microseconds": _timedelta_microseconds(policy.initial_delay),
        "multiplier_hex": policy.multiplier.hex(),
        "max_delay_microseconds": _timedelta_microseconds(policy.max_delay),
    }


def _decode_retry(value: Mapping[str, object]) -> InboundPublicationRetryPolicy:
    _require_exact_fields(value, _RETRY_FIELDS, label="retry policy")
    return InboundPublicationRetryPolicy(
        max_attempts=_integer(value, "max_attempts"),
        initial_delay=_timedelta(value, "initial_delay_microseconds"),
        multiplier=_hex_float(value, "multiplier_hex"),
        max_delay=_timedelta(value, "max_delay_microseconds"),
    )


def _event_schema_record(schema: InboundEventSchema) -> dict[str, object]:
    return {
        "schema_version": schema.schema_version,
        "event_type": schema.event_type,
        "event_schema_version": schema.event_schema_version,
        "internal_event_type": schema.internal_event_type,
        "required_fields": sorted(schema.required_fields),
        "optional_fields": sorted(schema.optional_fields),
        "max_raw_body_bytes": schema.max_raw_body_bytes,
        "max_normalized_payload_bytes": schema.max_normalized_payload_bytes,
        "max_json_depth": schema.max_json_depth,
        "max_mapping_items": schema.max_mapping_items,
        "max_sequence_items": schema.max_sequence_items,
        "max_string_length": schema.max_string_length,
        "reject_unknown_fields": schema.reject_unknown_fields,
    }


def _accepted_event_record(event: InboundAcceptedEvent) -> dict[str, object]:
    return {
        "schema_version": event.schema_version,
        "id": str(event.id),
        "receipt_id": str(event.receipt_id),
        "source_id": str(event.source_id),
        "source_event_id": event.source_event_id,
        "external_event_type": event.external_event_type,
        "external_schema_version": event.external_schema_version,
        "internal_event_type": event.internal_event_type,
        "occurred_at": _format_datetime(event.occurred_at),
        "accepted_at": _format_datetime(event.accepted_at),
        "updated_at": _format_datetime(event.updated_at),
        "normalized_payload": _thaw_json_mapping(event.normalized_payload),
        "normalized_payload_sha256": event.normalized_payload_sha256,
        "status": event.status.value,
        "correlation_id": event.correlation_id,
        "attempts": [_attempt_record(attempt) for attempt in event.attempts],
        "current_attempt": event.current_attempt,
        "publishing_at": _format_optional_datetime(event.publishing_at),
        "next_attempt_at": _format_optional_datetime(event.next_attempt_at),
        "terminal_at": _format_optional_datetime(event.terminal_at),
        "revision": event.revision,
    }


def _attempt_record(attempt: InboundPublicationAttempt) -> dict[str, object]:
    return {
        "schema_version": attempt.schema_version,
        "accepted_event_id": str(attempt.accepted_event_id),
        "number": attempt.number,
        "scheduled_at": _format_datetime(attempt.scheduled_at),
        "started_at": _format_datetime(attempt.started_at),
        "finished_at": _format_datetime(attempt.finished_at),
        "outcome": attempt.outcome.value,
        "retry_scheduled": attempt.retry_scheduled,
        "next_attempt_at": _format_optional_datetime(attempt.next_attempt_at),
        "error_category": attempt.error_category,
    }


def _decode_attempt(value: Mapping[str, object]) -> InboundPublicationAttempt:
    _require_exact_fields(value, _ATTEMPT_FIELDS, label="publication attempt")
    _require_schema(value, label="publication attempt")
    return InboundPublicationAttempt(
        accepted_event_id=_uuid(value, "accepted_event_id"),
        number=_integer(value, "number"),
        scheduled_at=_datetime(value, "scheduled_at"),
        started_at=_datetime(value, "started_at"),
        finished_at=_datetime(value, "finished_at"),
        outcome=InboundPublicationOutcome(_string(value, "outcome")),
        retry_scheduled=_boolean(value, "retry_scheduled"),
        next_attempt_at=_optional_datetime(value, "next_attempt_at"),
        error_category=_optional_string(value, "error_category"),
        schema_version=_integer(value, "schema_version"),
    )


def _receipt_record(receipt: InboundEventReceipt) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "id": str(receipt.id),
        "accepted_event_id": str(receipt.accepted_event_id),
        "source_id": str(receipt.source_id),
        "source_event_id": receipt.source_event_id,
        "external_event_type": receipt.external_event_type,
        "external_schema_version": receipt.external_schema_version,
        "accepted_at": _format_datetime(receipt.accepted_at),
        "correlation_id": receipt.correlation_id,
    }


def _replay_record(reservation: InboundReplayReservation) -> dict[str, object]:
    return {
        "schema_version": reservation.schema_version,
        "source_id": str(reservation.source_id),
        "kind": reservation.kind.value,
        "evidence_digest": reservation.evidence_digest,
        "accepted_event_id": str(reservation.accepted_event_id),
        "created_at": _format_datetime(reservation.created_at),
        "expires_at": _format_datetime(reservation.expires_at),
        "normalized_payload_sha256": reservation.normalized_payload_sha256,
    }


def _encode_envelope(kind: str, record: Mapping[str, object]) -> bytes:
    canonical_record = _canonical_json_bytes(record)
    envelope: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "kind": kind,
        "record": dict(record),
        "record_digest": hashlib.sha256(canonical_record).hexdigest(),
    }
    return _canonical_json_bytes(envelope)


def _decode_envelope(
    encoded: bytes,
    *,
    expected_kind: str,
    maximum_bytes: int,
    label: str,
) -> Mapping[str, object]:
    if type(encoded) is not bytes:
        raise TypeError("encoded inbound record must be bytes")
    if not encoded or len(encoded) > maximum_bytes:
        raise InboundCorruptionError(f"persisted inbound {label} size is outside bounds")
    try:
        decoded = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise InboundCorruptionError(f"persisted inbound {label} is not valid JSON") from exception
    envelope = _mapping(decoded, label=f"{label} envelope")
    _require_exact_fields(envelope, _ENVELOPE_FIELDS, label=f"{label} envelope")
    schema_version = _integer(envelope, "schema_version")
    if schema_version != _SCHEMA_VERSION:
        raise InboundSchemaError(f"persisted inbound {label} envelope schema is unsupported")
    if _string(envelope, "kind") != expected_kind:
        raise InboundCorruptionError(f"persisted inbound {label} kind is invalid")
    record = _mapping(envelope.get("record"), label=f"{label} record")
    supplied_digest = _string(envelope, "record_digest")
    expected_digest = hashlib.sha256(_canonical_json_bytes(record)).hexdigest()
    if not hmac.compare_digest(supplied_digest, expected_digest):
        raise InboundCorruptionError(f"persisted inbound {label} digest is invalid")
    canonical = _canonical_json_bytes(envelope)
    if canonical != encoded:
        raise InboundCorruptionError(f"persisted inbound {label} envelope is not canonical")
    return record


def _require_schema(value: Mapping[str, object], *, label: str) -> None:
    if _integer(value, "schema_version") != _SCHEMA_VERSION:
        raise InboundSchemaError(f"persisted inbound {label} schema is unsupported")


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise InboundCorruptionError(f"persisted inbound {label} fields are invalid")


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InboundCorruptionError(f"persisted inbound {label} is invalid")
    if not all(isinstance(key, str) for key in value):
        raise InboundCorruptionError(f"persisted inbound {label} keys are invalid")
    return cast(Mapping[str, object], value)


def _list(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise InboundCorruptionError(f"persisted inbound {label} is invalid")
    return cast(list[object], value)


def _string_list(value: object, *, label: str) -> list[str]:
    values = _list(value, label=label)
    if not all(isinstance(item, str) for item in values):
        raise InboundCorruptionError(f"persisted inbound {label} is invalid")
    return cast(list[str], values)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _optional_integer(value: Mapping[str, object], key: str) -> int | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, int) or isinstance(result, bool):
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _boolean(value: Mapping[str, object], key: str) -> bool:
    result = value.get(key)
    if type(result) is not bool:
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _uuid(value: Mapping[str, object], key: str) -> UUID:
    try:
        return UUID(_string(value, key))
    except ValueError as exception:
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid") from exception


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    supplied = _string(value, key)
    try:
        result = datetime.fromisoformat(supplied)
    except ValueError as exception:
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid") from exception
    if result.tzinfo is None or result.utcoffset() is None:
        raise InboundCorruptionError(f"persisted inbound field {key} must be timezone-aware")
    if _format_datetime(result) != supplied:
        raise InboundCorruptionError(f"persisted inbound field {key} is not canonical")
    return result


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    if value.get(key) is None:
        return None
    return _datetime(value, key)


def _format_datetime(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("inbound persisted datetime must be timezone-aware")
    return value.isoformat(timespec="microseconds")


def _format_optional_datetime(value: datetime | None) -> str | None:
    return None if value is None else _format_datetime(value)


def _timedelta(value: Mapping[str, object], key: str) -> timedelta:
    return timedelta(microseconds=_integer(value, key))


def _timedelta_microseconds(value: timedelta) -> int:
    return ((value.days * 86_400 + value.seconds) * 1_000_000) + value.microseconds


def _hex_float(value: Mapping[str, object], key: str) -> float:
    supplied = _string(value, key)
    try:
        result = float.fromhex(supplied)
    except ValueError as exception:
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid") from exception
    if result.hex() != supplied:
        raise InboundCorruptionError(f"persisted inbound field {key} is not canonical")
    return result


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exception:
        raise InboundCorruptionError(
            "persisted inbound state is not JSON-compatible"
        ) from exception


def _thaw_json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    return {key: _thaw_json(item) for key, item in value.items()}


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, object], value)
        return _thaw_json_mapping(mapping)
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value
