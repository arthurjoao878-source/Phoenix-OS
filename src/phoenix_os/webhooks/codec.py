"""Strict schema-v1 codecs for durable webhook persistence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks.contracts import (
    MAX_WEBHOOK_DELIVERY_BODY_BYTES,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookHttpStatusClass,
    WebhookRetryPolicy,
    WebhookSignatureScheme,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionStatus,
)
from phoenix_os.webhooks.errors import (
    WebhookCorruptionError,
    WebhookSchemaError,
)

_SCHEMA_VERSION = 1

_SUBSCRIPTION_KIND = "phoenix.webhook.subscription.record"
_DELIVERY_KIND = "phoenix.webhook.delivery.record"

_MAX_SUBSCRIPTION_DOCUMENT_BYTES = 262_144
_MAX_DELIVERY_DOCUMENT_BYTES = 2_097_152

_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "record",
        "record_digest",
    }
)

_SUBSCRIPTION_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "display_name",
        "event_types",
        "endpoint",
        "signing",
        "egress_policy",
        "created_at",
        "updated_at",
        "created_by",
        "retry",
        "resource_filters",
        "status",
        "disabled_at",
        "revoked_at",
        "revision",
    }
)

_ENDPOINT_FIELDS = frozenset(
    {
        "url",
        "allow_insecure_loopback",
    }
)

_SIGNING_FIELDS = frozenset(
    {
        "secret_ref",
        "scheme",
        "lease_ttl_microseconds",
    }
)

_SECRET_REF_FIELDS = frozenset(
    {
        "name",
        "namespace",
        "version",
    }
)

_RETRY_FIELDS = frozenset(
    {
        "max_attempts",
        "initial_delay_microseconds",
        "multiplier_hex",
        "max_delay_microseconds",
        "jitter_ratio_hex",
    }
)

_DELIVERY_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "subscription_id",
        "event_type",
        "deduplication_key",
        "canonical_body_base64",
        "body_sha256",
        "occurred_at",
        "created_at",
        "updated_at",
        "status",
        "source_event_id",
        "correlation_id",
        "attempts",
        "current_attempt",
        "in_flight_at",
        "next_attempt_at",
        "terminal_at",
        "revision",
    }
)

_ATTEMPT_FIELDS = frozenset(
    {
        "schema_version",
        "delivery_id",
        "number",
        "scheduled_at",
        "started_at",
        "finished_at",
        "outcome",
        "status_class",
        "retry_scheduled",
        "next_attempt_at",
        "error_category",
    }
)


def canonical_webhook_subscription_record_bytes(
    subscription: WebhookSubscription,
) -> bytes:
    """Return deterministic schema-v1 bytes for one subscription record."""

    if not isinstance(subscription, WebhookSubscription):
        raise TypeError("subscription must be WebhookSubscription")
    return _canonical_json_bytes(_subscription_record(subscription))


def webhook_subscription_digest(
    subscription: WebhookSubscription,
) -> str:
    """Return the stable integrity digest for one subscription record."""

    return hashlib.sha256(canonical_webhook_subscription_record_bytes(subscription)).hexdigest()


def encode_webhook_subscription(
    subscription: WebhookSubscription,
) -> bytes:
    """Encode one subscription in a strict integrity-protected envelope."""

    record = _subscription_record(subscription)
    return _encode_envelope(
        kind=_SUBSCRIPTION_KIND,
        record=record,
    )


def decode_webhook_subscription(
    encoded: bytes,
) -> WebhookSubscription:
    """Decode and strictly validate one persisted subscription."""

    record = _decode_envelope(
        encoded,
        expected_kind=_SUBSCRIPTION_KIND,
        maximum_bytes=_MAX_SUBSCRIPTION_DOCUMENT_BYTES,
        label="subscription",
    )
    _require_exact_fields(
        record,
        _SUBSCRIPTION_FIELDS,
        label="subscription record",
    )
    _require_schema(
        record,
        label="subscription record",
    )

    try:
        endpoint_document = _mapping(
            record.get("endpoint"),
            label="subscription endpoint",
        )
        _require_exact_fields(
            endpoint_document,
            _ENDPOINT_FIELDS,
            label="subscription endpoint",
        )

        secret_ref_document = _mapping(
            _mapping(
                record.get("signing"),
                label="subscription signing policy",
            ).get("secret_ref"),
            label="subscription signing secret reference",
        )
        signing_document = _mapping(
            record.get("signing"),
            label="subscription signing policy",
        )
        _require_exact_fields(
            signing_document,
            _SIGNING_FIELDS,
            label="subscription signing policy",
        )
        _require_exact_fields(
            secret_ref_document,
            _SECRET_REF_FIELDS,
            label="subscription signing secret reference",
        )

        retry_document = _mapping(
            record.get("retry"),
            label="subscription retry policy",
        )
        _require_exact_fields(
            retry_document,
            _RETRY_FIELDS,
            label="subscription retry policy",
        )

        subscription = WebhookSubscription(
            id=_uuid(record, "id"),
            name=_string(record, "name"),
            display_name=_string(record, "display_name"),
            event_types=frozenset(
                _string_list(
                    record.get("event_types"),
                    label="subscription event types",
                )
            ),
            endpoint=WebhookEndpoint(
                url=_string(endpoint_document, "url"),
                allow_insecure_loopback=_boolean(
                    endpoint_document,
                    "allow_insecure_loopback",
                ),
            ),
            signing=WebhookSigningPolicy(
                secret_ref=SecretRef(
                    name=_string(secret_ref_document, "name"),
                    namespace=_string(secret_ref_document, "namespace"),
                    version=_integer(secret_ref_document, "version"),
                ),
                scheme=WebhookSignatureScheme(_string(signing_document, "scheme")),
                lease_ttl=_timedelta(
                    signing_document,
                    "lease_ttl_microseconds",
                ),
            ),
            egress_policy=_string(record, "egress_policy"),
            created_at=_datetime(record, "created_at"),
            updated_at=_datetime(record, "updated_at"),
            created_by=_string(record, "created_by"),
            retry=WebhookRetryPolicy(
                max_attempts=_integer(retry_document, "max_attempts"),
                initial_delay=_timedelta(
                    retry_document,
                    "initial_delay_microseconds",
                ),
                multiplier=_hex_float(
                    retry_document,
                    "multiplier_hex",
                ),
                max_delay=_timedelta(
                    retry_document,
                    "max_delay_microseconds",
                ),
                jitter_ratio=_hex_float(
                    retry_document,
                    "jitter_ratio_hex",
                ),
            ),
            resource_filters=_resource_filters(record.get("resource_filters")),
            status=WebhookSubscriptionStatus(_string(record, "status")),
            disabled_at=_optional_datetime(record, "disabled_at"),
            revoked_at=_optional_datetime(record, "revoked_at"),
            revision=_integer(record, "revision"),
            schema_version=_integer(record, "schema_version"),
        )
    except (WebhookCorruptionError, WebhookSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise WebhookCorruptionError("persisted webhook subscription is invalid") from exception

    if _subscription_record(subscription) != record:
        raise WebhookCorruptionError("persisted webhook subscription is not canonical")

    return subscription


def canonical_webhook_delivery_record_bytes(
    delivery: WebhookDelivery,
) -> bytes:
    """Return deterministic schema-v1 bytes for one delivery record."""

    if not isinstance(delivery, WebhookDelivery):
        raise TypeError("delivery must be WebhookDelivery")
    return _canonical_json_bytes(_delivery_record(delivery))


def webhook_delivery_digest(
    delivery: WebhookDelivery,
) -> str:
    """Return the stable integrity digest for one delivery record."""

    return hashlib.sha256(canonical_webhook_delivery_record_bytes(delivery)).hexdigest()


def encode_webhook_delivery(
    delivery: WebhookDelivery,
) -> bytes:
    """Encode one delivery in a strict integrity-protected envelope."""

    record = _delivery_record(delivery)
    return _encode_envelope(
        kind=_DELIVERY_KIND,
        record=record,
    )


def decode_webhook_delivery(
    encoded: bytes,
) -> WebhookDelivery:
    """Decode and strictly validate one persisted delivery."""

    record = _decode_envelope(
        encoded,
        expected_kind=_DELIVERY_KIND,
        maximum_bytes=_MAX_DELIVERY_DOCUMENT_BYTES,
        label="delivery",
    )
    _require_exact_fields(
        record,
        _DELIVERY_FIELDS,
        label="delivery record",
    )
    _require_schema(
        record,
        label="delivery record",
    )

    try:
        attempt_values = _list(
            record.get("attempts"),
            label="delivery attempts",
        )
        attempts = tuple(
            _decode_attempt(
                _mapping(
                    value,
                    label="delivery attempt",
                )
            )
            for value in attempt_values
        )

        delivery = WebhookDelivery(
            id=_uuid(record, "id"),
            subscription_id=_uuid(record, "subscription_id"),
            event_type=_string(record, "event_type"),
            deduplication_key=_string(
                record,
                "deduplication_key",
            ),
            canonical_body=_base64_bytes(
                record,
                "canonical_body_base64",
            ),
            body_sha256=_string(record, "body_sha256"),
            occurred_at=_datetime(record, "occurred_at"),
            created_at=_datetime(record, "created_at"),
            updated_at=_datetime(record, "updated_at"),
            status=WebhookDeliveryStatus(_string(record, "status")),
            source_event_id=_optional_uuid(
                record,
                "source_event_id",
            ),
            correlation_id=_optional_string(
                record,
                "correlation_id",
            ),
            attempts=attempts,
            current_attempt=_optional_integer(
                record,
                "current_attempt",
            ),
            in_flight_at=_optional_datetime(
                record,
                "in_flight_at",
            ),
            next_attempt_at=_optional_datetime(
                record,
                "next_attempt_at",
            ),
            terminal_at=_optional_datetime(
                record,
                "terminal_at",
            ),
            revision=_integer(record, "revision"),
            schema_version=_integer(record, "schema_version"),
        )
    except (WebhookCorruptionError, WebhookSchemaError):
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise WebhookCorruptionError("persisted webhook delivery is invalid") from exception

    if _delivery_record(delivery) != record:
        raise WebhookCorruptionError("persisted webhook delivery is not canonical")

    return delivery


def _subscription_record(
    subscription: WebhookSubscription,
) -> dict[str, object]:
    filters = {
        event_name: {field_name: sorted(values) for field_name, values in sorted(fields.items())}
        for event_name, fields in sorted(subscription.resource_filters.items())
    }

    return {
        "schema_version": subscription.schema_version,
        "id": str(subscription.id),
        "name": subscription.name,
        "display_name": subscription.display_name,
        "event_types": sorted(subscription.event_types),
        "endpoint": {
            "url": subscription.endpoint.url,
            "allow_insecure_loopback": (subscription.endpoint.allow_insecure_loopback),
        },
        "signing": {
            "secret_ref": {
                "name": subscription.signing.secret_ref.name,
                "namespace": (subscription.signing.secret_ref.namespace),
                "version": subscription.signing.secret_ref.version,
            },
            "scheme": subscription.signing.scheme.value,
            "lease_ttl_microseconds": _timedelta_microseconds(subscription.signing.lease_ttl),
        },
        "egress_policy": subscription.egress_policy,
        "created_at": subscription.created_at.isoformat(),
        "updated_at": subscription.updated_at.isoformat(),
        "created_by": subscription.created_by,
        "retry": {
            "max_attempts": subscription.retry.max_attempts,
            "initial_delay_microseconds": _timedelta_microseconds(subscription.retry.initial_delay),
            "multiplier_hex": float(subscription.retry.multiplier).hex(),
            "max_delay_microseconds": _timedelta_microseconds(subscription.retry.max_delay),
            "jitter_ratio_hex": float(subscription.retry.jitter_ratio).hex(),
        },
        "resource_filters": filters,
        "status": subscription.status.value,
        "disabled_at": _optional_datetime_text(subscription.disabled_at),
        "revoked_at": _optional_datetime_text(subscription.revoked_at),
        "revision": subscription.revision,
    }


def _delivery_record(
    delivery: WebhookDelivery,
) -> dict[str, object]:
    return {
        "schema_version": delivery.schema_version,
        "id": str(delivery.id),
        "subscription_id": str(delivery.subscription_id),
        "event_type": delivery.event_type,
        "deduplication_key": delivery.deduplication_key,
        "canonical_body_base64": base64.b64encode(delivery.canonical_body).decode("ascii"),
        "body_sha256": delivery.body_sha256,
        "occurred_at": delivery.occurred_at.isoformat(),
        "created_at": delivery.created_at.isoformat(),
        "updated_at": delivery.updated_at.isoformat(),
        "status": delivery.status.value,
        "source_event_id": (
            None if delivery.source_event_id is None else str(delivery.source_event_id)
        ),
        "correlation_id": delivery.correlation_id,
        "attempts": [_attempt_record(attempt) for attempt in delivery.attempts],
        "current_attempt": delivery.current_attempt,
        "in_flight_at": _optional_datetime_text(delivery.in_flight_at),
        "next_attempt_at": _optional_datetime_text(delivery.next_attempt_at),
        "terminal_at": _optional_datetime_text(delivery.terminal_at),
        "revision": delivery.revision,
    }


def _attempt_record(
    attempt: WebhookAttempt,
) -> dict[str, object]:
    return {
        "schema_version": attempt.schema_version,
        "delivery_id": str(attempt.delivery_id),
        "number": attempt.number,
        "scheduled_at": attempt.scheduled_at.isoformat(),
        "started_at": attempt.started_at.isoformat(),
        "finished_at": attempt.finished_at.isoformat(),
        "outcome": attempt.outcome.value,
        "status_class": (None if attempt.status_class is None else attempt.status_class.value),
        "retry_scheduled": attempt.retry_scheduled,
        "next_attempt_at": _optional_datetime_text(attempt.next_attempt_at),
        "error_category": attempt.error_category,
    }


def _decode_attempt(
    document: Mapping[str, object],
) -> WebhookAttempt:
    _require_exact_fields(
        document,
        _ATTEMPT_FIELDS,
        label="delivery attempt",
    )
    _require_schema(
        document,
        label="delivery attempt",
    )

    status_class_text = _optional_string(
        document,
        "status_class",
    )

    try:
        attempt = WebhookAttempt(
            delivery_id=_uuid(document, "delivery_id"),
            number=_integer(document, "number"),
            scheduled_at=_datetime(document, "scheduled_at"),
            started_at=_datetime(document, "started_at"),
            finished_at=_datetime(document, "finished_at"),
            outcome=WebhookAttemptOutcome(_string(document, "outcome")),
            status_class=(
                None if status_class_text is None else WebhookHttpStatusClass(status_class_text)
            ),
            retry_scheduled=_boolean(
                document,
                "retry_scheduled",
            ),
            next_attempt_at=_optional_datetime(
                document,
                "next_attempt_at",
            ),
            error_category=_optional_string(
                document,
                "error_category",
            ),
            schema_version=_integer(
                document,
                "schema_version",
            ),
        )
    except WebhookCorruptionError:
        raise
    except (TypeError, ValueError) as exception:
        raise WebhookCorruptionError("persisted webhook attempt is invalid") from exception

    if _attempt_record(attempt) != document:
        raise WebhookCorruptionError("persisted webhook attempt is not canonical")

    return attempt


def _encode_envelope(
    *,
    kind: str,
    record: Mapping[str, object],
) -> bytes:
    envelope: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "kind": kind,
        "record": dict(record),
        "record_digest": hashlib.sha256(_canonical_json_bytes(record)).hexdigest(),
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
        raise TypeError(f"encoded webhook {label} must be bytes")
    if not encoded or len(encoded) > maximum_bytes:
        raise WebhookCorruptionError(f"persisted webhook {label} size is outside bounds")

    root = _load_json_mapping(
        encoded,
        label=f"{label} envelope",
    )

    canonical = _canonical_json_bytes(root)
    if not hmac.compare_digest(encoded, canonical):
        raise WebhookCorruptionError(f"persisted webhook {label} envelope is not canonical")

    _require_exact_fields(
        root,
        _ENVELOPE_FIELDS,
        label=f"{label} envelope",
    )
    _require_schema(
        root,
        label=f"{label} envelope",
    )

    if _string(root, "kind") != expected_kind:
        raise WebhookCorruptionError(f"persisted webhook {label} kind is invalid")

    record = _mapping(
        root.get("record"),
        label=f"{label} record",
    )

    expected_digest = _sha256(
        _string(root, "record_digest"),
        label=f"{label} record digest",
    )
    actual_digest = hashlib.sha256(_canonical_json_bytes(record)).hexdigest()

    if not hmac.compare_digest(
        expected_digest,
        actual_digest,
    ):
        raise WebhookCorruptionError(f"persisted webhook {label} digest does not match")

    return record


def _load_json_mapping(
    encoded: bytes,
    *,
    label: str,
) -> Mapping[str, object]:
    try:
        text = encoded.decode("utf-8")
        decoded = cast(
            object,
            json.loads(
                text,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            ),
        )
    except WebhookCorruptionError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exception:
        raise WebhookCorruptionError(f"persisted webhook {label} is not valid JSON") from exception

    return _mapping(
        decoded,
        label=label,
    )


def _strict_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WebhookCorruptionError("persisted webhook JSON contains duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(
    value: str,
) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _canonical_json_bytes(
    value: Mapping[str, object],
) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise WebhookCorruptionError(f"persisted webhook {label} fields are invalid")


def _require_schema(
    value: Mapping[str, object],
    *,
    label: str,
) -> None:
    version = _integer(
        value,
        "schema_version",
    )
    if version != _SCHEMA_VERSION:
        raise WebhookSchemaError(f"persisted webhook {label} schema is unsupported")


def _mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WebhookCorruptionError(f"persisted webhook {label} is invalid")
    if not all(isinstance(key, str) for key in value):
        raise WebhookCorruptionError(f"persisted webhook {label} keys are invalid")
    return cast(Mapping[str, object], value)


def _list(
    value: object,
    *,
    label: str,
) -> list[object]:
    if not isinstance(value, list):
        raise WebhookCorruptionError(f"persisted webhook {label} is invalid")
    return value


def _string(
    value: Mapping[str, object],
    key: str,
) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _optional_string(
    value: Mapping[str, object],
    key: str,
) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _integer(
    value: Mapping[str, object],
    key: str,
) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _optional_integer(
    value: Mapping[str, object],
    key: str,
) -> int | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, int) or isinstance(result, bool):
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _boolean(
    value: Mapping[str, object],
    key: str,
) -> bool:
    result = value.get(key)
    if type(result) is not bool:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _uuid(
    value: Mapping[str, object],
    key: str,
) -> UUID:
    try:
        return UUID(_string(value, key))
    except ValueError as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception


def _optional_uuid(
    value: Mapping[str, object],
    key: str,
) -> UUID | None:
    result = _optional_string(
        value,
        key,
    )
    if result is None:
        return None
    try:
        return UUID(result)
    except ValueError as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception


def _datetime(
    value: Mapping[str, object],
    key: str,
) -> datetime:
    try:
        return datetime.fromisoformat(_string(value, key))
    except ValueError as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception


def _optional_datetime(
    value: Mapping[str, object],
    key: str,
) -> datetime | None:
    result = _optional_string(
        value,
        key,
    )
    if result is None:
        return None
    try:
        return datetime.fromisoformat(result)
    except ValueError as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception


def _timedelta(
    value: Mapping[str, object],
    key: str,
) -> timedelta:
    microseconds = _integer(
        value,
        key,
    )
    try:
        return timedelta(microseconds=microseconds)
    except OverflowError as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception


def _hex_float(
    value: Mapping[str, object],
    key: str,
) -> float:
    supplied = _string(
        value,
        key,
    )
    try:
        return float.fromhex(supplied)
    except ValueError as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception


def _string_list(
    value: object,
    *,
    label: str,
) -> list[str]:
    supplied = _list(
        value,
        label=label,
    )
    result: list[str] = []
    for item in supplied:
        if not isinstance(item, str):
            raise WebhookCorruptionError(f"persisted webhook {label} is invalid")
        result.append(item)
    return result


def _resource_filters(
    value: object,
) -> dict[str, dict[str, frozenset[str]]]:
    events = _mapping(
        value,
        label="subscription resource filters",
    )
    result: dict[
        str,
        dict[str, frozenset[str]],
    ] = {}

    for event_name, supplied_fields in events.items():
        fields = _mapping(
            supplied_fields,
            label="subscription resource filter fields",
        )
        normalized_fields: dict[
            str,
            frozenset[str],
        ] = {}

        for field_name, supplied_values in fields.items():
            normalized_fields[field_name] = frozenset(
                _string_list(
                    supplied_values,
                    label="subscription resource filter values",
                )
            )

        result[event_name] = normalized_fields

    return result


def _base64_bytes(
    value: Mapping[str, object],
    key: str,
) -> bytes:
    supplied = _string(
        value,
        key,
    )
    try:
        decoded = base64.b64decode(
            supplied.encode("ascii"),
            validate=True,
        )
    except (
        UnicodeEncodeError,
        binascii.Error,
        ValueError,
    ) as exception:
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid") from exception

    if len(decoded) > MAX_WEBHOOK_DELIVERY_BODY_BYTES:
        raise WebhookCorruptionError("persisted webhook delivery body exceeds bounds")

    canonical = base64.b64encode(decoded).decode("ascii")
    if canonical != supplied:
        raise WebhookCorruptionError("persisted webhook delivery body is not canonical")

    return decoded


def _sha256(
    value: str,
    *,
    label: str,
) -> str:
    if (
        len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise WebhookCorruptionError(f"persisted webhook {label} is invalid")
    return value


def _timedelta_microseconds(
    value: timedelta,
) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _optional_datetime_text(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None
    return value.isoformat()
