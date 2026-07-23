from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookCorruptionError,
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookHttpStatusClass,
    WebhookRetryPolicy,
    WebhookSchemaError,
    WebhookSigningPolicy,
    WebhookSubscription,
    canonical_webhook_delivery_record_bytes,
    canonical_webhook_subscription_record_bytes,
    decode_webhook_delivery,
    decode_webhook_subscription,
    encode_webhook_delivery,
    encode_webhook_subscription,
    webhook_delivery_digest,
    webhook_subscription_digest,
)

_NOW = datetime(
    2026,
    7,
    22,
    12,
    0,
    tzinfo=UTC,
)

_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000024")
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000124")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000224")

_BODY = (
    b'{"delivery_id":"00000000-0000-4000-8000-000000000124",'
    b'"payload":{"safe":true},"schema_version":1}'
)
_BODY_DIGEST = hashlib.sha256(_BODY).hexdigest()
_DEDUPLICATION_KEY = hashlib.sha256(b"subscription:event").hexdigest()


def _subscription() -> WebhookSubscription:
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset(
            {
                "jobs.completed",
                "workflows.failed",
            }
        ),
        endpoint=WebhookEndpoint("https://hooks.example.com/phoenix"),
        signing=WebhookSigningPolicy(
            SecretRef(
                "release-webhook",
                "integrations",
                7,
            ),
            lease_ttl=timedelta(seconds=45),
        ),
        egress_policy="production.webhooks",
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:arthur",
        retry=WebhookRetryPolicy(
            max_attempts=6,
            initial_delay=timedelta(seconds=3),
            multiplier=2.5,
            max_delay=timedelta(minutes=30),
            jitter_ratio=0.2,
        ),
        resource_filters={
            "jobs.completed": {
                "job_id": frozenset(
                    {
                        "job-2",
                        "job-1",
                    }
                )
            },
            "workflows.failed": {
                "workflow_id": frozenset(
                    {
                        "release",
                    }
                )
            },
        },
    )


def _delivery() -> WebhookDelivery:
    scheduled_at = _NOW + timedelta(seconds=1)
    started_at = scheduled_at + timedelta(milliseconds=10)
    finished_at = started_at + timedelta(milliseconds=20)
    next_attempt_at = finished_at + timedelta(minutes=1)

    attempt = WebhookAttempt(
        delivery_id=_DELIVERY_ID,
        number=1,
        scheduled_at=scheduled_at,
        started_at=started_at,
        finished_at=finished_at,
        outcome=(WebhookAttemptOutcome.RETRYABLE_FAILURE),
        status_class=(WebhookHttpStatusClass.SERVER_ERROR),
        retry_scheduled=True,
        next_attempt_at=next_attempt_at,
        error_category="http.server",
    )

    return WebhookDelivery(
        id=_DELIVERY_ID,
        subscription_id=_SUBSCRIPTION_ID,
        event_type="jobs.completed",
        deduplication_key=_DEDUPLICATION_KEY,
        canonical_body=_BODY,
        body_sha256=_BODY_DIGEST,
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=finished_at,
        status=WebhookDeliveryStatus.RETRYING,
        source_event_id=_EVENT_ID,
        correlation_id="request-123",
        attempts=(attempt,),
        next_attempt_at=next_attempt_at,
        revision=3,
    )


def _canonical(
    value: object,
) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _document(
    encoded: bytes,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(encoded),
    )


def _refresh_record_digest(
    document: dict[str, Any],
) -> bytes:
    document["record_digest"] = hashlib.sha256(_canonical(document["record"])).hexdigest()
    return _canonical(document)


def test_subscription_codec_is_deterministic_and_round_trips() -> None:
    subscription = _subscription()

    first = encode_webhook_subscription(subscription)
    second = encode_webhook_subscription(subscription)

    assert first == second
    assert decode_webhook_subscription(first) == subscription


def test_subscription_codec_orders_set_backed_fields() -> None:
    subscription = _subscription()
    document = _document(encode_webhook_subscription(subscription))
    record = document["record"]

    assert record["event_types"] == [
        "jobs.completed",
        "workflows.failed",
    ]
    assert record["resource_filters"]["jobs.completed"]["job_id"] == [
        "job-1",
        "job-2",
    ]


def test_subscription_codec_persists_only_secret_reference() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    signing = document["record"]["signing"]

    assert set(signing) == {
        "secret_ref",
        "scheme",
        "lease_ttl_microseconds",
    }
    assert set(signing["secret_ref"]) == {
        "name",
        "namespace",
        "version",
    }
    assert "value" not in signing
    assert "material" not in signing


def test_delivery_codec_is_deterministic_and_round_trips() -> None:
    delivery = _delivery()

    first = encode_webhook_delivery(delivery)
    second = encode_webhook_delivery(delivery)

    assert first == second
    assert decode_webhook_delivery(first) == delivery


def test_delivery_codec_preserves_body_and_attempts() -> None:
    decoded = decode_webhook_delivery(encode_webhook_delivery(_delivery()))

    assert decoded.canonical_body == _BODY
    assert decoded.body_sha256 == _BODY_DIGEST
    assert len(decoded.attempts) == 1
    assert decoded.attempts[0].error_category == "http.server"


def test_digest_helpers_match_encoded_record_digest() -> None:
    subscription = _subscription()
    delivery = _delivery()

    subscription_document = _document(encode_webhook_subscription(subscription))
    delivery_document = _document(encode_webhook_delivery(delivery))

    assert subscription_document["record_digest"] == webhook_subscription_digest(subscription)
    assert delivery_document["record_digest"] == webhook_delivery_digest(delivery)

    assert (
        webhook_subscription_digest(subscription)
        == hashlib.sha256(canonical_webhook_subscription_record_bytes(subscription)).hexdigest()
    )

    assert (
        webhook_delivery_digest(delivery)
        == hashlib.sha256(canonical_webhook_delivery_record_bytes(delivery)).hexdigest()
    )


@pytest.mark.parametrize(
    ("decoder", "value"),
    [
        (
            decode_webhook_subscription,
            "not-bytes",
        ),
        (
            decode_webhook_delivery,
            bytearray(b"not-bytes"),
        ),
    ],
)
def test_decoders_require_exact_bytes(
    decoder: Any,
    value: object,
) -> None:
    with pytest.raises(TypeError):
        decoder(value)


@pytest.mark.parametrize(
    "encoded",
    [
        b"\xff",
        b"{}",
        b"[]",
        b'{"value":NaN}',
    ],
)
def test_subscription_decoder_rejects_malformed_documents(
    encoded: bytes,
) -> None:
    with pytest.raises(WebhookCorruptionError):
        decode_webhook_subscription(encoded)


def test_decoder_rejects_noncanonical_json() -> None:
    encoded = encode_webhook_subscription(_subscription())

    with pytest.raises(
        WebhookCorruptionError,
        match="not canonical",
    ):
        decode_webhook_subscription(encoded + b"\n")


def test_decoder_rejects_duplicate_json_keys() -> None:
    encoded = encode_webhook_subscription(_subscription())
    duplicate = encoded.replace(
        b'{"kind":',
        b'{"kind":"duplicate","kind":',
        1,
    )

    with pytest.raises(
        WebhookCorruptionError,
        match="duplicate",
    ):
        decode_webhook_subscription(duplicate)


def test_subscription_decoder_detects_record_tampering() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["display_name"] = "Tampered"
    tampered = _canonical(document)

    with pytest.raises(
        WebhookCorruptionError,
        match="digest does not match",
    ):
        decode_webhook_subscription(tampered)


def test_decoder_rejects_invalid_digest_format() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record_digest"] = "A" * 64

    with pytest.raises(
        WebhookCorruptionError,
        match="digest",
    ):
        decode_webhook_subscription(_canonical(document))


def test_decoder_rejects_unsupported_envelope_schema() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["schema_version"] = 2

    with pytest.raises(WebhookSchemaError):
        decode_webhook_subscription(_canonical(document))


def test_decoder_rejects_unsupported_record_schema() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["schema_version"] = 2
    encoded = _refresh_record_digest(document)

    with pytest.raises(WebhookSchemaError):
        decode_webhook_subscription(encoded)


def test_decoder_rejects_wrong_record_kind() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["kind"] = "phoenix.webhook.delivery.record"

    with pytest.raises(
        WebhookCorruptionError,
        match="kind",
    ):
        decode_webhook_subscription(_canonical(document))


def test_decoder_rejects_extra_envelope_fields() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["unexpected"] = True

    with pytest.raises(
        WebhookCorruptionError,
        match="fields",
    ):
        decode_webhook_subscription(_canonical(document))


def test_subscription_decoder_rejects_extra_record_fields() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["unexpected"] = True
    encoded = _refresh_record_digest(document)

    with pytest.raises(
        WebhookCorruptionError,
        match="fields",
    ):
        decode_webhook_subscription(encoded)


def test_delivery_decoder_rejects_extra_record_fields() -> None:
    document = _document(encode_webhook_delivery(_delivery()))
    document["record"]["unexpected"] = True
    encoded = _refresh_record_digest(document)

    with pytest.raises(
        WebhookCorruptionError,
        match="fields",
    ):
        decode_webhook_delivery(encoded)


def test_decoder_rejects_plaintext_secret_field() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["signing"]["secret_material"] = "must-not-persist"
    encoded = _refresh_record_digest(document)

    with pytest.raises(
        WebhookCorruptionError,
        match="fields",
    ):
        decode_webhook_subscription(encoded)


def test_decoder_rejects_unversioned_secret_reference() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["signing"]["secret_ref"]["version"] = None
    encoded = _refresh_record_digest(document)

    with pytest.raises(WebhookCorruptionError):
        decode_webhook_subscription(encoded)


def test_delivery_decoder_rejects_invalid_base64() -> None:
    document = _document(encode_webhook_delivery(_delivery()))
    document["record"]["canonical_body_base64"] = "!!!"
    encoded = _refresh_record_digest(document)

    with pytest.raises(WebhookCorruptionError):
        decode_webhook_delivery(encoded)


def test_delivery_decoder_rejects_body_digest_mismatch() -> None:
    document = _document(encode_webhook_delivery(_delivery()))
    document["record"]["canonical_body_base64"] = base64.b64encode(b'{"changed":true}').decode(
        "ascii"
    )
    encoded = _refresh_record_digest(document)

    with pytest.raises(WebhookCorruptionError):
        decode_webhook_delivery(encoded)


def test_delivery_decoder_rejects_invalid_attempt_outcome() -> None:
    document = _document(encode_webhook_delivery(_delivery()))
    document["record"]["attempts"][0]["outcome"] = "unknown"
    encoded = _refresh_record_digest(document)

    with pytest.raises(WebhookCorruptionError):
        decode_webhook_delivery(encoded)


def test_decoder_rejects_boolean_integer_field() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["revision"] = True
    encoded = _refresh_record_digest(document)

    with pytest.raises(WebhookCorruptionError):
        decode_webhook_subscription(encoded)


def test_decoder_rejects_noncanonical_normalized_metadata() -> None:
    document = _document(encode_webhook_subscription(_subscription()))
    document["record"]["name"] = " Release.Notifications "
    encoded = _refresh_record_digest(document)

    with pytest.raises(
        WebhookCorruptionError,
        match="not canonical",
    ):
        decode_webhook_subscription(encoded)


@pytest.mark.parametrize(
    ("decoder", "size"),
    [
        (
            decode_webhook_subscription,
            300_000,
        ),
        (
            decode_webhook_delivery,
            2_100_000,
        ),
    ],
)
def test_decoders_reject_oversized_documents(
    decoder: Any,
    size: int,
) -> None:
    with pytest.raises(
        WebhookCorruptionError,
        match="size",
    ):
        decoder(b"x" * size)
