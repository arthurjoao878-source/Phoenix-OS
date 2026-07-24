from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.configuration import SecretValue
from phoenix_os.events import Event
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretLease, SecretMetadata, SecretRef, SecretsManager
from phoenix_os.webhooks import (
    WEBHOOK_ATTEMPT_HEADER,
    WEBHOOK_CONTENT_TYPE,
    WEBHOOK_CONTENT_TYPE_HEADER,
    WEBHOOK_CORRELATION_ID_HEADER,
    WEBHOOK_ID_HEADER,
    WEBHOOK_KEY_VERSION_HEADER,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_TIMESTAMP_HEADER,
    WEBHOOK_USER_AGENT,
    WEBHOOK_USER_AGENT_HEADER,
    WebhookDelivery,
    WebhookEndpoint,
    WebhookEventType,
    WebhookPayload,
    WebhookSigner,
    WebhookSigningError,
    WebhookSigningPolicy,
    WebhookSubscription,
    canonical_webhook_signature_input,
    format_webhook_timestamp,
    new_webhook_delivery,
    verify_webhook_signature,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_SIGNING_TIME = datetime(2026, 7, 24, 12, 0, 1, 987654, tzinfo=UTC)
_EVENT_ID = UUID("00000000-0000-4000-8000-000000000024")
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000124")
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000224")


def _context() -> SecurityContext:
    return SecurityContext(
        principal="phoenix.webhooks",
        principal_type=PrincipalType.SYSTEM,
        authenticated=True,
        permissions=frozenset({"secret.read", "secret.lease.revoke"}),
        correlation_id="runtime-correlation",
    )


def _subscription(secret_ref: SecretRef) -> WebhookSubscription:
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/phoenix"),
        signing=WebhookSigningPolicy(secret_ref, lease_ttl=timedelta(seconds=10)),
        egress_policy="production.webhooks",
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
    )


def _delivery(subscription: WebhookSubscription) -> WebhookDelivery:
    event_type = WebhookEventType("jobs.completed")
    event = Event(
        id=_EVENT_ID,
        name=event_type.name,
        source="scheduler",
        occurred_at=_NOW,
        correlation_id="delivery-correlation",
        payload={"job_id": "job-1", "private_token": "must-not-leak"},
    )
    payload = WebhookPayload(
        event_type=event_type,
        data={"job_id": "job-1"},
    )
    return new_webhook_delivery(
        subscription,
        event,
        payload,
        delivery_id=_DELIVERY_ID,
        created_at=_SIGNING_TIME,
    )


async def _services(
    secret: object = "signing-secret",
) -> tuple[
    SecretsManager,
    SecretMetadata,
    WebhookSubscription,
    WebhookDelivery,
    WebhookSigner,
]:
    manager = SecretsManager(clock=lambda: _SIGNING_TIME)
    metadata = await manager.create(
        SecretRef("release-webhook", "integrations"),
        SecretValue(secret),
        SecurityContext(
            principal="maintainer:test",
            principal_type=PrincipalType.USER,
            authenticated=True,
            permissions=frozenset({"secret.create"}),
        ),
    )
    subscription = _subscription(metadata.ref)
    delivery = _delivery(subscription)
    signer = WebhookSigner(
        secrets=manager,
        context=_context(),
        clock=lambda: _SIGNING_TIME,
    )
    return manager, metadata, subscription, delivery, signer


@pytest.mark.asyncio
async def test_signer_builds_exact_headers_and_revokes_temporary_lease() -> None:
    manager, metadata, subscription, delivery, signer = await _services()

    signed = await signer.sign(delivery, subscription, attempt=1)

    canonical = canonical_webhook_signature_input(
        timestamp=_SIGNING_TIME,
        delivery_id=delivery.id,
        attempt=1,
        body=delivery.canonical_body,
    )
    expected_input = b"\n".join(
        (
            b"phoenix-webhook-signature-v1",
            b"2026-07-24T12:00:01Z",
            str(delivery.id).encode("ascii"),
            b"1",
            hashlib.sha256(delivery.canonical_body).hexdigest().encode("ascii"),
        )
    )
    expected_digest = hmac.new(
        b"signing-secret",
        expected_input,
        hashlib.sha256,
    ).hexdigest()

    assert canonical == expected_input
    assert signed.body == delivery.canonical_body
    assert signed.timestamp == _SIGNING_TIME.replace(microsecond=0)
    assert signed.key_version == metadata.ref.version == 1
    assert signed.headers == {
        WEBHOOK_CONTENT_TYPE_HEADER: WEBHOOK_CONTENT_TYPE,
        WEBHOOK_USER_AGENT_HEADER: WEBHOOK_USER_AGENT,
        WEBHOOK_ID_HEADER: str(delivery.id),
        WEBHOOK_TIMESTAMP_HEADER: "2026-07-24T12:00:01Z",
        WEBHOOK_SIGNATURE_HEADER: f"hmac-sha256-v1={expected_digest}",
        WEBHOOK_KEY_VERSION_HEADER: "1",
        WEBHOOK_ATTEMPT_HEADER: "1",
        WEBHOOK_CORRELATION_ID_HEADER: "delivery-correlation",
    }
    snapshot = await manager.snapshot()
    assert snapshot.leases == 1
    assert snapshot.active_leases == 0
    assert snapshot.revoked_leases == 1
    assert "signing-secret" not in repr(signed)
    assert expected_digest not in repr(signed)
    assert delivery.canonical_body.decode() not in repr(signed)


@pytest.mark.asyncio
async def test_signer_uses_canonical_input_and_verifier_compares_in_constant_time() -> None:
    _, _, subscription, delivery, signer = await _services(b"binary-key")

    signed = await signer.sign(delivery, subscription, attempt=2)
    headers = signed.headers

    assert verify_webhook_signature(
        b"binary-key",
        signature=headers[WEBHOOK_SIGNATURE_HEADER],
        timestamp=headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=headers[WEBHOOK_ID_HEADER],
        attempt=headers[WEBHOOK_ATTEMPT_HEADER],
        body=signed.body,
    )
    assert not verify_webhook_signature(
        b"wrong-key",
        signature=headers[WEBHOOK_SIGNATURE_HEADER],
        timestamp=headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=headers[WEBHOOK_ID_HEADER],
        attempt=headers[WEBHOOK_ATTEMPT_HEADER],
        body=signed.body,
    )
    assert not verify_webhook_signature(
        b"binary-key",
        signature=headers[WEBHOOK_SIGNATURE_HEADER],
        timestamp=headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=headers[WEBHOOK_ID_HEADER],
        attempt=headers[WEBHOOK_ATTEMPT_HEADER],
        body=signed.body + b" ",
    )


@pytest.mark.asyncio
async def test_signature_binds_timestamp_delivery_attempt_and_body_digest() -> None:
    _, _, subscription, delivery, signer = await _services()
    signed = await signer.sign(delivery, subscription, attempt=3)
    headers = signed.headers
    signature = headers[WEBHOOK_SIGNATURE_HEADER]

    assert not verify_webhook_signature(
        "signing-secret",
        signature=signature,
        timestamp="2026-07-24T12:00:02Z",
        delivery_id=headers[WEBHOOK_ID_HEADER],
        attempt=headers[WEBHOOK_ATTEMPT_HEADER],
        body=signed.body,
    )
    assert not verify_webhook_signature(
        "signing-secret",
        signature=signature,
        timestamp=headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=str(UUID(int=999)),
        attempt=headers[WEBHOOK_ATTEMPT_HEADER],
        body=signed.body,
    )
    assert not verify_webhook_signature(
        "signing-secret",
        signature=signature,
        timestamp=headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=headers[WEBHOOK_ID_HEADER],
        attempt="4",
        body=signed.body,
    )


@pytest.mark.asyncio
async def test_signer_resolves_exact_rotated_secret_versions() -> None:
    manager, first, subscription, delivery, signer = await _services("first-key")
    admin = SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"secret.rotate"}),
    )
    second = await manager.rotate(
        SecretRef("release-webhook", "integrations"),
        SecretValue("second-key"),
        admin,
    )
    rotated = replace(
        subscription,
        signing=WebhookSigningPolicy(second.ref, lease_ttl=timedelta(seconds=10)),
        updated_at=_SIGNING_TIME,
        revision=2,
    )

    first_signed = await signer.sign(delivery, subscription, attempt=1)
    second_signed = await signer.sign(delivery, rotated, attempt=1)

    assert first.ref.version == 1
    assert second.ref.version == 2
    assert first_signed.headers[WEBHOOK_KEY_VERSION_HEADER] == "1"
    assert second_signed.headers[WEBHOOK_KEY_VERSION_HEADER] == "2"
    assert (
        first_signed.headers[WEBHOOK_SIGNATURE_HEADER]
        != second_signed.headers[WEBHOOK_SIGNATURE_HEADER]
    )
    assert verify_webhook_signature(
        "first-key",
        signature=first_signed.headers[WEBHOOK_SIGNATURE_HEADER],
        timestamp=first_signed.headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=first_signed.headers[WEBHOOK_ID_HEADER],
        attempt=first_signed.headers[WEBHOOK_ATTEMPT_HEADER],
        body=first_signed.body,
    )
    assert verify_webhook_signature(
        "second-key",
        signature=second_signed.headers[WEBHOOK_SIGNATURE_HEADER],
        timestamp=second_signed.headers[WEBHOOK_TIMESTAMP_HEADER],
        delivery_id=second_signed.headers[WEBHOOK_ID_HEADER],
        attempt=second_signed.headers[WEBHOOK_ATTEMPT_HEADER],
        body=second_signed.body,
    )


@pytest.mark.asyncio
async def test_signer_rejects_mismatched_subscription_attempt_and_timestamp() -> None:
    _, metadata, subscription, delivery, signer = await _services()
    other = replace(
        subscription,
        id=UUID(int=333),
        name="other.notifications",
        signing=WebhookSigningPolicy(metadata.ref),
    )

    with pytest.raises(ValueError, match="another subscription"):
        await signer.sign(delivery, other, attempt=1)
    with pytest.raises(ValueError, match="attempt"):
        await signer.sign(delivery, subscription, attempt=0)
    with pytest.raises(ValueError, match="timezone-aware"):
        await signer.sign(
            delivery,
            subscription,
            attempt=1,
            timestamp=datetime(2026, 7, 24, 12, 0),
        )


@pytest.mark.asyncio
async def test_signer_wraps_secret_resolution_without_leaking_material() -> None:
    manager, metadata, subscription, delivery, signer = await _services("never-leak-this")
    revoker = SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"secret.revoke"}),
    )
    assert await manager.revoke(metadata.ref, revoker, reason="compromised")

    with pytest.raises(WebhookSigningError, match="webhook signing failed") as raised:
        await signer.sign(delivery, subscription, attempt=1)

    assert "never-leak-this" not in str(raised.value)
    assert "never-leak-this" not in repr(raised.value)
    assert (await manager.snapshot()).issued_leases == 0


@pytest.mark.asyncio
async def test_signer_rejects_empty_or_unsupported_secret_material() -> None:
    for value in ("", object()):
        _, _, subscription, delivery, signer = await _services(value)
        with pytest.raises(WebhookSigningError, match="webhook signing failed"):
            await signer.sign(delivery, subscription, attempt=1)


@pytest.mark.asyncio
async def test_signer_preserves_cancellation() -> None:
    class CancelledSecretsManager(SecretsManager):
        async def lease(
            self,
            ref: SecretRef,
            context: SecurityContext,
            *,
            ttl: timedelta | None = None,
        ) -> SecretLease:
            del ref, context, ttl
            await asyncio.sleep(0)
            raise asyncio.CancelledError

    manager = CancelledSecretsManager()
    subscription = _subscription(SecretRef("release-webhook", "integrations", 1))
    delivery = _delivery(subscription)
    signer = WebhookSigner(secrets=manager, context=_context())

    with pytest.raises(asyncio.CancelledError):
        await signer.sign(delivery, subscription, attempt=1)


@pytest.mark.asyncio
async def test_signer_fails_closed_when_lease_cleanup_fails() -> None:
    class CleanupFailingSecretsManager(SecretsManager):
        async def revoke_lease(self, *args: object, **kwargs: object) -> bool:
            await asyncio.sleep(0)
            raise RuntimeError("sensitive cleanup detail")

    manager = CleanupFailingSecretsManager(clock=lambda: _SIGNING_TIME)
    admin = SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"secret.create"}),
    )
    metadata = await manager.create(
        SecretRef("release-webhook", "integrations"),
        SecretValue("cleanup-key"),
        admin,
    )
    subscription = _subscription(metadata.ref)
    delivery = _delivery(subscription)
    signer = WebhookSigner(
        secrets=manager,
        context=_context(),
        clock=lambda: _SIGNING_TIME,
    )

    with pytest.raises(WebhookSigningError, match="lease cleanup failed") as raised:
        await signer.sign(delivery, subscription, attempt=1)

    assert "cleanup-key" not in str(raised.value)
    assert "sensitive cleanup detail" not in str(raised.value)


def test_timestamp_and_verifier_reject_noncanonical_wire_values() -> None:
    assert format_webhook_timestamp(_SIGNING_TIME) == "2026-07-24T12:00:01Z"
    body = b'{"ok":true}'
    signature_input = canonical_webhook_signature_input(
        timestamp=_SIGNING_TIME,
        delivery_id=_DELIVERY_ID,
        attempt=1,
        body=body,
    )
    digest = hmac.new(b"key", signature_input, hashlib.sha256).hexdigest()
    signature = f"hmac-sha256-v1={digest}"

    invalid_values = (
        {
            "signature": signature.upper(),
            "timestamp": "2026-07-24T12:00:01Z",
            "delivery_id": str(_DELIVERY_ID),
            "attempt": "1",
        },
        {
            "signature": signature,
            "timestamp": "2026-07-24T12:00:01+00:00",
            "delivery_id": str(_DELIVERY_ID),
            "attempt": "1",
        },
        {
            "signature": signature,
            "timestamp": "2026-07-24T12:00:01Z",
            "delivery_id": str(_DELIVERY_ID),
            "attempt": "01",
        },
    )
    for values in invalid_values:
        assert not verify_webhook_signature(
            "key",
            body=body,
            **cast(Any, values),
        )
