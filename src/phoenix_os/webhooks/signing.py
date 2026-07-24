"""Versioned HMAC signing for outbound Phoenix webhook requests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID

from phoenix_os.policy.contracts import SecurityContext
from phoenix_os.secrets.contracts import SecretLease
from phoenix_os.secrets.manager import SecretsManager
from phoenix_os.webhooks.contracts import (
    MAX_WEBHOOK_RETRY_ATTEMPTS,
    WebhookDelivery,
    WebhookSignatureScheme,
    WebhookSubscription,
)
from phoenix_os.webhooks.errors import WebhookSigningError

WEBHOOK_ATTEMPT_HEADER = "X-Phoenix-Webhook-Attempt"
WEBHOOK_CONTENT_TYPE = "application/json"
WEBHOOK_CONTENT_TYPE_HEADER = "Content-Type"
WEBHOOK_CORRELATION_ID_HEADER = "X-Phoenix-Correlation-Id"
WEBHOOK_ID_HEADER = "X-Phoenix-Webhook-Id"
WEBHOOK_KEY_VERSION_HEADER = "X-Phoenix-Webhook-Key-Version"
WEBHOOK_SIGNATURE_HEADER = "X-Phoenix-Webhook-Signature"
WEBHOOK_TIMESTAMP_HEADER = "X-Phoenix-Webhook-Timestamp"
WEBHOOK_USER_AGENT = "Phoenix-OS-Webhook/0.24"
WEBHOOK_USER_AGENT_HEADER = "User-Agent"

_SIGNATURE_PREFIX = b"phoenix-webhook-signature-v1"
_SIGNATURE_PATTERN = re.compile(r"hmac-sha256-v1=[0-9a-f]{64}\Z")
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

type WebhookSigningClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True, repr=False)
class WebhookSignedRequest:
    """Ephemeral signed request material that is never persisted."""

    delivery_id: UUID
    subscription_id: UUID
    attempt: int
    timestamp: datetime
    key_version: int
    scheme: WebhookSignatureScheme
    body: bytes = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.delivery_id, UUID):
            raise TypeError("webhook signed request delivery_id must be UUID")
        if not isinstance(self.subscription_id, UUID):
            raise TypeError("webhook signed request subscription_id must be UUID")
        if self.attempt <= 0 or self.attempt > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook signed request attempt is outside supported bounds")
        timestamp = _normalize_timestamp(self.timestamp)
        if self.key_version <= 0:
            raise ValueError("webhook signed request key version must be positive")
        scheme = WebhookSignatureScheme(self.scheme)
        if type(self.body) is not bytes or not self.body:
            raise ValueError("webhook signed request body must be non-empty bytes")
        headers = _freeze_headers(self.headers)
        _validate_signed_headers(
            headers,
            delivery_id=self.delivery_id,
            attempt=self.attempt,
            timestamp=timestamp,
            key_version=self.key_version,
            scheme=scheme,
        )
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "headers", headers)

    def __repr__(self) -> str:
        return (
            "WebhookSignedRequest("
            f"delivery_id={self.delivery_id!r}, "
            f"subscription_id={self.subscription_id!r}, "
            f"attempt={self.attempt}, "
            f"timestamp={self.timestamp!r}, "
            f"key_version={self.key_version}, "
            f"scheme={self.scheme!r}, "
            "body=<redacted>, headers=<redacted>)"
        )


class WebhookSigner:
    """Resolve an exact secret version and sign one immutable delivery body."""

    def __init__(
        self,
        *,
        secrets: SecretsManager,
        context: SecurityContext,
        clock: WebhookSigningClock | None = None,
    ) -> None:
        if not isinstance(secrets, SecretsManager):
            raise TypeError("secrets must be SecretsManager")
        if not isinstance(context, SecurityContext):
            raise TypeError("webhook signing context must be SecurityContext")
        if not context.authenticated:
            raise ValueError("webhook signing context must be authenticated")
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("webhook signing clock must be callable")
        self._secrets = secrets
        self._context = context
        self._clock = resolved_clock

    async def sign(
        self,
        delivery: WebhookDelivery,
        subscription: WebhookSubscription,
        *,
        attempt: int,
        timestamp: datetime | None = None,
    ) -> WebhookSignedRequest:
        if not isinstance(delivery, WebhookDelivery):
            raise TypeError("delivery must be WebhookDelivery")
        if not isinstance(subscription, WebhookSubscription):
            raise TypeError("subscription must be WebhookSubscription")
        if delivery.subscription_id != subscription.id:
            raise ValueError("webhook delivery belongs to another subscription")
        if attempt <= 0 or attempt > MAX_WEBHOOK_RETRY_ATTEMPTS:
            raise ValueError("webhook signing attempt is outside supported bounds")
        if subscription.signing.scheme is not WebhookSignatureScheme.HMAC_SHA256_V1:
            raise WebhookSigningError("unsupported webhook signature scheme")

        resolved_timestamp = self._now() if timestamp is None else _normalize_timestamp(timestamp)
        lease_context = replace(
            self._context,
            correlation_id=delivery.correlation_id or self._context.correlation_id,
            causation_id=delivery.id,
        )
        lease: SecretLease | None = None
        primary_failure = False
        key_material: bytearray | None = None

        try:
            lease = await self._secrets.lease(
                subscription.signing.secret_ref,
                lease_context,
                ttl=subscription.signing.lease_ttl,
            )
            if lease.ref != subscription.signing.secret_ref:
                raise WebhookSigningError("webhook signing resolved an unexpected secret version")

            key_material = _secret_key_bytes(lease.value.reveal())
            signature_input = canonical_webhook_signature_input(
                timestamp=resolved_timestamp,
                delivery_id=delivery.id,
                attempt=attempt,
                body=delivery.canonical_body,
            )
            digest = hmac.new(key_material, signature_input, hashlib.sha256).hexdigest()
            signature = f"{subscription.signing.scheme.value}={digest}"
            headers = {
                WEBHOOK_CONTENT_TYPE_HEADER: WEBHOOK_CONTENT_TYPE,
                WEBHOOK_USER_AGENT_HEADER: WEBHOOK_USER_AGENT,
                WEBHOOK_ID_HEADER: str(delivery.id),
                WEBHOOK_TIMESTAMP_HEADER: format_webhook_timestamp(resolved_timestamp),
                WEBHOOK_SIGNATURE_HEADER: signature,
                WEBHOOK_KEY_VERSION_HEADER: str(subscription.signing.key_version),
                WEBHOOK_ATTEMPT_HEADER: str(attempt),
            }
            if delivery.correlation_id is not None:
                headers[WEBHOOK_CORRELATION_ID_HEADER] = delivery.correlation_id

            return WebhookSignedRequest(
                delivery_id=delivery.id,
                subscription_id=subscription.id,
                attempt=attempt,
                timestamp=resolved_timestamp,
                key_version=subscription.signing.key_version,
                scheme=subscription.signing.scheme,
                body=delivery.canonical_body,
                headers=headers,
            )
        except asyncio.CancelledError:
            primary_failure = True
            raise
        except WebhookSigningError:
            primary_failure = True
            raise
        except Exception as exception:
            primary_failure = True
            raise WebhookSigningError("webhook signing failed") from exception
        finally:
            if key_material is not None:
                key_material[:] = b"\x00" * len(key_material)
            if lease is not None:
                try:
                    await self._secrets.revoke_lease(
                        lease.id,
                        lease_context,
                        reason="webhook signing complete",
                    )
                except asyncio.CancelledError:
                    if not primary_failure:
                        raise
                except Exception as exception:
                    if not primary_failure:
                        raise WebhookSigningError(
                            "webhook signing lease cleanup failed"
                        ) from exception

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime):
            raise TypeError("webhook signing clock must return datetime")
        return _normalize_timestamp(now)


def canonical_webhook_signature_input(
    *,
    timestamp: datetime,
    delivery_id: UUID,
    attempt: int,
    body: bytes,
) -> bytes:
    """Return the versioned canonical bytes covered by the request signature."""

    normalized_timestamp = _normalize_timestamp(timestamp)
    if not isinstance(delivery_id, UUID):
        raise TypeError("webhook signature delivery_id must be UUID")
    if attempt <= 0 or attempt > MAX_WEBHOOK_RETRY_ATTEMPTS:
        raise ValueError("webhook signature attempt is outside supported bounds")
    if type(body) is not bytes or not body:
        raise ValueError("webhook signature body must be non-empty bytes")

    body_digest = hashlib.sha256(body).hexdigest()
    return b"\n".join(
        (
            _SIGNATURE_PREFIX,
            format_webhook_timestamp(normalized_timestamp).encode("ascii"),
            str(delivery_id).encode("ascii"),
            str(attempt).encode("ascii"),
            body_digest.encode("ascii"),
        )
    )


def format_webhook_timestamp(value: datetime) -> str:
    """Format one aware timestamp in the exact webhook wire representation."""

    normalized = _normalize_timestamp(value)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_webhook_signature(
    secret: object,
    *,
    signature: str,
    timestamp: str,
    delivery_id: str,
    attempt: str,
    body: bytes,
) -> bool:
    """Verify one webhook signature using constant-time digest comparison."""

    key_material: bytearray | None = None
    try:
        if not isinstance(signature, str) or _SIGNATURE_PATTERN.fullmatch(signature) is None:
            return False
        parsed_timestamp = _parse_webhook_timestamp(timestamp)
        parsed_delivery_id = UUID(delivery_id)
        parsed_attempt = int(attempt)
        if str(parsed_attempt) != attempt:
            return False
        key_material = _secret_key_bytes(secret)
        signature_input = canonical_webhook_signature_input(
            timestamp=parsed_timestamp,
            delivery_id=parsed_delivery_id,
            attempt=parsed_attempt,
            body=body,
        )
        digest = hmac.new(key_material, signature_input, hashlib.sha256).hexdigest()
        expected = f"{WebhookSignatureScheme.HMAC_SHA256_V1.value}={digest}"
        return hmac.compare_digest(expected, signature)
    except (TypeError, ValueError):
        return False
    finally:
        if key_material is not None:
            key_material[:] = b"\x00" * len(key_material)


def _normalize_timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("webhook signing timestamp must be datetime")
    if value.tzinfo is None:
        raise ValueError("webhook signing timestamp must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _parse_webhook_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid webhook timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _secret_key_bytes(value: object) -> bytearray:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    elif isinstance(value, bytearray):
        encoded = bytes(value)
    elif isinstance(value, memoryview):
        encoded = value.tobytes()
    else:
        raise TypeError("webhook signing secret must be text or bytes")
    if not encoded:
        raise ValueError("webhook signing secret must not be empty")
    return bytearray(encoded)


def _freeze_headers(values: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(values, Mapping):
        raise TypeError("webhook signed request headers must be a mapping")
    result: dict[str, str] = {}
    for name, value in values.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("webhook signed request headers must contain strings")
        if not name or not value:
            raise ValueError("webhook signed request headers must not be blank")
        if name in result:
            raise ValueError("webhook signed request headers must be unique")
        result[name] = value
    return MappingProxyType(result)


def _validate_signed_headers(
    headers: Mapping[str, str],
    *,
    delivery_id: UUID,
    attempt: int,
    timestamp: datetime,
    key_version: int,
    scheme: WebhookSignatureScheme,
) -> None:
    required = {
        WEBHOOK_CONTENT_TYPE_HEADER,
        WEBHOOK_USER_AGENT_HEADER,
        WEBHOOK_ID_HEADER,
        WEBHOOK_TIMESTAMP_HEADER,
        WEBHOOK_SIGNATURE_HEADER,
        WEBHOOK_KEY_VERSION_HEADER,
        WEBHOOK_ATTEMPT_HEADER,
    }
    if not required.issubset(headers):
        raise ValueError("webhook signed request is missing required headers")
    if headers[WEBHOOK_CONTENT_TYPE_HEADER] != WEBHOOK_CONTENT_TYPE:
        raise ValueError("webhook signed request content type is invalid")
    if headers[WEBHOOK_USER_AGENT_HEADER] != WEBHOOK_USER_AGENT:
        raise ValueError("webhook signed request user agent is invalid")
    if headers[WEBHOOK_ID_HEADER] != str(delivery_id):
        raise ValueError("webhook signed request delivery header is inconsistent")
    if headers[WEBHOOK_TIMESTAMP_HEADER] != format_webhook_timestamp(timestamp):
        raise ValueError("webhook signed request timestamp header is inconsistent")
    if headers[WEBHOOK_KEY_VERSION_HEADER] != str(key_version):
        raise ValueError("webhook signed request key-version header is inconsistent")
    if headers[WEBHOOK_ATTEMPT_HEADER] != str(attempt):
        raise ValueError("webhook signed request attempt header is inconsistent")
    signature = headers[WEBHOOK_SIGNATURE_HEADER]
    if _SIGNATURE_PATTERN.fullmatch(signature) is None:
        raise ValueError("webhook signed request signature header is invalid")
    if not signature.startswith(f"{scheme.value}="):
        raise ValueError("webhook signed request signature scheme is inconsistent")


def _utc_now() -> datetime:
    return datetime.now(UTC)
