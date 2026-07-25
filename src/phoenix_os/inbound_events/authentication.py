"""Authentication boundary for secure inbound event sources."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
    control_plane_service_account_api_context,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
    ControlPlaneServiceAccountRequestNonce,
)
from phoenix_os.inbound_events.contracts import (
    InboundAuthenticationMode,
    InboundEventSource,
    InboundHmacPolicy,
    InboundHmacScheme,
    InboundRequestEvidence,
    InboundServiceAccountPolicy,
)
from phoenix_os.inbound_events.errors import InboundAuthenticationRejectedError
from phoenix_os.policy.contracts import SecurityContext
from phoenix_os.secrets.contracts import SecretLease, SecretRef
from phoenix_os.secrets.manager import SecretsManager

INBOUND_KEY_VERSION_HEADER = "X-Phoenix-Inbound-Key-Version"
INBOUND_NONCE_HEADER = "X-Phoenix-Inbound-Nonce"
INBOUND_REQUEST_ID_HEADER = "X-Phoenix-Inbound-Request-Id"
INBOUND_SIGNATURE_HEADER = "X-Phoenix-Inbound-Signature"
INBOUND_SOURCE_EVENT_ID_HEADER = "X-Phoenix-Inbound-Event-Id"
INBOUND_TIMESTAMP_HEADER = "X-Phoenix-Inbound-Timestamp"

_SIGNATURE_PREFIX = b"phoenix-inbound-signature-v1"
_SIGNATURE_PATTERN = re.compile(r"hmac-sha256-v1=[0-9a-f]{64}\Z")
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_IDENTIFIER_PATTERN = re.compile(r"[\x21-\x7e]{1,256}\Z")
_KEY_VERSION_PATTERN = re.compile(r"[1-9][0-9]{0,9}\Z")
_DUMMY_SECRET = b"phoenix-inbound-authentication-dummy-key-v1"

type InboundAuthenticationClock = Callable[[], datetime]


class InboundServiceAccountAuthenticator(Protocol):
    """RFC-0023 bearer authentication boundary."""

    def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext | None = None,
    ) -> Awaitable[ControlPlaneServiceAccountAuthentication | None]: ...


class InboundServiceAccountReplayBoundary(Protocol):
    """RFC-0023 nonce, timestamp, and request replay boundary."""

    def admit(
        self,
        authentication: ControlPlaneServiceAccountAuthentication,
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> Awaitable[None]: ...


class InboundServiceAccountPolicyBoundary(Protocol):
    """Exact token grants plus central policy approval."""

    def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> Awaitable[object]: ...


@dataclass(frozen=True, slots=True)
class InboundAuthenticationResult:
    """Credential-free trusted identity produced by inbound authentication."""

    source_id: UUID
    mode: InboundAuthenticationMode
    principal: str
    authenticated_at: datetime
    key_version: int | None = None
    service_account_id: UUID | None = None
    token_id: UUID | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        mode = InboundAuthenticationMode(self.mode)
        principal = self.principal.strip()
        authenticated_at = _normalize_timestamp(self.authenticated_at)

        if not principal or principal != self.principal:
            raise ValueError("inbound authentication principal is invalid")
        if any(ord(character) < 32 or ord(character) == 127 for character in principal):
            raise ValueError("inbound authentication principal contains control characters")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound authentication result schema version")

        if mode is InboundAuthenticationMode.HMAC_SHA256:
            expected = f"inbound-source:{self.source_id}"
            if principal != expected:
                raise ValueError("inbound HMAC principal does not match its source")
            if self.key_version is None or self.key_version <= 0:
                raise ValueError("inbound HMAC authentication requires a key version")
            if self.service_account_id is not None or self.token_id is not None:
                raise ValueError("inbound HMAC authentication cannot contain service-account ids")
        else:
            if not principal.startswith("service-account:"):
                raise ValueError("inbound service-account principal is invalid")
            if self.key_version is not None:
                raise ValueError(
                    "inbound service-account authentication cannot contain a key version"
                )
            if self.service_account_id is None or self.token_id is None:
                raise ValueError("inbound service-account authentication requires stable ids")

        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "authenticated_at", authenticated_at)


class InboundAuthenticationVerifier:
    """Verify HMAC or RFC-0023 credentials without exposing failure details."""

    def __init__(
        self,
        *,
        secrets: SecretsManager | None = None,
        security_context: SecurityContext | None = None,
        service_account_authenticator: InboundServiceAccountAuthenticator | None = None,
        service_account_replay: InboundServiceAccountReplayBoundary | None = None,
        service_account_policy: InboundServiceAccountPolicyBoundary | None = None,
        clock: InboundAuthenticationClock | None = None,
    ) -> None:
        if (secrets is None) != (security_context is None):
            raise ValueError(
                "inbound HMAC verification requires both SecretsManager and SecurityContext"
            )
        if secrets is not None and not isinstance(secrets, SecretsManager):
            raise TypeError("inbound secrets boundary must be SecretsManager")
        if security_context is not None:
            if not isinstance(security_context, SecurityContext):
                raise TypeError("inbound HMAC security context must be SecurityContext")
            if not security_context.authenticated:
                raise ValueError("inbound HMAC security context must be authenticated")

        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("inbound authentication clock must be callable")

        self._secrets = secrets
        self._security_context = security_context
        self._service_account_authenticator = service_account_authenticator
        self._service_account_replay = service_account_replay
        self._service_account_policy = service_account_policy
        self._clock = resolved_clock

    async def verify(
        self,
        source: InboundEventSource | None,
        evidence: InboundRequestEvidence,
        body: bytes,
        *,
        signature: str | None = None,
        key_version: str | None = None,
        authorization: str | None = None,
        service_account_context: ControlPlaneServiceAccountAuthenticationContext | None = None,
        request_target: str | None = None,
    ) -> InboundAuthenticationResult:
        """Return trusted identity or one generic authentication rejection."""

        if source is not None and not isinstance(source, InboundEventSource):
            raise TypeError("inbound source has an invalid type")
        if not isinstance(evidence, InboundRequestEvidence):
            raise TypeError("inbound request evidence has an invalid type")
        if type(body) is not bytes:
            raise TypeError("inbound request body must be bytes")

        now = self._now()
        actual_body_digest = hashlib.sha256(body).hexdigest()
        body_matches = hmac.compare_digest(actual_body_digest, evidence.body_sha256)

        if source is None:
            _dummy_signature_work(signature, evidence, body)
            raise InboundAuthenticationRejectedError

        source_matches = evidence.source_id == source.id
        timestamp_fresh = (
            now - source.timestamp_skew
            <= _normalize_timestamp(evidence.timestamp)
            <= now + source.timestamp_skew
        )

        if isinstance(source.authentication, InboundHmacPolicy):
            result = await self._verify_hmac(
                source,
                evidence,
                body,
                signature=signature,
                key_version=key_version,
                authorization=authorization,
                now=now,
            )
        else:
            result = await self._verify_service_account(
                source,
                evidence,
                actual_body_digest,
                signature=signature,
                key_version=key_version,
                authorization=authorization,
                service_account_context=service_account_context,
                request_target=request_target,
                now=now,
            )

        if not source.accepting or not source_matches or not body_matches or not timestamp_fresh:
            raise InboundAuthenticationRejectedError

        return result

    async def _verify_hmac(
        self,
        source: InboundEventSource,
        evidence: InboundRequestEvidence,
        body: bytes,
        *,
        signature: str | None,
        key_version: str | None,
        authorization: str | None,
        now: datetime,
    ) -> InboundAuthenticationResult:
        policy = source.authentication
        if not isinstance(policy, InboundHmacPolicy):  # pragma: no cover
            raise RuntimeError("inbound HMAC verifier received another authentication mode")

        parsed_version = _parse_key_version(key_version)
        valid_signature_shape = (
            isinstance(signature, str) and _SIGNATURE_PATTERN.fullmatch(signature) is not None
        )
        selected_ref = _select_hmac_ref(policy, parsed_version, now=now)

        if (
            authorization is not None
            or not valid_signature_shape
            or parsed_version is None
            or selected_ref is None
            or self._secrets is None
            or self._security_context is None
        ):
            _dummy_signature_work(signature, evidence, body)
            raise InboundAuthenticationRejectedError

        lease_context = replace(
            self._security_context,
            correlation_id=evidence.correlation_id or self._security_context.correlation_id,
            causation_id=source.id,
        )
        lease: SecretLease | None = None
        key_material: bytearray | None = None
        primary_failure = False

        try:
            lease = await self._secrets.lease(
                selected_ref,
                lease_context,
                ttl=policy.lease_ttl,
            )
            if lease.ref != selected_ref:
                raise InboundAuthenticationRejectedError

            key_material = _secret_key_bytes(lease.value.reveal())
            expected = compute_inbound_hmac_signature(
                key_material,
                source_id=source.id,
                request_id=evidence.request_id,
                source_event_id=evidence.source_event_id,
                timestamp=evidence.timestamp,
                nonce=evidence.nonce,
                body=body,
            )
            if not isinstance(signature, str):
                raise InboundAuthenticationRejectedError
            if not hmac.compare_digest(expected, signature):
                raise InboundAuthenticationRejectedError

            return InboundAuthenticationResult(
                source_id=source.id,
                mode=InboundAuthenticationMode.HMAC_SHA256,
                principal=f"inbound-source:{source.id}",
                authenticated_at=now,
                key_version=parsed_version,
            )
        except asyncio.CancelledError:
            primary_failure = True
            raise
        except InboundAuthenticationRejectedError:
            primary_failure = True
            raise
        except Exception:
            primary_failure = True
            raise InboundAuthenticationRejectedError from None
        finally:
            if key_material is not None:
                key_material[:] = b"\x00" * len(key_material)
            if lease is not None:
                try:
                    await self._secrets.revoke_lease(
                        lease.id,
                        lease_context,
                        reason="inbound HMAC verification complete",
                    )
                except asyncio.CancelledError:
                    if not primary_failure:
                        raise
                except Exception:
                    if not primary_failure:
                        raise InboundAuthenticationRejectedError from None

    async def _verify_service_account(
        self,
        source: InboundEventSource,
        evidence: InboundRequestEvidence,
        actual_body_digest: str,
        *,
        signature: str | None,
        key_version: str | None,
        authorization: str | None,
        service_account_context: ControlPlaneServiceAccountAuthenticationContext | None,
        request_target: str | None,
        now: datetime,
    ) -> InboundAuthenticationResult:
        policy = source.authentication
        if not isinstance(policy, InboundServiceAccountPolicy):  # pragma: no cover
            raise RuntimeError("inbound service-account verifier received another mode")

        if (
            signature is not None
            or key_version is not None
            or self._service_account_authenticator is None
            or self._service_account_replay is None
            or self._service_account_policy is None
            or request_target is None
        ):
            raise InboundAuthenticationRejectedError

        try:
            authentication = await self._service_account_authenticator.authenticate(
                authorization,
                context=service_account_context,
            )
            if authentication is None:
                raise InboundAuthenticationRejectedError

            replay_request = ControlPlaneServiceAccountReplayRequest(
                nonce=ControlPlaneServiceAccountRequestNonce(evidence.nonce),
                issued_at=evidence.timestamp,
                method="POST",
                target=request_target,
                body_digest=actual_body_digest,
            )
            await self._service_account_replay.admit(authentication, replay_request)

            api_context = control_plane_service_account_api_context(
                authentication,
                request_id=_service_account_request_uuid(source.id, evidence.request_id),
                correlation_id=evidence.correlation_id,
            )
            await self._service_account_policy.enforce(
                api_context,
                action=policy.required_action,
                resource=policy.resource,
            )

            return InboundAuthenticationResult(
                source_id=source.id,
                mode=InboundAuthenticationMode.SERVICE_ACCOUNT,
                principal=authentication.principal_name,
                authenticated_at=now,
                service_account_id=authentication.service_account_id,
                token_id=authentication.token_id,
            )
        except asyncio.CancelledError:
            raise
        except InboundAuthenticationRejectedError:
            raise
        except Exception:
            raise InboundAuthenticationRejectedError from None

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime):
            raise TypeError("inbound authentication clock must return datetime")
        return _normalize_timestamp(now)


def canonical_inbound_signature_input(
    *,
    source_id: UUID,
    request_id: str,
    source_event_id: str,
    timestamp: datetime,
    nonce: str,
    body: bytes,
) -> bytes:
    """Return exact versioned bytes covered by an inbound HMAC signature."""

    if not isinstance(source_id, UUID):
        raise TypeError("inbound signature source_id must be UUID")
    normalized_request_id = _canonical_identifier(request_id, label="request id")
    normalized_source_event_id = _canonical_identifier(
        source_event_id,
        label="source event id",
    )
    normalized_nonce = _canonical_identifier(nonce, label="nonce")
    normalized_timestamp = _normalize_timestamp(timestamp)
    if type(body) is not bytes:
        raise TypeError("inbound signature body must be bytes")

    return b"\n".join(
        (
            _SIGNATURE_PREFIX,
            str(source_id).encode("ascii"),
            normalized_request_id.encode("ascii"),
            normalized_source_event_id.encode("ascii"),
            format_inbound_timestamp(normalized_timestamp).encode("ascii"),
            normalized_nonce.encode("ascii"),
            hashlib.sha256(body).hexdigest().encode("ascii"),
        )
    )


def compute_inbound_hmac_signature(
    secret: object,
    *,
    source_id: UUID,
    request_id: str,
    source_event_id: str,
    timestamp: datetime,
    nonce: str,
    body: bytes,
) -> str:
    """Compute one versioned inbound HMAC signature."""

    key_material: bytearray | None = None
    try:
        key_material = _secret_key_bytes(secret)
        signature_input = canonical_inbound_signature_input(
            source_id=source_id,
            request_id=request_id,
            source_event_id=source_event_id,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        digest = hmac.new(key_material, signature_input, hashlib.sha256).hexdigest()
        return f"{InboundHmacScheme.HMAC_SHA256_V1.value}={digest}"
    finally:
        if key_material is not None:
            key_material[:] = b"\x00" * len(key_material)


def verify_inbound_hmac_signature(
    secret: object,
    *,
    signature: str,
    source_id: UUID,
    request_id: str,
    source_event_id: str,
    timestamp: datetime,
    nonce: str,
    body: bytes,
) -> bool:
    """Verify one inbound HMAC signature with constant-time comparison."""

    try:
        if not isinstance(signature, str) or _SIGNATURE_PATTERN.fullmatch(signature) is None:
            return False
        expected = compute_inbound_hmac_signature(
            secret,
            source_id=source_id,
            request_id=request_id,
            source_event_id=source_event_id,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        return hmac.compare_digest(expected, signature)
    except (TypeError, ValueError):
        return False


def format_inbound_timestamp(value: datetime) -> str:
    """Format one aware timestamp in the exact inbound wire representation."""

    return _normalize_timestamp(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_inbound_timestamp(value: str) -> datetime:
    """Parse the exact inbound wire timestamp."""

    if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid inbound timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _select_hmac_ref(
    policy: InboundHmacPolicy,
    key_version: int | None,
    *,
    now: datetime,
) -> SecretRef | None:
    if key_version is None:
        return None
    if key_version == policy.key_version:
        return policy.secret_ref

    predecessor = policy.predecessor_secret_ref
    valid_until = policy.predecessor_valid_until
    if (
        predecessor is not None
        and predecessor.version == key_version
        and valid_until is not None
        and now <= _normalize_timestamp(valid_until)
    ):
        return predecessor
    return None


def _parse_key_version(value: str | None) -> int | None:
    if not isinstance(value, str) or _KEY_VERSION_PATTERN.fullmatch(value) is None:
        return None
    parsed = int(value)
    return parsed if str(parsed) == value else None


def _canonical_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"inbound signature {label} must be str")
    if value != value.strip() or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"inbound signature {label} is invalid")
    return value


def _normalize_timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("inbound authentication timestamp must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("inbound authentication timestamp must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0)


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
        raise TypeError("inbound HMAC secret must be text or bytes")
    if not encoded:
        raise ValueError("inbound HMAC secret must not be empty")
    return bytearray(encoded)


def _dummy_signature_work(
    signature: str | None,
    evidence: InboundRequestEvidence,
    body: bytes,
) -> None:
    expected = compute_inbound_hmac_signature(
        _DUMMY_SECRET,
        source_id=evidence.source_id,
        request_id=evidence.request_id,
        source_event_id=evidence.source_event_id,
        timestamp=evidence.timestamp,
        nonce=evidence.nonce,
        body=body,
    )
    supplied = signature if isinstance(signature, str) else ""
    hmac.compare_digest(expected, supplied)


def _service_account_request_uuid(source_id: UUID, request_id: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"phoenix-inbound:{source_id}:{request_id}")


def _utc_now() -> datetime:
    return datetime.now(UTC)
