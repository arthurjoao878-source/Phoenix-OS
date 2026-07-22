from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountAuthorization,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenRotation,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountStatus,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRejectionReason,
)
from phoenix_os.control_plane.service_account_throttling import (
    ControlPlaneServiceAccountThrottleBlockReason,
)
from phoenix_os.events import BusClosedError, EventBus

_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class ControlPlaneServiceAccountAuditEvent(StrEnum):
    """Fixed service-account security events."""

    AUTHENTICATION_SUCCEEDED = "control-plane.service-account.authentication.succeeded"
    AUTHENTICATION_REJECTED = "control-plane.service-account.authentication.rejected"
    AUTHORIZATION_ALLOWED = "control-plane.service-account.authorization.allowed"
    AUTHORIZATION_DENIED = "control-plane.service-account.authorization.denied"
    THROTTLE_BLOCKED = "control-plane.service-account.throttle.blocked"
    REPLAY_REJECTED = "control-plane.service-account.replay.rejected"
    TOKEN_ISSUED = "control-plane.service-account.token.issued"
    TOKEN_ROTATED = "control-plane.service-account.token.rotated"
    TOKEN_REVOKED = "control-plane.service-account.token.revoked"
    TOKEN_EXPIRED = "control-plane.service-account.token.expired"
    ACCOUNT_CREATED = "control-plane.service-account.account.created"
    ACCOUNT_UPDATED = "control-plane.service-account.account.updated"
    ACCOUNT_DISABLED = "control-plane.service-account.account.disabled"
    ACCOUNT_ENABLED = "control-plane.service-account.account.enabled"
    ACCOUNT_REVOKED = "control-plane.service-account.account.revoked"


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountAuditSnapshot:
    """Identifier-free audit delivery counters."""

    emitted: int
    dropped: int
    last_event: ControlPlaneServiceAccountAuditEvent | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.emitted < 0 or self.dropped < 0:
            raise ValueError("service-account audit counters cannot be negative")

        event = (
            None
            if self.last_event is None
            else ControlPlaneServiceAccountAuditEvent(self.last_event)
        )

        if self.schema_version != 1:
            raise ValueError("unsupported service-account audit snapshot schema version")

        object.__setattr__(
            self,
            "last_event",
            event,
        )


class ControlPlaneServiceAccountAuditProtector:
    """Create domain-separated HMAC references."""

    def __init__(
        self,
        secret: bytes | bytearray | memoryview,
    ) -> None:
        key = bytes(secret)

        if len(key) < 32 or len(key) > 128:
            raise ValueError("service-account audit secret must contain 32 to 128 bytes")

        self._secret = key

    def account(
        self,
        account_id: object,
    ) -> str:
        return self._protect(
            "account",
            str(account_id),
        )

    def token(
        self,
        token_id: object,
    ) -> str:
        return self._protect(
            "token",
            str(token_id),
        )

    def client(
        self,
        context: (ControlPlaneServiceAccountAuthenticationContext),
    ) -> str:
        if not isinstance(
            context,
            ControlPlaneServiceAccountAuthenticationContext,
        ):
            raise TypeError("service-account audit client requires trusted transport context")

        return self._protect(
            "client",
            context.client_address,
        )

    def resource(
        self,
        resource: str,
    ) -> str:
        if not isinstance(resource, str):
            raise TypeError("service-account audit resource must be str")

        if not resource:
            raise ValueError("service-account audit resource must not be blank")

        return self._protect(
            "resource",
            resource,
        )

    def __repr__(self) -> str:
        return "ControlPlaneServiceAccountAuditProtector(<redacted>)"

    def _protect(
        self,
        kind: str,
        value: str,
    ) -> str:
        material = (f"phoenix-service-account-audit:v1:{kind}:{value}").encode()

        fingerprint = hmac.new(
            self._secret,
            material,
            hashlib.sha256,
        ).hexdigest()

        if _FINGERPRINT_PATTERN.fullmatch(fingerprint) is None:
            raise RuntimeError("service-account audit protection failed")

        return fingerprint


class ControlPlaneServiceAccountAudit:
    """Emit allowlisted credential-free security facts."""

    def __init__(
        self,
        events: EventBus | None,
        protector: (ControlPlaneServiceAccountAuditProtector),
    ) -> None:
        if not isinstance(
            protector,
            ControlPlaneServiceAccountAuditProtector,
        ):
            raise TypeError("service-account audit requires an audit protector")

        self._events = events
        self._protector = protector
        self._emitted = 0
        self._dropped = 0
        self._last_event: ControlPlaneServiceAccountAuditEvent | None = None
        self._lock = asyncio.Lock()

    async def authentication_succeeded(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        transport: (ControlPlaneServiceAccountAuthenticationContext),
    ) -> None:
        payload = self._authentication_payload(authentication)
        payload.update(self._transport_payload(transport))
        payload.update(
            {
                "action": "service-account.authenticate",
                "outcome": "succeeded",
                "result": "accepted",
            }
        )

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.AUTHENTICATION_SUCCEEDED,
            payload,
        )

    async def authentication_rejected(
        self,
        transport: (ControlPlaneServiceAccountAuthenticationContext),
    ) -> None:
        payload = self._transport_payload(transport)
        payload.update(
            {
                "action": "service-account.authenticate",
                "outcome": "denied",
                "result": "rejected",
            }
        )

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.AUTHENTICATION_REJECTED,
            payload,
        )

    async def authorization_decided(
        self,
        context: ControlPlaneServiceAccountApiContext,
        decision: ControlPlaneServiceAccountAuthorization,
    ) -> None:
        if not isinstance(
            context,
            ControlPlaneServiceAccountApiContext,
        ):
            raise TypeError("service-account authorization audit requires trusted API context")

        if not isinstance(
            decision,
            ControlPlaneServiceAccountAuthorization,
        ):
            raise TypeError("service-account authorization audit requires authorization decision")

        event = (
            ControlPlaneServiceAccountAuditEvent.AUTHORIZATION_ALLOWED
            if decision.allowed
            else ControlPlaneServiceAccountAuditEvent.AUTHORIZATION_DENIED
        )

        payload = self._authentication_payload(context.authentication)
        payload.update(
            {
                "action": decision.action,
                "outcome": ("allowed" if decision.allowed else "denied"),
                "result": ("accepted" if decision.allowed else "rejected"),
                "resource_fingerprint": (self._protector.resource(decision.resource)),
            }
        )

        await self._emit(
            event,
            payload,
            correlation_id=context.correlation_id,
            causation_id=context.request_id,
        )

    async def throttle_blocked(
        self,
        reason: (ControlPlaneServiceAccountThrottleBlockReason),
        *,
        transport: (ControlPlaneServiceAccountAuthenticationContext | None) = None,
        authentication: (ControlPlaneServiceAccountAuthentication | None) = None,
    ) -> None:
        normalized_reason = ControlPlaneServiceAccountThrottleBlockReason(reason)

        payload: dict[str, object] = {
            "action": "service-account.authenticate",
            "outcome": "denied",
            "result": normalized_reason.value,
        }

        if transport is not None:
            payload.update(self._transport_payload(transport))

        if authentication is not None:
            payload.update(self._authentication_payload(authentication))

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.THROTTLE_BLOCKED,
            payload,
        )

    async def replay_rejected(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        reason: (ControlPlaneServiceAccountReplayRejectionReason),
        *,
        context: (ControlPlaneServiceAccountApiContext | None) = None,
    ) -> None:
        normalized_reason = ControlPlaneServiceAccountReplayRejectionReason(reason)

        payload = self._authentication_payload(authentication)
        payload.update(
            {
                "action": "service-account.request",
                "outcome": "denied",
                "result": normalized_reason.value,
            }
        )

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.REPLAY_REJECTED,
            payload,
            correlation_id=(None if context is None else context.correlation_id),
            causation_id=(None if context is None else context.request_id),
        )

    async def token_issued(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> None:
        if (
            not isinstance(
                metadata,
                ControlPlaneApiTokenMetadata,
            )
            or metadata.status is not ControlPlaneApiTokenStatus.ACTIVE
        ):
            raise ValueError("issued audit fact requires active API-token metadata")

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.TOKEN_ISSUED,
            self._token_payload(
                metadata,
                action="service-account.token.issue",
                result="issued",
            ),
        )

    async def token_rotated(
        self,
        rotation: ControlPlaneApiTokenRotation,
    ) -> None:
        if not isinstance(
            rotation,
            ControlPlaneApiTokenRotation,
        ):
            raise TypeError("rotation audit fact requires API-token rotation")

        payload: dict[str, object] = {
            "action": "service-account.token.rotate",
            "outcome": "succeeded",
            "result": ("overlap" if rotation.overlapping else "immediate"),
            "account_fingerprint": (self._protector.account(rotation.successor.service_account_id)),
            "predecessor_token_fingerprint": (self._protector.token(rotation.predecessor.id)),
            "successor_token_fingerprint": (self._protector.token(rotation.successor.id)),
            "successor_token_version": (rotation.successor.token_version),
            "restriction_applied": (rotation.successor.restriction.restricted),
        }

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.TOKEN_ROTATED,
            payload,
        )

    async def token_revoked(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> None:
        if (
            not isinstance(
                metadata,
                ControlPlaneApiTokenMetadata,
            )
            or metadata.status is not ControlPlaneApiTokenStatus.REVOKED
        ):
            raise ValueError("revocation audit fact requires revoked API-token metadata")

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.TOKEN_REVOKED,
            self._token_payload(
                metadata,
                action="service-account.token.revoke",
                result="revoked",
            ),
        )

    async def token_expired(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> None:
        if (
            not isinstance(
                metadata,
                ControlPlaneApiTokenMetadata,
            )
            or metadata.status is not ControlPlaneApiTokenStatus.EXPIRED
        ):
            raise ValueError("expiration audit fact requires expired API-token metadata")

        await self._emit(
            ControlPlaneServiceAccountAuditEvent.TOKEN_EXPIRED,
            self._token_payload(
                metadata,
                action="service-account.token.expire",
                result="expired",
            ),
        )

    async def account_created(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        await self._account_event(
            ControlPlaneServiceAccountAuditEvent.ACCOUNT_CREATED,
            record,
            action="service-account.create",
            result="created",
            expected_status=(ControlPlaneServiceAccountStatus.ACTIVE),
        )

    async def account_updated(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        await self._account_event(
            ControlPlaneServiceAccountAuditEvent.ACCOUNT_UPDATED,
            record,
            action="service-account.update",
            result="updated",
            expected_status=None,
        )

    async def account_disabled(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        await self._account_event(
            ControlPlaneServiceAccountAuditEvent.ACCOUNT_DISABLED,
            record,
            action="service-account.disable",
            result="disabled",
            expected_status=(ControlPlaneServiceAccountStatus.DISABLED),
        )

    async def account_enabled(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        await self._account_event(
            ControlPlaneServiceAccountAuditEvent.ACCOUNT_ENABLED,
            record,
            action="service-account.enable",
            result="enabled",
            expected_status=(ControlPlaneServiceAccountStatus.ACTIVE),
        )

    async def account_revoked(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        await self._account_event(
            ControlPlaneServiceAccountAuditEvent.ACCOUNT_REVOKED,
            record,
            action="service-account.revoke",
            result="revoked",
            expected_status=(ControlPlaneServiceAccountStatus.REVOKED),
        )

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountAuditSnapshot:
        async with self._lock:
            return ControlPlaneServiceAccountAuditSnapshot(
                emitted=self._emitted,
                dropped=self._dropped,
                last_event=self._last_event,
            )

    async def _account_event(
        self,
        event: ControlPlaneServiceAccountAuditEvent,
        record: ControlPlaneServiceAccountRecord,
        *,
        action: str,
        result: str,
        expected_status: (ControlPlaneServiceAccountStatus | None),
    ) -> None:
        if not isinstance(
            record,
            ControlPlaneServiceAccountRecord,
        ):
            raise TypeError("account audit fact requires service-account record")

        if expected_status is not None and record.status is not expected_status:
            raise ValueError("service-account status does not match audit event")

        await self._emit(
            event,
            {
                "action": action,
                "outcome": "succeeded",
                "result": result,
                "account_fingerprint": (self._protector.account(record.id)),
                "account_revision": record.revision,
                "account_status": record.status.value,
            },
        )

    def _authentication_payload(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
    ) -> dict[str, object]:
        if not isinstance(
            authentication,
            ControlPlaneServiceAccountAuthentication,
        ):
            raise TypeError("service-account audit requires authentication evidence")

        return {
            "account_fingerprint": (self._protector.account(authentication.service_account_id)),
            "token_fingerprint": (self._protector.token(authentication.token_id)),
            "token_version": (authentication.token_version),
            "account_revision": (authentication.account_revision),
            "token_revision": (authentication.token_revision),
            "restriction_applied": (authentication.restriction_applied),
        }

    def _transport_payload(
        self,
        context: (ControlPlaneServiceAccountAuthenticationContext),
    ) -> dict[str, object]:
        if not isinstance(
            context,
            ControlPlaneServiceAccountAuthenticationContext,
        ):
            raise TypeError("service-account audit transport requires trusted context")

        return {
            "client_fingerprint": (self._protector.client(context)),
            "identity_source": (context.identity_source.value),
            "mutual_tls": context.mutual_tls,
        }

    def _token_payload(
        self,
        metadata: ControlPlaneApiTokenMetadata,
        *,
        action: str,
        result: str,
    ) -> dict[str, object]:
        return {
            "action": action,
            "outcome": "succeeded",
            "result": result,
            "account_fingerprint": (self._protector.account(metadata.service_account_id)),
            "token_fingerprint": (self._protector.token(metadata.id)),
            "token_version": metadata.token_version,
            "token_status": metadata.status.value,
            "restriction_applied": (metadata.restriction.restricted),
        }

    async def _emit(
        self,
        event: ControlPlaneServiceAccountAuditEvent,
        payload: Mapping[str, object],
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> None:
        emitted = False

        if self._events is not None:
            try:
                await self._events.emit(
                    event.value,
                    source=("phoenix.control-plane.service-account"),
                    payload=dict(payload),
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
                emitted = True
            except (BusClosedError, RuntimeError):
                emitted = False

        async with self._lock:
            if emitted:
                self._emitted += 1
            else:
                self._dropped += 1

            self._last_event = event
