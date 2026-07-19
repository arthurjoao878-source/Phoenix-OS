"""Durable local-operator session issuance, authentication, rotation, and revocation."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.durable_session_contracts import (
    MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionAccessClosedError,
    ControlPlaneDurableSessionConflictError,
)
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthentication
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorStatus,
)
from phoenix_os.events import BusClosedError, EventBus

type ControlPlaneDurableSessionClock = Callable[[], datetime]
type ControlPlaneDurableSessionSecretFactory = Callable[[], str]

_DUMMY_SESSION_DIGEST = hashlib.sha256(bytes(32)).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_secret_factory() -> str:
    return secrets.token_urlsafe(48)


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionGrant:
    """One-time plaintext material for a newly issued or rotated durable session."""

    session_id: UUID
    operator_id: UUID
    username: str
    token: ControlPlaneDurableSessionToken = field(repr=False)
    csrf_secret: ControlPlaneDurableCsrfSecret = field(repr=False)
    generation: int
    issued_at: datetime
    absolute_expires_at: datetime
    idle_expires_at: datetime
    rotate_after: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        username = self.username.strip().lower()
        if not username:
            raise ValueError("durable session grant username must not be blank")
        if self.generation <= 0:
            raise ValueError("durable session grant generation must be positive")
        for label, value in (
            ("issued_at", self.issued_at),
            ("absolute_expires_at", self.absolute_expires_at),
            ("idle_expires_at", self.idle_expires_at),
            ("rotate_after", self.rotate_after),
        ):
            _require_aware(value, label)
        if self.absolute_expires_at <= self.issued_at:
            raise ValueError("durable session grant absolute expiry must follow issuance")
        if not self.issued_at < self.idle_expires_at <= self.absolute_expires_at:
            raise ValueError("durable session grant idle expiry is inconsistent")
        if not self.issued_at < self.rotate_after <= self.absolute_expires_at:
            raise ValueError("durable session grant rotation time is inconsistent")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session grant schema version")
        object.__setattr__(self, "username", username)


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionAuthentication:
    """Safe authenticated identity and optional one-time rotation grant."""

    session_id: UUID
    operator_id: UUID
    principal: ControlPlanePrincipal
    generation: int
    authenticated_at: datetime
    absolute_expires_at: datetime
    idle_expires_at: datetime
    rotated_grant: ControlPlaneDurableSessionGrant | None = field(default=None, repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.generation <= 0:
            raise ValueError("durable session authentication generation must be positive")
        _require_aware(self.authenticated_at, "authenticated_at")
        _require_aware(self.absolute_expires_at, "absolute_expires_at")
        _require_aware(self.idle_expires_at, "idle_expires_at")
        if self.authenticated_at >= self.absolute_expires_at:
            raise ValueError("expired durable session cannot authenticate")
        if not self.authenticated_at < self.idle_expires_at <= self.absolute_expires_at:
            raise ValueError("durable session authentication idle expiry is inconsistent")
        if self.rotated_grant is not None:
            grant = self.rotated_grant
            if (
                grant.session_id != self.session_id
                or grant.operator_id != self.operator_id
                or grant.username != self.principal.name
                or grant.generation != self.generation
                or grant.absolute_expires_at != self.absolute_expires_at
                or grant.idle_expires_at != self.idle_expires_at
            ):
                raise ValueError("durable session rotation grant does not match authentication")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session authentication schema version")

    @property
    def rotated(self) -> bool:
        return self.rotated_grant is not None


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionAccessSnapshot:
    """Credential-free operational counters for the durable access service."""

    closed: bool
    issued: int
    authenticated: int
    rejected: int
    rotated: int
    expired: int
    revoked: int

    def __post_init__(self) -> None:
        if (
            min(
                self.issued,
                self.authenticated,
                self.rejected,
                self.rotated,
                self.expired,
                self.revoked,
            )
            < 0
        ):
            raise ValueError("durable session access counters cannot be negative")
        if self.rotated > self.authenticated:
            raise ValueError("rotated durable sessions cannot exceed authentications")


class ControlPlaneDurableSessionAccessService:
    """Issue and authenticate restart-safe sessions without retaining plaintext secrets."""

    def __init__(
        self,
        *,
        registry: ControlPlaneOperatorRegistry,
        repository: ControlPlaneDurableSessionRepository,
        policy: ControlPlaneDurableSessionPolicy | None = None,
        clock: ControlPlaneDurableSessionClock = _utc_now,
        token_factory: ControlPlaneDurableSessionSecretFactory = _default_secret_factory,
        csrf_factory: ControlPlaneDurableSessionSecretFactory = _default_secret_factory,
        events: EventBus | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("durable session clock must be callable")
        if not callable(token_factory):
            raise TypeError("durable session token factory must be callable")
        if not callable(csrf_factory):
            raise TypeError("durable session CSRF factory must be callable")
        self._registry = registry
        self._repository = repository
        self._policy = ControlPlaneDurableSessionPolicy() if policy is None else policy
        self._clock = clock
        self._token_factory = token_factory
        self._csrf_factory = csrf_factory
        self._events = events
        self._closed = False
        self._issued = 0
        self._authenticated = 0
        self._rejected = 0
        self._rotated = 0
        self._expired = 0
        self._revoked = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(self, context: object = None) -> None:
        del context
        self._require_open()

    async def stop(self, context: object = None) -> None:
        del context
        await self.close()

    async def issue(
        self,
        evidence: ControlPlaneOperatorAuthentication,
    ) -> ControlPlaneDurableSessionGrant:
        """Create generation one from freshly authenticated durable operator evidence."""

        self._require_open()
        now = self._now()
        operator = await self._registry.get(evidence.operator_id)
        if not _evidence_matches_operator(evidence, operator):
            await self._increment("rejected")
            raise ControlPlaneDurableSessionConflictError(
                "operator authentication evidence is stale"
            )
        assert operator is not None
        token, csrf_secret = self._new_secrets()
        record = ControlPlaneDurableSessionRecord.issue(
            operator_id=operator.id,
            username=operator.username,
            token=token,
            csrf_secret=csrf_secret,
            operator_revision=operator.revision,
            operator_token_version=operator.token_version,
            issued_at=now,
            policy=self._policy,
        )
        await self._repository.add(record)
        await self._increment("issued")
        await self._emit_session_event("issued", record, outcome="succeeded")
        return _grant(record, token=token, csrf_secret=csrf_secret)

    async def authenticate(
        self,
        token_value: str | None,
    ) -> ControlPlaneDurableSessionAuthentication | None:
        """Authenticate, reconcile expiry and identity, then touch or rotate atomically."""

        self._require_open()
        now = self._now()
        digest, syntactically_valid = _session_token_digest(token_value)
        record = await self._repository.get_by_token_digest(digest)
        expected = record.token_digest if record is not None else _DUMMY_SESSION_DIGEST
        digest_matches = hmac.compare_digest(digest, expected)
        if not syntactically_valid or record is None or not digest_matches:
            await self._increment("rejected")
            return None
        if record.status is not ControlPlaneDurableSessionStatus.ACTIVE:
            await self._increment("rejected")
            return None

        expiration_reason = record.expiration_reason_at(now)
        if expiration_reason is not None:
            await self._expire(record, reason=expiration_reason, now=now)
            await self._increment("rejected")
            return None

        operator = await self._registry.get(record.operator_id)
        invalidation_reason = _operator_invalidation_reason(record, operator)
        if invalidation_reason is not None:
            await self._revoke(record, reason=invalidation_reason, now=now)
            await self._increment("rejected")
            return None
        assert operator is not None

        if record.rotation_due_at(now):
            authentication = await self._rotate(record, operator=operator, now=now)
            if authentication is None:
                await self._increment("rejected")
                return None
        else:
            refreshed = await self._touch(record, now=now)
            if refreshed is None:
                await self._increment("rejected")
                return None
            authentication = _authentication(refreshed, operator=operator, now=now)
            await self._emit_session_event("renewed", refreshed, outcome="succeeded")

        async with self._lock:
            self._authenticated += 1
            if authentication.rotated:
                self._rotated += 1
        return authentication

    async def logout(self, token_value: str | None) -> bool:
        """Revoke one known active token while returning a generic result for all misses."""

        self._require_open()
        now = self._now()
        digest, syntactically_valid = _session_token_digest(token_value)
        record = await self._repository.get_by_token_digest(digest)
        expected = record.token_digest if record is not None else _DUMMY_SESSION_DIGEST
        matches = hmac.compare_digest(digest, expected)
        if (
            not syntactically_valid
            or record is None
            or not matches
            or record.status is not ControlPlaneDurableSessionStatus.ACTIVE
        ):
            return False
        return await self._revoke(
            record,
            reason=ControlPlaneDurableSessionTerminationReason.LOGOUT,
            now=now,
        )

    async def revoke_session(
        self,
        session_id: UUID,
        *,
        reason: ControlPlaneDurableSessionTerminationReason = (
            ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE
        ),
    ) -> bool:
        """Revoke one active session by UUID without bearer disclosure."""

        self._require_open()
        _require_revocation_reason(reason)
        record = await self._repository.get(session_id)
        if record is None or record.status is not ControlPlaneDurableSessionStatus.ACTIVE:
            return False
        return await self._revoke(record, reason=reason, now=self._now())

    async def revoke_operator_sessions(
        self,
        operator_id: UUID,
        *,
        reason: ControlPlaneDurableSessionTerminationReason = (
            ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE
        ),
    ) -> int:
        """Revoke every active generation for one operator within the configured bound."""

        self._require_open()
        _require_revocation_reason(reason)
        records = await self._repository.list_active_for_operator(
            operator_id,
            limit=MAX_DURABLE_SESSIONS_PER_OPERATOR,
        )
        changed = 0
        now = self._now()
        for record in records:
            if await self._revoke(record, reason=reason, now=now):
                changed += 1
        return changed

    async def snapshot(self) -> ControlPlaneDurableSessionAccessSnapshot:
        async with self._lock:
            return ControlPlaneDurableSessionAccessSnapshot(
                closed=self._closed,
                issued=self._issued,
                authenticated=self._authenticated,
                rejected=self._rejected,
                rotated=self._rotated,
                expired=self._expired,
                revoked=self._revoked,
            )

    async def close(self) -> None:
        """Close only this adapter; registry and repository lifecycles remain borrowed."""

        async with self._lock:
            self._closed = True

    async def _touch(
        self,
        record: ControlPlaneDurableSessionRecord,
        *,
        now: datetime,
    ) -> ControlPlaneDurableSessionRecord | None:
        idle_expires_at = self._policy.idle_expiry(
            now,
            absolute_expires_at=record.absolute_expires_at,
        )
        try:
            return await self._repository.touch(
                record.id,
                expected_revision=record.revision,
                seen_at=now,
                idle_expires_at=idle_expires_at,
            )
        except ControlPlaneDurableSessionConflictError:
            current = await self._repository.get_by_token_digest(record.token_digest)
            if current is None or current.status is not ControlPlaneDurableSessionStatus.ACTIVE:
                return None
            if current.expiration_reason_at(now) is not None or current.rotation_due_at(now):
                return None
            return current

    async def _rotate(
        self,
        record: ControlPlaneDurableSessionRecord,
        *,
        operator: ControlPlaneOperatorRecord,
        now: datetime,
    ) -> ControlPlaneDurableSessionAuthentication | None:
        token, csrf_secret = self._new_secrets()
        successor = ControlPlaneDurableSessionRecord.issue(
            operator_id=record.operator_id,
            username=record.username,
            token=token,
            csrf_secret=csrf_secret,
            operator_revision=operator.revision,
            operator_token_version=operator.token_version,
            issued_at=now,
            policy=self._policy,
            generation=record.generation + 1,
            predecessor_session_id=record.id,
            absolute_expires_at=record.absolute_expires_at,
        )
        try:
            rotation = await self._repository.rotate(
                record.id,
                expected_revision=record.revision,
                successor=successor,
                rotated_at=now,
            )
        except ControlPlaneDurableSessionConflictError:
            return None
        grant = _grant(rotation.successor, token=token, csrf_secret=csrf_secret)
        await self._emit_session_event("rotated", rotation.successor, outcome="succeeded")
        return _authentication(rotation.successor, operator=operator, now=now, grant=grant)

    async def _expire(
        self,
        record: ControlPlaneDurableSessionRecord,
        *,
        reason: ControlPlaneDurableSessionTerminationReason,
        now: datetime,
    ) -> bool:
        try:
            await self._repository.terminate(
                record.id,
                expected_revision=record.revision,
                status=ControlPlaneDurableSessionStatus.EXPIRED,
                reason=reason,
                terminated_at=_safe_terminal_time(record, now),
            )
        except ControlPlaneDurableSessionConflictError:
            return False
        await self._increment("expired")
        current = await self._repository.get(record.id)
        if current is not None:
            await self._emit_session_event("expired", current, outcome="succeeded")
        return True

    async def _revoke(
        self,
        record: ControlPlaneDurableSessionRecord,
        *,
        reason: ControlPlaneDurableSessionTerminationReason,
        now: datetime,
    ) -> bool:
        _require_revocation_reason(reason)
        try:
            await self._repository.terminate(
                record.id,
                expected_revision=record.revision,
                status=ControlPlaneDurableSessionStatus.REVOKED,
                reason=reason,
                terminated_at=_safe_terminal_time(record, now),
            )
        except ControlPlaneDurableSessionConflictError:
            return False
        await self._increment("revoked")
        current = await self._repository.get(record.id)
        if current is not None:
            event = (
                "logged-out"
                if reason is ControlPlaneDurableSessionTerminationReason.LOGOUT
                else "revoked"
            )
            await self._emit_session_event(event, current, outcome="succeeded")
        return True

    def _new_secrets(self) -> tuple[ControlPlaneDurableSessionToken, ControlPlaneDurableCsrfSecret]:
        token = ControlPlaneDurableSessionToken(self._token_factory())
        csrf_secret = ControlPlaneDurableCsrfSecret(self._csrf_factory())
        if hmac.compare_digest(token.digest, csrf_secret.digest):
            raise ControlPlaneDurableSessionConflictError(
                "durable session token and CSRF factories produced the same secret"
            )
        return token, csrf_secret

    async def _emit_session_event(
        self,
        event: str,
        record: ControlPlaneDurableSessionRecord,
        *,
        outcome: str,
    ) -> None:
        if self._events is None:
            return
        payload: Mapping[str, object] = {
            "action": f"operator-session.{event}",
            "actor": record.username,
            "generation": record.generation,
            "operator_id": str(record.operator_id),
            "outcome": outcome,
            "resource": f"operator-session:{record.id}",
            "session_id": str(record.id),
            "status": record.status.value,
        }
        if record.termination_reason is not None:
            payload = {**payload, "reason": record.termination_reason.value}
        try:
            await self._events.emit(
                f"control-plane.operator.session.{event}",
                source="phoenix.control-plane",
                payload=payload,
            )
        except (BusClosedError, RuntimeError):
            pass

    async def _increment(self, counter: str) -> None:
        async with self._lock:
            if counter == "issued":
                self._issued += 1
            elif counter == "rejected":
                self._rejected += 1
            elif counter == "expired":
                self._expired += 1
            elif counter == "revoked":
                self._revoked += 1
            else:
                raise AssertionError(f"unknown durable session counter: {counter}")

    def _now(self) -> datetime:
        now = self._clock()
        _require_aware(now, "durable session clock")
        return now

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneDurableSessionAccessClosedError(
                "durable session access service is closed"
            )


def _evidence_matches_operator(
    evidence: ControlPlaneOperatorAuthentication,
    operator: ControlPlaneOperatorRecord | None,
) -> bool:
    return (
        operator is not None
        and operator.status is ControlPlaneOperatorStatus.ACTIVE
        and operator.token_version == evidence.token_version
        and operator.username == evidence.principal.name
        and operator.effective_permissions == evidence.principal.permissions
    )


def _operator_invalidation_reason(
    record: ControlPlaneDurableSessionRecord,
    operator: ControlPlaneOperatorRecord | None,
) -> ControlPlaneDurableSessionTerminationReason | None:
    if operator is None or operator.status is not ControlPlaneOperatorStatus.ACTIVE:
        return ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE
    if operator.token_version != record.operator_token_version:
        return ControlPlaneDurableSessionTerminationReason.CREDENTIAL_ROTATED
    if operator.revision != record.operator_revision or operator.username != record.username:
        return ControlPlaneDurableSessionTerminationReason.PERMISSIONS_CHANGED
    return None


def _session_token_digest(value: str | None) -> tuple[str, bool]:
    if value is None or len(value) > 256:
        return _DUMMY_SESSION_DIGEST, False
    try:
        token = ControlPlaneDurableSessionToken(value)
    except ValueError:
        return _DUMMY_SESSION_DIGEST, False
    return token.digest, True


def _grant(
    record: ControlPlaneDurableSessionRecord,
    *,
    token: ControlPlaneDurableSessionToken,
    csrf_secret: ControlPlaneDurableCsrfSecret,
) -> ControlPlaneDurableSessionGrant:
    return ControlPlaneDurableSessionGrant(
        session_id=record.id,
        operator_id=record.operator_id,
        username=record.username,
        token=token,
        csrf_secret=csrf_secret,
        generation=record.generation,
        issued_at=record.issued_at,
        absolute_expires_at=record.absolute_expires_at,
        idle_expires_at=record.idle_expires_at,
        rotate_after=record.rotate_after,
    )


def _authentication(
    record: ControlPlaneDurableSessionRecord,
    *,
    operator: ControlPlaneOperatorRecord,
    now: datetime,
    grant: ControlPlaneDurableSessionGrant | None = None,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=record.id,
        operator_id=record.operator_id,
        principal=operator.principal(),
        generation=record.generation,
        authenticated_at=now,
        absolute_expires_at=record.absolute_expires_at,
        idle_expires_at=record.idle_expires_at,
        rotated_grant=grant,
    )


def _safe_terminal_time(record: ControlPlaneDurableSessionRecord, now: datetime) -> datetime:
    if now < record.last_seen_at:
        raise ControlPlaneDurableSessionConflictError("durable session clock moved backwards")
    return now


def _require_revocation_reason(reason: ControlPlaneDurableSessionTerminationReason) -> None:
    normalized = ControlPlaneDurableSessionTerminationReason(reason)
    if (
        normalized.expiration
        or normalized is ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED
    ):
        raise ValueError("durable session revocation requires a revocation reason")


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
