"""Bounded temporary sessions and login throttling for local operators."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorAccessRejectedError,
    ControlPlaneOperatorPermissionDeniedError,
    ControlPlaneOperatorRateLimitCapacityError,
    ControlPlaneOperatorSessionCapacityError,
    ControlPlaneOperatorSessionConflictError,
    ControlPlaneOperatorSessionStoreClosedError,
)
from phoenix_os.control_plane.operator_authentication import (
    ControlPlaneOperatorAuthenticator,
)
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorStatus,
)
from phoenix_os.events import BusClosedError, EventBus

DEFAULT_CONTROL_PLANE_OPERATOR_SESSION_TTL = timedelta(minutes=30)
MAX_CONTROL_PLANE_OPERATOR_SESSION_TTL = timedelta(hours=24)
MAX_CONTROL_PLANE_OPERATOR_SESSION_CAPACITY = 10_000
DEFAULT_CONTROL_PLANE_OPERATOR_SESSION_CAPACITY = 1_000
DEFAULT_CONTROL_PLANE_OPERATOR_SESSIONS_PER_OPERATOR = 8
MAX_CONTROL_PLANE_OPERATOR_SESSIONS_PER_OPERATOR = 64
DEFAULT_CONTROL_PLANE_OPERATOR_LOGIN_ATTEMPTS = 5
MAX_CONTROL_PLANE_OPERATOR_LOGIN_ATTEMPTS = 100
DEFAULT_CONTROL_PLANE_OPERATOR_LOGIN_WINDOW = timedelta(minutes=1)
MAX_CONTROL_PLANE_OPERATOR_LOGIN_WINDOW = timedelta(hours=1)
DEFAULT_CONTROL_PLANE_OPERATOR_RATE_LIMIT_CAPACITY = 2_000
MAX_CONTROL_PLANE_OPERATOR_RATE_LIMIT_CAPACITY = 20_000

_DUMMY_SESSION_DIGEST = hashlib.sha256(bytes(33)).hexdigest()
_GENERIC_ACCESS_MESSAGE = "control-plane operator access was rejected"


type ControlPlaneOperatorSessionClock = Callable[[], datetime]
type ControlPlaneOperatorSessionTokenFactory = Callable[[], str]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_token_factory() -> str:
    return secrets.token_urlsafe(32)


class ControlPlaneOperatorSessionStatus(StrEnum):
    """Lifecycle state stored for a temporary administrative session."""

    ACTIVE = "active"
    REVOKED = "revoked"


class ControlPlaneOperatorSessionRevocationReason(StrEnum):
    """Credential-free reason for terminal session invalidation."""

    LOGOUT = "logout"
    ADMINISTRATIVE = "administrative"
    OPERATOR_INACTIVE = "operator-inactive"
    CREDENTIAL_ROTATED = "credential-rotated"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneOperatorSessionToken:
    """One-time session bearer whose plaintext is redacted from representations."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.value != self.value.strip():
            raise ValueError("operator session token must not contain surrounding whitespace")
        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError(
                "operator session token must contain ASCII characters only"
            ) from exception
        if len(self.value) < 32 or len(self.value) > 128:
            raise ValueError("operator session token must contain between 32 and 128 characters")
        if any(not (character.isalnum() or character in "-._~") for character in self.value):
            raise ValueError("operator session token contains unsupported characters")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.value.encode("ascii")).hexdigest()

    def __repr__(self) -> str:
        return "ControlPlaneOperatorSessionToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorSessionRecord:
    """Immutable session record containing only a protected bearer digest."""

    id: UUID
    operator_id: UUID
    username: str
    token_digest: str = field(repr=False)
    operator_token_version: int
    issued_at: datetime
    expires_at: datetime
    status: ControlPlaneOperatorSessionStatus = ControlPlaneOperatorSessionStatus.ACTIVE
    revoked_at: datetime | None = None
    revocation_reason: ControlPlaneOperatorSessionRevocationReason | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        username = self.username.strip().lower()
        digest = self.token_digest.strip().lower()
        status = ControlPlaneOperatorSessionStatus(self.status)
        if not username or len(username) > 64:
            raise ValueError("operator session username is invalid")
        if len(digest) != 64:
            raise ValueError("operator session token digest must be SHA-256 hexadecimal")
        try:
            int(digest, 16)
        except ValueError as exception:
            raise ValueError(
                "operator session token digest must be SHA-256 hexadecimal"
            ) from exception
        if self.operator_token_version <= 0:
            raise ValueError("operator session token version must be positive")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("operator session expiry must follow issuance")
        if self.expires_at - self.issued_at > MAX_CONTROL_PLANE_OPERATOR_SESSION_TTL:
            raise ValueError("operator session lifetime exceeds the supported maximum")
        if self.revision <= 0:
            raise ValueError("operator session revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported control-plane operator session schema version")
        if status is ControlPlaneOperatorSessionStatus.ACTIVE:
            if self.revoked_at is not None or self.revocation_reason is not None:
                raise ValueError("active operator session cannot contain revocation facts")
        else:
            if self.revoked_at is None or self.revocation_reason is None:
                raise ValueError("revoked operator session requires revocation facts")
            _require_aware(self.revoked_at, "revoked_at")
            if self.revoked_at < self.issued_at:
                raise ValueError("operator session revocation cannot precede issuance")
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "token_digest", digest)
        object.__setattr__(self, "status", status)

    def active_at(self, now: datetime) -> bool:
        _require_aware(now, "now")
        return self.status is ControlPlaneOperatorSessionStatus.ACTIVE and now < self.expires_at


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorSessionGrant:
    """One-time login result containing a redacted temporary session bearer."""

    session_id: UUID
    operator_id: UUID
    username: str
    token: ControlPlaneOperatorSessionToken = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.username.strip():
            raise ValueError("operator session grant username must not be blank")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("operator session grant expiry must follow issuance")
        if self.schema_version != 1:
            raise ValueError("unsupported control-plane operator session grant schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorSessionAuthentication:
    """Safe evidence returned for one valid temporary operator session."""

    session_id: UUID
    operator_id: UUID
    principal: ControlPlanePrincipal
    authenticated_at: datetime
    expires_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        _require_aware(self.authenticated_at, "authenticated_at")
        _require_aware(self.expires_at, "expires_at")
        if self.authenticated_at >= self.expires_at:
            raise ValueError("expired operator session cannot authenticate")
        if self.schema_version != 1:
            raise ValueError("unsupported operator session authentication schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorSessionSnapshot:
    """Credential-free bounded session counters."""

    closed: bool
    sessions: int
    active: int
    revoked: int
    capacity: int
    max_sessions_per_operator: int

    def __post_init__(self) -> None:
        if min(self.sessions, self.active, self.revoked) < 0:
            raise ValueError("operator session counters cannot be negative")
        if self.active + self.revoked != self.sessions:
            raise ValueError("operator session status counters must equal entries")
        if self.capacity <= 0 or self.capacity > MAX_CONTROL_PLANE_OPERATOR_SESSION_CAPACITY:
            raise ValueError("operator session capacity is outside supported bounds")
        if self.sessions > self.capacity:
            raise ValueError("operator session entries cannot exceed capacity")
        if (
            self.max_sessions_per_operator <= 0
            or self.max_sessions_per_operator > MAX_CONTROL_PLANE_OPERATOR_SESSIONS_PER_OPERATOR
        ):
            raise ValueError("operator per-identity session limit is outside supported bounds")


class InMemoryControlPlaneOperatorSessionStore:
    """Bounded process-local session store with optimistic terminal revocation."""

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_CONTROL_PLANE_OPERATOR_SESSION_CAPACITY,
        max_sessions_per_operator: int = DEFAULT_CONTROL_PLANE_OPERATOR_SESSIONS_PER_OPERATOR,
    ) -> None:
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_OPERATOR_SESSION_CAPACITY:
            raise ValueError("operator session capacity is outside supported bounds")
        if max_sessions_per_operator <= 0 or (
            max_sessions_per_operator > MAX_CONTROL_PLANE_OPERATOR_SESSIONS_PER_OPERATOR
        ):
            raise ValueError("operator per-identity session limit is outside supported bounds")
        self._capacity = capacity
        self._max_sessions_per_operator = max_sessions_per_operator
        self._records: dict[UUID, ControlPlaneOperatorSessionRecord] = {}
        self._digest_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneOperatorSessionRecord) -> None:
        async with self._lock:
            self._require_open()
            if record.id in self._records or record.token_digest in self._digest_index:
                raise ControlPlaneOperatorSessionConflictError("operator session already exists")
            active_for_operator = sum(
                item.operator_id == record.operator_id
                and item.status is ControlPlaneOperatorSessionStatus.ACTIVE
                for item in self._records.values()
            )
            if active_for_operator >= self._max_sessions_per_operator:
                raise ControlPlaneOperatorSessionCapacityError(
                    "operator active session limit was reached"
                )
            if len(self._records) >= self._capacity:
                self._evict_oldest_terminal()
            if len(self._records) >= self._capacity:
                raise ControlPlaneOperatorSessionCapacityError("operator session store is full")
            self._records[record.id] = record
            self._digest_index[record.token_digest] = record.id

    async def get(self, session_id: UUID) -> ControlPlaneOperatorSessionRecord | None:
        async with self._lock:
            self._require_open()
            return self._records.get(session_id)

    async def get_by_token_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneOperatorSessionRecord | None:
        normalized = token_digest.strip().lower()
        async with self._lock:
            self._require_open()
            session_id = self._digest_index.get(normalized)
            return None if session_id is None else self._records.get(session_id)

    async def revoke(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        revoked_at: datetime,
        reason: ControlPlaneOperatorSessionRevocationReason,
    ) -> ControlPlaneOperatorSessionRecord:
        _require_aware(revoked_at, "revoked_at")
        async with self._lock:
            self._require_open()
            current = self._records.get(session_id)
            if current is None:
                raise ControlPlaneOperatorSessionConflictError("operator session was not found")
            if current.revision != expected_revision:
                raise ControlPlaneOperatorSessionConflictError("operator session revision conflict")
            if current.status is ControlPlaneOperatorSessionStatus.REVOKED:
                return current
            updated = replace(
                current,
                status=ControlPlaneOperatorSessionStatus.REVOKED,
                revoked_at=max(revoked_at, current.issued_at),
                revocation_reason=ControlPlaneOperatorSessionRevocationReason(reason),
                revision=current.revision + 1,
            )
            self._records[session_id] = updated
            return updated

    async def revoke_operator(
        self,
        operator_id: UUID,
        *,
        revoked_at: datetime,
        reason: ControlPlaneOperatorSessionRevocationReason,
    ) -> tuple[ControlPlaneOperatorSessionRecord, ...]:
        _require_aware(revoked_at, "revoked_at")
        async with self._lock:
            self._require_open()
            changed: list[ControlPlaneOperatorSessionRecord] = []
            for current in tuple(self._records.values()):
                if (
                    current.operator_id != operator_id
                    or current.status is ControlPlaneOperatorSessionStatus.REVOKED
                ):
                    continue
                updated = replace(
                    current,
                    status=ControlPlaneOperatorSessionStatus.REVOKED,
                    revoked_at=max(revoked_at, current.issued_at),
                    revocation_reason=ControlPlaneOperatorSessionRevocationReason(reason),
                    revision=current.revision + 1,
                )
                self._records[current.id] = updated
                changed.append(updated)
            changed.sort(key=lambda item: (item.issued_at, item.id.hex))
            return tuple(changed)

    async def snapshot(self) -> ControlPlaneOperatorSessionSnapshot:
        async with self._lock:
            records = tuple(self._records.values())
            return ControlPlaneOperatorSessionSnapshot(
                closed=self._closed,
                sessions=len(records),
                active=sum(
                    item.status is ControlPlaneOperatorSessionStatus.ACTIVE for item in records
                ),
                revoked=sum(
                    item.status is ControlPlaneOperatorSessionStatus.REVOKED for item in records
                ),
                capacity=self._capacity,
                max_sessions_per_operator=self._max_sessions_per_operator,
            )

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._digest_index.clear()
            self._closed = True

    def _evict_oldest_terminal(self) -> None:
        terminal = [
            item
            for item in self._records.values()
            if item.status is ControlPlaneOperatorSessionStatus.REVOKED
        ]
        if not terminal:
            return
        oldest = min(terminal, key=lambda item: (item.revoked_at or item.expires_at, item.id.hex))
        del self._records[oldest.id]
        self._digest_index.pop(oldest.token_digest, None)

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneOperatorSessionStoreClosedError(
                "control-plane operator session store is closed"
            )


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorRateLimitSnapshot:
    """Safe aggregate counters for bounded login throttling."""

    closed: bool
    tracked_keys: int
    denied: int
    capacity: int
    max_attempts: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.tracked_keys < 0 or self.denied < 0:
            raise ValueError("operator rate-limit counters cannot be negative")
        if self.capacity <= 0 or self.capacity > MAX_CONTROL_PLANE_OPERATOR_RATE_LIMIT_CAPACITY:
            raise ValueError("operator rate-limit capacity is outside supported bounds")
        if self.tracked_keys > self.capacity:
            raise ValueError("operator rate-limit entries cannot exceed capacity")
        if self.max_attempts <= 0 or self.max_attempts > MAX_CONTROL_PLANE_OPERATOR_LOGIN_ATTEMPTS:
            raise ValueError("operator login attempt limit is outside supported bounds")
        if self.window_seconds <= 0:
            raise ValueError("operator login window must be positive")


class ControlPlaneOperatorLoginRateLimiter:
    """Bounded sliding-window limiter keyed only by protected credential fingerprints."""

    def __init__(
        self,
        *,
        max_attempts: int = DEFAULT_CONTROL_PLANE_OPERATOR_LOGIN_ATTEMPTS,
        window: timedelta = DEFAULT_CONTROL_PLANE_OPERATOR_LOGIN_WINDOW,
        capacity: int = DEFAULT_CONTROL_PLANE_OPERATOR_RATE_LIMIT_CAPACITY,
    ) -> None:
        if max_attempts <= 0 or max_attempts > MAX_CONTROL_PLANE_OPERATOR_LOGIN_ATTEMPTS:
            raise ValueError("operator login attempt limit is outside supported bounds")
        if window <= timedelta(0) or window > MAX_CONTROL_PLANE_OPERATOR_LOGIN_WINDOW:
            raise ValueError("operator login window is outside supported bounds")
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_OPERATOR_RATE_LIMIT_CAPACITY:
            raise ValueError("operator rate-limit capacity is outside supported bounds")
        self._max_attempts = max_attempts
        self._window = window
        self._capacity = capacity
        self._attempts: dict[str, deque[datetime]] = {}
        self._denied = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def allow(self, fingerprint: str, *, now: datetime) -> bool:
        _require_aware(now, "now")
        async with self._lock:
            self._require_open()
            self._prune(now)
            attempts = self._attempts.get(fingerprint)
            allowed = attempts is None or len(attempts) < self._max_attempts
            if not allowed:
                self._denied += 1
            return allowed

    async def record_failure(self, fingerprint: str, *, now: datetime) -> None:
        _require_aware(now, "now")
        async with self._lock:
            self._require_open()
            self._prune(now)
            attempts = self._attempts.get(fingerprint)
            if attempts is None:
                if len(self._attempts) >= self._capacity:
                    raise ControlPlaneOperatorRateLimitCapacityError(
                        "operator login rate-limit capacity was reached"
                    )
                attempts = deque()
                self._attempts[fingerprint] = attempts
            attempts.append(now)

    async def record_success(self, fingerprint: str) -> None:
        async with self._lock:
            self._require_open()
            self._attempts.pop(fingerprint, None)

    async def snapshot(self) -> ControlPlaneOperatorRateLimitSnapshot:
        async with self._lock:
            return ControlPlaneOperatorRateLimitSnapshot(
                closed=self._closed,
                tracked_keys=len(self._attempts),
                denied=self._denied,
                capacity=self._capacity,
                max_attempts=self._max_attempts,
                window_seconds=int(self._window.total_seconds()),
            )

    async def close(self) -> None:
        async with self._lock:
            self._attempts.clear()
            self._closed = True

    def _prune(self, now: datetime) -> None:
        cutoff = now - self._window
        empty: list[str] = []
        for fingerprint, attempts in self._attempts.items():
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                empty.append(fingerprint)
        for fingerprint in empty:
            del self._attempts[fingerprint]

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneOperatorSessionStoreClosedError(
                "control-plane operator login limiter is closed"
            )


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorAccessSnapshot:
    """Aggregate non-sensitive counters for operator access management."""

    closed: bool
    logins_succeeded: int
    logins_rejected: int
    sessions_authenticated: int
    sessions_rejected: int
    sessions_expired: int
    sessions_revoked: int

    def __post_init__(self) -> None:
        counters = (
            self.logins_succeeded,
            self.logins_rejected,
            self.sessions_authenticated,
            self.sessions_rejected,
            self.sessions_expired,
            self.sessions_revoked,
        )
        if any(value < 0 for value in counters):
            raise ValueError("operator access counters cannot be negative")


class ControlPlaneOperatorAccessService:
    """Issue, authenticate, expire, and revoke bounded temporary operator sessions."""

    def __init__(
        self,
        *,
        registry: ControlPlaneOperatorRegistry,
        authenticator: ControlPlaneOperatorAuthenticator,
        sessions: InMemoryControlPlaneOperatorSessionStore,
        rate_limiter: ControlPlaneOperatorLoginRateLimiter,
        events: EventBus,
        ttl: timedelta = DEFAULT_CONTROL_PLANE_OPERATOR_SESSION_TTL,
        clock: ControlPlaneOperatorSessionClock = _utc_now,
        token_factory: ControlPlaneOperatorSessionTokenFactory = _default_token_factory,
    ) -> None:
        if ttl <= timedelta(0) or ttl > MAX_CONTROL_PLANE_OPERATOR_SESSION_TTL:
            raise ValueError("operator session TTL is outside supported bounds")
        if not callable(clock):
            raise TypeError("operator session clock must be callable")
        if not callable(token_factory):
            raise TypeError("operator session token factory must be callable")
        self._registry = registry
        self._authenticator = authenticator
        self._sessions = sessions
        self._rate_limiter = rate_limiter
        self._events = events
        self._ttl = ttl
        self._clock = clock
        self._token_factory = token_factory
        self._closed = False
        self._logins_succeeded = 0
        self._logins_rejected = 0
        self._sessions_authenticated = 0
        self._sessions_rejected = 0
        self._sessions_expired = 0
        self._sessions_revoked = 0
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

    async def login(self, authorization: str | None) -> ControlPlaneOperatorSessionGrant:
        """Exchange one long-lived operator credential for a bounded temporary session."""

        self._require_open()
        now = self._now()
        fingerprint = _authorization_fingerprint(authorization)
        if not await self._rate_limiter.allow(fingerprint, now=now):
            await self._reject_login(fingerprint, now=now, record_failure=False)
        evidence = await self._authenticator.authenticate(authorization)
        if evidence is None:
            await self._reject_login(fingerprint, now=now, record_failure=True)
        assert evidence is not None
        await self._rate_limiter.record_success(fingerprint)
        token = ControlPlaneOperatorSessionToken(self._token_factory())
        record = ControlPlaneOperatorSessionRecord(
            id=uuid4(),
            operator_id=evidence.operator_id,
            username=evidence.principal.name,
            token_digest=token.digest,
            operator_token_version=evidence.token_version,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        await self._sessions.add(record)
        async with self._lock:
            self._logins_succeeded += 1
        await self._emit(
            "control-plane.operator.authentication.succeeded",
            {
                "action": "operator.login",
                "actor": record.username,
                "operator_id": str(record.operator_id),
                "outcome": "success",
                "resource": "control-plane:local",
                "result_code": "operator.login-succeeded",
                "session_id": str(record.id),
            },
            correlation_id=f"operator-session:{record.id.hex}",
            causation_id=record.id,
        )
        await self._emit_session(record, "issued", "operator.session-issued")
        return ControlPlaneOperatorSessionGrant(
            session_id=record.id,
            operator_id=record.operator_id,
            username=record.username,
            token=token,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
        )

    async def authenticate(
        self,
        authorization: str | None,
    ) -> ControlPlaneOperatorSessionAuthentication | None:
        """Resolve one temporary session bearer with generic rejection semantics."""

        self._require_open()
        now = self._now()
        digest, syntactically_valid = _session_authorization_digest(authorization)
        record = await self._sessions.get_by_token_digest(digest)
        expected = record.token_digest if record is not None else _DUMMY_SESSION_DIGEST
        matches = hmac.compare_digest(digest, expected)
        if not syntactically_valid or record is None or not matches:
            await self._reject_session()
            return None
        if record.status is ControlPlaneOperatorSessionStatus.REVOKED:
            await self._reject_session()
            return None
        if now >= record.expires_at:
            await self._revoke_record(
                record,
                now=now,
                reason=ControlPlaneOperatorSessionRevocationReason.EXPIRED,
                event_action="expired",
                result_code="operator.session-expired",
            )
            async with self._lock:
                self._sessions_expired += 1
                self._sessions_rejected += 1
            return None
        operator = await self._registry.get(record.operator_id)
        if operator is None or operator.status is not ControlPlaneOperatorStatus.ACTIVE:
            await self._revoke_record(
                record,
                now=now,
                reason=ControlPlaneOperatorSessionRevocationReason.OPERATOR_INACTIVE,
                event_action="revoked",
                result_code="operator.session-operator-inactive",
            )
            await self._reject_session()
            return None
        if operator.token_version != record.operator_token_version:
            await self._revoke_record(
                record,
                now=now,
                reason=ControlPlaneOperatorSessionRevocationReason.CREDENTIAL_ROTATED,
                event_action="revoked",
                result_code="operator.session-credential-rotated",
            )
            await self._reject_session()
            return None
        evidence = ControlPlaneOperatorSessionAuthentication(
            session_id=record.id,
            operator_id=record.operator_id,
            principal=operator.principal(),
            authenticated_at=now,
            expires_at=record.expires_at,
        )
        async with self._lock:
            self._sessions_authenticated += 1
        return evidence

    async def logout(self, authorization: str | None) -> bool:
        """Revoke a known session while returning one generic boolean for unknown bearers."""

        self._require_open()
        now = self._now()
        digest, syntactically_valid = _session_authorization_digest(authorization)
        record = await self._sessions.get_by_token_digest(digest)
        expected = record.token_digest if record is not None else _DUMMY_SESSION_DIGEST
        if (
            not syntactically_valid
            or record is None
            or not hmac.compare_digest(digest, expected)
            or record.status is ControlPlaneOperatorSessionStatus.REVOKED
        ):
            await self._emit_generic_failure("operator.logout-rejected")
            return False
        await self._revoke_record(
            record,
            now=now,
            reason=ControlPlaneOperatorSessionRevocationReason.LOGOUT,
            event_action="logged-out",
            result_code="operator.logout-succeeded",
        )
        return True

    async def revoke_session(
        self,
        session_id: UUID,
        *,
        actor: ControlPlanePrincipal,
    ) -> bool:
        """Administratively revoke one session without exposing bearer material."""

        self._require_open()
        self._require_session_revoke_permission(actor)
        record = await self._sessions.get(session_id)
        if record is None or record.status is ControlPlaneOperatorSessionStatus.REVOKED:
            return False
        updated = await self._revoke_record(
            record,
            now=self._now(),
            reason=ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE,
            event_action="revoked",
            result_code="operator.session-administratively-revoked",
            actor=actor.name,
        )
        return updated.status is ControlPlaneOperatorSessionStatus.REVOKED

    async def revoke_operator_sessions(
        self,
        operator_id: UUID,
        *,
        actor: ControlPlanePrincipal,
        reason: ControlPlaneOperatorSessionRevocationReason = (
            ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE
        ),
    ) -> int:
        """Administratively revoke every active session for one operator."""

        self._require_open()
        self._require_session_revoke_permission(actor)
        return await self.invalidate_operator_sessions(
            operator_id,
            actor=actor.name,
            reason=reason,
        )

    async def invalidate_operator_sessions(
        self,
        operator_id: UUID,
        *,
        actor: str,
        reason: ControlPlaneOperatorSessionRevocationReason,
    ) -> int:
        """Invalidate sessions after an already-authorized operator lifecycle mutation."""

        self._require_open()
        now = self._now()
        changed = await self._sessions.revoke_operator(
            operator_id,
            revoked_at=now,
            reason=reason,
        )
        async with self._lock:
            self._sessions_revoked += len(changed)
        result_code = _operator_session_revocation_result_code(reason)
        for record in changed:
            await self._emit_session(
                record,
                "revoked",
                result_code,
                actor=actor,
            )
        return len(changed)

    async def snapshot(self) -> ControlPlaneOperatorAccessSnapshot:
        async with self._lock:
            return ControlPlaneOperatorAccessSnapshot(
                closed=self._closed,
                logins_succeeded=self._logins_succeeded,
                logins_rejected=self._logins_rejected,
                sessions_authenticated=self._sessions_authenticated,
                sessions_rejected=self._sessions_rejected,
                sessions_expired=self._sessions_expired,
                sessions_revoked=self._sessions_revoked,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
        await self._rate_limiter.close()
        await self._sessions.close()

    async def _reject_login(
        self,
        fingerprint: str,
        *,
        now: datetime,
        record_failure: bool,
    ) -> None:
        if record_failure:
            try:
                await self._rate_limiter.record_failure(fingerprint, now=now)
            except ControlPlaneOperatorRateLimitCapacityError:
                pass
        async with self._lock:
            self._logins_rejected += 1
        await self._emit_generic_failure("operator.login-rejected")
        raise ControlPlaneOperatorAccessRejectedError(_GENERIC_ACCESS_MESSAGE)

    async def _reject_session(self) -> None:
        async with self._lock:
            self._sessions_rejected += 1
        await self._emit_generic_failure("operator.session-rejected")

    async def _revoke_record(
        self,
        record: ControlPlaneOperatorSessionRecord,
        *,
        now: datetime,
        reason: ControlPlaneOperatorSessionRevocationReason,
        event_action: str,
        result_code: str,
        actor: str | None = None,
    ) -> ControlPlaneOperatorSessionRecord:
        updated = await self._sessions.revoke(
            record.id,
            expected_revision=record.revision,
            revoked_at=now,
            reason=reason,
        )
        async with self._lock:
            self._sessions_revoked += 1
        await self._emit_session(
            updated,
            event_action,
            result_code,
            actor=actor,
        )
        return updated

    async def _emit_session(
        self,
        record: ControlPlaneOperatorSessionRecord,
        action: str,
        result_code: str,
        *,
        actor: str | None = None,
    ) -> None:
        await self._emit(
            f"control-plane.operator.session.{action}",
            {
                "action": f"operator.session.{action}",
                "actor": actor or record.username,
                "operator_id": str(record.operator_id),
                "outcome": "success",
                "resource": f"operator-session:{record.id}",
                "result_code": result_code,
                "session_id": str(record.id),
            },
            correlation_id=f"operator-session:{record.id.hex}",
            causation_id=record.id,
        )

    async def _emit_generic_failure(self, result_code: str) -> None:
        await self._emit(
            "control-plane.operator.authentication.failed",
            MappingProxyType(
                {
                    "action": "operator.authenticate",
                    "actor": "anonymous",
                    "outcome": "denied",
                    "resource": "control-plane:local",
                    "result_code": result_code,
                }
            ),
        )

    async def _emit(
        self,
        name: str,
        payload: Mapping[str, object],
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> None:
        try:
            await self._events.emit(
                name,
                source="phoenix.control-plane",
                payload=payload,
                correlation_id=correlation_id,
                causation_id=causation_id,
            )
        except (BusClosedError, RuntimeError):
            pass

    @staticmethod
    def _require_session_revoke_permission(actor: ControlPlanePrincipal) -> None:
        if CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION not in actor.permissions:
            raise ControlPlaneOperatorPermissionDeniedError(
                "operator session revocation permission denied"
            )

    def _now(self) -> datetime:
        now = self._clock()
        _require_aware(now, "operator session clock")
        return now

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneOperatorSessionStoreClosedError(
                "control-plane operator access service is closed"
            )


def _operator_session_revocation_result_code(
    reason: ControlPlaneOperatorSessionRevocationReason,
) -> str:
    if reason is ControlPlaneOperatorSessionRevocationReason.CREDENTIAL_ROTATED:
        return "operator.session-credential-rotated"
    if reason is ControlPlaneOperatorSessionRevocationReason.OPERATOR_INACTIVE:
        return "operator.session-operator-inactive"
    if reason is ControlPlaneOperatorSessionRevocationReason.EXPIRED:
        return "operator.session-expired"
    if reason is ControlPlaneOperatorSessionRevocationReason.LOGOUT:
        return "operator.logout-succeeded"
    return "operator.session-administratively-revoked"


def _authorization_fingerprint(authorization: str | None) -> str:
    if authorization is None:
        return hashlib.sha256(b"missing").hexdigest()
    try:
        encoded = authorization.encode("ascii")
    except UnicodeEncodeError:
        return hashlib.sha256(b"non-ascii").hexdigest()
    return hashlib.sha256(encoded[:256]).hexdigest()


def _session_authorization_digest(authorization: str | None) -> tuple[str, bool]:
    if authorization is None or len(authorization) > 256:
        return _DUMMY_SESSION_DIGEST, False
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return _DUMMY_SESSION_DIGEST, False
    scheme, supplied = parts
    if scheme.lower() != "bearer" or not supplied or supplied != supplied.strip():
        return _DUMMY_SESSION_DIGEST, False
    try:
        token = ControlPlaneOperatorSessionToken(supplied)
    except ValueError:
        return _DUMMY_SESSION_DIGEST, False
    return token.digest, True


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
