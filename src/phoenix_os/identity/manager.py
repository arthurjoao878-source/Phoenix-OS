"""Authentication provider registry and secure session lifecycle management."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import secrets
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from phoenix_os.configuration.contracts import SecretValue
from phoenix_os.events import EventBus
from phoenix_os.identity.contracts import (
    AuthenticationCredential,
    AuthenticationProvider,
    AuthenticationRequest,
    AuthenticationSnapshot,
    Identity,
    ProviderRegistration,
    Session,
    SessionGrant,
    SessionPolicy,
    SessionRecord,
    SessionRepository,
    SessionStatus,
)
from phoenix_os.identity.errors import (
    AuthenticationManagerClosedError,
    AuthenticationProviderAlreadyRegisteredError,
    AuthenticationProviderError,
    AuthenticationProviderNotFoundError,
    AuthenticationRejectedError,
    SessionExpiredError,
    SessionLimitExceededError,
    SessionNotFoundError,
    SessionRevokedError,
    SessionTokenInvalidError,
)
from phoenix_os.identity.repository import InMemorySessionRepository
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import SecurityContext


def _normalize_provider(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("provider name must not be blank")
    return normalized


@dataclass(slots=True)
class _RegisteredProvider:
    registration: ProviderRegistration
    provider: AuthenticationProvider
    sequence: int


class AuthenticationManager:
    """Authenticate identities and issue revocable bearer sessions."""

    def __init__(
        self,
        providers: Iterable[tuple[str, AuthenticationProvider]] = (),
        *,
        repository: SessionRepository | None = None,
        policy: SessionPolicy | None = None,
        events: EventBus | None = None,
        observability: ObservabilityHub | None = None,
        token_factory: Callable[[], str] | None = None,
        clock: Callable[[], datetime] | None = None,
        source: str = "phoenix.identity",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        self._providers: dict[str, _RegisteredProvider] = {}
        self._by_registration: dict[UUID, str] = {}
        self._sequence = 0
        self._repository = repository or InMemorySessionRepository()
        self._policy = policy or SessionPolicy()
        self._events = events
        self._observability = observability
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source = normalized_source
        self._closed = False
        self._lock = asyncio.Lock()
        self._authentications = 0
        self._failures = 0
        self._revocations = 0
        for name, provider in providers:
            self._register_initial(name, provider)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def repository(self) -> SessionRepository:
        return self._repository

    async def register_provider(
        self,
        name: str,
        provider: AuthenticationProvider,
    ) -> ProviderRegistration:
        self._ensure_open()
        self._validate_provider(provider)
        async with self._lock:
            self._ensure_open()
            return self._register_initial(name, provider).registration

    async def unregister_provider(self, registration: ProviderRegistration) -> bool:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            name = self._by_registration.get(registration.id)
            if name is None or name != registration.name:
                return False
            current = self._providers.get(name)
            if current is None or current.registration != registration:
                return False
            del self._providers[name]
            del self._by_registration[registration.id]
            return True

    def provider_names(self) -> tuple[str, ...]:
        self._ensure_open()
        return tuple(
            item.registration.name
            for item in sorted(self._providers.values(), key=lambda item: item.sequence)
        )

    async def authenticate(
        self,
        provider: str,
        credential: AuthenticationCredential,
        *,
        expires_in: timedelta | None = None,
        metadata: Mapping[str, str] | None = None,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> SessionGrant:
        """Authenticate one credential and issue a new bearer session."""

        self._ensure_open()
        provider_name = _normalize_provider(provider)
        request = AuthenticationRequest(
            provider=provider_name,
            credential=credential,
            metadata={} if metadata is None else metadata,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )
        async with self._trace(
            "identity.authenticate", correlation_id, {"provider": provider_name}
        ):
            try:
                registered = self._provider(provider_name)
            except AuthenticationProviderNotFoundError:
                await self._record_failure(request, "provider_not_found")
                raise
            try:
                result = registered.provider.authenticate(request)
                identity = await result if inspect.isawaitable(result) else result
                if not isinstance(identity, Identity):
                    raise TypeError("authentication provider must return Identity")
            except asyncio.CancelledError:
                raise
            except AuthenticationRejectedError:
                await self._record_failure(request, "rejected")
                raise
            except Exception as exception:
                await self._record_failure(request, "provider_error")
                raise AuthenticationProviderError(provider_name, exception) from exception
            identity = replace(identity, provider=provider_name, authenticated_at=self._now())
            grant = await self._issue(
                identity,
                expires_in,
                request.metadata,
                correlation_id=correlation_id,
                causation_id=request.id,
            )

        async with self._lock:
            self._authentications += 1
        await self._emit(
            "identity.authentication.succeeded",
            correlation_id=correlation_id,
            causation_id=request.id,
            payload={
                "provider": provider_name,
                "subject": identity.subject,
                "session_id": str(grant.session.id),
            },
        )
        await self._metric(
            "identity.authentications", {"outcome": "success", "provider": provider_name}
        )
        return grant

    async def resolve(
        self,
        token: SecretValue | str,
        *,
        touch: bool = True,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> Session:
        """Resolve and validate a bearer token without exposing it to diagnostics."""

        self._ensure_open()
        digest = _digest_token(_reveal_token(token))
        outcome = "success"
        async with self._lock:
            record = await self._repository.find_by_digest(digest)
            if record is None:
                outcome = "invalid"
                session = None
            else:
                session = record.session
                now = self._now()
                if session.status is SessionStatus.REVOKED:
                    outcome = "revoked"
                elif session.status is SessionStatus.EXPIRED or not session.valid_at(now):
                    outcome = "expired"
                    session = replace(session, status=SessionStatus.EXPIRED)
                    await self._repository.save(replace(record, session=session))
                elif touch and now - session.last_seen_at >= self._policy.touch_interval:
                    idle_expires_at = None if session.idle_ttl is None else now + session.idle_ttl
                    session = replace(
                        session,
                        last_seen_at=now,
                        idle_expires_at=idle_expires_at,
                    )
                    await self._repository.save(replace(record, session=session))

        await self._metric("identity.session.resolutions", {"outcome": outcome})
        if outcome == "invalid" or session is None:
            raise SessionTokenInvalidError("invalid session token")
        if outcome == "revoked":
            raise SessionRevokedError("session has been revoked")
        if outcome == "expired":
            await self._emit(
                "identity.session.expired",
                correlation_id=correlation_id,
                causation_id=causation_id,
                payload={"session_id": str(session.id), "subject": session.identity.subject},
            )
            raise SessionExpiredError("session has expired")
        await self._emit(
            "identity.session.resolved",
            correlation_id=correlation_id,
            causation_id=causation_id,
            payload={"session_id": str(session.id), "subject": session.identity.subject},
        )
        return session

    async def session(self, session_id: UUID) -> Session:
        """Return session metadata by trusted identifier without authenticating a bearer."""

        self._ensure_open()
        record = await self._repository.get(session_id)
        if record is None:
            raise SessionNotFoundError(f"session not found: {session_id}")
        return record.session

    async def security_context(
        self,
        token: SecretValue | str,
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
        confirmed: bool = False,
    ) -> SecurityContext:
        session = await self.resolve(
            token,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )
        return session.security_context(
            correlation_id=correlation_id,
            causation_id=causation_id,
            confirmed=confirmed,
        )

    async def revoke(
        self,
        session_id: UUID,
        *,
        reason: str = "revoked",
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> bool:
        self._ensure_open()
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise ValueError("revocation reason must not be blank")
        async with self._lock:
            record = await self._repository.get(session_id)
            if record is None or record.session.status is not SessionStatus.ACTIVE:
                return False
            revoked = replace(
                record.session,
                status=SessionStatus.REVOKED,
                revoked_at=self._now(),
                revocation_reason=normalized_reason,
            )
            await self._repository.save(replace(record, session=revoked))
            self._revocations += 1
        await self._emit(
            "identity.session.revoked",
            correlation_id=correlation_id,
            causation_id=causation_id,
            payload={
                "session_id": str(session_id),
                "subject": revoked.identity.subject,
                "reason": normalized_reason,
            },
        )
        await self._metric("identity.session.revocations", {"reason": normalized_reason})
        return True

    async def revoke_token(
        self,
        token: SecretValue | str,
        *,
        reason: str = "logout",
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> bool:
        self._ensure_open()
        record = await self._repository.find_by_digest(_digest_token(_reveal_token(token)))
        if record is None:
            return False
        return await self.revoke(
            record.session.id,
            reason=reason,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )

    async def revoke_identity(
        self,
        subject: str,
        *,
        reason: str = "identity_revoked",
        correlation_id: str | None = None,
    ) -> int:
        self._ensure_open()
        records = await self._repository.list_for_subject(subject)
        revoked = 0
        for record in records:
            if await self.revoke(
                record.session.id,
                reason=reason,
                correlation_id=correlation_id,
            ):
                revoked += 1
        return revoked

    async def purge_expired(self) -> int:
        """Mark active sessions that exceeded absolute or idle deadlines as expired."""

        self._ensure_open()
        now = self._now()
        count = 0
        async with self._lock:
            for record in await self._repository.list_all():
                if record.session.status is SessionStatus.ACTIVE and not record.session.valid_at(
                    now
                ):
                    await self._repository.save(
                        replace(
                            record,
                            session=replace(record.session, status=SessionStatus.EXPIRED),
                        )
                    )
                    count += 1
        return count

    async def snapshot(self) -> AuthenticationSnapshot:
        records = await self._repository.list_all() if not self._closed else ()
        now = self._now()
        active = sum(record.session.valid_at(now) for record in records)
        async with self._lock:
            return AuthenticationSnapshot(
                closed=self._closed,
                providers=self.provider_names() if not self._closed else (),
                sessions=len(records),
                active_sessions=active,
                authentications=self._authentications,
                failures=self._failures,
                revocations=self._revocations,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._providers.clear()
            self._by_registration.clear()
            self._closed = True
        await self._repository.close()

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    async def _issue(
        self,
        identity: Identity,
        expires_in: timedelta | None,
        metadata: Mapping[str, str],
        *,
        correlation_id: str | None,
        causation_id: UUID | None,
    ) -> SessionGrant:
        ttl = self._policy.absolute_ttl if expires_in is None else expires_in
        if ttl <= timedelta(0) or ttl > self._policy.absolute_ttl:
            raise ValueError("expires_in must be positive and not exceed absolute_ttl")
        async with self._lock:
            active = [
                record
                for record in await self._repository.list_for_subject(identity.subject)
                if record.session.valid_at(self._now())
            ]
            if len(active) >= self._policy.max_sessions_per_identity:
                raise SessionLimitExceededError(
                    f"session limit exceeded for identity: {identity.subject}"
                )
            now = self._now()
            idle_ttl = self._policy.idle_ttl
            session = Session(
                id=uuid4(),
                identity=identity,
                issued_at=now,
                expires_at=now + ttl,
                last_seen_at=now,
                idle_expires_at=None if idle_ttl is None else now + idle_ttl,
                idle_ttl=idle_ttl,
                metadata=metadata,
            )
            raw_token = ""
            record: SessionRecord | None = None
            for _ in range(3):
                candidate = self._token_factory().strip()
                if len(candidate) < 32:
                    raise ValueError("token factory must return at least 32 non-blank characters")
                digest = _digest_token(candidate)
                if await self._repository.find_by_digest(digest) is None:
                    raw_token = candidate
                    record = SessionRecord(session=session, token_digest=digest)
                    break
            if record is None:
                raise RuntimeError("unable to generate a unique session token")
            await self._repository.save(record)
        await self._emit(
            "identity.session.issued",
            correlation_id=correlation_id,
            causation_id=causation_id,
            payload={"session_id": str(session.id), "subject": identity.subject},
        )
        return SessionGrant(session=session, token=SecretValue(raw_token))

    def _provider(self, name: str) -> _RegisteredProvider:
        try:
            return self._providers[name]
        except KeyError as exception:
            raise AuthenticationProviderNotFoundError(
                f"authentication provider not found: {name}"
            ) from exception

    def _register_initial(
        self,
        name: str,
        provider: AuthenticationProvider,
    ) -> _RegisteredProvider:
        normalized = _normalize_provider(name)
        self._validate_provider(provider)
        if normalized in self._providers:
            raise AuthenticationProviderAlreadyRegisteredError(
                f"authentication provider already registered: {normalized}"
            )
        registration = ProviderRegistration(uuid4(), normalized)
        registered = _RegisteredProvider(registration, provider, self._sequence)
        self._sequence += 1
        self._providers[normalized] = registered
        self._by_registration[registration.id] = normalized
        return registered

    @staticmethod
    def _validate_provider(provider: AuthenticationProvider) -> None:
        if not callable(getattr(provider, "authenticate", None)):
            raise TypeError("provider must expose a callable authenticate method")

    async def _record_failure(self, request: AuthenticationRequest, outcome: str) -> None:
        async with self._lock:
            self._failures += 1
        await self._emit(
            "identity.authentication.failed",
            correlation_id=request.correlation_id,
            causation_id=request.id,
            payload={"provider": request.provider, "outcome": outcome},
        )
        await self._metric(
            "identity.authentications",
            {"outcome": outcome, "provider": request.provider},
        )
        if self._observability is not None:
            await self._observability.log(
                "identity.authentication.failed",
                source=self._source,
                message="authentication failed",
                severity=Severity.WARNING,
                attributes={"provider": request.provider, "outcome": outcome},
                correlation_id=request.correlation_id,
                causation_id=request.id,
            )

    async def _emit(
        self,
        name: str,
        *,
        correlation_id: str | None,
        causation_id: UUID | None,
        payload: Mapping[str, object],
    ) -> None:
        if self._events is not None:
            await self._events.emit(
                name,
                source=self._source,
                payload=payload,
                correlation_id=correlation_id,
                causation_id=causation_id,
            )

    async def _metric(self, name: str, attributes: Mapping[str, object]) -> None:
        if self._observability is not None:
            await self._observability.metric(
                name,
                1,
                source=self._source,
                kind=MetricKind.COUNTER,
                attributes=attributes,
            )

    @asynccontextmanager
    async def _trace(
        self,
        name: str,
        correlation_id: str | None,
        attributes: Mapping[str, object],
    ) -> AsyncIterator[None]:
        if self._observability is None:
            yield
            return
        async with self._observability.span(
            name,
            source=self._source,
            attributes=attributes,
            correlation_id=correlation_id,
        ):
            yield

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("authentication clock must return timezone-aware datetimes")
        return now

    def _ensure_open(self) -> None:
        if self._closed:
            raise AuthenticationManagerClosedError("authentication manager is closed")


def _reveal_token(token: SecretValue | str) -> str:
    value = token.reveal(str) if isinstance(token, SecretValue) else token
    normalized = value.strip()
    if not normalized:
        raise SessionTokenInvalidError("session token must not be blank")
    return normalized


def _digest_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
