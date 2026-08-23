from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.authority import (
    AuthorityFreshnessRejectedError,
    CurrentSessionFreshnessValidator,
)
from phoenix_os.identity.contracts import Identity, Session, SessionStatus
from phoenix_os.identity.errors import SessionNotFoundError
from phoenix_os.policy import PrincipalType, SecurityContext

_SESSION_ID = UUID("10000000-0000-4000-8000-000000000033")
_OTHER_SESSION_ID = UUID("20000000-0000-4000-8000-000000000033")
_NOW = datetime(2026, 8, 19, 22, tzinfo=UTC)


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _SessionSource:
    def __init__(self, sessions: dict[UUID, Session]) -> None:
        self.sessions = sessions
        self.calls: list[UUID] = []

    async def session(self, session_id: UUID) -> Session:
        self.calls.append(session_id)
        session = self.sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError("session not found")
        return session


def _identity(
    subject: str = "arthur",
    principal_type: PrincipalType = PrincipalType.USER,
) -> Identity:
    return Identity(
        subject=subject,
        principal_type=principal_type,
        authenticated_at=_NOW - timedelta(minutes=5),
    )


def _session(
    *,
    session_id: UUID = _SESSION_ID,
    identity: Identity | None = None,
    status: SessionStatus = SessionStatus.ACTIVE,
    expires_at: datetime | None = None,
    idle_expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> Session:
    issued_at = _NOW - timedelta(minutes=5)
    resolved_idle = idle_expires_at
    idle_ttl = None
    if resolved_idle is not None:
        idle_ttl = resolved_idle - issued_at
    return Session(
        id=session_id,
        identity=_identity() if identity is None else identity,
        issued_at=issued_at,
        expires_at=_NOW + timedelta(hours=1) if expires_at is None else expires_at,
        last_seen_at=issued_at,
        idle_expires_at=resolved_idle,
        idle_ttl=idle_ttl,
        status=status,
        revoked_at=revoked_at,
        revocation_reason="revoked" if status is SessionStatus.REVOKED else None,
    )


def _context(
    *,
    session_id: UUID | None = _SESSION_ID,
    principal: str = "arthur",
    principal_type: PrincipalType = PrincipalType.USER,
    attributes: dict[str, str] | None = None,
) -> SecurityContext:
    resolved_attributes = (
        {
            "identity_provider": "local",
            **({} if session_id is None else {"session_id": str(session_id)}),
        }
        if attributes is None
        else attributes
    )
    return SecurityContext(
        principal=principal,
        principal_type=principal_type,
        authenticated=True,
        attributes=resolved_attributes,
        session_id=session_id,
    )


@pytest.mark.asyncio
async def test_non_session_backed_context_requires_no_session_lookup() -> None:
    source = _SessionSource({})
    validator = CurrentSessionFreshnessValidator(source, clock=_Clock())

    await validator.validate(_context(session_id=None))

    assert source.calls == []


@pytest.mark.asyncio
async def test_active_exact_session_is_current() -> None:
    session = _session()
    source = _SessionSource({_SESSION_ID: session})
    validator = CurrentSessionFreshnessValidator(source, clock=_Clock())

    await validator.validate(_context())

    assert source.calls == [_SESSION_ID]


@pytest.mark.asyncio
async def test_missing_structural_session_fails_closed() -> None:
    source = _SessionSource({})
    validator = CurrentSessionFreshnessValidator(source, clock=_Clock())

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(_context())

    assert source.calls == [_SESSION_ID]


@pytest.mark.asyncio
async def test_revoked_session_fails_closed() -> None:
    session = _session(
        status=SessionStatus.REVOKED,
        revoked_at=_NOW - timedelta(seconds=1),
    )
    validator = CurrentSessionFreshnessValidator(
        _SessionSource({_SESSION_ID: session}),
        clock=_Clock(),
    )

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(_context())


@pytest.mark.asyncio
async def test_absolute_expiry_fails_closed_even_if_status_is_still_active() -> None:
    session = _session(expires_at=_NOW)
    validator = CurrentSessionFreshnessValidator(
        _SessionSource({_SESSION_ID: session}),
        clock=_Clock(),
    )

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(_context())


@pytest.mark.asyncio
async def test_idle_expiry_fails_closed_even_if_status_is_still_active() -> None:
    session = _session(idle_expires_at=_NOW)
    validator = CurrentSessionFreshnessValidator(
        _SessionSource({_SESSION_ID: session}),
        clock=_Clock(),
    )

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(_context())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("principal", "principal_type"),
    [
        ("mallory", PrincipalType.USER),
        ("arthur", PrincipalType.SERVICE),
    ],
)
async def test_subject_substitution_fails_closed(
    principal: str,
    principal_type: PrincipalType,
) -> None:
    session = _session()
    validator = CurrentSessionFreshnessValidator(
        _SessionSource({_SESSION_ID: session}),
        clock=_Clock(),
    )

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(_context(principal=principal, principal_type=principal_type))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "context",
    [
        replace(_context(), roles=frozenset({"admin"})),
        replace(_context(), permissions=frozenset({"files.read"})),
        replace(_context(), scopes=frozenset({"workspace"})),
        replace(
            _context(),
            attributes={
                "identity_provider": "local",
                "session_id": str(_SESSION_ID),
                "tenant": "spoofed",
            },
        ),
        replace(
            _context(),
            attributes={
                "identity_provider": "other",
                "session_id": str(_SESSION_ID),
            },
        ),
    ],
)
async def test_current_session_identity_authority_facets_must_match(
    context: SecurityContext,
) -> None:
    validator = CurrentSessionFreshnessValidator(
        _SessionSource({_SESSION_ID: _session()}),
        clock=_Clock(),
    )

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(context)


@pytest.mark.asyncio
async def test_attribute_only_session_id_never_creates_session_authority() -> None:
    session = _session()
    source = _SessionSource({_SESSION_ID: session})
    validator = CurrentSessionFreshnessValidator(source, clock=_Clock())

    await validator.validate(
        _context(
            session_id=None,
            attributes={"session_id": str(_SESSION_ID)},
        )
    )

    assert source.calls == []


@pytest.mark.asyncio
async def test_attribute_session_id_cannot_override_structural_session_id() -> None:
    session = _session()
    source = _SessionSource({_SESSION_ID: session})
    validator = CurrentSessionFreshnessValidator(source, clock=_Clock())

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(
            _context(
                session_id=_OTHER_SESSION_ID,
                attributes={"session_id": str(_SESSION_ID)},
            )
        )

    assert source.calls == [_OTHER_SESSION_ID]


@pytest.mark.asyncio
async def test_source_returning_different_session_identity_fails_closed() -> None:
    source = _SessionSource({_SESSION_ID: _session(session_id=_OTHER_SESSION_ID)})
    validator = CurrentSessionFreshnessValidator(source, clock=_Clock())

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(_context())


@pytest.mark.asyncio
async def test_clock_must_be_timezone_aware() -> None:
    session = _session()
    validator = CurrentSessionFreshnessValidator(
        _SessionSource({_SESSION_ID: session}),
        clock=_Clock(datetime(2026, 8, 19, 22)),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        await validator.validate(_context())


def test_validator_requires_session_source() -> None:
    with pytest.raises(TypeError, match="SessionFreshnessSource"):
        CurrentSessionFreshnessValidator(object())  # type: ignore[arg-type]
