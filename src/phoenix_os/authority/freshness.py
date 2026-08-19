"""Fresh trusted-state validation for RFC-0033 authority admission."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.identity.contracts import Session, SessionStatus
from phoenix_os.identity.errors import SessionNotFoundError
from phoenix_os.policy import SecurityContext


class AuthorityFreshnessRejectedError(RuntimeError):
    """Current trusted state no longer supports the bound authority subject."""


@runtime_checkable
class SessionFreshnessSource(Protocol):
    """Trusted lookup of session metadata by structural session identity."""

    async def session(self, session_id: UUID) -> Session: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class CurrentSessionFreshnessValidator:
    """Validate live session authority without accepting bearer or attribute identity."""

    def __init__(
        self,
        source: SessionFreshnessSource,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(source, SessionFreshnessSource):
            raise TypeError("source must implement SessionFreshnessSource")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._source = source
        self._clock: Callable[[], datetime] = _utc_now if clock is None else clock

    async def validate(self, context: SecurityContext) -> None:
        """Fail closed when a session-backed context is no longer current."""

        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        session_id = context.session_id
        if session_id is None:
            return

        try:
            session = await self._source.session(session_id)
        except SessionNotFoundError as exception:
            raise AuthorityFreshnessRejectedError(
                "current session authority rejected"
            ) from exception

        if not isinstance(session, Session) or session.id != session_id:
            raise AuthorityFreshnessRejectedError("current session authority rejected")

        now = self._now()
        if session.status is not SessionStatus.ACTIVE or not session.valid_at(now):
            raise AuthorityFreshnessRejectedError("current session authority rejected")

        expected = session.security_context()
        if (
            expected.principal != context.principal
            or expected.principal_type is not context.principal_type
            or expected.authenticated is not context.authenticated
            or expected.roles != context.roles
            or expected.permissions != context.permissions
            or expected.scopes != context.scopes
            or expected.attributes != context.attributes
        ):
            raise AuthorityFreshnessRejectedError("current session authority rejected")

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock result must be datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock result must be timezone-aware")
        return value
