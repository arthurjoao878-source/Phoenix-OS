"""Task-local propagation of authenticated sessions and security contexts."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from uuid import UUID

from phoenix_os.identity.contracts import Session
from phoenix_os.policy import SecurityContext

_current_session: ContextVar[Session | None] = ContextVar("phoenix_current_session", default=None)
_current_security: ContextVar[SecurityContext | None] = ContextVar(
    "phoenix_current_security_context", default=None
)


def current_session() -> Session | None:
    """Return the session bound to the current asynchronous context."""

    return _current_session.get()


def current_security_context() -> SecurityContext | None:
    """Return the security context bound to the current asynchronous context."""

    return _current_security.get()


@contextmanager
def session_scope(
    session: Session,
    *,
    correlation_id: str | None = None,
    causation_id: UUID | None = None,
    confirmed: bool = False,
) -> Iterator[SecurityContext]:
    """Bind a session and derived SecurityContext for the duration of a block."""

    security = session.security_context(
        correlation_id=correlation_id,
        causation_id=causation_id,
        confirmed=confirmed,
    )
    session_token = _current_session.set(session)
    security_token = _current_security.set(security)
    try:
        yield security
    finally:
        _current_security.reset(security_token)
        _current_session.reset(session_token)
