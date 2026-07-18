"""Identity, authentication provider, and session APIs."""

from phoenix_os.identity.adapters import (
    AuthenticatedKernel,
    capability_context_from_session,
    state_context_from_session,
)
from phoenix_os.identity.context import current_security_context, current_session, session_scope
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
    PhoenixIdentityError,
    SessionError,
    SessionExpiredError,
    SessionLimitExceededError,
    SessionNotFoundError,
    SessionRepositoryClosedError,
    SessionRevokedError,
    SessionTokenInvalidError,
)
from phoenix_os.identity.manager import AuthenticationManager
from phoenix_os.identity.providers import AuthenticationHook, CallableAuthenticationProvider
from phoenix_os.identity.repository import InMemorySessionRepository, StateSessionRepository

__all__ = [
    "AuthenticatedKernel",
    "AuthenticationCredential",
    "AuthenticationHook",
    "AuthenticationManager",
    "AuthenticationManagerClosedError",
    "AuthenticationProvider",
    "AuthenticationProviderAlreadyRegisteredError",
    "AuthenticationProviderError",
    "AuthenticationProviderNotFoundError",
    "AuthenticationRejectedError",
    "AuthenticationRequest",
    "AuthenticationSnapshot",
    "CallableAuthenticationProvider",
    "Identity",
    "InMemorySessionRepository",
    "PhoenixIdentityError",
    "ProviderRegistration",
    "Session",
    "SessionError",
    "SessionExpiredError",
    "SessionGrant",
    "SessionLimitExceededError",
    "SessionNotFoundError",
    "SessionPolicy",
    "SessionRecord",
    "SessionRepository",
    "SessionRepositoryClosedError",
    "SessionRevokedError",
    "SessionStatus",
    "SessionTokenInvalidError",
    "StateSessionRepository",
    "capability_context_from_session",
    "current_security_context",
    "current_session",
    "session_scope",
    "state_context_from_session",
]
