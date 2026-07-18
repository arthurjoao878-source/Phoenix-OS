"""Identity and authentication exception hierarchy."""

from __future__ import annotations


class PhoenixIdentityError(Exception):
    """Base error for identity, authentication, and sessions."""


class AuthenticationManagerClosedError(PhoenixIdentityError):
    pass


class AuthenticationProviderAlreadyRegisteredError(PhoenixIdentityError):
    pass


class AuthenticationProviderNotFoundError(PhoenixIdentityError):
    pass


class AuthenticationRejectedError(PhoenixIdentityError):
    pass


class AuthenticationProviderError(PhoenixIdentityError):
    def __init__(self, provider: str, exception: Exception) -> None:
        super().__init__(f"authentication provider {provider!r} failed")
        self.provider = provider
        self.exception = exception


class SessionError(PhoenixIdentityError):
    pass


class SessionNotFoundError(SessionError):
    pass


class SessionTokenInvalidError(SessionError):
    pass


class SessionExpiredError(SessionError):
    pass


class SessionRevokedError(SessionError):
    pass


class SessionLimitExceededError(SessionError):
    pass


class SessionRepositoryClosedError(SessionError):
    pass
