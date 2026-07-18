"""Errors raised by Phoenix secrets vault APIs."""

from __future__ import annotations


class PhoenixSecretsError(Exception):
    """Base class for secrets and key-management failures."""


class SecretsManagerClosedError(PhoenixSecretsError):
    """Raised when a closed manager is used."""


class SecretStoreClosedError(PhoenixSecretsError):
    """Raised when a closed secret store is used."""


class SecretNotFoundError(PhoenixSecretsError):
    """Raised when a secret reference cannot be resolved."""


class SecretAlreadyExistsError(PhoenixSecretsError):
    """Raised when create is requested for an existing secret."""


class SecretRevokedError(PhoenixSecretsError):
    """Raised when a revoked secret version is requested."""


class SecretAccessDeniedError(PhoenixSecretsError):
    """Raised when an unauthenticated or unauthorized context requests a secret."""


class SecretLeaseError(PhoenixSecretsError):
    """Base class for lease failures."""


class SecretLeaseNotFoundError(SecretLeaseError):
    """Raised when a lease identifier does not exist."""


class SecretLeaseExpiredError(SecretLeaseError):
    """Raised when a lease has expired."""


class SecretLeaseRevokedError(SecretLeaseError):
    """Raised when a lease has been revoked."""


class SecretVersionError(PhoenixSecretsError):
    """Raised when an invalid secret version operation is requested."""
