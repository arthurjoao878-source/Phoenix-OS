"""Secrets vault and provider-neutral key-management APIs."""

from phoenix_os.secrets.configuration import SecretConfigResolver, parse_secret_ref
from phoenix_os.secrets.contracts import (
    KeyRef,
    SecretLease,
    SecretLeasePolicy,
    SecretLeaseStatus,
    SecretMetadata,
    SecretProtector,
    SecretRef,
    SecretsSnapshot,
    SecretStatus,
    SecretStore,
    SecretStoreSnapshot,
    StoredSecret,
)
from phoenix_os.secrets.errors import (
    PhoenixSecretsError,
    SecretAccessDeniedError,
    SecretAlreadyExistsError,
    SecretLeaseError,
    SecretLeaseExpiredError,
    SecretLeaseNotFoundError,
    SecretLeaseRevokedError,
    SecretNotFoundError,
    SecretRevokedError,
    SecretsManagerClosedError,
    SecretStoreClosedError,
    SecretVersionError,
)
from phoenix_os.secrets.manager import SecretsManager
from phoenix_os.secrets.memory import InMemorySecretStore

__all__ = [
    "InMemorySecretStore",
    "KeyRef",
    "PhoenixSecretsError",
    "SecretAccessDeniedError",
    "SecretAlreadyExistsError",
    "SecretConfigResolver",
    "SecretLease",
    "SecretLeaseError",
    "SecretLeaseExpiredError",
    "SecretLeaseNotFoundError",
    "SecretLeasePolicy",
    "SecretLeaseRevokedError",
    "SecretLeaseStatus",
    "SecretMetadata",
    "SecretNotFoundError",
    "SecretProtector",
    "SecretRef",
    "SecretRevokedError",
    "SecretStatus",
    "SecretStore",
    "SecretStoreClosedError",
    "SecretStoreSnapshot",
    "SecretVersionError",
    "SecretsManager",
    "SecretsManagerClosedError",
    "SecretsSnapshot",
    "StoredSecret",
    "parse_secret_ref",
]
