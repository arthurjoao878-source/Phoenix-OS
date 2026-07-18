"""Errors raised by the Phoenix audit ledger and security journal."""


class PhoenixAuditError(Exception):
    """Base class for audit failures."""


class AuditLedgerClosedError(PhoenixAuditError):
    """Raised when an operation requires an open audit ledger."""


class AuditStoreClosedError(PhoenixAuditError):
    """Raised when an append targets a closed audit store."""


class AuditAccessDeniedError(PhoenixAuditError):
    """Raised when a caller cannot inspect or verify audit history."""


class AuditSignerError(PhoenixAuditError):
    """Raised when an external signing provider fails."""


class AuditPersistenceError(PhoenixAuditError):
    """Raised when durable audit storage cannot complete an operation."""


class AuditSchemaError(AuditPersistenceError):
    """Raised when a durable audit schema is missing or incompatible."""


class AuditStoreCorruptionError(AuditPersistenceError):
    """Raised when persisted audit data cannot be decoded safely."""


class AuditRecoveryError(AuditPersistenceError):
    """Raised when a durable ledger cannot safely resume appending."""


class SecurityJournalStateError(PhoenixAuditError):
    """Raised when the Security Journal lifecycle is used incorrectly."""
