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


class SecurityJournalStateError(PhoenixAuditError):
    """Raised when the Security Journal lifecycle is used incorrectly."""
