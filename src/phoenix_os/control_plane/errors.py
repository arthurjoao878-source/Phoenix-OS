"""Control-plane transport and command exception hierarchy."""


class PhoenixControlPlaneError(Exception):
    """Base class for control-plane failures."""


class ControlPlaneServerStateError(PhoenixControlPlaneError):
    """Raised when the one-shot HTTP server lifecycle is used incorrectly."""


class ControlPlaneEventStreamStateError(PhoenixControlPlaneError):
    """Raised when the one-shot event stream lifecycle is used incorrectly."""


class ControlPlaneEventStreamBackpressureError(PhoenixControlPlaneError):
    """Raised when bounded long-poll waiter capacity has been exhausted."""


class ControlPlaneCommandPermissionDeniedError(PhoenixControlPlaneError):
    """Raised when a principal lacks the exact permission for a command action."""


class ControlPlaneIdempotencyConflictError(PhoenixControlPlaneError):
    """Raised when one key is reused for a different command fingerprint."""


class ControlPlaneIdempotencyCapacityError(PhoenixControlPlaneError):
    """Raised when bounded idempotency capacity contains only pending commands."""


class ControlPlaneIdempotencyStoreClosedError(PhoenixControlPlaneError):
    """Raised when a closed idempotency store receives a new operation."""


class ControlPlaneCommandStateError(PhoenixControlPlaneError):
    """Raised when command completion violates the reserved lifecycle."""


class ControlPlaneCommandBindingError(PhoenixControlPlaneError):
    """Raised when a command body does not match its signed intent identity."""


class ControlPlaneCsrfRejectedError(PhoenixControlPlaneError):
    """Raised when an origin-bound browser CSRF token cannot be validated."""


class ControlPlaneConfirmationNotRequiredError(PhoenixControlPlaneError):
    """Raised when confirmation is requested for a non-destructive action."""


class ControlPlaneConfirmationRejectedError(PhoenixControlPlaneError):
    """Raised for malformed, expired, mismatched, unknown, or replayed proofs."""


class ControlPlaneConfirmationCapacityError(PhoenixControlPlaneError):
    """Raised when bounded confirmation capacity contains only active challenges."""


class ControlPlaneConfirmationStoreClosedError(PhoenixControlPlaneError):
    """Raised when a closed confirmation service receives an operation."""


class ControlPlaneCommandJournalAlreadyExistsError(PhoenixControlPlaneError):
    """Raised when a command id or idempotency digest already exists."""


class ControlPlaneCommandJournalNotFoundError(PhoenixControlPlaneError):
    """Raised when a requested command journal record does not exist."""


class ControlPlaneCommandJournalConflictError(PhoenixControlPlaneError):
    """Raised for stale revisions or invalid command lifecycle transitions."""


class ControlPlaneCommandJournalCapacityError(PhoenixControlPlaneError):
    """Raised when the bounded command journal has no remaining capacity."""


class ControlPlaneCommandJournalRepositoryClosedError(PhoenixControlPlaneError):
    """Raised when a closed command journal repository receives an operation."""


class ControlPlaneCommandJournalPersistenceError(PhoenixControlPlaneError):
    """Raised when the durable journal cannot complete a State Store operation."""


class ControlPlaneCommandJournalCorruptionError(ControlPlaneCommandJournalPersistenceError):
    """Raised when persisted journal records or indexes fail strict validation."""


class ControlPlaneCommandJournalSchemaError(ControlPlaneCommandJournalCorruptionError):
    """Raised when persisted command-journal data uses an unsupported schema."""


class ControlPlaneCommandRecoveryWorkerStateError(PhoenixControlPlaneError):
    """Raised when the one-shot command recovery worker lifecycle is misused."""


class ControlPlaneCommandRetentionWorkerStateError(PhoenixControlPlaneError):
    """Raised when the one-shot command retention worker lifecycle is misused."""
