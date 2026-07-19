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


class ControlPlaneOperatorAlreadyExistsError(PhoenixControlPlaneError):
    """Raised when an operator id, username, or credential digest is duplicated."""


class ControlPlaneOperatorNotFoundError(PhoenixControlPlaneError):
    """Raised when a requested local operator does not exist."""


class ControlPlaneOperatorConflictError(PhoenixControlPlaneError):
    """Raised for stale revisions or invalid operator replacement state."""


class ControlPlaneOperatorStateError(ControlPlaneOperatorConflictError):
    """Raised when an operator lifecycle transition is not permitted."""


class ControlPlaneOperatorCapacityError(PhoenixControlPlaneError):
    """Raised when the bounded local operator registry is full."""


class ControlPlaneOperatorRegistryClosedError(PhoenixControlPlaneError):
    """Raised when a closed local operator registry receives an operation."""


class ControlPlaneOperatorPersistenceError(PhoenixControlPlaneError):
    """Raised when the durable operator registry cannot complete State Store work."""


class ControlPlaneOperatorCorruptionError(ControlPlaneOperatorPersistenceError):
    """Raised when persisted operator records or indexes fail strict validation."""


class ControlPlaneOperatorSchemaError(ControlPlaneOperatorCorruptionError):
    """Raised when persisted operator data uses an unsupported schema."""


class ControlPlaneOperatorAccessRejectedError(PhoenixControlPlaneError):
    """Raised with one generic message for rejected operator login attempts."""


class ControlPlaneOperatorSessionConflictError(PhoenixControlPlaneError):
    """Raised for duplicated, missing, or stale operator session mutations."""


class ControlPlaneOperatorSessionCapacityError(PhoenixControlPlaneError):
    """Raised when bounded operator session capacity is exhausted."""


class ControlPlaneOperatorSessionStoreClosedError(PhoenixControlPlaneError):
    """Raised when a closed operator session component receives work."""


class ControlPlaneOperatorRateLimitCapacityError(PhoenixControlPlaneError):
    """Raised when bounded login rate-limit tracking capacity is exhausted."""


class ControlPlaneOperatorPermissionDeniedError(PhoenixControlPlaneError):
    """Raised when an operator lacks an exact local access-management permission."""


class ControlPlaneDurableSessionAlreadyExistsError(PhoenixControlPlaneError):
    """Raised when a durable session id or protected token digest is duplicated."""


class ControlPlaneDurableSessionNotFoundError(PhoenixControlPlaneError):
    """Raised when a requested durable operator session does not exist."""


class ControlPlaneDurableSessionConflictError(PhoenixControlPlaneError):
    """Raised for stale revisions or invalid durable session transitions."""


class ControlPlaneDurableSessionCapacityError(PhoenixControlPlaneError):
    """Raised when bounded durable session capacity is exhausted."""


class ControlPlaneDurableSessionRepositoryClosedError(PhoenixControlPlaneError):
    """Raised when a closed durable session repository receives an operation."""


class ControlPlaneDurableSessionCorruptionError(PhoenixControlPlaneError):
    """Raised when persisted durable session state fails integrity validation."""


class ControlPlaneDurableSessionPersistenceError(PhoenixControlPlaneError):
    """Raised when the durable session State Store operation fails."""


class ControlPlaneDurableSessionSchemaError(ControlPlaneDurableSessionCorruptionError):
    """Raised when persisted durable session state uses an unsupported schema."""


class ControlPlaneDurableSessionAccessClosedError(PhoenixControlPlaneError):
    """Raised when a closed durable session access service receives work."""


class ControlPlaneDurableSessionRecoveryWorkerStateError(PhoenixControlPlaneError):
    """Raised when the durable session recovery worker lifecycle is misused."""


class ControlPlaneDurableSessionHttpRejectedError(PhoenixControlPlaneError):
    """Raised with one generic message for rejected durable-session HTTP evidence."""


class ControlPlaneDurableSessionCsrfRejectedError(PhoenixControlPlaneError):
    """Raised when session-bound rotating CSRF evidence fails closed."""


class ControlPlaneStepUpRejectedError(PhoenixControlPlaneError):
    """Raised with one generic message for rejected recent-authentication evidence."""


class ControlPlaneDurableSessionRetentionWorkerStateError(PhoenixControlPlaneError):
    """Raised when the durable session retention worker lifecycle is misused."""
