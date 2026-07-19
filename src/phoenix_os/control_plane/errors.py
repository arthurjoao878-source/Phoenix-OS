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
