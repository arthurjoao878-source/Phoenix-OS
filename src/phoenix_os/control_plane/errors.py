"""Control-plane transport exception hierarchy."""


class PhoenixControlPlaneError(Exception):
    """Base class for control-plane failures."""


class ControlPlaneServerStateError(PhoenixControlPlaneError):
    """Raised when the one-shot HTTP server lifecycle is used incorrectly."""


class ControlPlaneEventStreamStateError(PhoenixControlPlaneError):
    """Raised when the one-shot event stream lifecycle is used incorrectly."""


class ControlPlaneEventStreamBackpressureError(PhoenixControlPlaneError):
    """Raised when bounded long-poll waiter capacity has been exhausted."""
