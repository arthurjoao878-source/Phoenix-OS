"""Public package surface for Phoenix OS."""

from phoenix_os.events import (
    BusClosedError,
    DispatchFailure,
    DispatchReport,
    ErrorPolicy,
    Event,
    EventBus,
    EventDispatchError,
    Subscription,
)
from phoenix_os.kernel import (
    AllowAllAuthorizer,
    AuthorizationDecision,
    AuthorizationStatus,
    Handler,
    Kernel,
    KernelError,
    Request,
    Response,
    Route,
    Router,
)

__all__ = [
    "AllowAllAuthorizer",
    "AuthorizationDecision",
    "AuthorizationStatus",
    "BusClosedError",
    "DispatchFailure",
    "DispatchReport",
    "ErrorPolicy",
    "Event",
    "EventBus",
    "EventDispatchError",
    "Handler",
    "Kernel",
    "KernelError",
    "Request",
    "Response",
    "Route",
    "Router",
    "Subscription",
]

__version__ = "0.2.0"
