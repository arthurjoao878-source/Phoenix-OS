"""Kernel exceptions translated into safe responses."""


class KernelError(RuntimeError):
    status = 500
    code = "kernel_error"


class RouteNotFoundError(KernelError):
    status = 404
    code = "route_not_found"


class AuthorizationDeniedError(KernelError):
    status = 403
    code = "authorization_denied"


class ConfirmationRequiredError(KernelError):
    status = 409
    code = "confirmation_required"


class DeadlineExceededError(KernelError):
    status = 504
    code = "deadline_exceeded"
