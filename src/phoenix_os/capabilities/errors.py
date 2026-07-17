"""Safe domain errors raised by the Capability Registry."""


class CapabilityError(RuntimeError):
    status = 500
    code = "capability_error"


class CapabilityNotFoundError(CapabilityError):
    status = 404
    code = "capability_not_found"


class CapabilityAlreadyRegisteredError(CapabilityError):
    status = 409
    code = "capability_already_registered"


class CapabilityPermissionDeniedError(CapabilityError):
    status = 403
    code = "capability_permission_denied"


class CapabilityConfirmationRequiredError(CapabilityError):
    status = 409
    code = "capability_confirmation_required"


class CapabilityDeadlineExceededError(CapabilityError):
    status = 504
    code = "capability_deadline_exceeded"


class CapabilityExecutionError(CapabilityError):
    status = 502
    code = "capability_execution_failed"


class CapabilityPolicyError(CapabilityError):
    status = 500
    code = "capability_policy_failed"


class CapabilityRegistryClosedError(CapabilityError):
    status = 503
    code = "capability_registry_closed"
