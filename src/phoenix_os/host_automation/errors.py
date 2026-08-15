"""Safe public failures for OS-neutral host automation."""

from __future__ import annotations

from enum import StrEnum


class HostAutomationErrorCode(StrEnum):
    """Finite public error categories without native operating-system details."""

    AUTHORIZATION_REJECTED = "authorization_rejected"
    APPROVAL_REJECTED = "approval_rejected"
    LIMIT_EXCEEDED = "limit_exceeded"
    STALE_IDENTITY = "stale_identity"
    TARGET_NOT_FOUND = "target_not_found"
    APPLICATION_NOT_CONFIGURED = "application_not_configured"
    OPERATION_DISABLED = "operation_disabled"
    UNSAFE_DESKTOP = "unsafe_desktop"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    SERVICE_UNAVAILABLE = "service_unavailable"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INDETERMINATE_EFFECT = "indeterminate_effect"
    ADAPTER_FAILED = "adapter_failed"


class HostAutomationError(Exception):
    """Base class for safe host-automation failures."""

    code = HostAutomationErrorCode.ADAPTER_FAILED


class HostAutomationAuthorizationRejectedError(HostAutomationError):
    code = HostAutomationErrorCode.AUTHORIZATION_REJECTED

    def __init__(self) -> None:
        super().__init__("host automation request authorization failed")


class HostAutomationApprovalRejectedError(HostAutomationError):
    code = HostAutomationErrorCode.APPROVAL_REJECTED

    def __init__(self) -> None:
        super().__init__("host automation approval was not satisfied")


class HostAutomationLimitExceededError(HostAutomationError):
    code = HostAutomationErrorCode.LIMIT_EXCEEDED

    def __init__(self) -> None:
        super().__init__("host automation limit exceeded")


class HostAutomationStaleIdentityError(HostAutomationError):
    code = HostAutomationErrorCode.STALE_IDENTITY

    def __init__(self) -> None:
        super().__init__("host automation target identity is stale")


class HostAutomationTargetNotFoundError(HostAutomationError):
    code = HostAutomationErrorCode.TARGET_NOT_FOUND

    def __init__(self) -> None:
        super().__init__("host automation target is unavailable")


class HostApplicationNotConfiguredError(HostAutomationError):
    code = HostAutomationErrorCode.APPLICATION_NOT_CONFIGURED

    def __init__(self) -> None:
        super().__init__("host application is not configured")


class HostAutomationOperationDisabledError(HostAutomationError):
    code = HostAutomationErrorCode.OPERATION_DISABLED

    def __init__(self) -> None:
        super().__init__("host automation operation is disabled")


class HostAutomationUnsafeDesktopError(HostAutomationError):
    code = HostAutomationErrorCode.UNSAFE_DESKTOP

    def __init__(self) -> None:
        super().__init__("host desktop state is not safe for this operation")


class HostAutomationUnsupportedPlatformError(HostAutomationError):
    code = HostAutomationErrorCode.UNSUPPORTED_PLATFORM

    def __init__(self) -> None:
        super().__init__("host automation platform is unsupported")


class HostAutomationServiceUnavailableError(HostAutomationError):
    code = HostAutomationErrorCode.SERVICE_UNAVAILABLE

    def __init__(self) -> None:
        super().__init__("host automation service is unavailable")


class HostAutomationTimeoutError(HostAutomationError):
    code = HostAutomationErrorCode.TIMEOUT

    def __init__(self) -> None:
        super().__init__("host automation operation timed out")


class HostAutomationCancelledError(HostAutomationError):
    code = HostAutomationErrorCode.CANCELLED

    def __init__(self) -> None:
        super().__init__("host automation operation was cancelled")


class HostAutomationIndeterminateEffectError(HostAutomationError):
    code = HostAutomationErrorCode.INDETERMINATE_EFFECT

    def __init__(self) -> None:
        super().__init__("host automation effect outcome is indeterminate")


class HostAutomationAdapterError(HostAutomationError):
    code = HostAutomationErrorCode.ADAPTER_FAILED

    def __init__(self) -> None:
        super().__init__("host automation adapter failed")
