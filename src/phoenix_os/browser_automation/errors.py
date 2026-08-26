"""Safe public failures for secure browser automation."""

from __future__ import annotations

from enum import StrEnum


class BrowserAutomationErrorCode(StrEnum):
    """Finite public error categories without page, network, credential, or native details."""

    REJECTED = "rejected"
    STALE = "stale"
    LIMIT_EXCEEDED = "limit_exceeded"
    TARGET_NOT_FOUND = "target_not_found"
    OPERATION_DISABLED = "operation_disabled"
    SERVICE_UNAVAILABLE = "service_unavailable"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INDETERMINATE_EFFECT = "indeterminate_effect"
    ADAPTER_FAILED = "adapter_failed"
    CONFIGURATION_INVALID = "configuration_invalid"


class BrowserAutomationError(Exception):
    """Base class for content-minimized browser-automation failures."""

    code = BrowserAutomationErrorCode.ADAPTER_FAILED


class BrowserAutomationRejectedError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.REJECTED

    def __init__(self) -> None:
        super().__init__("browser automation request was rejected")


class BrowserAutomationStaleError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.STALE

    def __init__(self) -> None:
        super().__init__("browser automation state is stale")


class BrowserAutomationLimitExceededError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.LIMIT_EXCEEDED

    def __init__(self) -> None:
        super().__init__("browser automation limit exceeded")


class BrowserAutomationTargetNotFoundError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.TARGET_NOT_FOUND

    def __init__(self) -> None:
        super().__init__("browser automation target is unavailable")


class BrowserAutomationOperationDisabledError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.OPERATION_DISABLED

    def __init__(self) -> None:
        super().__init__("browser automation operation is disabled")


class BrowserAutomationServiceUnavailableError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.SERVICE_UNAVAILABLE

    def __init__(self) -> None:
        super().__init__("browser automation service is unavailable")


class BrowserAutomationTimeoutError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.TIMEOUT

    def __init__(self) -> None:
        super().__init__("browser automation operation timed out")


class BrowserAutomationCancelledError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.CANCELLED

    def __init__(self) -> None:
        super().__init__("browser automation operation was cancelled")


class BrowserAutomationIndeterminateEffectError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.INDETERMINATE_EFFECT

    def __init__(self) -> None:
        super().__init__("browser automation effect outcome is indeterminate")


class BrowserAutomationAdapterError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.ADAPTER_FAILED

    def __init__(self) -> None:
        super().__init__("browser automation adapter failed")


class BrowserAutomationConfigurationError(BrowserAutomationError):
    code = BrowserAutomationErrorCode.CONFIGURATION_INVALID

    def __init__(self) -> None:
        super().__init__("browser automation configuration is invalid")
