import pytest

from phoenix_os.host_automation import (
    HostApplicationNotConfiguredError,
    HostAutomationAdapterError,
    HostAutomationApprovalRejectedError,
    HostAutomationAuthorizationRejectedError,
    HostAutomationCancelledError,
    HostAutomationError,
    HostAutomationErrorCode,
    HostAutomationIndeterminateEffectError,
    HostAutomationLimitExceededError,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
    HostAutomationTargetNotFoundError,
    HostAutomationTimeoutError,
    HostAutomationUnsafeDesktopError,
    HostAutomationUnsupportedPlatformError,
)


@pytest.mark.parametrize(
    ("error", "code", "message"),
    (
        (
            HostAutomationAuthorizationRejectedError(),
            HostAutomationErrorCode.AUTHORIZATION_REJECTED,
            "host automation request authorization failed",
        ),
        (
            HostAutomationApprovalRejectedError(),
            HostAutomationErrorCode.APPROVAL_REJECTED,
            "host automation approval was not satisfied",
        ),
        (
            HostAutomationLimitExceededError(),
            HostAutomationErrorCode.LIMIT_EXCEEDED,
            "host automation limit exceeded",
        ),
        (
            HostAutomationStaleIdentityError(),
            HostAutomationErrorCode.STALE_IDENTITY,
            "host automation target identity is stale",
        ),
        (
            HostAutomationTargetNotFoundError(),
            HostAutomationErrorCode.TARGET_NOT_FOUND,
            "host automation target is unavailable",
        ),
        (
            HostApplicationNotConfiguredError(),
            HostAutomationErrorCode.APPLICATION_NOT_CONFIGURED,
            "host application is not configured",
        ),
        (
            HostAutomationOperationDisabledError(),
            HostAutomationErrorCode.OPERATION_DISABLED,
            "host automation operation is disabled",
        ),
        (
            HostAutomationUnsafeDesktopError(),
            HostAutomationErrorCode.UNSAFE_DESKTOP,
            "host desktop state is not safe for this operation",
        ),
        (
            HostAutomationUnsupportedPlatformError(),
            HostAutomationErrorCode.UNSUPPORTED_PLATFORM,
            "host automation platform is unsupported",
        ),
        (
            HostAutomationServiceUnavailableError(),
            HostAutomationErrorCode.SERVICE_UNAVAILABLE,
            "host automation service is unavailable",
        ),
        (
            HostAutomationTimeoutError(),
            HostAutomationErrorCode.TIMEOUT,
            "host automation operation timed out",
        ),
        (
            HostAutomationCancelledError(),
            HostAutomationErrorCode.CANCELLED,
            "host automation operation was cancelled",
        ),
        (
            HostAutomationIndeterminateEffectError(),
            HostAutomationErrorCode.INDETERMINATE_EFFECT,
            "host automation effect outcome is indeterminate",
        ),
        (
            HostAutomationAdapterError(),
            HostAutomationErrorCode.ADAPTER_FAILED,
            "host automation adapter failed",
        ),
    ),
)
def test_public_errors_use_stable_content_free_categories(
    error: HostAutomationError,
    code: HostAutomationErrorCode,
    message: str,
) -> None:
    assert error.code is code
    assert str(error) == message
    for forbidden in ("C:\\", "HWND", "PID=", "token=", "clipboard="):
        assert forbidden not in str(error)
