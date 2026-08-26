import pytest

from phoenix_os.browser_automation import (
    BrowserAutomationAdapterError,
    BrowserAutomationCancelledError,
    BrowserAutomationConfigurationError,
    BrowserAutomationError,
    BrowserAutomationErrorCode,
    BrowserAutomationIndeterminateEffectError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationOperationDisabledError,
    BrowserAutomationRejectedError,
    BrowserAutomationServiceUnavailableError,
    BrowserAutomationStaleError,
    BrowserAutomationTargetNotFoundError,
    BrowserAutomationTimeoutError,
)

_ERROR_TYPES = (
    BrowserAutomationRejectedError,
    BrowserAutomationStaleError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationTargetNotFoundError,
    BrowserAutomationOperationDisabledError,
    BrowserAutomationServiceUnavailableError,
    BrowserAutomationTimeoutError,
    BrowserAutomationCancelledError,
    BrowserAutomationIndeterminateEffectError,
    BrowserAutomationAdapterError,
    BrowserAutomationConfigurationError,
)


def test_browser_errors_are_finite_safe_public_failures() -> None:
    for error_type in _ERROR_TYPES:
        error = error_type()
        assert isinstance(error, BrowserAutomationError)
        assert isinstance(error.code, BrowserAutomationErrorCode)
        rendered = str(error).lower()
        for forbidden in (
            "http://",
            "https://",
            "cookie",
            "authorization:",
            "password",
            "traceback",
            "selector",
            "xpath",
        ):
            assert forbidden not in rendered


def test_browser_errors_do_not_accept_caller_supplied_detail_strings() -> None:
    with pytest.raises(TypeError):
        BrowserAutomationAdapterError("secret remote detail")  # type: ignore[call-arg]
