"""Safe errors for the provider-neutral inference boundary."""

from __future__ import annotations

from enum import StrEnum


class InferenceErrorCode(StrEnum):
    """Stable public error categories without provider-private details."""

    REGISTRY_CLOSED = "registry_closed"
    PROVIDER_ALREADY_REGISTERED = "provider_already_registered"
    PROVIDER_NOT_FOUND = "provider_not_found"
    MODEL_ALREADY_REGISTERED = "model_already_registered"
    MODEL_NOT_FOUND = "model_not_found"
    CAPABILITY_MISMATCH = "capability_mismatch"
    CODEC_INVALID = "codec_invalid"
    AUTHORIZATION_REJECTED = "authorization_rejected"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    ENDPOINT_REJECTED = "endpoint_rejected"
    SATURATED = "saturated"
    TIMEOUT = "timeout"
    LIMIT_EXCEEDED = "limit_exceeded"
    MALFORMED_OUTPUT = "malformed_output"
    CANCELLED = "cancelled"
    PROVIDER_FAILED = "provider_failed"


class InferenceEndpointRejectionCode(StrEnum):
    """Finite endpoint-admission reasons safe for local diagnostics."""

    DNS_NO_ADDRESSES = "dns_no_addresses"
    TOO_MANY_ADDRESSES = "too_many_addresses"
    INVALID_ADDRESS = "invalid_address"
    LOOPBACK_RESOLUTION_MISMATCH = "loopback_resolution_mismatch"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"


class InferenceError(Exception):
    """Base class for inference failures."""

    code = InferenceErrorCode.PROVIDER_FAILED


class InferenceRegistryClosedError(InferenceError):
    code = InferenceErrorCode.REGISTRY_CLOSED


class ModelProviderAlreadyRegisteredError(InferenceError):
    code = InferenceErrorCode.PROVIDER_ALREADY_REGISTERED


class ModelProviderNotFoundError(InferenceError):
    code = InferenceErrorCode.PROVIDER_NOT_FOUND


class ModelAlreadyRegisteredError(InferenceError):
    code = InferenceErrorCode.MODEL_ALREADY_REGISTERED


class ModelNotFoundError(InferenceError):
    code = InferenceErrorCode.MODEL_NOT_FOUND


class ModelCapabilityMismatchError(InferenceError):
    code = InferenceErrorCode.CAPABILITY_MISMATCH


class InferenceCodecError(InferenceError):
    """Generic bounded-codec failure without document contents."""

    code = InferenceErrorCode.CODEC_INVALID

    def __init__(self, message: str = "inference document is invalid") -> None:
        super().__init__(message)


class InferenceAuthorizationRejectedError(InferenceError):
    """Generic default-deny result without provider or model enumeration."""

    code = InferenceErrorCode.AUTHORIZATION_REJECTED

    def __init__(self) -> None:
        super().__init__("inference request authorization failed")


class InferenceCredentialUnavailableError(InferenceError):
    """Generic credential failure without secret names, versions, or material."""

    code = InferenceErrorCode.CREDENTIAL_UNAVAILABLE

    def __init__(self) -> None:
        super().__init__("inference credential is unavailable")


class InferenceEndpointRejectedError(InferenceError):
    """Generic endpoint rejection with one finite local diagnostic category."""

    code = InferenceErrorCode.ENDPOINT_REJECTED

    def __init__(self, category: InferenceEndpointRejectionCode) -> None:
        if not isinstance(category, InferenceEndpointRejectionCode):
            raise TypeError("category must be InferenceEndpointRejectionCode")
        self.category = category
        super().__init__("inference endpoint rejected")


class InferenceSaturatedError(InferenceError):
    """Fail-fast admission rejection without provider or model enumeration."""

    code = InferenceErrorCode.SATURATED

    def __init__(self) -> None:
        super().__init__("inference capacity is unavailable")


class InferenceTimeoutError(InferenceError):
    """Generic deadline, first-byte, or total-duration timeout."""

    code = InferenceErrorCode.TIMEOUT

    def __init__(self) -> None:
        super().__init__("inference execution timed out")


class InferenceLimitExceededError(InferenceError):
    """Generic request, response, byte, token, or chunk limit rejection."""

    code = InferenceErrorCode.LIMIT_EXCEEDED

    def __init__(self) -> None:
        super().__init__("inference limit exceeded")


class InferenceMalformedOutputError(InferenceError):
    """Generic malformed provider response or stream failure."""

    code = InferenceErrorCode.MALFORMED_OUTPUT

    def __init__(self) -> None:
        super().__init__("model provider output is invalid")


class InferenceCancelledError(InferenceError):
    """Provider-reported cancellation distinct from caller task cancellation."""

    code = InferenceErrorCode.CANCELLED

    def __init__(self) -> None:
        super().__init__("inference execution was cancelled")


class ModelProviderExecutionError(InferenceError):
    """Generic provider failure without private adapter details."""

    code = InferenceErrorCode.PROVIDER_FAILED

    def __init__(self) -> None:
        super().__init__("model provider execution failed")
