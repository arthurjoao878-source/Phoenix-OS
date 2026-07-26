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
    PROVIDER_FAILED = "provider_failed"


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


class ModelProviderExecutionError(InferenceError):
    """Generic provider failure without private adapter details."""

    code = InferenceErrorCode.PROVIDER_FAILED

    def __init__(self) -> None:
        super().__init__("model provider execution failed")
