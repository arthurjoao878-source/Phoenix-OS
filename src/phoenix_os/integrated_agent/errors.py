"""Safe public failures for RFC-0036 integrated agent contracts."""

from __future__ import annotations

from enum import StrEnum


class IntegratedAgentErrorCode(StrEnum):
    """Finite content-free integrated-agent error categories."""

    REJECTED = "rejected"
    VALIDATION_FAILED = "validation_failed"
    CONFIGURATION_INVALID = "configuration_invalid"
    CODEC_INVALID = "codec_invalid"
    PROVENANCE_OVERFLOW = "provenance_overflow"
    DATA_FLOW_DENIED = "data_flow_denied"
    LIMIT_EXCEEDED = "limit_exceeded"
    STALE = "stale"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    INDETERMINATE_EFFECT = "indeterminate_effect"
    INTERNAL_FAILURE = "internal_failure"


class IntegratedAgentError(Exception):
    """Base class for bounded content-minimized integrated-agent failures."""

    code = IntegratedAgentErrorCode.INTERNAL_FAILURE


class IntegratedAgentCodecError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.CODEC_INVALID

    def __init__(self, message: str = "integrated agent document is invalid") -> None:
        super().__init__(message)


class IntegratedAgentConfigurationError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.CONFIGURATION_INVALID

    def __init__(self) -> None:
        super().__init__("integrated agent configuration is invalid")


class IntegratedAgentProvenanceOverflowError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.PROVENANCE_OVERFLOW

    def __init__(self) -> None:
        super().__init__("integrated agent provenance exceeds configured bounds")
