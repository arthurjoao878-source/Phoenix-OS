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


class IntegratedAgentRejectedError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.REJECTED

    def __init__(self, message: str = "integrated agent request was rejected") -> None:
        super().__init__(message)


class IntegratedAgentValidationError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.VALIDATION_FAILED

    def __init__(self, message: str = "integrated agent request validation failed") -> None:
        super().__init__(message)


class IntegratedAgentStaleError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.STALE

    def __init__(self, message: str = "integrated agent state is stale") -> None:
        super().__init__(message)


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


class IntegratedAgentDataFlowDeniedError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.DATA_FLOW_DENIED

    def __init__(self) -> None:
        super().__init__("integrated agent data flow was denied")


class IntegratedAgentBudgetExhaustedError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.LIMIT_EXCEEDED

    def __init__(self) -> None:
        super().__init__("integrated agent budget is exhausted")


class IntegratedAgentDeadlineExceededError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.TIMEOUT

    def __init__(self) -> None:
        super().__init__("integrated agent deadline was exceeded")


class IntegratedAgentCancelledError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.CANCELLED

    def __init__(self) -> None:
        super().__init__("integrated agent execution was cancelled")


class IntegratedAgentIndeterminateEffectError(IntegratedAgentError):
    code = IntegratedAgentErrorCode.INDETERMINATE_EFFECT

    def __init__(self) -> None:
        super().__init__("integrated agent effect is indeterminate")
