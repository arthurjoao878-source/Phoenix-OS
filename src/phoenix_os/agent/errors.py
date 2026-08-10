"""Safe bounded errors for the Phoenix-owned agent boundary."""

from __future__ import annotations

from enum import StrEnum


class AgentErrorCode(StrEnum):
    REGISTRY_CLOSED = "registry_closed"
    TOOL_ALREADY_REGISTERED = "tool_already_registered"
    TOOL_NOT_FOUND = "tool_not_found"
    SCHEMA_INVALID = "schema_invalid"
    CODEC_INVALID = "codec_invalid"
    LIMIT_EXCEEDED = "limit_exceeded"
    MALFORMED_PROPOSAL = "malformed_proposal"
    AUTHORIZATION_REJECTED = "authorization_rejected"
    APPROVAL_REJECTED = "approval_rejected"
    TOOL_FAILED = "tool_failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SERVICE_UNAVAILABLE = "service_unavailable"
    STATE_CONFLICT = "state_conflict"
    ADMINISTRATION_DENIED = "administration_denied"
    ADMINISTRATION_CONFLICT = "administration_conflict"
    COORDINATION_REJECTED = "coordination_rejected"
    COORDINATION_REGISTRY_CLOSED = "coordination_registry_closed"
    DELEGABLE_AGENT_ALREADY_REGISTERED = "delegable_agent_already_registered"
    DELEGABLE_AGENT_NOT_FOUND = "delegable_agent_not_found"


class AgentError(Exception):
    """Base class for public agent failures without private model or tool content."""

    code = AgentErrorCode.TOOL_FAILED


class AgentRegistryClosedError(AgentError):
    code = AgentErrorCode.REGISTRY_CLOSED

    def __init__(self) -> None:
        super().__init__("agent tool registry is closed")


class ToolAlreadyRegisteredError(AgentError):
    code = AgentErrorCode.TOOL_ALREADY_REGISTERED

    def __init__(self) -> None:
        super().__init__("tool is already registered")


class ToolNotFoundError(AgentError):
    code = AgentErrorCode.TOOL_NOT_FOUND

    def __init__(self) -> None:
        super().__init__("tool was not found")


class AgentSchemaError(AgentError):
    code = AgentErrorCode.SCHEMA_INVALID

    def __init__(self, message: str = "agent schema is invalid") -> None:
        super().__init__(message)


class AgentCodecError(AgentError):
    code = AgentErrorCode.CODEC_INVALID

    def __init__(self, message: str = "agent document is invalid") -> None:
        super().__init__(message)


class AgentLimitExceededError(AgentError):
    code = AgentErrorCode.LIMIT_EXCEEDED

    def __init__(self) -> None:
        super().__init__("agent limit exceeded")


class AgentMalformedProposalError(AgentError):
    code = AgentErrorCode.MALFORMED_PROPOSAL

    def __init__(self) -> None:
        super().__init__("agent tool proposal is invalid")


class AgentAuthorizationRejectedError(AgentError):
    code = AgentErrorCode.AUTHORIZATION_REJECTED

    def __init__(self) -> None:
        super().__init__("agent authorization failed")


class AgentApprovalRejectedError(AgentError):
    code = AgentErrorCode.APPROVAL_REJECTED

    def __init__(self) -> None:
        super().__init__("agent approval failed")


class ToolExecutionError(AgentError):
    code = AgentErrorCode.TOOL_FAILED

    def __init__(self) -> None:
        super().__init__("tool execution failed")


class AgentTimeoutError(AgentError):
    code = AgentErrorCode.TIMEOUT

    def __init__(self) -> None:
        super().__init__("agent execution timed out")


class AgentCancelledError(AgentError):
    code = AgentErrorCode.CANCELLED

    def __init__(self) -> None:
        super().__init__("agent execution was cancelled")


class AgentServiceUnavailableError(AgentError):
    code = AgentErrorCode.SERVICE_UNAVAILABLE

    def __init__(self) -> None:
        super().__init__("agent service is unavailable")


class AgentStateConflictError(AgentError):
    code = AgentErrorCode.STATE_CONFLICT

    def __init__(self) -> None:
        super().__init__("agent state transition conflict")


class AgentAdministrationAccessDeniedError(AgentError):
    code = AgentErrorCode.ADMINISTRATION_DENIED

    def __init__(self) -> None:
        super().__init__("agent administration access denied")


class AgentAdministrationConflictError(AgentError):
    code = AgentErrorCode.ADMINISTRATION_CONFLICT

    def __init__(self) -> None:
        super().__init__("agent administration revision conflict")


class AgentCoordinationError(AgentError):
    code = AgentErrorCode.COORDINATION_REJECTED

    def __init__(self, message: str = "agent coordination failed") -> None:
        super().__init__(message)


class AgentDelegationRegistryClosedError(AgentCoordinationError):
    code = AgentErrorCode.COORDINATION_REGISTRY_CLOSED

    def __init__(self) -> None:
        super().__init__("agent delegation registry is closed")


class DelegableAgentAlreadyRegisteredError(AgentCoordinationError):
    code = AgentErrorCode.DELEGABLE_AGENT_ALREADY_REGISTERED

    def __init__(self) -> None:
        super().__init__("delegable agent is already registered")


class DelegableAgentNotFoundError(AgentCoordinationError):
    code = AgentErrorCode.DELEGABLE_AGENT_NOT_FOUND

    def __init__(self) -> None:
        super().__init__("delegable agent was not found")
