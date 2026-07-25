"""Errors raised by secure inbound event persistence."""


class PhoenixInboundEventError(Exception):
    """Base class for inbound-event subsystem failures."""


class InboundAuthenticationRejectedError(PhoenixInboundEventError):
    """Generic authentication failure without source or credential details."""

    def __init__(self) -> None:
        super().__init__("inbound request authentication failed")


class InboundReplayRejectedError(PhoenixInboundEventError):
    """Generic public rejection for reused request or nonce evidence."""

    def __init__(self) -> None:
        super().__init__("inbound request replay rejected")


class InboundIdempotencyConflictError(PhoenixInboundEventError):
    """Generic conflict for source-event identity reused with new content."""

    def __init__(self) -> None:
        super().__init__("inbound source-event content conflicts")


class InboundAdmissionRejectedError(PhoenixInboundEventError):
    """Generic rejection when a finite admission limit is exhausted."""

    def __init__(self) -> None:
        super().__init__("inbound admission limit exceeded")


class InboundAdmissionLimiterClosedError(PhoenixInboundEventError):
    """Raised when a closed admission limiter receives work."""


class InboundPolicyDeniedError(PhoenixInboundEventError):
    """Generic authenticated policy denial before durable acceptance."""

    def __init__(self) -> None:
        super().__init__("inbound submission policy denied")


class InboundGatewayUnavailableError(PhoenixInboundEventError):
    """Raised when the gateway cannot safely complete a request."""


class InboundSchemaRegistrationError(PhoenixInboundEventError):
    """Raised when reviewed schema registration cannot complete."""


class InboundPayloadValidationError(PhoenixInboundEventError):
    """Generic invalid external envelope or payload rejection."""

    def __init__(self) -> None:
        super().__init__("inbound event payload is invalid")


class InboundNormalizerError(PhoenixInboundEventError):
    """Generic reviewed normalizer failure without private exception text."""

    def __init__(self) -> None:
        super().__init__("inbound event normalization failed")


class InboundManagerAccessDeniedError(PhoenixInboundEventError):
    """Raised when inbound administration lacks an exact permission."""


class InboundManagerClosedError(PhoenixInboundEventError):
    """Raised when a closed inbound manager receives work."""


class InboundPublisherClosedError(PhoenixInboundEventError):
    """Raised when a closed inbound publisher receives work."""


class InboundPublisherStateError(PhoenixInboundEventError):
    """Raised for invalid Runtime-owned publisher worker transitions."""


class InboundRecoveryClosedError(PhoenixInboundEventError):
    """Raised when a closed inbound recovery service receives work."""


class InboundRecoveryStateError(PhoenixInboundEventError):
    """Raised for invalid Runtime-owned recovery worker transitions."""


class InboundRedriveAccessDeniedError(PhoenixInboundEventError):
    """Raised when dead-letter redrive lacks exact authorization."""


class InboundRedriveNotEligibleError(PhoenixInboundEventError):
    """Raised when an inbound event cannot be explicitly redriven."""


class InboundSourceAlreadyExistsError(PhoenixInboundEventError):
    """Raised when an inbound source id or name already exists."""


class InboundSourceNotFoundError(PhoenixInboundEventError):
    """Raised when an inbound source does not exist."""


class InboundSourceConflictError(PhoenixInboundEventError):
    """Raised for stale revisions or invalid source transitions."""


class InboundSourceCapacityError(PhoenixInboundEventError):
    """Raised when bounded source capacity is exhausted."""


class InboundEventAlreadyExistsError(PhoenixInboundEventError):
    """Raised when an accepted event or source-event identity already exists."""


class InboundEventNotFoundError(PhoenixInboundEventError):
    """Raised when an accepted event does not exist."""


class InboundEventConflictError(PhoenixInboundEventError):
    """Raised for stale revisions or invalid event transitions."""


class InboundEventCapacityError(PhoenixInboundEventError):
    """Raised when bounded accepted-event capacity is exhausted."""


class InboundReplayAlreadyExistsError(PhoenixInboundEventError):
    """Raised when replay evidence is already reserved."""


class InboundReplayCapacityError(PhoenixInboundEventError):
    """Raised when bounded replay capacity is exhausted."""


class InboundSourceRepositoryClosedError(PhoenixInboundEventError):
    """Raised when a closed source repository receives work."""


class InboundEventRepositoryClosedError(PhoenixInboundEventError):
    """Raised when a closed accepted-event repository receives work."""


class InboundReplayRepositoryClosedError(PhoenixInboundEventError):
    """Raised when a closed replay repository receives work."""


class InboundPersistenceError(PhoenixInboundEventError):
    """Raised when durable inbound-event persistence cannot complete."""


class InboundCorruptionError(InboundPersistenceError):
    """Raised when persisted inbound-event state fails strict validation."""


class InboundSchemaError(InboundCorruptionError):
    """Raised when persisted inbound-event state uses an unsupported schema."""
