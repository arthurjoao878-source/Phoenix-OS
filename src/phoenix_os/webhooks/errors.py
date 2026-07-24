"""Errors raised by durable Phoenix webhook delivery."""


class PhoenixWebhookError(Exception):
    """Base class for webhook subsystem failures."""


class WebhookSubscriptionAlreadyExistsError(PhoenixWebhookError):
    """Raised when a subscription id or name already exists."""


class WebhookSubscriptionNotFoundError(PhoenixWebhookError):
    """Raised when a requested subscription does not exist."""


class WebhookSubscriptionConflictError(PhoenixWebhookError):
    """Raised for stale revisions or invalid subscription transitions."""


class WebhookSubscriptionCapacityError(PhoenixWebhookError):
    """Raised when bounded subscription capacity is exhausted."""


class WebhookDeliveryAlreadyExistsError(PhoenixWebhookError):
    """Raised when a delivery id or deduplication key already exists."""


class WebhookDeliveryNotFoundError(PhoenixWebhookError):
    """Raised when a requested delivery does not exist."""


class WebhookDeliveryConflictError(PhoenixWebhookError):
    """Raised for stale revisions or invalid delivery transitions."""


class WebhookDeliveryCapacityError(PhoenixWebhookError):
    """Raised when bounded delivery capacity is exhausted."""


class WebhookSubscriptionRepositoryClosedError(PhoenixWebhookError):
    """Raised when a closed subscription repository receives work."""


class WebhookDeliveryRepositoryClosedError(PhoenixWebhookError):
    """Raised when a closed delivery repository receives work."""


class WebhookDeliverySchedulerClosedError(PhoenixWebhookError):
    """Raised when a closed delivery scheduler receives work."""


class WebhookPersistenceError(PhoenixWebhookError):
    """Raised when durable webhook persistence cannot complete."""


class WebhookCorruptionError(WebhookPersistenceError):
    """Raised when persisted webhook state fails strict validation."""


class WebhookSchemaError(WebhookCorruptionError):
    """Raised when persisted webhook state uses an unsupported schema."""


def _normalize_failure_category(value: str) -> str:
    normalized = value.strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if (
        not normalized
        or len(normalized) > 64
        or not normalized[0].isalpha()
        or any(character not in allowed for character in normalized)
    ):
        raise ValueError("webhook failure category contains unsupported characters")
    return normalized


class WebhookEndpointRejectedError(PhoenixWebhookError):
    """Raised when an endpoint fails strict outbound validation."""

    def __init__(self, category: str) -> None:
        self.category = _normalize_failure_category(category)
        super().__init__(f"webhook endpoint rejected: {self.category}")


class WebhookEventAdapterStateError(PhoenixWebhookError):
    """Raised for invalid Event Bus adapter lifecycle transitions."""


class WebhookSigningError(PhoenixWebhookError):
    """Raised when request signing cannot be completed safely."""


class WebhookTransportError(PhoenixWebhookError):
    """Raised for a safe classified outbound transport failure."""

    def __init__(self, category: str, *, retryable: bool = False) -> None:
        if type(retryable) is not bool:
            raise TypeError("webhook transport retryable flag must be bool")
        self.category = _normalize_failure_category(category)
        self.retryable = retryable
        super().__init__(f"webhook transport failed: {self.category}")


class WebhookDispatcherClosedError(PhoenixWebhookError):
    """Raised when a closed dispatcher receives work."""


class WebhookRecoveryClosedError(PhoenixWebhookError):
    """Raised when closed webhook recovery services receive work."""


class WebhookRedriveAccessDeniedError(PhoenixWebhookError):
    """Raised when explicit dead-letter retry lacks authorization."""


class WebhookRedriveNotEligibleError(PhoenixWebhookError):
    """Raised when a delivery cannot be explicitly retried."""

    def __init__(self, category: str) -> None:
        self.category = _normalize_failure_category(category)
        super().__init__(f"webhook redrive rejected: {self.category}")


class WebhookManagerClosedError(PhoenixWebhookError):
    """Raised when a closed webhook manager receives work."""


class WebhookEventAlreadyRegisteredError(PhoenixWebhookError):
    """Raised when a webhook event type is already registered."""


class WebhookEventNotFoundError(PhoenixWebhookError):
    """Raised when a webhook event type is not registered."""


class WebhookEventRegistryClosedError(PhoenixWebhookError):
    """Raised when a closed webhook event registry receives work."""


class WebhookPayloadSerializationError(PhoenixWebhookError):
    """Raised when a registered serializer produces an invalid payload."""


class WebhookResourceFilterError(PhoenixWebhookError):
    """Raised when subscription filters are unsupported by registered events."""
