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


class WebhookPersistenceError(PhoenixWebhookError):
    """Raised when durable webhook persistence cannot complete."""


class WebhookCorruptionError(WebhookPersistenceError):
    """Raised when persisted webhook state fails strict validation."""


class WebhookSchemaError(WebhookCorruptionError):
    """Raised when persisted webhook state uses an unsupported schema."""


class WebhookEndpointRejectedError(PhoenixWebhookError):
    """Raised when an endpoint fails strict outbound validation."""


class WebhookSigningError(PhoenixWebhookError):
    """Raised when request signing cannot be completed safely."""


class WebhookTransportError(PhoenixWebhookError):
    """Raised for a safe classified outbound transport failure."""


class WebhookDispatcherClosedError(PhoenixWebhookError):
    """Raised when a closed dispatcher receives work."""


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
