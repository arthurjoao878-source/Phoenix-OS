"""Bounded in-memory repositories for durable webhook state."""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import ClassVar
from uuid import UUID

from phoenix_os.webhooks.contracts import (
    DEFAULT_WEBHOOK_PAGE_REQUEST,
    MAX_WEBHOOK_DELIVERY_CAPACITY,
    MAX_WEBHOOK_SUBSCRIPTION_CAPACITY,
    WebhookDelivery,
    WebhookDeliveryPage,
    WebhookDeliveryRepositorySnapshot,
    WebhookDeliveryStatus,
    WebhookPageInfo,
    WebhookPageRequest,
    WebhookSubscription,
    WebhookSubscriptionPage,
    WebhookSubscriptionRepositorySnapshot,
    WebhookSubscriptionStatus,
    _normalize_name,
    _normalize_sha256,
)
from phoenix_os.webhooks.errors import (
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliveryCapacityError,
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryRepositoryClosedError,
    WebhookSubscriptionAlreadyExistsError,
    WebhookSubscriptionCapacityError,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
    WebhookSubscriptionRepositoryClosedError,
)


class InMemoryWebhookSubscriptionRepository:
    """Process-local subscription repository with bounded unique indexes."""

    def __init__(self, *, capacity: int = 256) -> None:
        if capacity <= 0 or capacity > MAX_WEBHOOK_SUBSCRIPTION_CAPACITY:
            raise ValueError(
                "webhook subscription capacity must be between 1 and "
                f"{MAX_WEBHOOK_SUBSCRIPTION_CAPACITY}"
            )
        self._capacity = capacity
        self._subscriptions: dict[UUID, WebhookSubscription] = {}
        self._name_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, subscription: WebhookSubscription) -> None:
        async with self._lock:
            self._require_open()
            if subscription.id in self._subscriptions:
                raise WebhookSubscriptionAlreadyExistsError(
                    "webhook subscription id already exists"
                )
            if subscription.name in self._name_index:
                raise WebhookSubscriptionAlreadyExistsError(
                    "webhook subscription name already exists"
                )
            if len(self._subscriptions) >= self._capacity:
                raise WebhookSubscriptionCapacityError(
                    "webhook subscription repository capacity has been exhausted"
                )
            self._subscriptions[subscription.id] = subscription
            self._name_index[subscription.name] = subscription.id

    async def get(self, subscription_id: UUID) -> WebhookSubscription | None:
        async with self._lock:
            self._require_open()
            return self._subscriptions.get(subscription_id)

    async def get_by_name(self, name: str) -> WebhookSubscription | None:
        normalized = _normalize_name(name, label="webhook subscription")
        async with self._lock:
            self._require_open()
            subscription_id = self._name_index.get(normalized)
            if subscription_id is None:
                return None
            return self._subscriptions[subscription_id]

    async def list(
        self,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> WebhookSubscriptionPage:
        async with self._lock:
            self._require_open()
            ordered = tuple(
                sorted(
                    self._subscriptions.values(),
                    key=lambda item: (item.name, item.id.hex),
                )
            )
            items = ordered[request.offset : request.offset + request.limit]
            return WebhookSubscriptionPage(
                items=items,
                page=WebhookPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )

    async def replace(
        self,
        subscription: WebhookSubscription,
        *,
        expected_revision: int,
    ) -> WebhookSubscription:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        async with self._lock:
            self._require_open()
            current = self._subscriptions.get(subscription.id)
            if current is None:
                raise WebhookSubscriptionNotFoundError("webhook subscription was not found")
            self._validate_replacement(
                current,
                subscription,
                expected_revision=expected_revision,
            )
            name_owner = self._name_index.get(subscription.name)
            if name_owner is not None and name_owner != subscription.id:
                raise WebhookSubscriptionAlreadyExistsError(
                    "webhook subscription name already exists"
                )
            if current.name != subscription.name:
                del self._name_index[current.name]
                self._name_index[subscription.name] = subscription.id
            self._subscriptions[subscription.id] = subscription
            return subscription

    async def snapshot(self) -> WebhookSubscriptionRepositorySnapshot:
        async with self._lock:
            statuses = Counter(item.status for item in self._subscriptions.values())
            return WebhookSubscriptionRepositorySnapshot(
                closed=self._closed,
                subscriptions=len(self._subscriptions),
                active=statuses[WebhookSubscriptionStatus.ACTIVE],
                disabled=statuses[WebhookSubscriptionStatus.DISABLED],
                revoked=statuses[WebhookSubscriptionStatus.REVOKED],
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._subscriptions.clear()
            self._name_index.clear()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise WebhookSubscriptionRepositoryClosedError(
                "webhook subscription repository is closed"
            )

    @staticmethod
    def _validate_replacement(
        current: WebhookSubscription,
        replacement: WebhookSubscription,
        *,
        expected_revision: int,
    ) -> None:
        if current.revision != expected_revision:
            raise WebhookSubscriptionConflictError("webhook subscription revision conflict")
        if replacement.revision != expected_revision + 1:
            raise WebhookSubscriptionConflictError(
                "replacement webhook subscription revision must increment exactly once"
            )
        if replacement.created_at != current.created_at:
            raise WebhookSubscriptionConflictError(
                "replacement webhook subscription cannot change created_at"
            )
        if replacement.created_by != current.created_by:
            raise WebhookSubscriptionConflictError(
                "replacement webhook subscription cannot change created_by"
            )
        if replacement.updated_at < current.updated_at:
            raise WebhookSubscriptionConflictError(
                "replacement webhook subscription updated_at cannot move backwards"
            )
        if replacement.schema_version != current.schema_version:
            raise WebhookSubscriptionConflictError(
                "replacement webhook subscription cannot change schema version"
            )
        if current.status is WebhookSubscriptionStatus.REVOKED:
            raise WebhookSubscriptionConflictError("revoked webhook subscription is terminal")


class InMemoryWebhookDeliveryRepository:
    """Process-local delivery repository with bounded deduplication state."""

    _ALLOWED_TRANSITIONS: ClassVar[
        dict[WebhookDeliveryStatus, frozenset[WebhookDeliveryStatus]]
    ] = {
        WebhookDeliveryStatus.PENDING: frozenset(
            {
                WebhookDeliveryStatus.IN_FLIGHT,
                WebhookDeliveryStatus.CANCELLED,
            }
        ),
        WebhookDeliveryStatus.IN_FLIGHT: frozenset(
            {
                WebhookDeliveryStatus.RETRYING,
                WebhookDeliveryStatus.SUCCEEDED,
                WebhookDeliveryStatus.FAILED,
                WebhookDeliveryStatus.DEAD_LETTER,
                WebhookDeliveryStatus.CANCELLED,
            }
        ),
        WebhookDeliveryStatus.RETRYING: frozenset(
            {
                WebhookDeliveryStatus.IN_FLIGHT,
                WebhookDeliveryStatus.CANCELLED,
            }
        ),
    }

    def __init__(self, *, capacity: int = 4_096) -> None:
        if capacity <= 0 or capacity > MAX_WEBHOOK_DELIVERY_CAPACITY:
            raise ValueError(
                f"webhook delivery capacity must be between 1 and {MAX_WEBHOOK_DELIVERY_CAPACITY}"
            )
        self._capacity = capacity
        self._deliveries: dict[UUID, WebhookDelivery] = {}
        self._deduplication_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, delivery: WebhookDelivery) -> None:
        async with self._lock:
            self._require_open()
            if delivery.id in self._deliveries:
                raise WebhookDeliveryAlreadyExistsError("webhook delivery id already exists")
            if delivery.deduplication_key in self._deduplication_index:
                raise WebhookDeliveryAlreadyExistsError(
                    "webhook delivery deduplication key already exists"
                )
            if len(self._deliveries) >= self._capacity:
                raise WebhookDeliveryCapacityError(
                    "webhook delivery repository capacity has been exhausted"
                )
            self._deliveries[delivery.id] = delivery
            self._deduplication_index[delivery.deduplication_key] = delivery.id

    async def get(self, delivery_id: UUID) -> WebhookDelivery | None:
        async with self._lock:
            self._require_open()
            return self._deliveries.get(delivery_id)

    async def get_by_deduplication_key(
        self,
        deduplication_key: str,
    ) -> WebhookDelivery | None:
        normalized = _normalize_sha256(
            deduplication_key,
            label="webhook delivery deduplication key",
        )
        async with self._lock:
            self._require_open()
            delivery_id = self._deduplication_index.get(normalized)
            if delivery_id is None:
                return None
            return self._deliveries[delivery_id]

    async def list(
        self,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> WebhookDeliveryPage:
        async with self._lock:
            self._require_open()
            ordered = tuple(
                sorted(
                    self._deliveries.values(),
                    key=lambda item: (item.created_at, item.id.hex),
                )
            )
            items = ordered[request.offset : request.offset + request.limit]
            return WebhookDeliveryPage(
                items=items,
                page=WebhookPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )

    async def replace(
        self,
        delivery: WebhookDelivery,
        *,
        expected_revision: int,
    ) -> WebhookDelivery:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        async with self._lock:
            self._require_open()
            current = self._deliveries.get(delivery.id)
            if current is None:
                raise WebhookDeliveryNotFoundError("webhook delivery was not found")
            self._validate_replacement(
                current,
                delivery,
                expected_revision=expected_revision,
            )
            owner = self._deduplication_index.get(delivery.deduplication_key)
            if owner is not None and owner != delivery.id:
                raise WebhookDeliveryAlreadyExistsError(
                    "webhook delivery deduplication key already exists"
                )
            self._deliveries[delivery.id] = delivery
            return delivery

    async def snapshot(self) -> WebhookDeliveryRepositorySnapshot:
        async with self._lock:
            statuses = Counter(item.status for item in self._deliveries.values())
            return WebhookDeliveryRepositorySnapshot(
                closed=self._closed,
                deliveries=len(self._deliveries),
                pending=statuses[WebhookDeliveryStatus.PENDING],
                in_flight=statuses[WebhookDeliveryStatus.IN_FLIGHT],
                retrying=statuses[WebhookDeliveryStatus.RETRYING],
                succeeded=statuses[WebhookDeliveryStatus.SUCCEEDED],
                failed=statuses[WebhookDeliveryStatus.FAILED],
                dead_letter=statuses[WebhookDeliveryStatus.DEAD_LETTER],
                cancelled=statuses[WebhookDeliveryStatus.CANCELLED],
                attempts=sum(item.completed_attempts for item in self._deliveries.values()),
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._deliveries.clear()
            self._deduplication_index.clear()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise WebhookDeliveryRepositoryClosedError("webhook delivery repository is closed")

    @classmethod
    def _validate_replacement(
        cls,
        current: WebhookDelivery,
        replacement: WebhookDelivery,
        *,
        expected_revision: int,
    ) -> None:
        if current.revision != expected_revision:
            raise WebhookDeliveryConflictError("webhook delivery revision conflict")
        if replacement.revision != expected_revision + 1:
            raise WebhookDeliveryConflictError(
                "replacement webhook delivery revision must increment exactly once"
            )
        cls._validate_immutable_metadata(current, replacement)
        if replacement.updated_at < current.updated_at:
            raise WebhookDeliveryConflictError(
                "replacement webhook delivery updated_at cannot move backwards"
            )
        if current.status.terminal:
            raise WebhookDeliveryConflictError("terminal webhook delivery is immutable")

        allowed = cls._ALLOWED_TRANSITIONS.get(current.status, frozenset())
        if replacement.status not in allowed:
            raise WebhookDeliveryConflictError(
                "webhook delivery lifecycle transition is not allowed"
            )
        cls._validate_attempt_history(current, replacement)

    @staticmethod
    def _validate_immutable_metadata(
        current: WebhookDelivery,
        replacement: WebhookDelivery,
    ) -> None:
        immutable_fields = (
            "subscription_id",
            "event_type",
            "deduplication_key",
            "canonical_body",
            "body_sha256",
            "occurred_at",
            "created_at",
            "source_event_id",
            "correlation_id",
            "schema_version",
        )
        for field_name in immutable_fields:
            if getattr(replacement, field_name) != getattr(current, field_name):
                raise WebhookDeliveryConflictError(
                    f"replacement webhook delivery cannot change {field_name}"
                )

    @staticmethod
    def _validate_attempt_history(
        current: WebhookDelivery,
        replacement: WebhookDelivery,
    ) -> None:
        completed = len(current.attempts)
        if replacement.attempts[:completed] != current.attempts:
            raise WebhookDeliveryConflictError(
                "replacement webhook delivery cannot rewrite attempt history"
            )
        added = len(replacement.attempts) - completed
        if added < 0 or added > 1:
            raise WebhookDeliveryConflictError(
                "replacement webhook delivery may append at most one attempt"
            )

        if current.status is WebhookDeliveryStatus.IN_FLIGHT:
            if replacement.status is WebhookDeliveryStatus.CANCELLED:
                if added != 0:
                    raise WebhookDeliveryConflictError(
                        "cancelled webhook delivery cannot append an attempt"
                    )
                return
            if added != 1:
                raise WebhookDeliveryConflictError(
                    "completed in-flight webhook delivery must append one attempt"
                )
            if replacement.attempts[-1].number != current.current_attempt:
                raise WebhookDeliveryConflictError(
                    "completed webhook attempt number does not match in-flight state"
                )
            return

        if added != 0:
            raise WebhookDeliveryConflictError(
                "webhook delivery may append attempts only while in flight"
            )
