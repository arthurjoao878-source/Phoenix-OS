"""State Store repository for durable webhook subscriptions."""

from __future__ import annotations

import hmac
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast
from uuid import UUID

from phoenix_os.state import (
    ABSENT_VERSION,
    PhoenixStateError,
    StateConflictError,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateStore,
)
from phoenix_os.webhooks.codec import (
    decode_webhook_delivery,
    decode_webhook_subscription,
    encode_webhook_delivery,
    encode_webhook_subscription,
    webhook_delivery_digest,
    webhook_subscription_digest,
)
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
    WebhookCorruptionError,
    WebhookDeliveryAlreadyExistsError,
    WebhookDeliveryCapacityError,
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryRepositoryClosedError,
    WebhookPersistenceError,
    WebhookSubscriptionAlreadyExistsError,
    WebhookSubscriptionCapacityError,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
    WebhookSubscriptionRepositoryClosedError,
)

_SCHEMA_VERSION = 1
_SUBSCRIPTION_RECORD_KIND = "phoenix.webhook.subscription.record"
_SUBSCRIPTION_NAME_INDEX_KIND = "phoenix.webhook.subscription.name-index"
_SUBSCRIPTION_RECORD_PREFIX = "subscription_record_"
_SUBSCRIPTION_NAME_PREFIX = "subscription_name_"

_SUBSCRIPTION_NAME_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "subscription_id",
        "name",
        "revision",
        "record_digest",
    }
)


@dataclass(frozen=True, slots=True)
class _DecodedSubscriptionNameIndex:
    subscription_id: UUID
    name: str
    revision: int
    record_digest: str


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exception:
        raise WebhookCorruptionError(
            "persisted webhook subscription state is not JSON-compatible"
        ) from exception


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WebhookCorruptionError(f"persisted webhook {label} is invalid")
    if not all(isinstance(key, str) for key in value):
        raise WebhookCorruptionError(f"persisted webhook {label} keys are invalid")
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise WebhookCorruptionError(f"persisted webhook field {key} is invalid")
    return result


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise WebhookCorruptionError(f"persisted webhook {label} fields are invalid")


def _subscription_envelope(
    subscription: WebhookSubscription,
) -> dict[str, object]:
    encoded = encode_webhook_subscription(subscription)

    try:
        decoded = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RuntimeError("webhook subscription encoder returned invalid JSON") from exception

    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise RuntimeError("webhook subscription encoder returned an invalid envelope")

    return cast(dict[str, object], decoded)


def _decode_subscription_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> WebhookSubscription:
    envelope = _mapping(
        stored.value,
        label="subscription record envelope",
    )
    return decode_webhook_subscription(_canonical_json_bytes(envelope))


def _subscription_name_index_document(
    subscription: WebhookSubscription,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _SUBSCRIPTION_NAME_INDEX_KIND,
        "subscription_id": str(subscription.id),
        "name": subscription.name,
        "revision": subscription.revision,
        "record_digest": webhook_subscription_digest(subscription),
    }


def _decode_subscription_name_index_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> _DecodedSubscriptionNameIndex:
    document = _mapping(
        stored.value,
        label="subscription name index",
    )
    _require_exact_fields(
        document,
        _SUBSCRIPTION_NAME_INDEX_FIELDS,
        label="subscription name index",
    )

    schema_version = _integer(document, "schema_version")
    if schema_version != _SCHEMA_VERSION:
        raise WebhookCorruptionError(
            "persisted webhook subscription name-index schema is unsupported"
        )

    if _string(document, "kind") != _SUBSCRIPTION_NAME_INDEX_KIND:
        raise WebhookCorruptionError("persisted webhook subscription name-index kind is invalid")

    supplied_name = _string(document, "name")
    try:
        name = _normalize_name(
            supplied_name,
            label="webhook subscription",
        )
        subscription_id = UUID(_string(document, "subscription_id"))
        supplied_digest = _string(document, "record_digest")
        record_digest = _normalize_sha256(
            supplied_digest,
            label="webhook subscription record digest",
        )
    except ValueError as exception:
        raise WebhookCorruptionError(
            "persisted webhook subscription name index is invalid"
        ) from exception

    revision = _integer(document, "revision")
    if revision <= 0:
        raise WebhookCorruptionError(
            "persisted webhook subscription name-index revision is invalid"
        )

    if supplied_name != name or supplied_digest != record_digest:
        raise WebhookCorruptionError("persisted webhook subscription name index is not canonical")

    return _DecodedSubscriptionNameIndex(
        subscription_id=subscription_id,
        name=name,
        revision=revision,
        record_digest=record_digest,
    )


def _verify_subscription_name_index(
    index: _DecodedSubscriptionNameIndex,
    subscription: WebhookSubscription,
) -> None:
    if index.subscription_id != subscription.id:
        raise WebhookCorruptionError(
            "persisted webhook subscription name index has a mismatched identity"
        )
    if index.name != subscription.name:
        raise WebhookCorruptionError(
            "persisted webhook subscription name index has a mismatched name"
        )
    if index.revision != subscription.revision:
        raise WebhookCorruptionError(
            "persisted webhook subscription name index has a mismatched revision"
        )

    expected_digest = webhook_subscription_digest(subscription)
    if not hmac.compare_digest(index.record_digest, expected_digest):
        raise WebhookCorruptionError(
            "persisted webhook subscription name index has a mismatched digest"
        )


def _validate_subscription_replacement(
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


def _validate_persisted_subscription_collection(
    stored_records: Sequence[StateRecord[object]],
    stored_indexes: Sequence[StateRecord[object]],
    *,
    namespace: str,
) -> tuple[WebhookSubscription, ...]:
    by_id: dict[UUID, WebhookSubscription] = {}
    by_name: dict[str, WebhookSubscription] = {}

    for stored in stored_records:
        subscription = _decode_subscription_state(stored)
        expected_key_name = f"{_SUBSCRIPTION_RECORD_PREFIX}{subscription.id.hex}"

        if stored.key.namespace != namespace or stored.key.name != expected_key_name:
            raise WebhookCorruptionError(
                "persisted webhook subscription identity does not match its state key"
            )
        if subscription.id in by_id:
            raise WebhookCorruptionError(
                "persisted webhook subscriptions contain duplicate identities"
            )
        if subscription.name in by_name:
            raise WebhookCorruptionError("persisted webhook subscriptions contain duplicate names")

        by_id[subscription.id] = subscription
        by_name[subscription.name] = subscription

    indexed_names: set[str] = set()
    indexed_ids: set[UUID] = set()

    for stored in stored_indexes:
        index = _decode_subscription_name_index_state(stored)
        expected_key_name = f"{_SUBSCRIPTION_NAME_PREFIX}{index.name}"

        if stored.key.namespace != namespace or stored.key.name != expected_key_name:
            raise WebhookCorruptionError(
                "persisted webhook subscription name index does not match its state key"
            )
        if index.name in indexed_names or index.subscription_id in indexed_ids:
            raise WebhookCorruptionError(
                "persisted webhook subscription name indexes contain duplicates"
            )

        indexed_subscription = by_id.get(index.subscription_id)
        if indexed_subscription is None:
            raise WebhookCorruptionError(
                "persisted webhook subscription name index references a missing record"
            )

        _verify_subscription_name_index(index, indexed_subscription)
        indexed_names.add(index.name)
        indexed_ids.add(index.subscription_id)

    if indexed_names != set(by_name) or indexed_ids != set(by_id):
        raise WebhookCorruptionError(
            "persisted webhook subscription records have incomplete name indexes"
        )

    return tuple(by_id.values())


class StateWebhookSubscriptionRepository:
    """Persist webhook subscriptions through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 256,
        namespace: str = "webhook-subscriptions",
        context: StateOperationContext | None = None,
    ) -> None:
        if capacity <= 0 or capacity > MAX_WEBHOOK_SUBSCRIPTION_CAPACITY:
            raise ValueError(
                "webhook subscription capacity must be between 1 and "
                f"{MAX_WEBHOOK_SUBSCRIPTION_CAPACITY}"
            )

        probe = StateKey(
            namespace,
            f"{_SUBSCRIPTION_RECORD_PREFIX}{'0' * 32}",
            dict,
        )

        self._store = store
        self._capacity = capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.webhook.subscription-repository",
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, subscription: WebhookSubscription) -> None:
        self._ensure_open()

        record_key = self._subscription_record_key(subscription.id)
        name_key = self._subscription_name_key(subscription.name)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_SUBSCRIPTION_RECORD_PREFIX,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_SUBSCRIPTION_NAME_PREFIX,
                )
                subscriptions = _validate_persisted_subscription_collection(
                    stored_records,
                    stored_indexes,
                    namespace=self._namespace,
                )

                if len(subscriptions) >= self._capacity:
                    raise WebhookSubscriptionCapacityError(
                        "webhook subscription repository capacity has been exhausted"
                    )

                if await transaction.get(record_key) is not None:
                    raise WebhookSubscriptionAlreadyExistsError(
                        "webhook subscription id already exists"
                    )
                if await transaction.get(name_key) is not None:
                    raise WebhookSubscriptionAlreadyExistsError(
                        "webhook subscription name already exists"
                    )

                await transaction.put(
                    record_key,
                    _subscription_envelope(subscription),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    name_key,
                    _subscription_name_index_document(subscription),
                    expected_version=ABSENT_VERSION,
                )

        except (
            WebhookCorruptionError,
            WebhookSubscriptionAlreadyExistsError,
            WebhookSubscriptionCapacityError,
        ):
            raise
        except StateConflictError as exception:
            raise WebhookSubscriptionAlreadyExistsError(
                "webhook subscription identity already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook subscription persistence operation failed"
            ) from exception

    async def get(
        self,
        subscription_id: UUID,
    ) -> WebhookSubscription | None:
        self._ensure_open()

        try:
            stored = await self._store.get(
                self._subscription_record_key(subscription_id),
                context=self._context,
            )
            if stored is None:
                return None

            subscription = _decode_subscription_state(stored)
            if subscription.id != subscription_id:
                raise WebhookCorruptionError(
                    "persisted webhook subscription identity does not match its state key"
                )

            return await self._read_and_verify_name_index(subscription)

        except WebhookCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook subscription persistence operation failed"
            ) from exception

    async def get_by_name(
        self,
        name: str,
    ) -> WebhookSubscription | None:
        self._ensure_open()
        normalized = _normalize_name(
            name,
            label="webhook subscription",
        )

        try:
            stored_index = await self._store.get(
                self._subscription_name_key(normalized),
                context=self._context,
            )
            if stored_index is None:
                return None

            index = _decode_subscription_name_index_state(stored_index)
            if (
                stored_index.key.namespace != self._namespace
                or stored_index.key.name != f"{_SUBSCRIPTION_NAME_PREFIX}{normalized}"
                or index.name != normalized
            ):
                raise WebhookCorruptionError(
                    "persisted webhook subscription name index does not match its state key"
                )

            stored_record = await self._store.get(
                self._subscription_record_key(index.subscription_id),
                context=self._context,
            )
            if stored_record is None:
                raise WebhookCorruptionError(
                    "persisted webhook subscription name index references a missing record"
                )

            subscription = _decode_subscription_state(stored_record)
            _verify_subscription_name_index(index, subscription)

            return await self._read_and_verify_name_index(subscription)

        except WebhookCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook subscription persistence operation failed"
            ) from exception

    async def list(
        self,
        request: WebhookPageRequest = DEFAULT_WEBHOOK_PAGE_REQUEST,
    ) -> WebhookSubscriptionPage:
        subscriptions = await self._load_subscriptions()
        ordered = tuple(
            sorted(
                subscriptions,
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
        self._ensure_open()

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        record_key = self._subscription_record_key(subscription.id)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_SUBSCRIPTION_RECORD_PREFIX,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_SUBSCRIPTION_NAME_PREFIX,
                )
                _validate_persisted_subscription_collection(
                    stored_records,
                    stored_indexes,
                    namespace=self._namespace,
                )

                stored_current = await transaction.get(record_key)
                if stored_current is None:
                    raise WebhookSubscriptionNotFoundError("webhook subscription was not found")

                current = _decode_subscription_state(stored_current)
                _validate_subscription_replacement(
                    current,
                    subscription,
                    expected_revision=expected_revision,
                )

                old_name_key = self._subscription_name_key(current.name)
                stored_old_name = await transaction.get(old_name_key)
                if stored_old_name is None:
                    raise WebhookCorruptionError(
                        "persisted webhook subscription record has an incomplete name index"
                    )

                _verify_subscription_name_index(
                    _decode_subscription_name_index_state(stored_old_name),
                    current,
                )

                new_name_key = self._subscription_name_key(subscription.name)
                stored_new_name = await transaction.get(new_name_key)

                if new_name_key != old_name_key and stored_new_name is not None:
                    raise WebhookSubscriptionAlreadyExistsError(
                        "webhook subscription name already exists"
                    )

                await transaction.put(
                    record_key,
                    _subscription_envelope(subscription),
                    expected_version=stored_current.version,
                )

                if new_name_key == old_name_key:
                    await transaction.put(
                        old_name_key,
                        _subscription_name_index_document(subscription),
                        expected_version=stored_old_name.version,
                    )
                else:
                    await transaction.delete(
                        old_name_key,
                        expected_version=stored_old_name.version,
                    )
                    await transaction.put(
                        new_name_key,
                        _subscription_name_index_document(subscription),
                        expected_version=ABSENT_VERSION,
                    )

                return subscription

        except (
            WebhookCorruptionError,
            WebhookSubscriptionAlreadyExistsError,
            WebhookSubscriptionConflictError,
            WebhookSubscriptionNotFoundError,
        ):
            raise
        except StateConflictError as exception:
            raise WebhookSubscriptionConflictError(
                "webhook subscription state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook subscription persistence operation failed"
            ) from exception

    async def snapshot(self) -> WebhookSubscriptionRepositorySnapshot:
        subscriptions = await self._load_subscriptions(
            require_open=False,
        )
        statuses = Counter(item.status for item in subscriptions)

        return WebhookSubscriptionRepositorySnapshot(
            closed=self._closed,
            subscriptions=len(subscriptions),
            active=statuses[WebhookSubscriptionStatus.ACTIVE],
            disabled=statuses[WebhookSubscriptionStatus.DISABLED],
            revoked=statuses[WebhookSubscriptionStatus.REVOKED],
            capacity=self._capacity,
        )

    async def close(self) -> None:
        # The runtime owns the borrowed State Store lifecycle.
        self._closed = True

    async def _read_and_verify_name_index(
        self,
        subscription: WebhookSubscription,
    ) -> WebhookSubscription:
        stored_index = await self._store.get(
            self._subscription_name_key(subscription.name),
            context=self._context,
        )
        if stored_index is None:
            raise WebhookCorruptionError(
                "persisted webhook subscription record has an incomplete name index"
            )

        expected_key_name = f"{_SUBSCRIPTION_NAME_PREFIX}{subscription.name}"
        if (
            stored_index.key.namespace != self._namespace
            or stored_index.key.name != expected_key_name
        ):
            raise WebhookCorruptionError(
                "persisted webhook subscription name index does not match its state key"
            )

        _verify_subscription_name_index(
            _decode_subscription_name_index_state(stored_index),
            subscription,
        )
        return subscription

    async def _load_subscriptions(
        self,
        *,
        require_open: bool = True,
    ) -> tuple[WebhookSubscription, ...]:
        if require_open:
            self._ensure_open()

        try:
            stored_records = await self._store.list(
                namespace=self._namespace,
                prefix=_SUBSCRIPTION_RECORD_PREFIX,
                context=self._context,
            )
            stored_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_SUBSCRIPTION_NAME_PREFIX,
                context=self._context,
            )
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook subscription persistence operation failed"
            ) from exception

        subscriptions = _validate_persisted_subscription_collection(
            stored_records,
            stored_indexes,
            namespace=self._namespace,
        )

        if len(subscriptions) > self._capacity:
            raise WebhookCorruptionError(
                "persisted webhook subscriptions exceed configured repository capacity"
            )

        return subscriptions

    def _subscription_record_key(
        self,
        subscription_id: UUID,
    ) -> StateKey[dict[str, object]]:
        return StateKey(
            self._namespace,
            f"{_SUBSCRIPTION_RECORD_PREFIX}{subscription_id.hex}",
            dict,
        )

    def _subscription_name_key(
        self,
        name: str,
    ) -> StateKey[dict[str, object]]:
        normalized = _normalize_name(
            name,
            label="webhook subscription",
        )
        return StateKey(
            self._namespace,
            f"{_SUBSCRIPTION_NAME_PREFIX}{normalized}",
            dict,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookSubscriptionRepositoryClosedError(
                "webhook subscription repository is closed"
            )


_DELIVERY_DEDUPLICATION_INDEX_KIND = "phoenix.webhook.delivery.deduplication-index"
_DELIVERY_RECORD_PREFIX = "delivery_record_"
_DELIVERY_DEDUPLICATION_PREFIX = "delivery_deduplication_"

_DELIVERY_DEDUPLICATION_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "delivery_id",
        "deduplication_key",
        "revision",
        "record_digest",
    }
)

_ALLOWED_DELIVERY_TRANSITIONS = {
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


@dataclass(frozen=True, slots=True)
class _DecodedDeliveryDeduplicationIndex:
    delivery_id: UUID
    deduplication_key: str
    revision: int
    record_digest: str


def _delivery_envelope(
    delivery: WebhookDelivery,
) -> dict[str, object]:
    encoded = encode_webhook_delivery(delivery)

    try:
        decoded = json.loads(encoded.decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exception:
        raise RuntimeError("webhook delivery encoder returned invalid JSON") from exception

    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise RuntimeError("webhook delivery encoder returned an invalid envelope")

    return cast(dict[str, object], decoded)


def _decode_delivery_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> WebhookDelivery:
    envelope = _mapping(
        stored.value,
        label="delivery record envelope",
    )
    return decode_webhook_delivery(_canonical_json_bytes(envelope))


def _delivery_deduplication_index_document(
    delivery: WebhookDelivery,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _DELIVERY_DEDUPLICATION_INDEX_KIND,
        "delivery_id": str(delivery.id),
        "deduplication_key": delivery.deduplication_key,
        "revision": delivery.revision,
        "record_digest": webhook_delivery_digest(delivery),
    }


def _decode_delivery_deduplication_index_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> _DecodedDeliveryDeduplicationIndex:
    document = _mapping(
        stored.value,
        label="delivery deduplication index",
    )
    _require_exact_fields(
        document,
        _DELIVERY_DEDUPLICATION_INDEX_FIELDS,
        label="delivery deduplication index",
    )

    schema_version = _integer(
        document,
        "schema_version",
    )
    if schema_version != _SCHEMA_VERSION:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication-index schema is unsupported"
        )

    if _string(document, "kind") != _DELIVERY_DEDUPLICATION_INDEX_KIND:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication-index kind is invalid"
        )

    supplied_key = _string(
        document,
        "deduplication_key",
    )
    supplied_digest = _string(
        document,
        "record_digest",
    )

    try:
        delivery_id = UUID(_string(document, "delivery_id"))
        deduplication_key = _normalize_sha256(
            supplied_key,
            label="webhook delivery deduplication key",
        )
        record_digest = _normalize_sha256(
            supplied_digest,
            label="webhook delivery record digest",
        )
    except ValueError as exception:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication index is invalid"
        ) from exception

    revision = _integer(
        document,
        "revision",
    )
    if revision <= 0:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication-index revision is invalid"
        )

    if supplied_key != deduplication_key or supplied_digest != record_digest:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication index is not canonical"
        )

    return _DecodedDeliveryDeduplicationIndex(
        delivery_id=delivery_id,
        deduplication_key=deduplication_key,
        revision=revision,
        record_digest=record_digest,
    )


def _verify_delivery_deduplication_index(
    index: _DecodedDeliveryDeduplicationIndex,
    delivery: WebhookDelivery,
) -> None:
    if index.delivery_id != delivery.id:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication index has a mismatched identity"
        )

    if index.deduplication_key != delivery.deduplication_key:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication index has a mismatched key"
        )

    if index.revision != delivery.revision:
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication index has a mismatched revision"
        )

    expected_digest = webhook_delivery_digest(delivery)
    if not hmac.compare_digest(
        index.record_digest,
        expected_digest,
    ):
        raise WebhookCorruptionError(
            "persisted webhook delivery deduplication index has a mismatched digest"
        )


def _validate_delivery_replacement(
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
        if getattr(replacement, field_name) != getattr(
            current,
            field_name,
        ):
            raise WebhookDeliveryConflictError(
                f"replacement webhook delivery cannot change {field_name}"
            )

    if replacement.updated_at < current.updated_at:
        raise WebhookDeliveryConflictError(
            "replacement webhook delivery updated_at cannot move backwards"
        )

    if current.status.terminal:
        raise WebhookDeliveryConflictError("terminal webhook delivery is immutable")

    allowed = _ALLOWED_DELIVERY_TRANSITIONS.get(
        current.status,
        frozenset(),
    )
    if replacement.status not in allowed:
        raise WebhookDeliveryConflictError("webhook delivery lifecycle transition is not allowed")

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


def _validate_persisted_delivery_collection(
    stored_records: Sequence[StateRecord[object]],
    stored_indexes: Sequence[StateRecord[object]],
    *,
    namespace: str,
) -> tuple[WebhookDelivery, ...]:
    by_id: dict[UUID, WebhookDelivery] = {}
    by_deduplication_key: dict[str, WebhookDelivery] = {}

    for stored in stored_records:
        delivery = _decode_delivery_state(stored)
        expected_key_name = f"{_DELIVERY_RECORD_PREFIX}{delivery.id.hex}"

        if stored.key.namespace != namespace or stored.key.name != expected_key_name:
            raise WebhookCorruptionError(
                "persisted webhook delivery identity does not match its state key"
            )

        if delivery.id in by_id:
            raise WebhookCorruptionError(
                "persisted webhook deliveries contain duplicate identities"
            )

        if delivery.deduplication_key in by_deduplication_key:
            raise WebhookCorruptionError(
                "persisted webhook deliveries contain duplicate deduplication keys"
            )

        by_id[delivery.id] = delivery
        by_deduplication_key[delivery.deduplication_key] = delivery

    indexed_ids: set[UUID] = set()
    indexed_keys: set[str] = set()

    for stored in stored_indexes:
        index = _decode_delivery_deduplication_index_state(stored)
        expected_key_name = f"{_DELIVERY_DEDUPLICATION_PREFIX}{index.deduplication_key}"

        if stored.key.namespace != namespace or stored.key.name != expected_key_name:
            raise WebhookCorruptionError(
                "persisted webhook delivery deduplication index does not match its state key"
            )

        if index.delivery_id in indexed_ids or index.deduplication_key in indexed_keys:
            raise WebhookCorruptionError(
                "persisted webhook delivery deduplication indexes contain duplicates"
            )

        indexed_delivery = by_id.get(index.delivery_id)
        if indexed_delivery is None:
            raise WebhookCorruptionError(
                "persisted webhook delivery deduplication index references a missing record"
            )

        _verify_delivery_deduplication_index(
            index,
            indexed_delivery,
        )
        indexed_ids.add(index.delivery_id)
        indexed_keys.add(index.deduplication_key)

    if indexed_ids != set(by_id) or indexed_keys != set(by_deduplication_key):
        raise WebhookCorruptionError(
            "persisted webhook delivery records have incomplete deduplication indexes"
        )

    return tuple(by_id.values())


class StateWebhookDeliveryRepository:
    """Persist webhook deliveries through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 4_096,
        namespace: str = "webhook-deliveries",
        context: StateOperationContext | None = None,
    ) -> None:
        if capacity <= 0 or capacity > MAX_WEBHOOK_DELIVERY_CAPACITY:
            raise ValueError(
                f"webhook delivery capacity must be between 1 and {MAX_WEBHOOK_DELIVERY_CAPACITY}"
            )

        probe = StateKey(
            namespace,
            f"{_DELIVERY_RECORD_PREFIX}{'0' * 32}",
            dict,
        )

        self._store = store
        self._capacity = capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": ("phoenix.webhook.delivery-repository"),
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(
        self,
        delivery: WebhookDelivery,
    ) -> None:
        self._ensure_open()

        record_key = self._delivery_record_key(delivery.id)
        deduplication_key = self._delivery_deduplication_key(delivery.deduplication_key)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_DELIVERY_RECORD_PREFIX,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_DELIVERY_DEDUPLICATION_PREFIX,
                )

                deliveries = _validate_persisted_delivery_collection(
                    stored_records,
                    stored_indexes,
                    namespace=self._namespace,
                )

                if len(deliveries) >= self._capacity:
                    raise WebhookDeliveryCapacityError(
                        "webhook delivery repository capacity has been exhausted"
                    )

                if await transaction.get(record_key) is not None:
                    raise WebhookDeliveryAlreadyExistsError("webhook delivery id already exists")

                if await transaction.get(deduplication_key) is not None:
                    raise WebhookDeliveryAlreadyExistsError(
                        "webhook delivery deduplication key already exists"
                    )

                await transaction.put(
                    record_key,
                    _delivery_envelope(delivery),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    deduplication_key,
                    _delivery_deduplication_index_document(delivery),
                    expected_version=ABSENT_VERSION,
                )

        except (
            WebhookCorruptionError,
            WebhookDeliveryAlreadyExistsError,
            WebhookDeliveryCapacityError,
        ):
            raise
        except StateConflictError as exception:
            raise WebhookDeliveryAlreadyExistsError(
                "webhook delivery identity already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook delivery persistence operation failed"
            ) from exception

    async def get(
        self,
        delivery_id: UUID,
    ) -> WebhookDelivery | None:
        self._ensure_open()

        try:
            stored = await self._store.get(
                self._delivery_record_key(delivery_id),
                context=self._context,
            )
            if stored is None:
                return None

            delivery = _decode_delivery_state(stored)
            if delivery.id != delivery_id:
                raise WebhookCorruptionError(
                    "persisted webhook delivery identity does not match its state key"
                )

            return await self._read_and_verify_deduplication_index(delivery)

        except WebhookCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook delivery persistence operation failed"
            ) from exception

    async def get_by_deduplication_key(
        self,
        deduplication_key: str,
    ) -> WebhookDelivery | None:
        self._ensure_open()
        normalized = _normalize_sha256(
            deduplication_key,
            label="webhook delivery deduplication key",
        )

        try:
            stored_index = await self._store.get(
                self._delivery_deduplication_key(normalized),
                context=self._context,
            )
            if stored_index is None:
                return None

            index = _decode_delivery_deduplication_index_state(stored_index)
            expected_key_name = f"{_DELIVERY_DEDUPLICATION_PREFIX}{normalized}"

            if (
                stored_index.key.namespace != self._namespace
                or stored_index.key.name != expected_key_name
                or index.deduplication_key != normalized
            ):
                raise WebhookCorruptionError(
                    "persisted webhook delivery deduplication index does not match its state key"
                )

            stored_record = await self._store.get(
                self._delivery_record_key(index.delivery_id),
                context=self._context,
            )
            if stored_record is None:
                raise WebhookCorruptionError(
                    "persisted webhook delivery deduplication index references a missing record"
                )

            delivery = _decode_delivery_state(stored_record)
            _verify_delivery_deduplication_index(
                index,
                delivery,
            )

            return await self._read_and_verify_deduplication_index(delivery)

        except WebhookCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook delivery persistence operation failed"
            ) from exception

    async def list(
        self,
        request: WebhookPageRequest = (DEFAULT_WEBHOOK_PAGE_REQUEST),
    ) -> WebhookDeliveryPage:
        deliveries = await self._load_deliveries()
        ordered = tuple(
            sorted(
                deliveries,
                key=lambda item: (
                    item.created_at,
                    item.id.hex,
                ),
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
        self._ensure_open()

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        record_key = self._delivery_record_key(delivery.id)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_DELIVERY_RECORD_PREFIX,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_DELIVERY_DEDUPLICATION_PREFIX,
                )
                _validate_persisted_delivery_collection(
                    stored_records,
                    stored_indexes,
                    namespace=self._namespace,
                )

                stored_current = await transaction.get(record_key)
                if stored_current is None:
                    raise WebhookDeliveryNotFoundError("webhook delivery was not found")

                current = _decode_delivery_state(stored_current)
                _validate_delivery_replacement(
                    current,
                    delivery,
                    expected_revision=expected_revision,
                )

                index_key = self._delivery_deduplication_key(current.deduplication_key)
                stored_index = await transaction.get(index_key)
                if stored_index is None:
                    raise WebhookCorruptionError(
                        "persisted webhook delivery record has an incomplete deduplication index"
                    )

                _verify_delivery_deduplication_index(
                    _decode_delivery_deduplication_index_state(stored_index),
                    current,
                )

                await transaction.put(
                    record_key,
                    _delivery_envelope(delivery),
                    expected_version=(stored_current.version),
                )
                await transaction.put(
                    index_key,
                    _delivery_deduplication_index_document(delivery),
                    expected_version=stored_index.version,
                )

                return delivery

        except (
            WebhookCorruptionError,
            WebhookDeliveryConflictError,
            WebhookDeliveryNotFoundError,
        ):
            raise
        except StateConflictError as exception:
            raise WebhookDeliveryConflictError(
                "webhook delivery state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook delivery persistence operation failed"
            ) from exception

    async def snapshot(
        self,
    ) -> WebhookDeliveryRepositorySnapshot:
        deliveries = await self._load_deliveries(require_open=False)
        statuses = Counter(item.status for item in deliveries)

        return WebhookDeliveryRepositorySnapshot(
            closed=self._closed,
            deliveries=len(deliveries),
            pending=statuses[WebhookDeliveryStatus.PENDING],
            in_flight=statuses[WebhookDeliveryStatus.IN_FLIGHT],
            retrying=statuses[WebhookDeliveryStatus.RETRYING],
            succeeded=statuses[WebhookDeliveryStatus.SUCCEEDED],
            failed=statuses[WebhookDeliveryStatus.FAILED],
            dead_letter=statuses[WebhookDeliveryStatus.DEAD_LETTER],
            cancelled=statuses[WebhookDeliveryStatus.CANCELLED],
            attempts=sum(item.completed_attempts for item in deliveries),
            capacity=self._capacity,
        )

    async def close(self) -> None:
        # The runtime owns the borrowed State Store lifecycle.
        self._closed = True

    async def _read_and_verify_deduplication_index(
        self,
        delivery: WebhookDelivery,
    ) -> WebhookDelivery:
        stored_index = await self._store.get(
            self._delivery_deduplication_key(delivery.deduplication_key),
            context=self._context,
        )
        if stored_index is None:
            raise WebhookCorruptionError(
                "persisted webhook delivery record has an incomplete deduplication index"
            )

        expected_key_name = f"{_DELIVERY_DEDUPLICATION_PREFIX}{delivery.deduplication_key}"
        if (
            stored_index.key.namespace != self._namespace
            or stored_index.key.name != expected_key_name
        ):
            raise WebhookCorruptionError(
                "persisted webhook delivery deduplication index does not match its state key"
            )

        _verify_delivery_deduplication_index(
            _decode_delivery_deduplication_index_state(stored_index),
            delivery,
        )
        return delivery

    async def _load_deliveries(
        self,
        *,
        require_open: bool = True,
    ) -> tuple[WebhookDelivery, ...]:
        if require_open:
            self._ensure_open()

        try:
            stored_records = await self._store.list(
                namespace=self._namespace,
                prefix=_DELIVERY_RECORD_PREFIX,
                context=self._context,
            )
            stored_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_DELIVERY_DEDUPLICATION_PREFIX,
                context=self._context,
            )
        except PhoenixStateError as exception:
            raise WebhookPersistenceError(
                "webhook delivery persistence operation failed"
            ) from exception

        deliveries = _validate_persisted_delivery_collection(
            stored_records,
            stored_indexes,
            namespace=self._namespace,
        )

        if len(deliveries) > self._capacity:
            raise WebhookCorruptionError(
                "persisted webhook deliveries exceed configured repository capacity"
            )

        return deliveries

    def _delivery_record_key(
        self,
        delivery_id: UUID,
    ) -> StateKey[dict[str, object]]:
        return StateKey(
            self._namespace,
            f"{_DELIVERY_RECORD_PREFIX}{delivery_id.hex}",
            dict,
        )

    def _delivery_deduplication_key(
        self,
        deduplication_key: str,
    ) -> StateKey[dict[str, object]]:
        normalized = _normalize_sha256(
            deduplication_key,
            label="webhook delivery deduplication key",
        )
        return StateKey(
            self._namespace,
            f"{_DELIVERY_DEDUPLICATION_PREFIX}{normalized}",
            dict,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookDeliveryRepositoryClosedError("webhook delivery repository is closed")
