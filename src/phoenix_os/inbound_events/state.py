"""State Store-backed repositories for secure durable inbound events."""

from __future__ import annotations

import hmac
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import cast
from uuid import UUID

from phoenix_os.inbound_events.codec import (
    decode_inbound_accepted_event,
    decode_inbound_receipt,
    decode_inbound_replay,
    decode_inbound_source,
    encode_inbound_accepted_event,
    encode_inbound_receipt,
    encode_inbound_replay,
    encode_inbound_source,
    inbound_accepted_event_digest,
    inbound_receipt_digest,
    inbound_source_digest,
)
from phoenix_os.inbound_events.contracts import (
    DEFAULT_INBOUND_PAGE_REQUEST,
    MAX_INBOUND_EVENT_CAPACITY,
    MAX_INBOUND_REPLAY_CAPACITY,
    MAX_INBOUND_SOURCE_CAPACITY,
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventPage,
    InboundEventReceipt,
    InboundEventRepositorySnapshot,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundPageInfo,
    InboundPageRequest,
    InboundPublicationStatus,
    InboundReplayKind,
    InboundReplayPage,
    InboundReplayRepositorySnapshot,
    InboundReplayReservation,
    InboundSourcePage,
    InboundSourceRepositorySnapshot,
    _normalize_name,
    _normalize_sha256,
    _validate_idempotent_replay_reservations,
)
from phoenix_os.inbound_events.errors import (
    InboundCorruptionError,
    InboundEventAlreadyExistsError,
    InboundEventCapacityError,
    InboundEventConflictError,
    InboundEventNotFoundError,
    InboundEventRepositoryClosedError,
    InboundPersistenceError,
    InboundReplayAlreadyExistsError,
    InboundReplayCapacityError,
    InboundReplayRepositoryClosedError,
    InboundSourceAlreadyExistsError,
    InboundSourceCapacityError,
    InboundSourceConflictError,
    InboundSourceNotFoundError,
    InboundSourceRepositoryClosedError,
)
from phoenix_os.inbound_events.memory import (
    _validate_event_replacement,
    _validate_source_replacement,
)
from phoenix_os.state import (
    ABSENT_VERSION,
    PhoenixStateError,
    StateConflictError,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateStore,
)

_SCHEMA_VERSION = 1
_SOURCE_RECORD_PREFIX = "source_record_"
_SOURCE_NAME_PREFIX = "source_name_"
_EVENT_RECORD_PREFIX = "event_record_"
_RECEIPT_RECORD_PREFIX = "receipt_record_"
_SOURCE_EVENT_PREFIX = "source_event_"
_REPLAY_PREFIX = "replay_"

_SOURCE_NAME_INDEX_KIND = "phoenix.inbound.source.name-index"
_SOURCE_EVENT_INDEX_KIND = "phoenix.inbound.source-event.index"

_SOURCE_NAME_INDEX_FIELDS = frozenset(
    {"schema_version", "kind", "source_id", "name", "revision", "record_digest"}
)
_SOURCE_EVENT_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "source_id",
        "evidence_digest",
        "accepted_event_id",
        "receipt_id",
        "normalized_payload_sha256",
        "event_revision",
        "event_record_digest",
        "receipt_record_digest",
    }
)


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
        raise InboundCorruptionError(
            "persisted inbound state is not JSON-compatible"
        ) from exception


def _envelope(encoded: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RuntimeError(f"inbound {label} encoder returned invalid JSON") from exception
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RuntimeError(f"inbound {label} encoder returned an invalid envelope")
    return cast(dict[str, object], value)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise InboundCorruptionError(f"persisted inbound {label} is invalid")
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise InboundCorruptionError(f"persisted inbound field {key} is invalid")
    return result


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise InboundCorruptionError(f"persisted inbound {label} fields are invalid")


def _decode_source_record(stored: StateRecord[object]) -> InboundEventSource:
    return decode_inbound_source(
        _canonical_json_bytes(_mapping(stored.value, label="source record envelope"))
    )


def _decode_event_record(stored: StateRecord[object]) -> InboundAcceptedEvent:
    return decode_inbound_accepted_event(
        _canonical_json_bytes(_mapping(stored.value, label="event record envelope"))
    )


def _decode_receipt_record(stored: StateRecord[object]) -> InboundEventReceipt:
    return decode_inbound_receipt(
        _canonical_json_bytes(_mapping(stored.value, label="receipt record envelope"))
    )


def _decode_replay_record(stored: StateRecord[object]) -> InboundReplayReservation:
    return decode_inbound_replay(
        _canonical_json_bytes(_mapping(stored.value, label="replay record envelope"))
    )


def _source_name_index_document(source: InboundEventSource) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _SOURCE_NAME_INDEX_KIND,
        "source_id": str(source.id),
        "name": source.name,
        "revision": source.revision,
        "record_digest": inbound_source_digest(source),
    }


@dataclass(frozen=True, slots=True)
class _DecodedSourceNameIndex:
    source_id: UUID
    name: str
    revision: int
    record_digest: str


def _decode_source_name_index(stored: StateRecord[object]) -> _DecodedSourceNameIndex:
    document = _mapping(stored.value, label="source name index")
    _require_exact_fields(document, _SOURCE_NAME_INDEX_FIELDS, label="source name index")
    if _integer(document, "schema_version") != _SCHEMA_VERSION:
        raise InboundCorruptionError("persisted inbound source name-index schema is unsupported")
    if _string(document, "kind") != _SOURCE_NAME_INDEX_KIND:
        raise InboundCorruptionError("persisted inbound source name-index kind is invalid")
    supplied_name = _string(document, "name")
    supplied_digest = _string(document, "record_digest")
    try:
        source_id = UUID(_string(document, "source_id"))
        name = _normalize_name(supplied_name, label="inbound source")
        record_digest = _normalize_sha256(
            supplied_digest,
            label="inbound source record digest",
        )
    except ValueError as exception:
        raise InboundCorruptionError(
            "persisted inbound source name index is invalid"
        ) from exception
    revision = _integer(document, "revision")
    if revision <= 0 or supplied_name != name or supplied_digest != record_digest:
        raise InboundCorruptionError("persisted inbound source name index is not canonical")
    return _DecodedSourceNameIndex(source_id, name, revision, record_digest)


def _verify_source_name_index(
    index: _DecodedSourceNameIndex,
    source: InboundEventSource,
) -> None:
    if index.source_id != source.id or index.name != source.name:
        raise InboundCorruptionError("persisted inbound source name index has mismatched identity")
    if index.revision != source.revision:
        raise InboundCorruptionError("persisted inbound source name index has mismatched revision")
    if not hmac.compare_digest(index.record_digest, inbound_source_digest(source)):
        raise InboundCorruptionError("persisted inbound source name index has mismatched digest")


def _validate_source_collection(
    records: Sequence[StateRecord[object]],
    indexes: Sequence[StateRecord[object]],
    *,
    namespace: str,
) -> tuple[InboundEventSource, ...]:
    by_id: dict[UUID, InboundEventSource] = {}
    by_name: dict[str, InboundEventSource] = {}
    for stored in records:
        source = _decode_source_record(stored)
        if stored.key.namespace != namespace or stored.key.name != (
            f"{_SOURCE_RECORD_PREFIX}{source.id.hex}"
        ):
            raise InboundCorruptionError(
                "persisted inbound source identity does not match its state key"
            )
        if source.id in by_id or source.name in by_name:
            raise InboundCorruptionError("persisted inbound sources contain duplicate identities")
        by_id[source.id] = source
        by_name[source.name] = source

    indexed_ids: set[UUID] = set()
    indexed_names: set[str] = set()
    for stored in indexes:
        index = _decode_source_name_index(stored)
        if stored.key.namespace != namespace or stored.key.name != (
            f"{_SOURCE_NAME_PREFIX}{index.name}"
        ):
            raise InboundCorruptionError(
                "persisted inbound source name index does not match its state key"
            )
        indexed_source = by_id.get(index.source_id)
        if indexed_source is None:
            raise InboundCorruptionError(
                "persisted inbound source name index references a missing record"
            )
        if index.source_id in indexed_ids or index.name in indexed_names:
            raise InboundCorruptionError("persisted inbound source name indexes contain duplicates")
        _verify_source_name_index(index, indexed_source)
        indexed_ids.add(index.source_id)
        indexed_names.add(index.name)
    if indexed_ids != set(by_id) or indexed_names != set(by_name):
        raise InboundCorruptionError(
            "persisted inbound source records have incomplete name indexes"
        )
    return tuple(by_id.values())


class StateInboundSourceRepository:
    """Persist inbound source metadata through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 256,
        namespace: str = "inbound-sources",
        context: StateOperationContext | None = None,
    ) -> None:
        if not 1 <= capacity <= MAX_INBOUND_SOURCE_CAPACITY:
            raise ValueError(
                f"inbound source capacity must be between 1 and {MAX_INBOUND_SOURCE_CAPACITY}"
            )
        probe = StateKey(namespace, f"{_SOURCE_RECORD_PREFIX}{'0' * 32}", dict)
        self._store = store
        self._capacity = capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.inbound.source-repository",
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, source: InboundEventSource) -> None:
        self._require_open()
        try:
            async with self._store.transaction(context=self._context) as transaction:
                records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_SOURCE_RECORD_PREFIX,
                )
                indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_SOURCE_NAME_PREFIX,
                )
                sources = _validate_source_collection(
                    records,
                    indexes,
                    namespace=self._namespace,
                )
                if any(item.id == source.id for item in sources):
                    raise InboundSourceAlreadyExistsError("inbound source id already exists")
                if any(item.name == source.name for item in sources):
                    raise InboundSourceAlreadyExistsError("inbound source name already exists")
                if len(sources) >= self._capacity:
                    raise InboundSourceCapacityError(
                        "inbound source repository capacity has been exhausted"
                    )
                await transaction.put(
                    self._source_key(source.id),
                    _envelope(encode_inbound_source(source), label="source"),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    self._source_name_key(source.name),
                    _source_name_index_document(source),
                    expected_version=ABSENT_VERSION,
                )
        except (
            InboundSourceAlreadyExistsError,
            InboundSourceCapacityError,
            InboundCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise InboundSourceAlreadyExistsError(
                "inbound source id or name already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source persistence failed") from exception

    async def get(self, source_id: UUID) -> InboundEventSource | None:
        self._require_open()
        try:
            stored = await self._store.get(self._source_key(source_id), context=self._context)
            if stored is None:
                return None
            source = _decode_source_record(cast(StateRecord[object], stored))
            if source.id != source_id:
                raise InboundCorruptionError(
                    "persisted inbound source identity does not match its state key"
                )
            index_stored = await self._store.get(
                self._source_name_key(source.name),
                context=self._context,
            )
            if index_stored is None:
                raise InboundCorruptionError("persisted inbound source name index is missing")
            _verify_source_name_index(
                _decode_source_name_index(cast(StateRecord[object], index_stored)),
                source,
            )
            return source
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source read failed") from exception

    async def get_by_name(self, name: str) -> InboundEventSource | None:
        self._require_open()
        normalized = _normalize_name(name, label="inbound source")
        try:
            stored = await self._store.get(
                self._source_name_key(normalized),
                context=self._context,
            )
            if stored is None:
                return None
            index = _decode_source_name_index(cast(StateRecord[object], stored))
            source = await self.get(index.source_id)
            if source is None:
                raise InboundCorruptionError(
                    "persisted inbound source name index references a missing record"
                )
            _verify_source_name_index(index, source)
            return source
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source name lookup failed") from exception

    async def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundSourcePage:
        self._require_open()
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_SOURCE_RECORD_PREFIX,
                context=self._context,
            )
            indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_SOURCE_NAME_PREFIX,
                context=self._context,
            )
            ordered = tuple(
                sorted(
                    _validate_source_collection(records, indexes, namespace=self._namespace),
                    key=lambda item: (item.name, item.id.hex),
                )
            )
            items = ordered[request.offset : request.offset + request.limit]
            return InboundSourcePage(
                items=items,
                page=InboundPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source listing failed") from exception

    async def replace(
        self,
        source: InboundEventSource,
        *,
        expected_revision: int,
    ) -> InboundEventSource:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        self._require_open()
        try:
            async with self._store.transaction(context=self._context) as transaction:
                record_key = self._source_key(source.id)
                stored = await transaction.get(record_key)
                if stored is None:
                    raise InboundSourceNotFoundError("inbound source was not found")
                current = _decode_source_record(cast(StateRecord[object], stored))
                _validate_source_replacement(
                    current,
                    source,
                    expected_revision=expected_revision,
                )
                new_name_stored = await transaction.get(self._source_name_key(source.name))
                if current.name != source.name and new_name_stored is not None:
                    raise InboundSourceAlreadyExistsError("inbound source name already exists")
                await transaction.put(
                    record_key,
                    _envelope(encode_inbound_source(source), label="source"),
                    expected_version=stored.version,
                )
                if current.name != source.name:
                    old_index = await transaction.get(self._source_name_key(current.name))
                    if old_index is None:
                        raise InboundCorruptionError(
                            "persisted inbound source name index is missing"
                        )
                    _verify_source_name_index(
                        _decode_source_name_index(cast(StateRecord[object], old_index)),
                        current,
                    )
                    await transaction.delete(
                        cast(StateKey[object], self._source_name_key(current.name)),
                        expected_version=old_index.version,
                    )
                    await transaction.put(
                        self._source_name_key(source.name),
                        _source_name_index_document(source),
                        expected_version=ABSENT_VERSION,
                    )
                else:
                    if new_name_stored is None:
                        raise InboundCorruptionError(
                            "persisted inbound source name index is missing"
                        )
                    _verify_source_name_index(
                        _decode_source_name_index(cast(StateRecord[object], new_name_stored)),
                        current,
                    )
                    await transaction.put(
                        self._source_name_key(source.name),
                        _source_name_index_document(source),
                        expected_version=new_name_stored.version,
                    )
                return source
        except (
            InboundSourceNotFoundError,
            InboundSourceAlreadyExistsError,
            InboundSourceConflictError,
            InboundCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise InboundSourceConflictError("inbound source revision conflict") from exception
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source replacement failed") from exception

    async def snapshot(self) -> InboundSourceRepositorySnapshot:
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_SOURCE_RECORD_PREFIX,
                context=self._context,
            )
            indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_SOURCE_NAME_PREFIX,
                context=self._context,
            )
            sources = _validate_source_collection(
                records,
                indexes,
                namespace=self._namespace,
            )
            statuses = Counter(item.status for item in sources)
            return InboundSourceRepositorySnapshot(
                closed=self._closed,
                sources=len(sources),
                active=statuses[InboundEventSourceStatus.ACTIVE],
                disabled=statuses[InboundEventSourceStatus.DISABLED],
                revoked=statuses[InboundEventSourceStatus.REVOKED],
                capacity=self._capacity,
            )
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source snapshot failed") from exception

    async def close(self) -> None:
        self._closed = True

    def _source_key(self, source_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_SOURCE_RECORD_PREFIX}{source_id.hex}", dict)

    def _source_name_key(self, name: str) -> StateKey[dict[str, object]]:
        normalized = _normalize_name(name, label="inbound source")
        return StateKey(self._namespace, f"{_SOURCE_NAME_PREFIX}{normalized}", dict)

    def _require_open(self) -> None:
        if self._closed:
            raise InboundSourceRepositoryClosedError("inbound source repository is closed")


def _source_event_index_document(
    event: InboundAcceptedEvent,
    receipt: InboundEventReceipt,
    evidence_digest: str,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _SOURCE_EVENT_INDEX_KIND,
        "source_id": str(event.source_id),
        "evidence_digest": evidence_digest,
        "accepted_event_id": str(event.id),
        "receipt_id": str(receipt.id),
        "normalized_payload_sha256": event.normalized_payload_sha256,
        "event_revision": event.revision,
        "event_record_digest": inbound_accepted_event_digest(event),
        "receipt_record_digest": inbound_receipt_digest(receipt),
    }


@dataclass(frozen=True, slots=True)
class _DecodedSourceEventIndex:
    source_id: UUID
    evidence_digest: str
    accepted_event_id: UUID
    receipt_id: UUID
    normalized_payload_sha256: str
    event_revision: int
    event_record_digest: str
    receipt_record_digest: str


def _decode_source_event_index(stored: StateRecord[object]) -> _DecodedSourceEventIndex:
    document = _mapping(stored.value, label="source-event index")
    _require_exact_fields(document, _SOURCE_EVENT_INDEX_FIELDS, label="source-event index")
    if _integer(document, "schema_version") != _SCHEMA_VERSION:
        raise InboundCorruptionError("persisted inbound source-event index schema is unsupported")
    if _string(document, "kind") != _SOURCE_EVENT_INDEX_KIND:
        raise InboundCorruptionError("persisted inbound source-event index kind is invalid")
    try:
        index = _DecodedSourceEventIndex(
            source_id=UUID(_string(document, "source_id")),
            evidence_digest=_normalize_sha256(
                _string(document, "evidence_digest"),
                label="inbound source-event digest",
            ),
            accepted_event_id=UUID(_string(document, "accepted_event_id")),
            receipt_id=UUID(_string(document, "receipt_id")),
            normalized_payload_sha256=_normalize_sha256(
                _string(document, "normalized_payload_sha256"),
                label="inbound normalized payload digest",
            ),
            event_revision=_integer(document, "event_revision"),
            event_record_digest=_normalize_sha256(
                _string(document, "event_record_digest"),
                label="inbound event record digest",
            ),
            receipt_record_digest=_normalize_sha256(
                _string(document, "receipt_record_digest"),
                label="inbound receipt record digest",
            ),
        )
    except ValueError as exception:
        raise InboundCorruptionError(
            "persisted inbound source-event index is invalid"
        ) from exception
    if index.event_revision <= 0:
        raise InboundCorruptionError("persisted inbound source-event revision is invalid")
    return index


def _verify_source_event_index(
    index: _DecodedSourceEventIndex,
    event: InboundAcceptedEvent,
    receipt: InboundEventReceipt,
) -> None:
    if (
        index.source_id != event.source_id
        or index.accepted_event_id != event.id
        or index.receipt_id != receipt.id
        or event.receipt_id != receipt.id
    ):
        raise InboundCorruptionError("persisted inbound source-event index has mismatched identity")
    if index.normalized_payload_sha256 != event.normalized_payload_sha256:
        raise InboundCorruptionError("persisted inbound source-event index has mismatched payload")
    if index.event_revision != event.revision:
        raise InboundCorruptionError("persisted inbound source-event index has mismatched revision")
    if not hmac.compare_digest(
        index.event_record_digest,
        inbound_accepted_event_digest(event),
    ):
        raise InboundCorruptionError(
            "persisted inbound source-event index has mismatched event digest"
        )
    if not hmac.compare_digest(index.receipt_record_digest, inbound_receipt_digest(receipt)):
        raise InboundCorruptionError(
            "persisted inbound source-event index has mismatched receipt digest"
        )


class StateInboundEventRepository:
    """Persist accepted events, receipts, indexes, and replay evidence atomically."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 4_096,
        replay_capacity: int = 16_384,
        namespace: str = "inbound-events",
        context: StateOperationContext | None = None,
    ) -> None:
        if not 1 <= capacity <= MAX_INBOUND_EVENT_CAPACITY:
            raise ValueError(
                f"inbound event capacity must be between 1 and {MAX_INBOUND_EVENT_CAPACITY}"
            )
        if not 1 <= replay_capacity <= MAX_INBOUND_REPLAY_CAPACITY:
            raise ValueError(
                f"inbound replay capacity must be between 1 and {MAX_INBOUND_REPLAY_CAPACITY}"
            )
        probe = StateKey(namespace, f"{_EVENT_RECORD_PREFIX}{'0' * 32}", dict)
        self._store = store
        self._capacity = capacity
        self._replay_capacity = replay_capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.inbound.event-repository",
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def accept(self, acceptance: InboundAcceptance) -> None:
        self._require_open()
        event = acceptance.event
        receipt = acceptance.receipt
        source_reservation = next(
            item
            for item in acceptance.replay_reservations
            if item.kind is InboundReplayKind.SOURCE_EVENT_ID
        )
        try:
            async with self._store.transaction(context=self._context) as transaction:
                event_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_EVENT_RECORD_PREFIX,
                )
                replay_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_REPLAY_PREFIX,
                )
                for stored_event in event_records:
                    persisted_event = _decode_event_record(stored_event)
                    if stored_event.key.name != (f"{_EVENT_RECORD_PREFIX}{persisted_event.id.hex}"):
                        raise InboundCorruptionError(
                            "persisted inbound event identity does not match its state key"
                        )
                for stored_replay in replay_records:
                    persisted_replay = _decode_replay_record(stored_replay)
                    if stored_replay.key.name != (
                        _state_replay_key(self._namespace, persisted_replay).name
                    ):
                        raise InboundCorruptionError(
                            "persisted inbound replay identity does not match its state key"
                        )
                keys = (
                    self._event_key(event.id),
                    self._receipt_key(receipt.id),
                    self._source_event_key(event.source_id, source_reservation.evidence_digest),
                )
                for key in keys:
                    if await transaction.get(key) is not None:
                        raise InboundEventAlreadyExistsError(
                            "inbound event, receipt, or source-event identity already exists"
                        )
                for reservation in acceptance.replay_reservations:
                    if await transaction.get(self._replay_key(reservation)) is not None:
                        raise InboundReplayAlreadyExistsError(
                            f"inbound {reservation.kind.value} evidence is already reserved"
                        )
                if len(event_records) >= self._capacity:
                    raise InboundEventCapacityError(
                        "inbound event repository capacity has been exhausted"
                    )
                if (
                    len(replay_records) + len(acceptance.replay_reservations)
                    > self._replay_capacity
                ):
                    raise InboundReplayCapacityError(
                        "inbound replay repository capacity has been exhausted"
                    )
                await transaction.put(
                    self._event_key(event.id),
                    _envelope(encode_inbound_accepted_event(event), label="accepted event"),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    self._receipt_key(receipt.id),
                    _envelope(encode_inbound_receipt(receipt), label="receipt"),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    self._source_event_key(event.source_id, source_reservation.evidence_digest),
                    _source_event_index_document(
                        event,
                        receipt,
                        source_reservation.evidence_digest,
                    ),
                    expected_version=ABSENT_VERSION,
                )
                for reservation in acceptance.replay_reservations:
                    await transaction.put(
                        self._replay_key(reservation),
                        _envelope(encode_inbound_replay(reservation), label="replay"),
                        expected_version=ABSENT_VERSION,
                    )
        except (
            InboundEventAlreadyExistsError,
            InboundEventCapacityError,
            InboundReplayAlreadyExistsError,
            InboundReplayCapacityError,
            InboundCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise InboundEventAlreadyExistsError(
                "inbound acceptance identity already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound atomic acceptance failed") from exception

    async def reserve_idempotent_replay(
        self,
        accepted_event_id: UUID,
        reservations: tuple[InboundReplayReservation, InboundReplayReservation],
    ) -> None:
        self._require_open()
        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_event = await transaction.get(self._event_key(accepted_event_id))
                if stored_event is None:
                    raise InboundEventNotFoundError("inbound accepted event was not found")
                event = _decode_event_record(cast(StateRecord[object], stored_event))
                if event.id != accepted_event_id:
                    raise InboundCorruptionError(
                        "persisted inbound event identity does not match its state key"
                    )
                validated = _validate_idempotent_replay_reservations(
                    event,
                    reservations,
                )
                replay_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_REPLAY_PREFIX,
                )
                for stored_replay in replay_records:
                    persisted = _decode_replay_record(stored_replay)
                    if stored_replay.key.name != (
                        _state_replay_key(self._namespace, persisted).name
                    ):
                        raise InboundCorruptionError(
                            "persisted inbound replay identity does not match its state key"
                        )
                for reservation in validated:
                    if await transaction.get(self._replay_key(reservation)) is not None:
                        raise InboundReplayAlreadyExistsError(
                            f"inbound {reservation.kind.value} evidence is already reserved"
                        )
                if len(replay_records) + len(validated) > self._replay_capacity:
                    raise InboundReplayCapacityError(
                        "inbound replay repository capacity has been exhausted"
                    )
                for reservation in validated:
                    await transaction.put(
                        self._replay_key(reservation),
                        _envelope(
                            encode_inbound_replay(reservation),
                            label="replay",
                        ),
                        expected_version=ABSENT_VERSION,
                    )
        except (
            InboundEventNotFoundError,
            InboundReplayAlreadyExistsError,
            InboundReplayCapacityError,
            InboundCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise InboundReplayAlreadyExistsError(
                "inbound request or nonce evidence is already reserved"
            ) from exception
        except PhoenixStateError as exception:
            raise InboundPersistenceError(
                "inbound idempotent replay persistence failed"
            ) from exception

    async def get(self, accepted_event_id: UUID) -> InboundAcceptedEvent | None:
        self._require_open()
        try:
            stored = await self._store.get(
                self._event_key(accepted_event_id),
                context=self._context,
            )
            if stored is None:
                return None
            event = _decode_event_record(cast(StateRecord[object], stored))
            if event.id != accepted_event_id:
                raise InboundCorruptionError(
                    "persisted inbound event identity does not match its state key"
                )
            receipt = await self.get_receipt(event.receipt_id)
            if receipt is None:
                raise InboundCorruptionError("persisted inbound event receipt is missing")
            source_index = await self._find_source_index_for_event(event)
            _verify_source_event_index(source_index, event, receipt)
            return event
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound event read failed") from exception

    async def get_receipt(self, receipt_id: UUID) -> InboundEventReceipt | None:
        self._require_open()
        try:
            stored = await self._store.get(
                self._receipt_key(receipt_id),
                context=self._context,
            )
            if stored is None:
                return None
            receipt = _decode_receipt_record(cast(StateRecord[object], stored))
            if receipt.id != receipt_id:
                raise InboundCorruptionError(
                    "persisted inbound receipt identity does not match its state key"
                )
            return receipt
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound receipt read failed") from exception

    async def get_by_source_event_digest(
        self,
        source_id: UUID,
        source_event_digest: str,
    ) -> InboundAcceptedEvent | None:
        self._require_open()
        digest = _normalize_sha256(
            source_event_digest,
            label="inbound source-event digest",
        )
        try:
            stored = await self._store.get(
                self._source_event_key(source_id, digest),
                context=self._context,
            )
            if stored is None:
                return None
            index = _decode_source_event_index(cast(StateRecord[object], stored))
            if index.source_id != source_id or index.evidence_digest != digest:
                raise InboundCorruptionError(
                    "persisted inbound source-event index does not match its state key"
                )
            event_stored = await self._store.get(
                self._event_key(index.accepted_event_id),
                context=self._context,
            )
            receipt_stored = await self._store.get(
                self._receipt_key(index.receipt_id),
                context=self._context,
            )
            if event_stored is None or receipt_stored is None:
                raise InboundCorruptionError(
                    "persisted inbound source-event index references missing records"
                )
            event = _decode_event_record(cast(StateRecord[object], event_stored))
            receipt = _decode_receipt_record(cast(StateRecord[object], receipt_stored))
            _verify_source_event_index(index, event, receipt)
            return event
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound source-event lookup failed") from exception

    async def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundEventPage:
        self._require_open()
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_EVENT_RECORD_PREFIX,
                context=self._context,
            )
            events = tuple(_decode_event_record(item) for item in records)
            for stored, event in zip(records, events, strict=True):
                if stored.key.name != f"{_EVENT_RECORD_PREFIX}{event.id.hex}":
                    raise InboundCorruptionError(
                        "persisted inbound event identity does not match its state key"
                    )
                receipt = await self.get_receipt(event.receipt_id)
                if receipt is None:
                    raise InboundCorruptionError("persisted inbound event receipt is missing")
                _verify_source_event_index(
                    await self._find_source_index_for_event(event),
                    event,
                    receipt,
                )
            ordered = tuple(sorted(events, key=lambda item: (item.accepted_at, item.id.hex)))
            items = ordered[request.offset : request.offset + request.limit]
            return InboundEventPage(
                items=items,
                page=InboundPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound event listing failed") from exception

    async def replace(
        self,
        event: InboundAcceptedEvent,
        *,
        expected_revision: int,
    ) -> InboundAcceptedEvent:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        self._require_open()
        try:
            async with self._store.transaction(context=self._context) as transaction:
                event_key = self._event_key(event.id)
                stored = await transaction.get(event_key)
                if stored is None:
                    raise InboundEventNotFoundError("inbound accepted event was not found")
                current = _decode_event_record(cast(StateRecord[object], stored))
                _validate_event_replacement(
                    current,
                    event,
                    expected_revision=expected_revision,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=f"{_SOURCE_EVENT_PREFIX}{event.source_id.hex}_",
                )
                decoded_indexes = tuple(_decode_source_event_index(item) for item in stored_indexes)
                matches = tuple(
                    (stored_index, index)
                    for stored_index, index in zip(stored_indexes, decoded_indexes, strict=True)
                    if index.accepted_event_id == event.id
                )
                if len(matches) != 1:
                    raise InboundCorruptionError(
                        "persisted inbound source-event index is missing or ambiguous"
                    )
                index_stored, index = matches[0]
                expected_index_key = self._source_event_key(
                    event.source_id,
                    index.evidence_digest,
                )
                if index_stored.key.name != expected_index_key.name:
                    raise InboundCorruptionError(
                        "persisted inbound source-event index does not match its state key"
                    )
                receipt_stored = await transaction.get(self._receipt_key(event.receipt_id))
                if receipt_stored is None:
                    raise InboundCorruptionError("persisted inbound event receipt is missing")
                receipt = _decode_receipt_record(cast(StateRecord[object], receipt_stored))
                _verify_source_event_index(index, current, receipt)
                await transaction.put(
                    event_key,
                    _envelope(encode_inbound_accepted_event(event), label="accepted event"),
                    expected_version=stored.version,
                )
                await transaction.put(
                    cast(StateKey[dict[str, object]], index_stored.key),
                    _source_event_index_document(
                        event,
                        receipt,
                        index.evidence_digest,
                    ),
                    expected_version=index_stored.version,
                )
                return event
        except (
            InboundEventNotFoundError,
            InboundEventConflictError,
            InboundCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise InboundEventConflictError("inbound event revision conflict") from exception
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound event replacement failed") from exception

    async def snapshot(self) -> InboundEventRepositorySnapshot:
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_EVENT_RECORD_PREFIX,
                context=self._context,
            )
            events = tuple(_decode_event_record(item) for item in records)
            for stored, event in zip(records, events, strict=True):
                if stored.key.name != f"{_EVENT_RECORD_PREFIX}{event.id.hex}":
                    raise InboundCorruptionError(
                        "persisted inbound event identity does not match its state key"
                    )
                receipt_stored = await self._store.get(
                    self._receipt_key(event.receipt_id),
                    context=self._context,
                )
                if receipt_stored is None:
                    raise InboundCorruptionError("persisted inbound event receipt is missing")
                receipt = _decode_receipt_record(cast(StateRecord[object], receipt_stored))
                _verify_source_event_index(
                    await self._find_source_index_for_event(event),
                    event,
                    receipt,
                )
            statuses = Counter(item.status for item in events)
            return InboundEventRepositorySnapshot(
                closed=self._closed,
                events=len(events),
                pending=statuses[InboundPublicationStatus.PENDING],
                publishing=statuses[InboundPublicationStatus.PUBLISHING],
                retrying=statuses[InboundPublicationStatus.RETRYING],
                published=statuses[InboundPublicationStatus.PUBLISHED],
                dead_letter=statuses[InboundPublicationStatus.DEAD_LETTER],
                discarded=statuses[InboundPublicationStatus.DISCARDED],
                attempts=sum(item.completed_attempts for item in events),
                capacity=self._capacity,
            )
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound event snapshot failed") from exception

    async def close(self) -> None:
        self._closed = True

    async def _find_source_index_for_event(
        self,
        event: InboundAcceptedEvent,
    ) -> _DecodedSourceEventIndex:
        stored_indexes = await self._store.list(
            namespace=self._namespace,
            prefix=f"{_SOURCE_EVENT_PREFIX}{event.source_id.hex}_",
            context=self._context,
        )
        decoded = tuple(_decode_source_event_index(item) for item in stored_indexes)
        matches = [item for item in decoded if item.accepted_event_id == event.id]
        if len(matches) != 1:
            raise InboundCorruptionError(
                "persisted inbound source-event index is missing or ambiguous"
            )
        return matches[0]

    def _event_key(self, event_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_EVENT_RECORD_PREFIX}{event_id.hex}", dict)

    def _receipt_key(self, receipt_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_RECEIPT_RECORD_PREFIX}{receipt_id.hex}", dict)

    def _source_event_key(
        self,
        source_id: UUID,
        evidence_digest: str,
    ) -> StateKey[dict[str, object]]:
        digest = _normalize_sha256(evidence_digest, label="inbound source-event digest")
        return StateKey(
            self._namespace,
            f"{_SOURCE_EVENT_PREFIX}{source_id.hex}_{digest}",
            dict,
        )

    def _replay_key(
        self,
        reservation: InboundReplayReservation,
    ) -> StateKey[dict[str, object]]:
        return _state_replay_key(self._namespace, reservation)

    def _require_open(self) -> None:
        if self._closed:
            raise InboundEventRepositoryClosedError("inbound event repository is closed")


def _state_replay_key(
    namespace: str,
    reservation: InboundReplayReservation,
) -> StateKey[dict[str, object]]:
    return StateKey(
        namespace,
        (
            f"{_REPLAY_PREFIX}{reservation.source_id.hex}_"
            f"{reservation.kind.value}_{reservation.evidence_digest}"
        ),
        dict,
    )


class StateInboundReplayRepository:
    """Read and prune durable replay reservations from the shared event namespace."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 16_384,
        namespace: str = "inbound-events",
        context: StateOperationContext | None = None,
    ) -> None:
        if not 1 <= capacity <= MAX_INBOUND_REPLAY_CAPACITY:
            raise ValueError(
                f"inbound replay capacity must be between 1 and {MAX_INBOUND_REPLAY_CAPACITY}"
            )
        probe = StateKey(namespace, f"{_REPLAY_PREFIX}{'0' * 32}_nonce_{'0' * 64}", dict)
        self._store = store
        self._capacity = capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.inbound.replay-repository",
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def get(
        self,
        source_id: UUID,
        kind: InboundReplayKind,
        evidence_digest: str,
    ) -> InboundReplayReservation | None:
        self._require_open()
        normalized_kind = InboundReplayKind(kind)
        digest = _normalize_sha256(
            evidence_digest,
            label="inbound replay evidence digest",
        )
        key = StateKey(
            self._namespace,
            f"{_REPLAY_PREFIX}{source_id.hex}_{normalized_kind.value}_{digest}",
            dict,
        )
        try:
            stored = await self._store.get(key, context=self._context)
            if stored is None:
                return None
            reservation = _decode_replay_record(cast(StateRecord[object], stored))
            if reservation.key != (source_id, normalized_kind, digest):
                raise InboundCorruptionError(
                    "persisted inbound replay identity does not match its state key"
                )
            return reservation
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound replay read failed") from exception

    async def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundReplayPage:
        self._require_open()
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_REPLAY_PREFIX,
                context=self._context,
            )
            reservations: list[InboundReplayReservation] = []
            keys: set[tuple[UUID, InboundReplayKind, str]] = set()
            for stored in records:
                reservation = _decode_replay_record(stored)
                expected_name = _state_replay_key(self._namespace, reservation).name
                if stored.key.namespace != self._namespace or stored.key.name != expected_name:
                    raise InboundCorruptionError(
                        "persisted inbound replay identity does not match its state key"
                    )
                if reservation.key in keys:
                    raise InboundCorruptionError(
                        "persisted inbound replay reservations contain duplicates"
                    )
                keys.add(reservation.key)
                reservations.append(reservation)
            ordered = tuple(
                sorted(
                    reservations,
                    key=lambda item: (
                        item.created_at,
                        item.source_id.hex,
                        item.kind.value,
                        item.evidence_digest,
                    ),
                )
            )
            items = ordered[request.offset : request.offset + request.limit]
            return InboundReplayPage(
                items=items,
                page=InboundPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound replay listing failed") from exception

    async def prune_expired(self, *, now: datetime) -> int:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        self._require_open()
        try:
            async with self._store.transaction(context=self._context) as transaction:
                records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_REPLAY_PREFIX,
                )
                expired = 0
                for stored in records:
                    reservation = _decode_replay_record(stored)
                    expected_name = _state_replay_key(self._namespace, reservation).name
                    if stored.key.name != expected_name:
                        raise InboundCorruptionError(
                            "persisted inbound replay identity does not match its state key"
                        )
                    if reservation.expires_at > now:
                        continue
                    await transaction.delete(
                        stored.key,
                        expected_version=stored.version,
                    )
                    expired += 1
                return expired
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound replay pruning failed") from exception

    async def snapshot(self) -> InboundReplayRepositorySnapshot:
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_REPLAY_PREFIX,
                context=self._context,
            )
            reservations = tuple(_decode_replay_record(item) for item in records)
            for stored, reservation in zip(records, reservations, strict=True):
                expected_name = _state_replay_key(self._namespace, reservation).name
                if stored.key.namespace != self._namespace or stored.key.name != expected_name:
                    raise InboundCorruptionError(
                        "persisted inbound replay identity does not match its state key"
                    )
            kinds = Counter(item.kind for item in reservations)
            return InboundReplayRepositorySnapshot(
                closed=self._closed,
                reservations=len(reservations),
                request_ids=kinds[InboundReplayKind.REQUEST_ID],
                nonces=kinds[InboundReplayKind.NONCE],
                source_events=kinds[InboundReplayKind.SOURCE_EVENT_ID],
                capacity=self._capacity,
            )
        except InboundCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise InboundPersistenceError("inbound replay snapshot failed") from exception

    async def close(self) -> None:
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise InboundReplayRepositoryClosedError("inbound replay repository is closed")
