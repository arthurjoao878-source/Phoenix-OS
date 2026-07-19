"""Durable command journal backed by the provider-neutral Phoenix State Store."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from typing import cast
from uuid import UUID

from phoenix_os.control_plane.commands import ControlPlaneCommandAction
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandJournalAlreadyExistsError,
    ControlPlaneCommandJournalCapacityError,
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandJournalCorruptionError,
    ControlPlaneCommandJournalNotFoundError,
    ControlPlaneCommandJournalPersistenceError,
    ControlPlaneCommandJournalRepositoryClosedError,
    ControlPlaneCommandJournalSchemaError,
)
from phoenix_os.control_plane.journal_contracts import (
    DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    MAX_COMMAND_JOURNAL_CAPACITY,
    ControlPlaneCommandJournalPage,
    ControlPlaneCommandJournalPageInfo,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalSnapshot,
    ControlPlaneCommandJournalStatus,
)
from phoenix_os.policy import PrincipalType
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
_RECORD_KIND = "phoenix.control-plane.command-journal.record"
_INDEX_KIND = "phoenix.control-plane.command-journal.idempotency-index"
_RECORD_PREFIX = "record_"
_INDEX_PREFIX = "idempotency_"
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "command_id",
        "action",
        "target",
        "principal",
        "idempotency_digest",
        "fingerprint",
        "status",
        "requested_at",
        "updated_at",
        "completed_at",
        "result_code",
        "revision",
    }
)
_RECORD_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record", "record_digest"})
_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "command_id",
        "idempotency_digest",
        "fingerprint",
    }
)
_ALLOWED_TRANSITIONS: dict[
    ControlPlaneCommandJournalStatus,
    frozenset[ControlPlaneCommandJournalStatus],
] = {
    ControlPlaneCommandJournalStatus.PENDING: frozenset(
        {
            ControlPlaneCommandJournalStatus.EXECUTING,
            ControlPlaneCommandJournalStatus.SUCCEEDED,
            ControlPlaneCommandJournalStatus.REJECTED,
            ControlPlaneCommandJournalStatus.FAILED,
        }
    ),
    ControlPlaneCommandJournalStatus.EXECUTING: frozenset(
        {
            ControlPlaneCommandJournalStatus.SUCCEEDED,
            ControlPlaneCommandJournalStatus.REJECTED,
            ControlPlaneCommandJournalStatus.FAILED,
        }
    ),
    ControlPlaneCommandJournalStatus.SUCCEEDED: frozenset(),
    ControlPlaneCommandJournalStatus.REJECTED: frozenset(),
    ControlPlaneCommandJournalStatus.FAILED: frozenset(),
}


def canonical_command_journal_record_bytes(
    record: ControlPlaneCommandJournalRecord,
) -> bytes:
    """Return deterministic schema-v1 JSON bytes for one payload-free record."""

    return _canonical_json_bytes(_record_document(record))


def command_journal_record_digest(record: ControlPlaneCommandJournalRecord) -> str:
    """Return the SHA-256 digest used to detect accidental record corruption."""

    return hashlib.sha256(canonical_command_journal_record_bytes(record)).hexdigest()


class StateControlPlaneCommandJournalRepository:
    """Persist command records and idempotency indexes through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 4096,
        namespace: str = "control-plane-command-journal",
        context: StateOperationContext | None = None,
    ) -> None:
        if capacity <= 0 or capacity > MAX_COMMAND_JOURNAL_CAPACITY:
            raise ValueError(
                f"command journal capacity must be between 1 and {MAX_COMMAND_JOURNAL_CAPACITY}"
            )
        probe = StateKey(namespace, f"{_RECORD_PREFIX}{'0' * 32}", dict)
        self._store = store
        self._capacity = capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.control-plane.command-journal",
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneCommandJournalRecord) -> None:
        self._ensure_open()
        record_key = self._record_key(record.command_id)
        index_key = self._index_key(record.idempotency_digest)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_RECORD_PREFIX,
                )
                indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_INDEX_PREFIX,
                )
                _validate_persisted_collection(records, indexes)
                existing_record = await transaction.get(record_key)
                existing_index = await transaction.get(index_key)
                if existing_record is not None:
                    raise ControlPlaneCommandJournalAlreadyExistsError(
                        "command journal record already exists"
                    )
                if existing_index is not None:
                    raise ControlPlaneCommandJournalAlreadyExistsError(
                        "command journal idempotency digest already exists"
                    )
                if len(records) >= self._capacity:
                    raise ControlPlaneCommandJournalCapacityError(
                        "command journal capacity has been exhausted"
                    )
                await transaction.put(
                    record_key,
                    _record_envelope(record),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    index_key,
                    _index_document(record),
                    expected_version=ABSENT_VERSION,
                )
        except (
            ControlPlaneCommandJournalAlreadyExistsError,
            ControlPlaneCommandJournalCapacityError,
            ControlPlaneCommandJournalCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneCommandJournalAlreadyExistsError(
                "command journal record or idempotency digest already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneCommandJournalPersistenceError(
                "command journal persistence operation failed"
            ) from exception

    async def get(self, command_id: UUID) -> ControlPlaneCommandJournalRecord | None:
        self._ensure_open()
        try:
            stored = await self._store.get(
                self._record_key(command_id),
                context=self._context,
            )
            if stored is None:
                return None
            record = _decode_record_state(stored)
            if record.command_id != command_id:
                raise ControlPlaneCommandJournalCorruptionError(
                    "persisted command journal identity does not match its state key"
                )
            stored_index = await self._store.get(
                self._index_key(record.idempotency_digest),
                context=self._context,
            )
        except ControlPlaneCommandJournalCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneCommandJournalPersistenceError(
                "command journal persistence operation failed"
            ) from exception
        if stored_index is None:
            raise ControlPlaneCommandJournalCorruptionError(
                "persisted command journal record has no idempotency index"
            )
        index = _decode_index_state(stored_index)
        if stored_index.key.name != f"{_INDEX_PREFIX}{index.idempotency_digest}":
            raise ControlPlaneCommandJournalCorruptionError(
                "persisted command journal index does not match its state key"
            )
        _verify_index_record(index, record)
        return record

    async def get_by_idempotency_digest(
        self,
        digest: str,
    ) -> ControlPlaneCommandJournalRecord | None:
        self._ensure_open()
        normalized = _normalize_digest(digest, label="idempotency digest")
        try:
            stored_index = await self._store.get(
                self._index_key(normalized),
                context=self._context,
            )
            if stored_index is None:
                return None
            index = _decode_index_state(stored_index)
            if index.idempotency_digest != normalized:
                raise ControlPlaneCommandJournalCorruptionError(
                    "persisted command journal index does not match its state key"
                )
            stored_record = await self._store.get(
                self._record_key(index.command_id),
                context=self._context,
            )
        except ControlPlaneCommandJournalCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneCommandJournalPersistenceError(
                "command journal persistence operation failed"
            ) from exception
        if stored_record is None:
            raise ControlPlaneCommandJournalCorruptionError(
                "persisted command journal index references a missing record"
            )
        record = _decode_record_state(stored_record)
        _verify_index_record(index, record)
        return record

    async def list_page(
        self,
        request: ControlPlaneCommandJournalPageRequest = DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    ) -> ControlPlaneCommandJournalPage:
        self._ensure_open()
        records = await self._load_records()
        ordered = tuple(
            sorted(
                records,
                key=lambda item: (
                    -item.requested_at.timestamp(),
                    item.command_id.hex,
                ),
            )
        )
        items = ordered[request.offset : request.offset + request.limit]
        return ControlPlaneCommandJournalPage(
            items=items,
            page=ControlPlaneCommandJournalPageInfo.from_slice(
                request,
                returned=len(items),
                total=len(ordered),
            ),
        )

    async def transition(
        self,
        command_id: UUID,
        *,
        expected_revision: int,
        status: ControlPlaneCommandJournalStatus,
        updated_at: datetime,
        result_code: str | None = None,
    ) -> ControlPlaneCommandJournalRecord:
        self._ensure_open()
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        if updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")
        normalized_status = ControlPlaneCommandJournalStatus(status)
        key = self._record_key(command_id)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored = await transaction.get(key)
                if stored is None:
                    raise ControlPlaneCommandJournalNotFoundError(
                        "command journal record was not found"
                    )
                current = _decode_record_state(stored)
                if current.command_id != command_id:
                    raise ControlPlaneCommandJournalCorruptionError(
                        "persisted command journal identity does not match its state key"
                    )
                stored_index = await transaction.get(self._index_key(current.idempotency_digest))
                if stored_index is None:
                    raise ControlPlaneCommandJournalCorruptionError(
                        "persisted command journal record has no idempotency index"
                    )
                _verify_index_record(_decode_index_state(stored_index), current)
                if current.revision != expected_revision:
                    raise ControlPlaneCommandJournalConflictError(
                        "command journal revision conflict"
                    )
                if normalized_status not in _ALLOWED_TRANSITIONS[current.status]:
                    raise ControlPlaneCommandJournalConflictError(
                        "command journal lifecycle transition is not allowed"
                    )
                if updated_at < current.updated_at:
                    raise ControlPlaneCommandJournalConflictError(
                        "command journal update time cannot move backwards"
                    )
                terminal = normalized_status.terminal
                updated = replace(
                    current,
                    status=normalized_status,
                    updated_at=updated_at,
                    completed_at=updated_at if terminal else None,
                    result_code=result_code if terminal else None,
                    revision=current.revision + 1,
                )
                await transaction.put(
                    key,
                    _record_envelope(updated),
                    expected_version=stored.version,
                )
                return updated
        except (
            ControlPlaneCommandJournalConflictError,
            ControlPlaneCommandJournalCorruptionError,
            ControlPlaneCommandJournalNotFoundError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneCommandJournalConflictError(
                "command journal state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneCommandJournalPersistenceError(
                "command journal persistence operation failed"
            ) from exception

    async def delete_terminal(
        self,
        command_id: UUID,
        *,
        expected_revision: int,
    ) -> None:
        self._ensure_open()
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        record_key = self._record_key(command_id)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_record = await transaction.get(record_key)
                if stored_record is None:
                    raise ControlPlaneCommandJournalNotFoundError(
                        "command journal record was not found"
                    )
                record = _decode_record_state(stored_record)
                if record.command_id != command_id:
                    raise ControlPlaneCommandJournalCorruptionError(
                        "persisted command journal identity does not match its state key"
                    )
                index_key = self._index_key(record.idempotency_digest)
                stored_index = await transaction.get(index_key)
                if stored_index is None:
                    raise ControlPlaneCommandJournalCorruptionError(
                        "persisted command journal record has no idempotency index"
                    )
                _verify_index_record(_decode_index_state(stored_index), record)
                if record.revision != expected_revision:
                    raise ControlPlaneCommandJournalConflictError(
                        "command journal revision conflict"
                    )
                if not record.status.terminal:
                    raise ControlPlaneCommandJournalConflictError(
                        "non-terminal command journal record cannot be deleted"
                    )
                await transaction.delete(
                    record_key,
                    expected_version=stored_record.version,
                )
                await transaction.delete(
                    index_key,
                    expected_version=stored_index.version,
                )
        except (
            ControlPlaneCommandJournalConflictError,
            ControlPlaneCommandJournalCorruptionError,
            ControlPlaneCommandJournalNotFoundError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneCommandJournalConflictError(
                "command journal state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneCommandJournalPersistenceError(
                "command journal persistence operation failed"
            ) from exception

    async def snapshot(self) -> ControlPlaneCommandJournalSnapshot:
        records = await self._load_records(require_open=False)
        counts = Counter(record.status for record in records)
        return ControlPlaneCommandJournalSnapshot(
            closed=self._closed,
            entries=len(records),
            pending=counts[ControlPlaneCommandJournalStatus.PENDING],
            executing=counts[ControlPlaneCommandJournalStatus.EXECUTING],
            succeeded=counts[ControlPlaneCommandJournalStatus.SUCCEEDED],
            rejected=counts[ControlPlaneCommandJournalStatus.REJECTED],
            failed=counts[ControlPlaneCommandJournalStatus.FAILED],
            capacity=self._capacity,
        )

    async def close(self) -> None:
        # The repository borrows the State Store; Runtime owns the store lifecycle.
        self._closed = True

    async def _load_records(
        self,
        *,
        require_open: bool = True,
    ) -> tuple[ControlPlaneCommandJournalRecord, ...]:
        if require_open:
            self._ensure_open()
        try:
            stored_records = await self._store.list(
                namespace=self._namespace,
                prefix=_RECORD_PREFIX,
                context=self._context,
            )
            stored_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_INDEX_PREFIX,
                context=self._context,
            )
        except PhoenixStateError as exception:
            raise ControlPlaneCommandJournalPersistenceError(
                "command journal persistence operation failed"
            ) from exception
        return _validate_persisted_collection(stored_records, stored_indexes)

    def _record_key(self, command_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_RECORD_PREFIX}{command_id.hex}", dict)

    def _index_key(self, digest: str) -> StateKey[dict[str, object]]:
        normalized = _normalize_digest(digest, label="idempotency digest")
        return StateKey(self._namespace, f"{_INDEX_PREFIX}{normalized}", dict)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ControlPlaneCommandJournalRepositoryClosedError(
                "command journal repository is closed"
            )


class _DecodedIndex:
    __slots__ = ("command_id", "fingerprint", "idempotency_digest")

    def __init__(
        self,
        *,
        command_id: UUID,
        idempotency_digest: str,
        fingerprint: str,
    ) -> None:
        self.command_id = command_id
        self.idempotency_digest = idempotency_digest
        self.fingerprint = fingerprint


def _validate_persisted_collection(
    stored_records: tuple[StateRecord[object], ...],
    stored_indexes: tuple[StateRecord[object], ...],
) -> tuple[ControlPlaneCommandJournalRecord, ...]:
    records = tuple(_decode_record_state(item) for item in stored_records)
    indexes = tuple(_decode_index_state(item) for item in stored_indexes)
    command_ids = tuple(record.command_id for record in records)
    record_digests = tuple(record.idempotency_digest for record in records)
    index_digests = tuple(index.idempotency_digest for index in indexes)
    index_commands = tuple(index.command_id for index in indexes)
    if (
        len(command_ids) != len(set(command_ids))
        or len(record_digests) != len(set(record_digests))
        or len(index_digests) != len(set(index_digests))
        or len(index_commands) != len(set(index_commands))
    ):
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal contains duplicate identities"
        )
    if len(records) != len(indexes):
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal records and indexes are incomplete"
        )
    by_digest = {index.idempotency_digest: index for index in indexes}
    for stored_record, record in zip(stored_records, records, strict=True):
        if stored_record.key.name != f"{_RECORD_PREFIX}{record.command_id.hex}":
            raise ControlPlaneCommandJournalCorruptionError(
                "persisted command journal identity does not match its state key"
            )
        index = by_digest.get(record.idempotency_digest)
        if index is None:
            raise ControlPlaneCommandJournalCorruptionError(
                "persisted command journal record has no idempotency index"
            )
        _verify_index_record(index, record)
    for stored_index, index in zip(stored_indexes, indexes, strict=True):
        if stored_index.key.name != f"{_INDEX_PREFIX}{index.idempotency_digest}":
            raise ControlPlaneCommandJournalCorruptionError(
                "persisted command journal index does not match its state key"
            )
    return records


def _record_document(record: ControlPlaneCommandJournalRecord) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "command_id": str(record.command_id),
        "action": record.action.value,
        "target": record.target,
        "principal": record.principal,
        "idempotency_digest": record.idempotency_digest,
        "fingerprint": record.fingerprint,
        "status": record.status.value,
        "requested_at": record.requested_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "completed_at": (None if record.completed_at is None else record.completed_at.isoformat()),
        "result_code": record.result_code,
        "revision": record.revision,
    }


def _record_envelope(record: ControlPlaneCommandJournalRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _RECORD_KIND,
        "record": _record_document(record),
        "record_digest": command_journal_record_digest(record),
    }


def _index_document(record: ControlPlaneCommandJournalRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _INDEX_KIND,
        "command_id": str(record.command_id),
        "idempotency_digest": record.idempotency_digest,
        "fingerprint": record.fingerprint,
    }


def _decode_record_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> ControlPlaneCommandJournalRecord:
    value = _mapping(stored.value, label="record envelope")
    _require_exact_fields(value, _RECORD_ENVELOPE_FIELDS, label="record envelope")
    _require_schema(value)
    if _string(value, "kind") != _RECORD_KIND:
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal record kind is invalid"
        )
    document = _mapping(value.get("record"), label="record")
    _require_exact_fields(document, _RECORD_FIELDS, label="record")
    expected_digest = _normalize_digest(
        _string(value, "record_digest"),
        label="record digest",
    )
    actual_digest = hashlib.sha256(_canonical_json_bytes(document)).hexdigest()
    if not _constant_time_equal(expected_digest, actual_digest):
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal record digest does not match"
        )
    try:
        schema_version = _integer(document, "schema_version")
        if schema_version != _SCHEMA_VERSION:
            raise ControlPlaneCommandJournalSchemaError(
                "persisted command journal record schema is unsupported"
            )
        return ControlPlaneCommandJournalRecord(
            command_id=UUID(_string(document, "command_id")),
            action=ControlPlaneCommandAction(_string(document, "action")),
            target=_string(document, "target"),
            principal=_string(document, "principal"),
            idempotency_digest=_string(document, "idempotency_digest"),
            fingerprint=_string(document, "fingerprint"),
            status=ControlPlaneCommandJournalStatus(_string(document, "status")),
            requested_at=datetime.fromisoformat(_string(document, "requested_at")),
            updated_at=datetime.fromisoformat(_string(document, "updated_at")),
            completed_at=_optional_datetime(document, "completed_at"),
            result_code=_optional_string(document, "result_code"),
            revision=_integer(document, "revision"),
            schema_version=schema_version,
        )
    except ControlPlaneCommandJournalSchemaError:
        raise
    except (TypeError, ValueError) as exception:
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal record is invalid"
        ) from exception


def _decode_index_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> _DecodedIndex:
    value = _mapping(stored.value, label="idempotency index")
    _require_exact_fields(value, _INDEX_FIELDS, label="idempotency index")
    _require_schema(value)
    if _string(value, "kind") != _INDEX_KIND:
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal index kind is invalid"
        )
    try:
        return _DecodedIndex(
            command_id=UUID(_string(value, "command_id")),
            idempotency_digest=_normalize_digest(
                _string(value, "idempotency_digest"),
                label="idempotency digest",
            ),
            fingerprint=_normalize_digest(
                _string(value, "fingerprint"),
                label="fingerprint",
            ),
        )
    except (TypeError, ValueError) as exception:
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal idempotency index is invalid"
        ) from exception


def _verify_index_record(
    index: _DecodedIndex,
    record: ControlPlaneCommandJournalRecord,
) -> None:
    if (
        index.command_id != record.command_id
        or index.idempotency_digest != record.idempotency_digest
        or index.fingerprint != record.fingerprint
    ):
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal index and record do not match"
        )


def _require_schema(value: Mapping[str, object]) -> None:
    try:
        schema_version = _integer(value, "schema_version")
    except ValueError as exception:
        raise ControlPlaneCommandJournalCorruptionError(
            "persisted command journal schema field is invalid"
        ) from exception
    if schema_version != _SCHEMA_VERSION:
        raise ControlPlaneCommandJournalSchemaError(
            "persisted command journal schema is unsupported"
        )


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise ControlPlaneCommandJournalCorruptionError(
            f"persisted command journal {label} fields are invalid"
        )


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ControlPlaneCommandJournalCorruptionError(
            f"persisted command journal {label} is invalid"
        )
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted command journal field: {key}")
    return result


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted command journal field: {key}")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError(f"invalid persisted command journal field: {key}")
    return result


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    raw = _optional_string(value, key)
    return None if raw is None else datetime.fromisoformat(raw)


def _normalize_digest(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{label} must be a SHA-256 hexadecimal digest")
    return normalized


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _constant_time_equal(left: str, right: str) -> bool:
    return (
        hashlib.sha256(left.encode("ascii")).digest()
        == hashlib.sha256(right.encode("ascii")).digest()
    )
