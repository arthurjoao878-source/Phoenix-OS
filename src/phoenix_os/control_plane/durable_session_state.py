"""Durable operator-session repository backed by the Phoenix State Store."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol, cast
from uuid import UUID

from phoenix_os.control_plane.durable_session_contracts import (
    DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    DEFAULT_DURABLE_SESSIONS_PER_OPERATOR,
    MAX_DURABLE_SESSION_CAPACITY,
    MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ControlPlaneDurableSessionPage,
    ControlPlaneDurableSessionPageInfo,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRotation,
    ControlPlaneDurableSessionSnapshot,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionAlreadyExistsError,
    ControlPlaneDurableSessionCapacityError,
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionCorruptionError,
    ControlPlaneDurableSessionNotFoundError,
    ControlPlaneDurableSessionPersistenceError,
    ControlPlaneDurableSessionRepositoryClosedError,
    ControlPlaneDurableSessionSchemaError,
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
_RECORD_KIND = "phoenix.control-plane.durable-session.record"
_TOKEN_INDEX_KIND = "phoenix.control-plane.durable-session.token-index"
_OPERATOR_INDEX_KIND = "phoenix.control-plane.durable-session.operator-index"
_LINEAGE_INDEX_KIND = "phoenix.control-plane.durable-session.lineage-index"
_RECORD_PREFIX = "session_"
_TOKEN_PREFIX = "token_"
_OPERATOR_PREFIX = "operator_"
_LINEAGE_PREFIX = "lineage_"
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "operator_id",
        "username",
        "token_digest",
        "csrf_digest",
        "operator_revision",
        "operator_token_version",
        "generation",
        "issued_at",
        "last_seen_at",
        "absolute_expires_at",
        "idle_expires_at",
        "rotate_after",
        "status",
        "terminated_at",
        "termination_reason",
        "predecessor_session_id",
        "successor_session_id",
        "revision",
    }
)
_RECORD_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record", "record_digest"})
_TOKEN_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "session_id",
        "operator_id",
        "token_digest",
        "status",
        "generation",
        "revision",
        "record_digest",
    }
)
_OPERATOR_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "session_id",
        "operator_id",
        "username",
        "issued_at",
        "status",
        "generation",
        "revision",
        "record_digest",
    }
)
_LINEAGE_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "session_id",
        "operator_id",
        "generation",
        "predecessor_session_id",
        "successor_session_id",
        "revision",
        "record_digest",
    }
)


def canonical_control_plane_durable_session_record_bytes(
    record: ControlPlaneDurableSessionRecord,
) -> bytes:
    """Return deterministic schema-v1 JSON bytes for one digest-only session record."""

    return _canonical_json_bytes(_record_document(record))


def control_plane_durable_session_record_digest(
    record: ControlPlaneDurableSessionRecord,
) -> str:
    """Return the SHA-256 checksum used to bind persisted records and indexes."""

    return hashlib.sha256(canonical_control_plane_durable_session_record_bytes(record)).hexdigest()


class StateControlPlaneDurableSessionRepository:
    """Persist session records and all lookup indexes through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 4096,
        max_sessions_per_operator: int = DEFAULT_DURABLE_SESSIONS_PER_OPERATOR,
        namespace: str = "control-plane-durable-sessions",
        context: StateOperationContext | None = None,
    ) -> None:
        if capacity <= 0 or capacity > MAX_DURABLE_SESSION_CAPACITY:
            raise ValueError(
                f"durable session capacity must be between 1 and {MAX_DURABLE_SESSION_CAPACITY}"
            )
        if (
            max_sessions_per_operator <= 0
            or max_sessions_per_operator > MAX_DURABLE_SESSIONS_PER_OPERATOR
        ):
            raise ValueError("durable session per-operator limit is outside supported bounds")
        probe = StateKey(namespace, f"{_RECORD_PREFIX}{'0' * 32}", dict)
        self._store = store
        self._capacity = capacity
        self._max_sessions_per_operator = max_sessions_per_operator
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.control-plane.durable-session-repository",
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneDurableSessionRecord) -> None:
        self._ensure_open()
        try:
            async with self._store.transaction(context=self._context) as transaction:
                collection = await self._load_transaction_collection(transaction)
                records = _validate_persisted_collection(*collection)
                if len(records) >= self._capacity:
                    raise ControlPlaneDurableSessionCapacityError(
                        "durable session repository capacity has been exhausted"
                    )
                _require_available_identity(records, record)
                if (
                    record.predecessor_session_id is not None
                    or record.successor_session_id is not None
                    or record.generation != 1
                ):
                    raise ControlPlaneDurableSessionConflictError(
                        "lineage-bound durable sessions must be created through rotate"
                    )
                if record.status is ControlPlaneDurableSessionStatus.ACTIVE:
                    _require_operator_capacity(
                        records,
                        record.operator_id,
                        self._max_sessions_per_operator,
                    )
                await self._put_new_record(transaction, record)
        except (
            ControlPlaneDurableSessionAlreadyExistsError,
            ControlPlaneDurableSessionCapacityError,
            ControlPlaneDurableSessionConflictError,
            ControlPlaneDurableSessionCorruptionError,
            ControlPlaneDurableSessionSchemaError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneDurableSessionAlreadyExistsError(
                "durable session identity already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception

    async def get(self, session_id: UUID) -> ControlPlaneDurableSessionRecord | None:
        self._ensure_open()
        try:
            stored = await self._store.get(self._record_key(session_id), context=self._context)
            if stored is None:
                return None
            record = _decode_record_state(stored)
            if record.id != session_id or stored.key.name != f"{_RECORD_PREFIX}{record.id.hex}":
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session identity does not match its state key"
                )
            await self._read_and_verify_indexes(record)
            await self._verify_direct_lineage(record)
            return record
        except (
            ControlPlaneDurableSessionCorruptionError,
            ControlPlaneDurableSessionSchemaError,
        ):
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception

    async def get_by_token_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneDurableSessionRecord | None:
        self._ensure_open()
        normalized = _normalize_digest(token_digest)
        try:
            stored_index = await self._store.get(
                self._token_key(normalized),
                context=self._context,
            )
            if stored_index is None:
                return None
            index = _decode_token_index_state(stored_index)
            if stored_index.key.name != f"{_TOKEN_PREFIX}{normalized}" or not hmac.compare_digest(
                index.token_digest,
                normalized,
            ):
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session token index does not match its state key"
                )
            stored_record = await self._store.get(
                self._record_key(index.session_id),
                context=self._context,
            )
            if stored_record is None:
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session token index references a missing record"
                )
            record = _decode_record_state(stored_record)
            _verify_token_index(index, record)
            await self._read_and_verify_indexes(record)
            await self._verify_direct_lineage(record)
            return record
        except (
            ControlPlaneDurableSessionCorruptionError,
            ControlPlaneDurableSessionSchemaError,
        ):
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception

    async def list_page(
        self,
        request: ControlPlaneDurableSessionPageRequest = DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    ) -> ControlPlaneDurableSessionPage:
        records = await self._load_records()
        filtered = tuple(
            record
            for record in records
            if (request.operator_id is None or record.operator_id == request.operator_id)
            and (request.status is None or record.status is request.status)
        )
        ordered = tuple(
            sorted(filtered, key=lambda item: (-item.issued_at.timestamp(), item.id.hex))
        )
        items = ordered[request.offset : request.offset + request.limit]
        return ControlPlaneDurableSessionPage(
            items=items,
            page=ControlPlaneDurableSessionPageInfo.from_slice(
                request,
                returned=len(items),
                total=len(ordered),
            ),
        )

    async def list_active_for_operator(
        self,
        operator_id: UUID,
        *,
        limit: int = MAX_DURABLE_SESSIONS_PER_OPERATOR,
    ) -> tuple[ControlPlaneDurableSessionRecord, ...]:
        if limit <= 0 or limit > MAX_DURABLE_SESSIONS_PER_OPERATOR:
            raise ValueError("durable active-session limit is outside supported bounds")
        records = await self._load_records()
        return tuple(
            sorted(
                (
                    record
                    for record in records
                    if record.operator_id == operator_id
                    and record.status is ControlPlaneDurableSessionStatus.ACTIVE
                ),
                key=lambda item: (-item.issued_at.timestamp(), item.id.hex),
            )[:limit]
        )

    async def touch(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        seen_at: datetime,
        idle_expires_at: datetime,
    ) -> ControlPlaneDurableSessionRecord:
        _validate_revision(expected_revision)
        _require_aware(seen_at, "seen_at")
        _require_aware(idle_expires_at, "idle_expires_at")
        try:
            return await self._replace_active(
                session_id,
                expected_revision=expected_revision,
                build=lambda current: _touch_record(
                    current,
                    seen_at=seen_at,
                    idle_expires_at=idle_expires_at,
                ),
            )
        except StateConflictError as exception:
            raise ControlPlaneDurableSessionConflictError(
                "durable session state changed concurrently"
            ) from exception

    async def terminate(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        status: ControlPlaneDurableSessionStatus,
        reason: ControlPlaneDurableSessionTerminationReason,
        terminated_at: datetime,
    ) -> ControlPlaneDurableSessionRecord:
        _validate_revision(expected_revision)
        _require_aware(terminated_at, "terminated_at")
        normalized_status = ControlPlaneDurableSessionStatus(status)
        normalized_reason = ControlPlaneDurableSessionTerminationReason(reason)
        _validate_termination(normalized_status, normalized_reason)
        try:
            return await self._replace_active(
                session_id,
                expected_revision=expected_revision,
                build=lambda current: _terminate_record(
                    current,
                    status=normalized_status,
                    reason=normalized_reason,
                    terminated_at=terminated_at,
                ),
            )
        except StateConflictError as exception:
            raise ControlPlaneDurableSessionConflictError(
                "durable session state changed concurrently"
            ) from exception

    async def rotate(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        successor: ControlPlaneDurableSessionRecord,
        rotated_at: datetime,
    ) -> ControlPlaneDurableSessionRotation:
        self._ensure_open()
        _validate_revision(expected_revision)
        _require_aware(rotated_at, "rotated_at")
        try:
            async with self._store.transaction(context=self._context) as transaction:
                collection = await self._load_transaction_collection(transaction)
                records = _validate_persisted_collection(*collection)
                current_stored = await transaction.get(self._record_key(session_id))
                if current_stored is None:
                    raise ControlPlaneDurableSessionNotFoundError(
                        "durable session record was not found"
                    )
                current = _decode_record_state(current_stored)
                _require_revision(current, expected_revision)
                _require_active(current)
                if len(records) >= self._capacity:
                    raise ControlPlaneDurableSessionCapacityError(
                        "durable session repository capacity has been exhausted"
                    )
                _require_available_identity(records, successor)
                _validate_successor(current, successor, rotated_at)
                previous = replace(
                    current,
                    status=ControlPlaneDurableSessionStatus.ROTATED,
                    terminated_at=rotated_at,
                    termination_reason=ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
                    successor_session_id=successor.id,
                    revision=current.revision + 1,
                )
                await self._replace_record(transaction, current_stored, current, previous)
                await self._put_new_record(transaction, successor)
                return ControlPlaneDurableSessionRotation(
                    previous=previous,
                    successor=successor,
                )
        except (
            ControlPlaneDurableSessionAlreadyExistsError,
            ControlPlaneDurableSessionCapacityError,
            ControlPlaneDurableSessionConflictError,
            ControlPlaneDurableSessionCorruptionError,
            ControlPlaneDurableSessionNotFoundError,
            ControlPlaneDurableSessionSchemaError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneDurableSessionConflictError(
                "durable session state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception

    async def delete_terminal(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
    ) -> None:
        self._ensure_open()
        _validate_revision(expected_revision)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                collection = await self._load_transaction_collection(transaction)
                _validate_persisted_collection(*collection)
                stored_record = await transaction.get(self._record_key(session_id))
                if stored_record is None:
                    raise ControlPlaneDurableSessionNotFoundError(
                        "durable session record was not found"
                    )
                record = _decode_record_state(stored_record)
                _require_revision(record, expected_revision)
                if not record.status.terminal:
                    raise ControlPlaneDurableSessionConflictError(
                        "active durable session cannot be deleted"
                    )
                if (
                    record.predecessor_session_id is not None
                    or record.successor_session_id is not None
                ):
                    raise ControlPlaneDurableSessionConflictError(
                        "lineage-bound durable session requires chain-aware retention"
                    )
                token_stored, operator_stored, lineage_stored = await self._get_indexes(
                    transaction,
                    record,
                )
                await transaction.delete(
                    self._record_key(record.id),
                    expected_version=stored_record.version,
                )
                await transaction.delete(
                    self._token_key(record.token_digest),
                    expected_version=token_stored.version,
                )
                await transaction.delete(
                    self._operator_key(record),
                    expected_version=operator_stored.version,
                )
                await transaction.delete(
                    self._lineage_key(record.id),
                    expected_version=lineage_stored.version,
                )
        except (
            ControlPlaneDurableSessionConflictError,
            ControlPlaneDurableSessionCorruptionError,
            ControlPlaneDurableSessionNotFoundError,
            ControlPlaneDurableSessionSchemaError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneDurableSessionConflictError(
                "durable session state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception

    async def snapshot(self) -> ControlPlaneDurableSessionSnapshot:
        records = await self._load_records(require_open=False)
        counts = Counter(record.status for record in records)
        return ControlPlaneDurableSessionSnapshot(
            closed=self._closed,
            entries=len(records),
            active=counts[ControlPlaneDurableSessionStatus.ACTIVE],
            revoked=counts[ControlPlaneDurableSessionStatus.REVOKED],
            expired=counts[ControlPlaneDurableSessionStatus.EXPIRED],
            rotated=counts[ControlPlaneDurableSessionStatus.ROTATED],
            capacity=self._capacity,
            max_sessions_per_operator=self._max_sessions_per_operator,
        )

    async def close(self) -> None:
        # The repository borrows the State Store; Runtime owns the store lifecycle.
        self._closed = True

    async def _replace_active(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        build: Callable[[ControlPlaneDurableSessionRecord], ControlPlaneDurableSessionRecord],
    ) -> ControlPlaneDurableSessionRecord:
        self._ensure_open()
        builder = build
        try:
            async with self._store.transaction(context=self._context) as transaction:
                collection = await self._load_transaction_collection(transaction)
                _validate_persisted_collection(*collection)
                stored = await transaction.get(self._record_key(session_id))
                if stored is None:
                    raise ControlPlaneDurableSessionNotFoundError(
                        "durable session record was not found"
                    )
                current = _decode_record_state(stored)
                _require_revision(current, expected_revision)
                _require_active(current)
                replacement = builder(current)
                await self._replace_record(transaction, stored, current, replacement)
                return replacement
        except (
            ControlPlaneDurableSessionConflictError,
            ControlPlaneDurableSessionCorruptionError,
            ControlPlaneDurableSessionNotFoundError,
            ControlPlaneDurableSessionSchemaError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneDurableSessionConflictError(
                "durable session state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception

    async def _load_records(
        self,
        *,
        require_open: bool = True,
    ) -> tuple[ControlPlaneDurableSessionRecord, ...]:
        if require_open:
            self._ensure_open()
        try:
            stored_records = await self._store.list(
                namespace=self._namespace,
                prefix=_RECORD_PREFIX,
                context=self._context,
            )
            stored_token_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_TOKEN_PREFIX,
                context=self._context,
            )
            stored_operator_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_OPERATOR_PREFIX,
                context=self._context,
            )
            stored_lineage_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_LINEAGE_PREFIX,
                context=self._context,
            )
        except PhoenixStateError as exception:
            raise ControlPlaneDurableSessionPersistenceError(
                "durable session persistence operation failed"
            ) from exception
        records = _validate_persisted_collection(
            stored_records,
            stored_token_indexes,
            stored_operator_indexes,
            stored_lineage_indexes,
        )
        if len(records) > self._capacity:
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable sessions exceed configured repository capacity"
            )
        active_by_operator = Counter(
            record.operator_id
            for record in records
            if record.status is ControlPlaneDurableSessionStatus.ACTIVE
        )
        if any(count > self._max_sessions_per_operator for count in active_by_operator.values()):
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted active sessions exceed the configured per-operator limit"
            )
        return records

    async def _load_transaction_collection(
        self, transaction: object
    ) -> tuple[
        tuple[StateRecord[object], ...],
        tuple[StateRecord[object], ...],
        tuple[StateRecord[object], ...],
        tuple[StateRecord[object], ...],
    ]:
        tx = cast("_TransactionLike", transaction)
        return (
            await tx.list(namespace=self._namespace, prefix=_RECORD_PREFIX),
            await tx.list(namespace=self._namespace, prefix=_TOKEN_PREFIX),
            await tx.list(namespace=self._namespace, prefix=_OPERATOR_PREFIX),
            await tx.list(namespace=self._namespace, prefix=_LINEAGE_PREFIX),
        )

    async def _put_new_record(
        self, transaction: object, record: ControlPlaneDurableSessionRecord
    ) -> None:
        tx = cast("_TransactionLike", transaction)
        await tx.put(
            self._record_key(record.id),
            _record_envelope(record),
            expected_version=ABSENT_VERSION,
        )
        await tx.put(
            self._token_key(record.token_digest),
            _token_index_document(record),
            expected_version=ABSENT_VERSION,
        )
        await tx.put(
            self._operator_key(record),
            _operator_index_document(record),
            expected_version=ABSENT_VERSION,
        )
        await tx.put(
            self._lineage_key(record.id),
            _lineage_index_document(record),
            expected_version=ABSENT_VERSION,
        )

    async def _replace_record(
        self,
        transaction: object,
        stored: StateRecord[object],
        current: ControlPlaneDurableSessionRecord,
        replacement: ControlPlaneDurableSessionRecord,
    ) -> None:
        tx = cast("_TransactionLike", transaction)
        token_stored, operator_stored, lineage_stored = await self._get_indexes(tx, current)
        if replacement.id != current.id or replacement.token_digest != current.token_digest:
            raise ControlPlaneDurableSessionConflictError(
                "durable session replacement cannot change identity or token digest"
            )
        if (
            replacement.operator_id != current.operator_id
            or replacement.username != current.username
        ):
            raise ControlPlaneDurableSessionConflictError(
                "durable session replacement cannot change operator identity"
            )
        if replacement.revision != current.revision + 1:
            raise ControlPlaneDurableSessionConflictError(
                "durable session replacement revision must increment exactly once"
            )
        await tx.put(
            self._record_key(replacement.id),
            _record_envelope(replacement),
            expected_version=stored.version,
        )
        await tx.put(
            self._token_key(replacement.token_digest),
            _token_index_document(replacement),
            expected_version=token_stored.version,
        )
        await tx.put(
            self._operator_key(replacement),
            _operator_index_document(replacement),
            expected_version=operator_stored.version,
        )
        await tx.put(
            self._lineage_key(replacement.id),
            _lineage_index_document(replacement),
            expected_version=lineage_stored.version,
        )

    async def _get_indexes(
        self,
        transaction: object,
        record: ControlPlaneDurableSessionRecord,
    ) -> tuple[StateRecord[object], StateRecord[object], StateRecord[object]]:
        tx = cast("_TransactionLike", transaction)
        token = await tx.get(self._token_key(record.token_digest))
        operator = await tx.get(self._operator_key(record))
        lineage = await tx.get(self._lineage_key(record.id))
        if token is None or operator is None or lineage is None:
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session record has incomplete indexes"
            )
        _verify_token_index(_decode_token_index_state(token), record)
        _verify_operator_index(_decode_operator_index_state(operator), record)
        _verify_lineage_index(_decode_lineage_index_state(lineage), record)
        return token, operator, lineage

    async def _read_and_verify_indexes(self, record: ControlPlaneDurableSessionRecord) -> None:
        token = await self._store.get(self._token_key(record.token_digest), context=self._context)
        operator = await self._store.get(self._operator_key(record), context=self._context)
        lineage = await self._store.get(self._lineage_key(record.id), context=self._context)
        if token is None or operator is None or lineage is None:
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session record has incomplete indexes"
            )
        token_index = _decode_token_index_state(token)
        operator_index = _decode_operator_index_state(operator)
        lineage_index = _decode_lineage_index_state(lineage)
        if token.key.name != f"{_TOKEN_PREFIX}{record.token_digest}":
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session token index does not match its state key"
            )
        if operator.key.name != _operator_key_name(record):
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session operator index does not match its state key"
            )
        if lineage.key.name != f"{_LINEAGE_PREFIX}{record.id.hex}":
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session lineage index does not match its state key"
            )
        _verify_token_index(token_index, record)
        _verify_operator_index(operator_index, record)
        _verify_lineage_index(lineage_index, record)

    async def _verify_direct_lineage(self, record: ControlPlaneDurableSessionRecord) -> None:
        if record.predecessor_session_id is not None:
            stored = await self._store.get(
                self._record_key(record.predecessor_session_id),
                context=self._context,
            )
            if stored is None:
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session predecessor is missing"
                )
            _verify_lineage_pair(_decode_record_state(stored), record)
        if record.successor_session_id is not None:
            stored = await self._store.get(
                self._record_key(record.successor_session_id),
                context=self._context,
            )
            if stored is None:
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session successor is missing"
                )
            _verify_lineage_pair(record, _decode_record_state(stored))

    def _record_key(self, session_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_RECORD_PREFIX}{session_id.hex}", dict)

    def _token_key(self, token_digest: str) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_TOKEN_PREFIX}{_normalize_digest(token_digest)}", dict)

    def _operator_key(
        self, record: ControlPlaneDurableSessionRecord
    ) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, _operator_key_name(record), dict)

    def _lineage_key(self, session_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_LINEAGE_PREFIX}{session_id.hex}", dict)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ControlPlaneDurableSessionRepositoryClosedError(
                "durable session repository is closed"
            )


class _TransactionLike(Protocol):
    async def get(self, key: StateKey[dict[str, object]]) -> StateRecord[object] | None: ...

    async def list(
        self,
        *,
        namespace: str,
        prefix: str,
    ) -> tuple[StateRecord[object], ...]: ...

    async def put(
        self,
        key: StateKey[dict[str, object]],
        value: dict[str, object],
        *,
        expected_version: int,
    ) -> StateRecord[object]: ...

    async def delete(
        self,
        key: StateKey[dict[str, object]],
        *,
        expected_version: int,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _TokenIndex:
    session_id: UUID
    operator_id: UUID
    token_digest: str
    status: ControlPlaneDurableSessionStatus
    generation: int
    revision: int
    record_digest: str


@dataclass(frozen=True, slots=True)
class _OperatorIndex:
    session_id: UUID
    operator_id: UUID
    username: str
    issued_at: datetime
    status: ControlPlaneDurableSessionStatus
    generation: int
    revision: int
    record_digest: str


@dataclass(frozen=True, slots=True)
class _LineageIndex:
    session_id: UUID
    operator_id: UUID
    generation: int
    predecessor_session_id: UUID | None
    successor_session_id: UUID | None
    revision: int
    record_digest: str


def _record_document(record: ControlPlaneDurableSessionRecord) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "id": str(record.id),
        "operator_id": str(record.operator_id),
        "username": record.username,
        "token_digest": record.token_digest,
        "csrf_digest": record.csrf_digest,
        "operator_revision": record.operator_revision,
        "operator_token_version": record.operator_token_version,
        "generation": record.generation,
        "issued_at": record.issued_at.isoformat(),
        "last_seen_at": record.last_seen_at.isoformat(),
        "absolute_expires_at": record.absolute_expires_at.isoformat(),
        "idle_expires_at": record.idle_expires_at.isoformat(),
        "rotate_after": record.rotate_after.isoformat(),
        "status": record.status.value,
        "terminated_at": None if record.terminated_at is None else record.terminated_at.isoformat(),
        "termination_reason": (
            None if record.termination_reason is None else record.termination_reason.value
        ),
        "predecessor_session_id": (
            None if record.predecessor_session_id is None else str(record.predecessor_session_id)
        ),
        "successor_session_id": (
            None if record.successor_session_id is None else str(record.successor_session_id)
        ),
        "revision": record.revision,
    }


def _record_envelope(record: ControlPlaneDurableSessionRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _RECORD_KIND,
        "record": _record_document(record),
        "record_digest": control_plane_durable_session_record_digest(record),
    }


def _token_index_document(record: ControlPlaneDurableSessionRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _TOKEN_INDEX_KIND,
        "session_id": str(record.id),
        "operator_id": str(record.operator_id),
        "token_digest": record.token_digest,
        "status": record.status.value,
        "generation": record.generation,
        "revision": record.revision,
        "record_digest": control_plane_durable_session_record_digest(record),
    }


def _operator_index_document(record: ControlPlaneDurableSessionRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _OPERATOR_INDEX_KIND,
        "session_id": str(record.id),
        "operator_id": str(record.operator_id),
        "username": record.username,
        "issued_at": record.issued_at.isoformat(),
        "status": record.status.value,
        "generation": record.generation,
        "revision": record.revision,
        "record_digest": control_plane_durable_session_record_digest(record),
    }


def _lineage_index_document(record: ControlPlaneDurableSessionRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _LINEAGE_INDEX_KIND,
        "session_id": str(record.id),
        "operator_id": str(record.operator_id),
        "generation": record.generation,
        "predecessor_session_id": (
            None if record.predecessor_session_id is None else str(record.predecessor_session_id)
        ),
        "successor_session_id": (
            None if record.successor_session_id is None else str(record.successor_session_id)
        ),
        "revision": record.revision,
        "record_digest": control_plane_durable_session_record_digest(record),
    }


def _decode_record_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> ControlPlaneDurableSessionRecord:
    value = _mapping(stored.value, label="record envelope")
    _require_exact_fields(value, _RECORD_ENVELOPE_FIELDS, label="record envelope")
    _require_schema(value)
    if _string(value, "kind") != _RECORD_KIND:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session record kind is invalid"
        )
    document = _mapping(value.get("record"), label="record")
    _require_exact_fields(document, _RECORD_FIELDS, label="record")
    expected_digest = _normalize_digest(_string(value, "record_digest"))
    actual_digest = hashlib.sha256(_canonical_json_bytes(document)).hexdigest()
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session record digest does not match"
        )
    try:
        schema_version = _positive_integer(document, "schema_version")
        if schema_version != _SCHEMA_VERSION:
            raise ControlPlaneDurableSessionSchemaError(
                "persisted durable session record schema is unsupported"
            )
        record = ControlPlaneDurableSessionRecord(
            id=_uuid(document, "id"),
            operator_id=_uuid(document, "operator_id"),
            username=_string(document, "username"),
            token_digest=_string(document, "token_digest"),
            csrf_digest=_string(document, "csrf_digest"),
            operator_revision=_positive_integer(document, "operator_revision"),
            operator_token_version=_positive_integer(document, "operator_token_version"),
            generation=_positive_integer(document, "generation"),
            issued_at=_datetime(document, "issued_at"),
            last_seen_at=_datetime(document, "last_seen_at"),
            absolute_expires_at=_datetime(document, "absolute_expires_at"),
            idle_expires_at=_datetime(document, "idle_expires_at"),
            rotate_after=_datetime(document, "rotate_after"),
            status=ControlPlaneDurableSessionStatus(_string(document, "status")),
            terminated_at=_optional_datetime(document, "terminated_at"),
            termination_reason=_optional_termination_reason(document, "termination_reason"),
            predecessor_session_id=_optional_uuid(document, "predecessor_session_id"),
            successor_session_id=_optional_uuid(document, "successor_session_id"),
            revision=_positive_integer(document, "revision"),
            schema_version=schema_version,
        )
        if _record_document(record) != dict(document):
            raise ValueError("persisted durable session record is not canonical")
        return record
    except ControlPlaneDurableSessionSchemaError:
        raise
    except (TypeError, ValueError) as exception:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session record is invalid"
        ) from exception


def _decode_token_index_state(stored: StateRecord[object]) -> _TokenIndex:
    value = _mapping(stored.value, label="token index")
    _require_exact_fields(value, _TOKEN_INDEX_FIELDS, label="token index")
    _require_schema(value)
    if _string(value, "kind") != _TOKEN_INDEX_KIND:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session token index kind is invalid"
        )
    try:
        return _TokenIndex(
            session_id=_uuid(value, "session_id"),
            operator_id=_uuid(value, "operator_id"),
            token_digest=_normalize_digest(_string(value, "token_digest")),
            status=ControlPlaneDurableSessionStatus(_string(value, "status")),
            generation=_positive_integer(value, "generation"),
            revision=_positive_integer(value, "revision"),
            record_digest=_normalize_digest(_string(value, "record_digest")),
        )
    except (TypeError, ValueError) as exception:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session token index is invalid"
        ) from exception


def _decode_operator_index_state(stored: StateRecord[object]) -> _OperatorIndex:
    value = _mapping(stored.value, label="operator index")
    _require_exact_fields(value, _OPERATOR_INDEX_FIELDS, label="operator index")
    _require_schema(value)
    if _string(value, "kind") != _OPERATOR_INDEX_KIND:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session operator index kind is invalid"
        )
    try:
        return _OperatorIndex(
            session_id=_uuid(value, "session_id"),
            operator_id=_uuid(value, "operator_id"),
            username=_string(value, "username"),
            issued_at=_datetime(value, "issued_at"),
            status=ControlPlaneDurableSessionStatus(_string(value, "status")),
            generation=_positive_integer(value, "generation"),
            revision=_positive_integer(value, "revision"),
            record_digest=_normalize_digest(_string(value, "record_digest")),
        )
    except (TypeError, ValueError) as exception:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session operator index is invalid"
        ) from exception


def _decode_lineage_index_state(stored: StateRecord[object]) -> _LineageIndex:
    value = _mapping(stored.value, label="lineage index")
    _require_exact_fields(value, _LINEAGE_INDEX_FIELDS, label="lineage index")
    _require_schema(value)
    if _string(value, "kind") != _LINEAGE_INDEX_KIND:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session lineage index kind is invalid"
        )
    try:
        return _LineageIndex(
            session_id=_uuid(value, "session_id"),
            operator_id=_uuid(value, "operator_id"),
            generation=_positive_integer(value, "generation"),
            predecessor_session_id=_optional_uuid(value, "predecessor_session_id"),
            successor_session_id=_optional_uuid(value, "successor_session_id"),
            revision=_positive_integer(value, "revision"),
            record_digest=_normalize_digest(_string(value, "record_digest")),
        )
    except (TypeError, ValueError) as exception:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session lineage index is invalid"
        ) from exception


def _validate_persisted_collection(
    stored_records: tuple[StateRecord[object], ...],
    stored_token_indexes: tuple[StateRecord[object], ...],
    stored_operator_indexes: tuple[StateRecord[object], ...],
    stored_lineage_indexes: tuple[StateRecord[object], ...],
) -> tuple[ControlPlaneDurableSessionRecord, ...]:
    records = tuple(_decode_record_state(item) for item in stored_records)
    token_indexes = tuple(_decode_token_index_state(item) for item in stored_token_indexes)
    operator_indexes = tuple(_decode_operator_index_state(item) for item in stored_operator_indexes)
    lineage_indexes = tuple(_decode_lineage_index_state(item) for item in stored_lineage_indexes)
    if not (len(records) == len(token_indexes) == len(operator_indexes) == len(lineage_indexes)):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session records and indexes are incomplete"
        )
    ids = tuple(record.id for record in records)
    token_digests = tuple(record.token_digest for record in records)
    csrf_digests = tuple(record.csrf_digest for record in records)
    if (
        len(ids) != len(set(ids))
        or len(token_digests) != len(set(token_digests))
        or len(csrf_digests) != len(set(csrf_digests))
        or set(token_digests).intersection(csrf_digests)
    ):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable sessions contain duplicate protected identities"
        )
    if (
        len({index.session_id for index in token_indexes}) != len(token_indexes)
        or len({index.token_digest for index in token_indexes}) != len(token_indexes)
        or len({index.session_id for index in operator_indexes}) != len(operator_indexes)
        or len({index.session_id for index in lineage_indexes}) != len(lineage_indexes)
    ):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable sessions contain duplicate indexes"
        )
    records_by_id = {record.id: record for record in records}
    token_by_digest = {index.token_digest: index for index in token_indexes}
    operator_by_session = {index.session_id: index for index in operator_indexes}
    lineage_by_session = {index.session_id: index for index in lineage_indexes}
    for stored, record in zip(stored_records, records, strict=True):
        if stored.key.name != f"{_RECORD_PREFIX}{record.id.hex}":
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session identity does not match its state key"
            )
        token_index = token_by_digest.get(record.token_digest)
        operator_index = operator_by_session.get(record.id)
        lineage_index = lineage_by_session.get(record.id)
        if token_index is None or operator_index is None or lineage_index is None:
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session record has incomplete indexes"
            )
        _verify_token_index(token_index, record)
        _verify_operator_index(operator_index, record)
        _verify_lineage_index(lineage_index, record)
    for stored_token, token_index_item in zip(stored_token_indexes, token_indexes, strict=True):
        if stored_token.key.name != f"{_TOKEN_PREFIX}{token_index_item.token_digest}":
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session token index does not match its state key"
            )
    for stored_operator, operator_index_item in zip(
        stored_operator_indexes, operator_indexes, strict=True
    ):
        indexed_record = records_by_id.get(operator_index_item.session_id)
        if indexed_record is None or stored_operator.key.name != _operator_key_name(indexed_record):
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session operator index does not match its state key"
            )
    for stored_lineage, lineage_index_item in zip(
        stored_lineage_indexes, lineage_indexes, strict=True
    ):
        if stored_lineage.key.name != f"{_LINEAGE_PREFIX}{lineage_index_item.session_id.hex}":
            raise ControlPlaneDurableSessionCorruptionError(
                "persisted durable session lineage index does not match its state key"
            )
    for record in records:
        if record.predecessor_session_id is not None:
            predecessor = records_by_id.get(record.predecessor_session_id)
            if predecessor is None:
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session predecessor is missing"
                )
            _verify_lineage_pair(predecessor, record)
        if record.successor_session_id is not None:
            successor = records_by_id.get(record.successor_session_id)
            if successor is None:
                raise ControlPlaneDurableSessionCorruptionError(
                    "persisted durable session successor is missing"
                )
            _verify_lineage_pair(record, successor)
    return records


def _verify_token_index(index: _TokenIndex, record: ControlPlaneDurableSessionRecord) -> None:
    digest = control_plane_durable_session_record_digest(record)
    if (
        index.session_id != record.id
        or index.operator_id != record.operator_id
        or not hmac.compare_digest(index.token_digest, record.token_digest)
        or index.status is not record.status
        or index.generation != record.generation
        or index.revision != record.revision
        or not hmac.compare_digest(index.record_digest, digest)
    ):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session token index and record do not match"
        )


def _verify_operator_index(index: _OperatorIndex, record: ControlPlaneDurableSessionRecord) -> None:
    digest = control_plane_durable_session_record_digest(record)
    if (
        index.session_id != record.id
        or index.operator_id != record.operator_id
        or index.username != record.username
        or index.issued_at != record.issued_at
        or index.status is not record.status
        or index.generation != record.generation
        or index.revision != record.revision
        or not hmac.compare_digest(index.record_digest, digest)
    ):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session operator index and record do not match"
        )


def _verify_lineage_index(index: _LineageIndex, record: ControlPlaneDurableSessionRecord) -> None:
    digest = control_plane_durable_session_record_digest(record)
    if (
        index.session_id != record.id
        or index.operator_id != record.operator_id
        or index.generation != record.generation
        or index.predecessor_session_id != record.predecessor_session_id
        or index.successor_session_id != record.successor_session_id
        or index.revision != record.revision
        or not hmac.compare_digest(index.record_digest, digest)
    ):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session lineage index and record do not match"
        )


def _verify_lineage_pair(
    predecessor: ControlPlaneDurableSessionRecord,
    successor: ControlPlaneDurableSessionRecord,
) -> None:
    if (
        predecessor.status is not ControlPlaneDurableSessionStatus.ROTATED
        or predecessor.successor_session_id != successor.id
        or successor.predecessor_session_id != predecessor.id
        or successor.generation != predecessor.generation + 1
        or predecessor.operator_id != successor.operator_id
        or predecessor.username != successor.username
        or predecessor.operator_revision != successor.operator_revision
        or predecessor.operator_token_version != successor.operator_token_version
        or predecessor.absolute_expires_at != successor.absolute_expires_at
        or predecessor.terminated_at != successor.issued_at
    ):
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session rotation lineage is inconsistent"
        )


def _require_available_identity(
    records: tuple[ControlPlaneDurableSessionRecord, ...],
    record: ControlPlaneDurableSessionRecord,
) -> None:
    if any(item.id == record.id for item in records):
        raise ControlPlaneDurableSessionAlreadyExistsError(
            "durable session identity already exists"
        )
    if any(hmac.compare_digest(item.token_digest, record.token_digest) for item in records):
        raise ControlPlaneDurableSessionAlreadyExistsError(
            "durable session token digest already exists"
        )
    protected = {item.token_digest for item in records} | {item.csrf_digest for item in records}
    if record.csrf_digest in protected or record.token_digest in {
        item.csrf_digest for item in records
    }:
        raise ControlPlaneDurableSessionAlreadyExistsError(
            "durable session protected digest already exists"
        )


def _require_operator_capacity(
    records: tuple[ControlPlaneDurableSessionRecord, ...],
    operator_id: UUID,
    maximum: int,
) -> None:
    active = sum(
        record.operator_id == operator_id
        and record.status is ControlPlaneDurableSessionStatus.ACTIVE
        for record in records
    )
    if active >= maximum:
        raise ControlPlaneDurableSessionCapacityError(
            "durable session per-operator limit has been reached"
        )


def _touch_record(
    current: ControlPlaneDurableSessionRecord,
    *,
    seen_at: datetime,
    idle_expires_at: datetime,
) -> ControlPlaneDurableSessionRecord:
    if seen_at < current.last_seen_at:
        raise ControlPlaneDurableSessionConflictError(
            "durable session activity time cannot move backwards"
        )
    if seen_at >= current.absolute_expires_at:
        raise ControlPlaneDurableSessionConflictError(
            "durable session activity cannot reach or exceed absolute expiry"
        )
    if idle_expires_at <= seen_at or idle_expires_at > current.absolute_expires_at:
        raise ControlPlaneDurableSessionConflictError("durable session idle expiry is inconsistent")
    return replace(
        current,
        last_seen_at=seen_at,
        idle_expires_at=idle_expires_at,
        revision=current.revision + 1,
    )


def _terminate_record(
    current: ControlPlaneDurableSessionRecord,
    *,
    status: ControlPlaneDurableSessionStatus,
    reason: ControlPlaneDurableSessionTerminationReason,
    terminated_at: datetime,
) -> ControlPlaneDurableSessionRecord:
    if terminated_at < current.last_seen_at:
        raise ControlPlaneDurableSessionConflictError(
            "durable session termination cannot precede last activity"
        )
    return replace(
        current,
        status=status,
        terminated_at=terminated_at,
        termination_reason=reason,
        revision=current.revision + 1,
    )


def _validate_termination(
    status: ControlPlaneDurableSessionStatus,
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    if status not in {
        ControlPlaneDurableSessionStatus.REVOKED,
        ControlPlaneDurableSessionStatus.EXPIRED,
    }:
        raise ValueError("durable session terminate requires revoked or expired status")
    if status is ControlPlaneDurableSessionStatus.EXPIRED:
        if not reason.expiration:
            raise ValueError("expired durable session requires an expiration reason")
    elif reason.expiration or reason is ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED:
        raise ValueError("revoked durable session requires a revocation reason")


def _validate_successor(
    current: ControlPlaneDurableSessionRecord,
    successor: ControlPlaneDurableSessionRecord,
    rotated_at: datetime,
) -> None:
    if successor.status is not ControlPlaneDurableSessionStatus.ACTIVE:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation successor must be active"
        )
    if successor.operator_id != current.operator_id or successor.username != current.username:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation cannot change operator identity"
        )
    if successor.operator_revision != current.operator_revision or (
        successor.operator_token_version != current.operator_token_version
    ):
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation cannot change operator credential facts"
        )
    if successor.generation != current.generation + 1:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation generation is inconsistent"
        )
    if successor.predecessor_session_id != current.id:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation predecessor is inconsistent"
        )
    if successor.issued_at != rotated_at or successor.last_seen_at != rotated_at:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation time is inconsistent"
        )
    if successor.absolute_expires_at != current.absolute_expires_at:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation cannot extend absolute expiry"
        )
    if rotated_at < current.last_seen_at or rotated_at >= current.absolute_expires_at:
        raise ControlPlaneDurableSessionConflictError(
            "durable session rotation time is outside the active lifetime"
        )


def _require_revision(record: ControlPlaneDurableSessionRecord, expected_revision: int) -> None:
    if record.revision != expected_revision:
        raise ControlPlaneDurableSessionConflictError("durable session revision conflict")


def _require_active(record: ControlPlaneDurableSessionRecord) -> None:
    if record.status is not ControlPlaneDurableSessionStatus.ACTIVE:
        raise ControlPlaneDurableSessionConflictError("durable session record is terminal")


def _validate_revision(value: int) -> None:
    if value <= 0:
        raise ValueError("expected_revision must be positive")


def _operator_key_name(record: ControlPlaneDurableSessionRecord) -> str:
    return f"{_OPERATOR_PREFIX}{record.operator_id.hex}_{record.id.hex}"


def _require_schema(value: Mapping[str, object]) -> None:
    try:
        schema_version = _positive_integer(value, "schema_version")
    except ValueError as exception:
        raise ControlPlaneDurableSessionCorruptionError(
            "persisted durable session schema field is invalid"
        ) from exception
    if schema_version != _SCHEMA_VERSION:
        raise ControlPlaneDurableSessionSchemaError(
            "persisted durable session schema is unsupported"
        )


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise ControlPlaneDurableSessionCorruptionError(
            f"persisted durable session {label} fields are invalid"
        )


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ControlPlaneDurableSessionCorruptionError(
            f"persisted durable session {label} is invalid"
        )
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted durable session field: {key}")
    return result


def _positive_integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool) or result <= 0:
        raise ValueError(f"invalid persisted durable session field: {key}")
    return result


def _uuid(value: Mapping[str, object], key: str) -> UUID:
    raw = _string(value, key)
    result = UUID(raw)
    if raw != str(result):
        raise ValueError(f"invalid persisted durable session field: {key}")
    return result


def _optional_uuid(value: Mapping[str, object], key: str) -> UUID | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"invalid persisted durable session field: {key}")
    result = UUID(raw)
    if raw != str(result):
        raise ValueError(f"invalid persisted durable session field: {key}")
    return result


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    raw = _string(value, key)
    result = datetime.fromisoformat(raw)
    _require_aware(result, key)
    if raw != result.isoformat():
        raise ValueError(f"invalid persisted durable session field: {key}")
    return result


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"invalid persisted durable session field: {key}")
    result = datetime.fromisoformat(raw)
    _require_aware(result, key)
    if raw != result.isoformat():
        raise ValueError(f"invalid persisted durable session field: {key}")
    return result


def _optional_termination_reason(
    value: Mapping[str, object],
    key: str,
) -> ControlPlaneDurableSessionTerminationReason | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"invalid persisted durable session field: {key}")
    return ControlPlaneDurableSessionTerminationReason(raw)


def _normalize_digest(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("durable session token digest must be SHA-256 hexadecimal")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
