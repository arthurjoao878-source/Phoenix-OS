"""Authoritative State Store-backed persistence for secure Phoenix agent memory."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.agent.memory_contracts import (
    MemoryDeleteRequest,
    MemoryId,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordStatus,
    MemoryRecordVersion,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemoryWriteRequest,
)
from phoenix_os.state.contracts import ABSENT_VERSION, StateKey, StateStore, StateTransaction
from phoenix_os.state.errors import (
    StateConflictError,
    StateSerializationError,
    StateStoreClosedError,
    StateTransactionError,
    StateTypeError,
)
from phoenix_os.state.memory import MemoryStateStore

_MEMORY_STATE_NAMESPACE = "agent-memory"
_MEMORY_DOCUMENT_SCHEMA_VERSION = 1
_MAX_MEMORY_SCOPE_LIST = 100_000
_MEMORY_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "namespace",
        "scope_kind",
        "scope_id",
        "memory_id",
        "version",
        "content",
        "content_digest",
        "metadata",
        "provenance",
        "created_at",
        "updated_at",
        "expires_at",
        "deleted_at",
    }
)
_PROVENANCE_FIELDS = frozenset(
    {
        "origin",
        "content_digest",
        "created_at",
        "source_version",
        "source_run_id",
        "source_agent_id",
        "source_principal_id",
        "attributes",
    }
)

type Clock = Callable[[], datetime]
type MemoryStateDocument = dict[str, object]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _now(clock: Clock) -> datetime:
    value = clock()
    _require_aware(value, label="clock result")
    return value


def _scope_digest(scope: MemoryScope) -> str:
    if not isinstance(scope, MemoryScope):
        raise TypeError("scope must be MemoryScope")
    identity = f"{scope.namespace.value}\0{scope.kind.value}\0{scope.scope_id.value}".encode()
    return hashlib.sha256(identity).hexdigest()


def _scope_prefix(scope: MemoryScope) -> str:
    return f"record.{_scope_digest(scope)}."


def _record_key(scope: MemoryScope, memory_id: MemoryId) -> StateKey[MemoryStateDocument]:
    if not isinstance(memory_id, MemoryId):
        raise TypeError("memory_id must be MemoryId")
    return StateKey[MemoryStateDocument](
        _MEMORY_STATE_NAMESPACE,
        f"{_scope_prefix(scope)}{memory_id.value.hex}",
    )


def _safe_state_failure(exception: Exception) -> Exception:
    if isinstance(exception, StateConflictError):
        return AgentStateConflictError()
    if isinstance(exception, StateStoreClosedError):
        return AgentServiceUnavailableError()
    if isinstance(
        exception,
        (StateSerializationError, StateTypeError, StateTransactionError),
    ):
        return AgentCodecError("agent memory persistence is invalid")
    return exception


def _parse_datetime(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise AgentCodecError("agent memory document is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exception:
        raise AgentCodecError("agent memory document is invalid") from exception
    try:
        _require_aware(parsed, label=label)
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("agent memory document is invalid") from exception
    return parsed


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AgentCodecError("agent memory document is invalid")
    return value


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise AgentCodecError("agent memory document is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise AgentCodecError("agent memory document is invalid")
        result[key] = item
    return result


def _encode_provenance(provenance: MemoryProvenance) -> MemoryStateDocument:
    return {
        "origin": provenance.origin.value,
        "content_digest": provenance.content_digest,
        "created_at": provenance.created_at.isoformat(),
        "source_version": provenance.source_version,
        "source_run_id": (
            None if provenance.source_run_id is None else str(provenance.source_run_id)
        ),
        "source_agent_id": (
            None if provenance.source_agent_id is None else str(provenance.source_agent_id)
        ),
        "source_principal_id": (
            None if provenance.source_principal_id is None else str(provenance.source_principal_id)
        ),
        "attributes": dict(provenance.attributes),
    }


def _decode_provenance(value: object) -> MemoryProvenance:
    if not isinstance(value, Mapping) or set(value) != _PROVENANCE_FIELDS:
        raise AgentCodecError("agent memory document is invalid")
    origin_raw = value["origin"]
    content_digest = value["content_digest"]
    if not isinstance(origin_raw, str) or not isinstance(content_digest, str):
        raise AgentCodecError("agent memory document is invalid")

    source_run_raw = _optional_string(value["source_run_id"])
    source_agent_raw = _optional_string(value["source_agent_id"])
    source_principal_raw = _optional_string(value["source_principal_id"])
    try:
        source_run_id = None if source_run_raw is None else AgentRunId(UUID(source_run_raw))
        source_agent_id = None if source_agent_raw is None else AgentId(source_agent_raw)
        source_principal_id = (
            None if source_principal_raw is None else MemoryScopeId(source_principal_raw)
        )
        return MemoryProvenance(
            origin=MemoryOriginKind(origin_raw),
            content_digest=content_digest,
            created_at=_parse_datetime(value["created_at"], label="provenance created_at"),
            source_version=_optional_string(value["source_version"]),
            source_run_id=source_run_id,
            source_agent_id=source_agent_id,
            source_principal_id=source_principal_id,
            attributes=_string_mapping(value["attributes"]),
        )
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("agent memory document is invalid") from exception


def _encode_record(record: MemoryRecord) -> MemoryStateDocument:
    return {
        "schema_version": _MEMORY_DOCUMENT_SCHEMA_VERSION,
        "status": record.status.value,
        "namespace": record.scope.namespace.value,
        "scope_kind": record.scope.kind.value,
        "scope_id": record.scope.scope_id.value,
        "memory_id": str(record.memory_id),
        "version": record.version.value,
        "content": record.content,
        "content_digest": record.content_digest,
        "metadata": dict(record.metadata),
        "provenance": (
            None if record.provenance is None else _encode_provenance(record.provenance)
        ),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "deleted_at": (None if record.deleted_at is None else record.deleted_at.isoformat()),
    }


def _decode_record(
    value: object,
    *,
    expected_scope: MemoryScope | None = None,
    expected_memory_id: MemoryId | None = None,
) -> MemoryRecord:
    if not isinstance(value, Mapping) or set(value) != _MEMORY_DOCUMENT_FIELDS:
        raise AgentCodecError("agent memory document is invalid")
    if value["schema_version"] != _MEMORY_DOCUMENT_SCHEMA_VERSION:
        raise AgentCodecError("agent memory document is invalid")

    namespace_raw = value["namespace"]
    scope_kind_raw = value["scope_kind"]
    scope_id_raw = value["scope_id"]
    memory_id_raw = value["memory_id"]
    version_raw = value["version"]
    status_raw = value["status"]
    digest_raw = value["content_digest"]

    if not all(
        isinstance(item, str)
        for item in (
            namespace_raw,
            scope_kind_raw,
            scope_id_raw,
            memory_id_raw,
            status_raw,
            digest_raw,
        )
    ):
        raise AgentCodecError("agent memory document is invalid")
    if isinstance(version_raw, bool) or not isinstance(version_raw, int):
        raise AgentCodecError("agent memory document is invalid")

    try:
        scope = MemoryScope(
            namespace=MemoryNamespace(namespace_raw),
            kind=MemoryScopeKind(scope_kind_raw),
            scope_id=MemoryScopeId(scope_id_raw),
        )
        memory_id = MemoryId(UUID(memory_id_raw))
        status = MemoryRecordStatus(status_raw)
        provenance = (
            None if value["provenance"] is None else _decode_provenance(value["provenance"])
        )
        content_raw = value["content"]
        if content_raw is not None and not isinstance(content_raw, str):
            raise AgentCodecError("agent memory document is invalid")
        record = MemoryRecord(
            scope=scope,
            memory_id=memory_id,
            version=MemoryRecordVersion(version_raw),
            status=status,
            content_digest=digest_raw,
            created_at=_parse_datetime(value["created_at"], label="created_at"),
            updated_at=_parse_datetime(value["updated_at"], label="updated_at"),
            expires_at=_parse_datetime(value["expires_at"], label="expires_at"),
            content=content_raw,
            provenance=provenance,
            metadata=_string_mapping(value["metadata"]),
            deleted_at=(
                None
                if value["deleted_at"] is None
                else _parse_datetime(value["deleted_at"], label="deleted_at")
            ),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("agent memory document is invalid") from exception

    if expected_scope is not None and record.scope != expected_scope:
        raise AgentCodecError("agent memory document is invalid")
    if expected_memory_id is not None and record.memory_id != expected_memory_id:
        raise AgentCodecError("agent memory document is invalid")
    return record


def _require_state_identity[T](
    record: MemoryRecord,
    *,
    state_key: StateKey[T],
) -> None:
    expected = _record_key(record.scope, record.memory_id)
    if state_key.canonical != expected.canonical:
        raise AgentCodecError("agent memory document is invalid")


def _active_record_from_request(
    request: MemoryWriteRequest,
    *,
    now: datetime,
    current: MemoryRecord | None,
    limits: MemoryLimits,
) -> MemoryRecord:
    content_bytes = len(request.content.encode("utf-8"))
    if content_bytes > limits.max_record_bytes:
        raise AgentLimitExceededError()
    if request.created_at > now or request.provenance.created_at > request.created_at:
        raise AgentStateConflictError()
    if current is None:
        version = MemoryRecordVersion()
        created_at = now
    else:
        if (
            current.status is not MemoryRecordStatus.ACTIVE
            or current.expires_at <= now
            or now < current.updated_at
        ):
            raise AgentStateConflictError()
        if request.expected_version is None or current.version != request.expected_version:
            raise AgentStateConflictError()
        version = current.version.next()
        created_at = current.created_at

    return MemoryRecord(
        scope=request.scope,
        memory_id=request.memory_id,
        version=version,
        status=MemoryRecordStatus.ACTIVE,
        content_digest=request.provenance.content_digest,
        created_at=created_at,
        updated_at=now,
        expires_at=now + limits.retention.record_ttl,
        content=request.content,
        provenance=request.provenance,
        metadata=request.metadata,
    )


def _tombstone(record: MemoryRecord, *, now: datetime, limits: MemoryLimits) -> MemoryRecord:
    if record.status is not MemoryRecordStatus.ACTIVE or now < record.updated_at:
        raise AgentStateConflictError()
    return MemoryRecord(
        scope=record.scope,
        memory_id=record.memory_id,
        version=record.version.next(),
        status=MemoryRecordStatus.TOMBSTONED,
        content_digest=record.content_digest,
        created_at=record.created_at,
        updated_at=now,
        expires_at=now + limits.retention.tombstone_retention,
        content=None,
        provenance=None,
        metadata={},
        deleted_at=now,
    )


@runtime_checkable
class MemoryStore(Protocol):
    """Authoritative memory persistence boundary below policy authorization."""

    @property
    def closed(self) -> bool: ...

    @property
    def limits(self) -> MemoryLimits: ...

    async def write(self, request: MemoryWriteRequest) -> MemoryRecord: ...

    async def read(self, request: MemoryReadRequest) -> MemoryRecord | None: ...

    async def delete(self, request: MemoryDeleteRequest) -> None: ...

    async def list_scope(
        self,
        scope: MemoryScope,
        *,
        limit: int | None = None,
    ) -> tuple[MemoryRecord, ...]: ...

    async def purge_expired(self, scope: MemoryScope) -> int: ...

    async def list_scopes(self, *, limit: int) -> tuple[MemoryScope, ...]: ...

    async def close(self) -> None: ...


class StateStoreMemoryStore:
    """Authoritative memory records composed over one Phoenix State Store."""

    def __init__(
        self,
        state_store: StateStore,
        *,
        limits: MemoryLimits | None = None,
        clock: Clock = _utc_now,
        owns_state_store: bool = False,
    ) -> None:
        if limits is not None and not isinstance(limits, MemoryLimits):
            raise TypeError("limits must be MemoryLimits or None")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(owns_state_store, bool):
            raise TypeError("owns_state_store must be bool")
        self._state_store = state_store
        self._limits = MemoryLimits() if limits is None else limits
        self._clock = clock
        self._owns_state_store = owns_state_store
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def limits(self) -> MemoryLimits:
        return self._limits

    async def write(self, request: MemoryWriteRequest) -> MemoryRecord:
        if not isinstance(request, MemoryWriteRequest):
            raise TypeError("request must be MemoryWriteRequest")
        self._ensure_open()
        now = _now(self._clock)
        if request.created_at > now:
            raise AgentStateConflictError()
        key = _record_key(request.scope, request.memory_id)
        try:
            async with self._state_store.transaction() as transaction:
                stored = await transaction.get(key)
                if stored is None:
                    current = None
                    if request.expected_version is not None:
                        raise AgentStateConflictError()
                    state_expected = ABSENT_VERSION
                else:
                    current = _decode_record(
                        stored.value,
                        expected_scope=request.scope,
                        expected_memory_id=request.memory_id,
                    )
                    _require_state_identity(current, state_key=stored.key)
                    if request.expected_version is None:
                        raise AgentStateConflictError()
                    state_expected = stored.version

                candidate = _active_record_from_request(
                    request,
                    now=now,
                    current=current,
                    limits=self._limits,
                )
                await self._require_capacity(
                    transaction,
                    request.scope,
                    candidate,
                    now=now,
                    replacing=request.memory_id if current is not None else None,
                )
                await transaction.put(
                    key,
                    _encode_record(candidate),
                    expected_version=state_expected,
                    ttl=self._active_physical_ttl(),
                )
                return candidate
        except (
            StateConflictError,
            StateSerializationError,
            StateStoreClosedError,
            StateTransactionError,
            StateTypeError,
        ) as exception:
            raise _safe_state_failure(exception) from None

    async def read(self, request: MemoryReadRequest) -> MemoryRecord | None:
        if not isinstance(request, MemoryReadRequest):
            raise TypeError("request must be MemoryReadRequest")
        self._ensure_open()
        key = _record_key(request.scope, request.memory_id)
        try:
            stored = await self._state_store.get(key)
        except (
            StateSerializationError,
            StateStoreClosedError,
            StateTypeError,
        ) as exception:
            raise _safe_state_failure(exception) from None
        if stored is None:
            if request.expected_version is not None:
                raise AgentStateConflictError()
            return None
        record = _decode_record(
            stored.value,
            expected_scope=request.scope,
            expected_memory_id=request.memory_id,
        )
        _require_state_identity(record, state_key=stored.key)
        now = _now(self._clock)
        if record.status is not MemoryRecordStatus.ACTIVE or record.expires_at <= now:
            if request.expected_version is not None:
                raise AgentStateConflictError()
            return None
        if request.expected_version is not None and record.version != request.expected_version:
            raise AgentStateConflictError()
        return record

    async def delete(self, request: MemoryDeleteRequest) -> None:
        if not isinstance(request, MemoryDeleteRequest):
            raise TypeError("request must be MemoryDeleteRequest")
        self._ensure_open()
        now = _now(self._clock)
        if request.created_at > now:
            raise AgentStateConflictError()
        key = _record_key(request.scope, request.memory_id)
        try:
            async with self._state_store.transaction() as transaction:
                stored = await transaction.get(key)
                if stored is None:
                    raise AgentStateConflictError()
                current = _decode_record(
                    stored.value,
                    expected_scope=request.scope,
                    expected_memory_id=request.memory_id,
                )
                _require_state_identity(current, state_key=stored.key)
                if (
                    current.status is not MemoryRecordStatus.ACTIVE
                    or current.expires_at <= now
                    or current.version != request.expected_version
                ):
                    raise AgentStateConflictError()
                tombstone = _tombstone(current, now=now, limits=self._limits)
                await transaction.put(
                    key,
                    _encode_record(tombstone),
                    expected_version=stored.version,
                    ttl=self._limits.retention.tombstone_retention,
                )
        except (
            StateConflictError,
            StateSerializationError,
            StateStoreClosedError,
            StateTransactionError,
            StateTypeError,
        ) as exception:
            raise _safe_state_failure(exception) from None

    async def list_scope(
        self,
        scope: MemoryScope,
        *,
        limit: int | None = None,
    ) -> tuple[MemoryRecord, ...]:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        self._ensure_open()
        resolved_limit = self._limits.max_records_per_scope if limit is None else limit
        if isinstance(resolved_limit, bool) or not isinstance(resolved_limit, int):
            raise TypeError("limit must be an integer")
        if resolved_limit <= 0 or resolved_limit > self._limits.max_records_per_scope:
            raise ValueError("limit is outside configured memory bounds")
        try:
            stored_records = await self._state_store.list(
                namespace=_MEMORY_STATE_NAMESPACE,
                prefix=_scope_prefix(scope),
            )
        except (StateStoreClosedError, StateSerializationError) as exception:
            raise _safe_state_failure(exception) from None

        now = _now(self._clock)
        active: list[MemoryRecord] = []
        for stored in stored_records:
            record = _decode_record(stored.value, expected_scope=scope)
            _require_state_identity(record, state_key=stored.key)
            if record.status is MemoryRecordStatus.ACTIVE and record.expires_at > now:
                active.append(record)
        active.sort(key=lambda record: record.memory_id)
        return tuple(active[:resolved_limit])

    async def purge_expired(self, scope: MemoryScope) -> int:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        self._ensure_open()
        try:
            stored_records = await self._state_store.list(
                namespace=_MEMORY_STATE_NAMESPACE,
                prefix=_scope_prefix(scope),
            )
        except (StateStoreClosedError, StateSerializationError) as exception:
            raise _safe_state_failure(exception) from None

        now = _now(self._clock)
        candidates: list[MemoryId] = []
        for stored in stored_records:
            record = _decode_record(stored.value, expected_scope=scope)
            _require_state_identity(record, state_key=stored.key)
            if record.expires_at <= now:
                candidates.append(record.memory_id)

        purged = 0
        for memory_id in candidates:
            if await self._purge_one(scope, memory_id, now=now):
                purged += 1
        return purged

    async def list_scopes(self, *, limit: int) -> tuple[MemoryScope, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0 or limit > _MAX_MEMORY_SCOPE_LIST:
            raise ValueError("limit is outside supported memory scope bounds")
        self._ensure_open()
        try:
            stored_records = await self._state_store.list(
                namespace=_MEMORY_STATE_NAMESPACE,
                prefix="record.",
            )
        except (StateStoreClosedError, StateSerializationError) as exception:
            raise _safe_state_failure(exception) from None

        by_identity: dict[tuple[str, str, str], MemoryScope] = {}
        for stored in stored_records:
            record = _decode_record(stored.value)
            _require_state_identity(record, state_key=stored.key)
            identity = (
                record.scope.namespace.value,
                record.scope.kind.value,
                record.scope.scope_id.value,
            )
            by_identity[identity] = record.scope
        ordered = tuple(by_identity[key] for key in sorted(by_identity))
        return ordered[:limit]

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_state_store:
            try:
                await self._state_store.close()
            except StateStoreClosedError:
                return

    async def _require_capacity(
        self,
        transaction: StateTransaction,
        scope: MemoryScope,
        candidate: MemoryRecord,
        *,
        now: datetime,
        replacing: MemoryId | None,
    ) -> None:
        records = await transaction.list(
            namespace=_MEMORY_STATE_NAMESPACE,
            prefix=_scope_prefix(scope),
        )
        count = 0
        total_bytes = 0
        for stored in records:
            record = _decode_record(stored.value, expected_scope=scope)
            _require_state_identity(record, state_key=stored.key)
            if replacing is not None and record.memory_id == replacing:
                continue
            if record.status is not MemoryRecordStatus.ACTIVE or record.expires_at <= now:
                continue
            count += 1
            total_bytes += record.content_bytes

        if count + 1 > self._limits.max_records_per_scope:
            raise AgentLimitExceededError()
        if total_bytes + candidate.content_bytes > self._limits.max_total_bytes_per_scope:
            raise AgentLimitExceededError()

    async def _purge_one(
        self,
        scope: MemoryScope,
        memory_id: MemoryId,
        *,
        now: datetime,
    ) -> bool:
        key = _record_key(scope, memory_id)
        try:
            async with self._state_store.transaction() as transaction:
                stored = await transaction.get(key)
                if stored is None:
                    return False
                current = _decode_record(
                    stored.value,
                    expected_scope=scope,
                    expected_memory_id=memory_id,
                )
                _require_state_identity(current, state_key=stored.key)
                if current.expires_at > now:
                    return False
                if current.status is MemoryRecordStatus.TOMBSTONED:
                    await transaction.delete(
                        StateKey[object](
                            key.namespace,
                            key.name,
                        ),
                        expected_version=stored.version,
                    )
                    return True
                tombstone = _tombstone(current, now=now, limits=self._limits)
                await transaction.put(
                    key,
                    _encode_record(tombstone),
                    expected_version=stored.version,
                    ttl=self._limits.retention.tombstone_retention,
                )
                return True
        except StateConflictError:
            return False
        except (
            StateSerializationError,
            StateStoreClosedError,
            StateTransactionError,
            StateTypeError,
        ) as exception:
            raise _safe_state_failure(exception) from None

    def _active_physical_ttl(self) -> timedelta:
        return self._limits.retention.record_ttl + self._limits.retention.tombstone_retention

    def _ensure_open(self) -> None:
        if self._closed or self._state_store.closed:
            raise AgentServiceUnavailableError()


class InMemoryAgentMemoryStore(StateStoreMemoryStore):
    """Reference authoritative memory store over Phoenix's MemoryStateStore."""

    def __init__(
        self,
        *,
        limits: MemoryLimits | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        state_store = MemoryStateStore(
            clock=clock,
            source="phoenix.agent.memory.state",
        )
        super().__init__(
            state_store,
            limits=limits,
            clock=clock,
            owns_state_store=True,
        )
