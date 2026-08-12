"""Authoritative State Store-backed persistence for secure agent workspaces."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.agent.workspace_backing import (
    InMemoryWorkspaceBackingAdapter,
    WorkspaceBackingAdapter,
    WorkspaceBackingKey,
    workspace_backing_key,
)
from phoenix_os.agent.workspace_contracts import (
    ArtifactDeleteRequest,
    ArtifactDigest,
    ArtifactId,
    ArtifactListRequest,
    ArtifactListResult,
    ArtifactLogicalPath,
    ArtifactMediaType,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactVersion,
    ArtifactWriteRequest,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceScopeId,
    WorkspaceScopeKind,
    artifact_content_digest,
)
from phoenix_os.state.contracts import (
    ABSENT_VERSION,
    StateKey,
    StateStore,
    StateTransaction,
    TransactionState,
)
from phoenix_os.state.errors import (
    StateConflictError,
    StateSerializationError,
    StateStoreClosedError,
    StateTransactionError,
    StateTypeError,
)
from phoenix_os.state.memory import MemoryStateStore

_WORKSPACE_STATE_NAMESPACE = "agent-workspace"
_WORKSPACE_DOCUMENT_SCHEMA_VERSION = 1
_WORKSPACE_LEDGER_SCHEMA_VERSION = 1
_WORKSPACE_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "namespace",
        "scope_kind",
        "scope_id",
        "artifact_id",
        "version",
        "logical_path",
        "content_digest",
        "byte_length",
        "media_type",
        "metadata",
        "provenance",
        "created_at",
        "updated_at",
        "expires_at",
        "deleted_at",
        "backing_key",
    }
)
_WORKSPACE_LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "namespace",
        "scope_kind",
        "scope_id",
        "artifact_ids",
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
type WorkspaceStateDocument = dict[str, object]


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


def _scope_digest(scope: WorkspaceScope) -> str:
    if not isinstance(scope, WorkspaceScope):
        raise TypeError("scope must be WorkspaceScope")
    identity = f"{scope.namespace.value}\0{scope.kind.value}\0{scope.scope_id.value}".encode()
    return hashlib.sha256(identity).hexdigest()


def _record_prefix(scope: WorkspaceScope) -> str:
    return f"record.{_scope_digest(scope)}."


def _record_key(
    scope: WorkspaceScope,
    artifact_id: ArtifactId,
) -> StateKey[WorkspaceStateDocument]:
    if not isinstance(artifact_id, ArtifactId):
        raise TypeError("artifact_id must be ArtifactId")
    return StateKey[WorkspaceStateDocument](
        _WORKSPACE_STATE_NAMESPACE,
        f"{_record_prefix(scope)}{artifact_id.value.hex}",
    )


def _ledger_key(scope: WorkspaceScope) -> StateKey[WorkspaceStateDocument]:
    return StateKey[WorkspaceStateDocument](
        _WORKSPACE_STATE_NAMESPACE,
        f"ledger.{_scope_digest(scope)}",
    )


def _safe_failure(exception: Exception) -> Exception:
    if isinstance(exception, AgentError):
        return exception
    if isinstance(exception, StateConflictError):
        return AgentStateConflictError()
    if isinstance(exception, StateStoreClosedError):
        return AgentServiceUnavailableError()
    if isinstance(
        exception,
        (StateSerializationError, StateTypeError, StateTransactionError),
    ):
        return AgentCodecError("workspace authoritative metadata is invalid")
    return AgentServiceUnavailableError()


def _safe_backing_failure(exception: Exception) -> Exception:
    if isinstance(exception, AgentServiceUnavailableError):
        return AgentServiceUnavailableError()
    if isinstance(exception, AgentStateConflictError):
        return AgentStateConflictError()
    if isinstance(exception, AgentLimitExceededError):
        return AgentLimitExceededError()
    if isinstance(exception, AgentCodecError):
        return AgentCodecError("workspace backing is inconsistent")
    return AgentServiceUnavailableError()


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise AgentCodecError("workspace authoritative metadata is invalid")
    try:
        parsed = datetime.fromisoformat(value)
        _require_aware(parsed, label="persisted timestamp")
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("workspace authoritative metadata is invalid") from exception
    return parsed


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AgentCodecError("workspace authoritative metadata is invalid")
    return value


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise AgentCodecError("workspace authoritative metadata is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise AgentCodecError("workspace authoritative metadata is invalid")
        result[key] = item
    return result


def _encode_provenance(provenance: ArtifactProvenance) -> WorkspaceStateDocument:
    return {
        "origin": provenance.origin.value,
        "content_digest": provenance.content_digest.value,
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


def _decode_provenance(value: object) -> ArtifactProvenance:
    if not isinstance(value, Mapping) or set(value) != _PROVENANCE_FIELDS:
        raise AgentCodecError("workspace authoritative metadata is invalid")
    origin_raw = value["origin"]
    digest_raw = value["content_digest"]
    if not isinstance(origin_raw, str) or not isinstance(digest_raw, str):
        raise AgentCodecError("workspace authoritative metadata is invalid")

    source_run_raw = _optional_string(value["source_run_id"])
    source_agent_raw = _optional_string(value["source_agent_id"])
    source_principal_raw = _optional_string(value["source_principal_id"])
    try:
        return ArtifactProvenance(
            origin=ArtifactOriginKind(origin_raw),
            content_digest=ArtifactDigest(digest_raw),
            created_at=_parse_datetime(value["created_at"]),
            source_version=_optional_string(value["source_version"]),
            source_run_id=(None if source_run_raw is None else AgentRunId(UUID(source_run_raw))),
            source_agent_id=(None if source_agent_raw is None else AgentId(source_agent_raw)),
            source_principal_id=(
                None if source_principal_raw is None else WorkspaceScopeId(source_principal_raw)
            ),
            attributes=_string_mapping(value["attributes"]),
        )
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("workspace authoritative metadata is invalid") from exception


def _encode_record(
    record: ArtifactRecord,
    backing_key: WorkspaceBackingKey | None,
) -> WorkspaceStateDocument:
    return {
        "schema_version": _WORKSPACE_DOCUMENT_SCHEMA_VERSION,
        "status": record.status.value,
        "namespace": record.scope.namespace.value,
        "scope_kind": record.scope.kind.value,
        "scope_id": record.scope.scope_id.value,
        "artifact_id": str(record.artifact_id),
        "version": record.version.value,
        "logical_path": (None if record.logical_path is None else record.logical_path.value),
        "content_digest": record.content_digest.value,
        "byte_length": record.byte_length,
        "media_type": None if record.media_type is None else record.media_type.value,
        "metadata": dict(record.metadata),
        "provenance": (
            None if record.provenance is None else _encode_provenance(record.provenance)
        ),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "deleted_at": None if record.deleted_at is None else record.deleted_at.isoformat(),
        "backing_key": None if backing_key is None else backing_key.value,
    }


def _decode_record(
    value: object,
    *,
    limits: WorkspaceLimits,
    now: datetime,
    expected_scope: WorkspaceScope | None = None,
    expected_artifact_id: ArtifactId | None = None,
) -> tuple[ArtifactRecord, WorkspaceBackingKey | None]:
    if not isinstance(value, Mapping) or set(value) != _WORKSPACE_DOCUMENT_FIELDS:
        raise AgentCodecError("workspace authoritative metadata is invalid")
    if value["schema_version"] != _WORKSPACE_DOCUMENT_SCHEMA_VERSION:
        raise AgentCodecError("workspace authoritative metadata is invalid")

    status_raw = value["status"]
    namespace_raw = value["namespace"]
    scope_kind_raw = value["scope_kind"]
    scope_id_raw = value["scope_id"]
    artifact_id_raw = value["artifact_id"]
    digest_raw = value["content_digest"]
    if not all(
        isinstance(item, str)
        for item in (
            status_raw,
            namespace_raw,
            scope_kind_raw,
            scope_id_raw,
            artifact_id_raw,
            digest_raw,
        )
    ):
        raise AgentCodecError("workspace authoritative metadata is invalid")
    assert isinstance(status_raw, str)
    assert isinstance(namespace_raw, str)
    assert isinstance(scope_kind_raw, str)
    assert isinstance(scope_id_raw, str)
    assert isinstance(artifact_id_raw, str)
    assert isinstance(digest_raw, str)
    version_raw = value["version"]
    byte_length_raw = value["byte_length"]
    if (
        isinstance(version_raw, bool)
        or not isinstance(version_raw, int)
        or isinstance(byte_length_raw, bool)
        or not isinstance(byte_length_raw, int)
    ):
        raise AgentCodecError("workspace authoritative metadata is invalid")

    logical_path_raw = _optional_string(value["logical_path"])
    media_type_raw = _optional_string(value["media_type"])
    backing_key_raw = _optional_string(value["backing_key"])
    try:
        scope = WorkspaceScope(
            namespace=WorkspaceNamespace(namespace_raw),
            kind=WorkspaceScopeKind(scope_kind_raw),
            scope_id=WorkspaceScopeId(scope_id_raw),
        )
        artifact_id = ArtifactId(UUID(artifact_id_raw))
        status = ArtifactStatus(status_raw)
        record = ArtifactRecord(
            scope=scope,
            artifact_id=artifact_id,
            version=ArtifactVersion(version_raw),
            status=status,
            content_digest=ArtifactDigest(digest_raw),
            byte_length=byte_length_raw,
            created_at=_parse_datetime(value["created_at"]),
            updated_at=_parse_datetime(value["updated_at"]),
            expires_at=_parse_datetime(value["expires_at"]),
            logical_path=(
                None if logical_path_raw is None else ArtifactLogicalPath(logical_path_raw)
            ),
            media_type=(None if media_type_raw is None else ArtifactMediaType(media_type_raw)),
            provenance=(
                None if value["provenance"] is None else _decode_provenance(value["provenance"])
            ),
            metadata=_string_mapping(value["metadata"]),
            deleted_at=(
                None if value["deleted_at"] is None else _parse_datetime(value["deleted_at"])
            ),
        )
        backing_key = None if backing_key_raw is None else WorkspaceBackingKey(backing_key_raw)
    except AgentCodecError:
        raise
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("workspace authoritative metadata is invalid") from exception

    if expected_scope is not None and record.scope != expected_scope:
        raise AgentCodecError("workspace authoritative metadata is invalid")
    if expected_artifact_id is not None and record.artifact_id != expected_artifact_id:
        raise AgentCodecError("workspace authoritative metadata is invalid")
    if record.status is ArtifactStatus.ACTIVE:
        if backing_key is None:
            raise AgentCodecError("workspace authoritative metadata is invalid")
        _require_backing_identity(record, backing_key)
    elif backing_key is not None:
        raise AgentCodecError("workspace authoritative metadata is invalid")
    _require_record_within_limits(record, limits=limits, now=now)
    return record, backing_key


def _require_record_within_limits(
    record: ArtifactRecord,
    *,
    limits: WorkspaceLimits,
    now: datetime,
) -> None:
    """Revalidate untrusted persisted metadata against current trusted bounds."""

    if record.updated_at > now:
        raise AgentCodecError("workspace authoritative metadata is invalid")

    retention_duration = record.expires_at - record.updated_at
    if record.status is ArtifactStatus.ACTIVE:
        if retention_duration > limits.retention.artifact_ttl:
            raise AgentCodecError("workspace authoritative metadata is invalid")
        if record.byte_length > limits.max_artifact_bytes:
            raise AgentCodecError("workspace authoritative metadata is invalid")
        if record.logical_path is None:
            raise AgentCodecError("workspace authoritative metadata is invalid")
        if (
            len(record.logical_path.value.encode("utf-8")) > limits.max_logical_path_bytes
            or len(record.logical_path.segments) > limits.max_logical_path_segments
        ):
            raise AgentCodecError("workspace authoritative metadata is invalid")
        return

    if retention_duration > limits.retention.tombstone_retention:
        raise AgentCodecError("workspace authoritative metadata is invalid")


def _require_backing_identity(record: ArtifactRecord, key: WorkspaceBackingKey) -> None:
    expected_segments = (
        _scope_digest(record.scope),
        record.artifact_id.value.hex,
        f"v{record.version.value}",
    )
    if key.segments[:3] != expected_segments:
        raise AgentCodecError("workspace authoritative metadata is invalid")


def _require_state_identity[T](
    record: ArtifactRecord,
    *,
    state_key: StateKey[T],
) -> None:
    expected = _record_key(record.scope, record.artifact_id)
    if state_key.canonical != expected.canonical:
        raise AgentCodecError("workspace authoritative metadata is invalid")


def _encode_ledger(
    scope: WorkspaceScope,
    artifact_ids: frozenset[ArtifactId],
) -> WorkspaceStateDocument:
    return {
        "schema_version": _WORKSPACE_LEDGER_SCHEMA_VERSION,
        "namespace": scope.namespace.value,
        "scope_kind": scope.kind.value,
        "scope_id": scope.scope_id.value,
        "artifact_ids": sorted(item.value.hex for item in artifact_ids),
    }


def _decode_ledger(
    value: object,
    *,
    expected_scope: WorkspaceScope,
    limits: WorkspaceLimits,
) -> frozenset[ArtifactId]:
    if not isinstance(value, Mapping) or set(value) != _WORKSPACE_LEDGER_FIELDS:
        raise AgentCodecError("workspace identity ledger is invalid")
    if value["schema_version"] != _WORKSPACE_LEDGER_SCHEMA_VERSION:
        raise AgentCodecError("workspace identity ledger is invalid")
    namespace_raw = value["namespace"]
    scope_kind_raw = value["scope_kind"]
    scope_id_raw = value["scope_id"]
    artifact_ids_raw = value["artifact_ids"]
    if (
        not isinstance(namespace_raw, str)
        or not isinstance(scope_kind_raw, str)
        or not isinstance(scope_id_raw, str)
        or not isinstance(artifact_ids_raw, Sequence)
        or isinstance(artifact_ids_raw, (str, bytes, bytearray))
    ):
        raise AgentCodecError("workspace identity ledger is invalid")
    if len(artifact_ids_raw) > limits.max_artifact_id_history_per_scope:
        raise AgentCodecError("workspace identity ledger is invalid")
    normalized_ids: list[str] = []
    for item in artifact_ids_raw:
        if not isinstance(item, str):
            raise AgentCodecError("workspace identity ledger is invalid")
        normalized_ids.append(item)
    if normalized_ids != sorted(normalized_ids):
        raise AgentCodecError("workspace identity ledger is invalid")

    try:
        scope = WorkspaceScope(
            namespace=WorkspaceNamespace(namespace_raw),
            kind=WorkspaceScopeKind(scope_kind_raw),
            scope_id=WorkspaceScopeId(scope_id_raw),
        )
        artifact_ids = frozenset(ArtifactId(UUID(hex=item)) for item in normalized_ids)
    except (TypeError, ValueError) as exception:
        raise AgentCodecError("workspace identity ledger is invalid") from exception
    if scope != expected_scope or len(artifact_ids) != len(normalized_ids):
        raise AgentCodecError("workspace identity ledger is invalid")
    return artifact_ids


def _active_record_from_request(
    request: ArtifactWriteRequest,
    *,
    now: datetime,
    current: ArtifactRecord | None,
    limits: WorkspaceLimits,
) -> ArtifactRecord:
    content_length = len(request.content)
    if content_length > limits.max_artifact_bytes:
        raise AgentLimitExceededError()
    if (
        len(request.logical_path.value.encode("utf-8")) > limits.max_logical_path_bytes
        or len(request.logical_path.segments) > limits.max_logical_path_segments
    ):
        raise AgentLimitExceededError()
    if request.created_at > now or request.provenance.created_at > request.created_at:
        raise AgentStateConflictError()

    if current is None:
        version = ArtifactVersion()
        created_at = now
    else:
        if (
            current.status is not ArtifactStatus.ACTIVE
            or current.expires_at <= now
            or now < current.updated_at
            or request.expected_version is None
            or current.version != request.expected_version
        ):
            raise AgentStateConflictError()
        version = current.version.next()
        created_at = current.created_at

    return ArtifactRecord(
        scope=request.scope,
        artifact_id=request.artifact_id,
        version=version,
        status=ArtifactStatus.ACTIVE,
        logical_path=request.logical_path,
        content_digest=request.provenance.content_digest,
        byte_length=content_length,
        media_type=request.media_type,
        provenance=request.provenance,
        metadata=request.metadata,
        created_at=created_at,
        updated_at=now,
        expires_at=now + limits.retention.artifact_ttl,
    )


def _tombstone(
    record: ArtifactRecord,
    *,
    now: datetime,
    limits: WorkspaceLimits,
) -> ArtifactRecord:
    if record.status is not ArtifactStatus.ACTIVE or now < record.updated_at:
        raise AgentStateConflictError()
    return ArtifactRecord(
        scope=record.scope,
        artifact_id=record.artifact_id,
        version=record.version.next(),
        status=ArtifactStatus.TOMBSTONED,
        content_digest=record.content_digest,
        byte_length=0,
        created_at=record.created_at,
        updated_at=now,
        expires_at=now + limits.retention.tombstone_retention,
        deleted_at=now,
    )


class StateStoreWorkspaceStore:
    """Authoritative workspace metadata composed with immutable backing bytes."""

    def __init__(
        self,
        state_store: StateStore,
        backing: WorkspaceBackingAdapter,
        *,
        limits: WorkspaceLimits | None = None,
        clock: Clock = _utc_now,
        owns_state_store: bool = False,
        owns_backing: bool = False,
    ) -> None:
        if limits is not None and not isinstance(limits, WorkspaceLimits):
            raise TypeError("limits must be WorkspaceLimits or None")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(owns_state_store, bool):
            raise TypeError("owns_state_store must be bool")
        if not isinstance(owns_backing, bool):
            raise TypeError("owns_backing must be bool")
        self._state_store = state_store
        self._backing = backing
        self._limits = WorkspaceLimits() if limits is None else limits
        self._clock = clock
        self._owns_state_store = owns_state_store
        self._owns_backing = owns_backing
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def limits(self) -> WorkspaceLimits:
        return self._limits

    async def write(self, request: ArtifactWriteRequest) -> ArtifactRecord:
        if not isinstance(request, ArtifactWriteRequest):
            raise TypeError("request must be ArtifactWriteRequest")
        self._ensure_open()
        now = _now(self._clock)
        if request.created_at > now:
            raise AgentStateConflictError()

        record_key = _record_key(request.scope, request.artifact_id)
        ledger_key = _ledger_key(request.scope)
        candidate: ArtifactRecord | None = None
        candidate_backing: WorkspaceBackingKey | None = None
        previous_backing: WorkspaceBackingKey | None = None
        transaction = self._state_store.transaction()
        try:
            await transaction.__aenter__()
            stored = await transaction.get(record_key)
            stored_ledger = await transaction.get(ledger_key)
            ledger = (
                frozenset()
                if stored_ledger is None
                else _decode_ledger(
                    stored_ledger.value,
                    expected_scope=request.scope,
                    limits=self._limits,
                )
            )

            if stored is None:
                if request.expected_version is not None or request.artifact_id in ledger:
                    raise AgentStateConflictError()
                if len(ledger) >= self._limits.max_artifact_id_history_per_scope:
                    raise AgentLimitExceededError()
                current = None
                state_expected = ABSENT_VERSION
                next_ledger = frozenset((*ledger, request.artifact_id))
            else:
                current, previous_backing = _decode_record(
                    stored.value,
                    limits=self._limits,
                    now=now,
                    expected_scope=request.scope,
                    expected_artifact_id=request.artifact_id,
                )
                _require_state_identity(current, state_key=stored.key)
                if request.artifact_id not in ledger:
                    raise AgentCodecError("workspace identity ledger is invalid")
                if request.expected_version is None:
                    raise AgentStateConflictError()
                state_expected = stored.version
                next_ledger = ledger

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
                ledger=next_ledger,
                now=now,
                replacing=request.artifact_id if current is not None else None,
            )

            candidate_backing = workspace_backing_key(
                request.scope,
                request.artifact_id,
                candidate.version,
            )
            await self._write_and_verify_backing(
                candidate_backing,
                request.content,
                record=candidate,
            )
            await transaction.put(
                record_key,
                _encode_record(candidate, candidate_backing),
                expected_version=state_expected,
                ttl=self._active_physical_ttl(),
            )
            if stored is None:
                await transaction.put(
                    ledger_key,
                    _encode_ledger(request.scope, next_ledger),
                    expected_version=(
                        ABSENT_VERSION if stored_ledger is None else stored_ledger.version
                    ),
                )
            await transaction.commit()
        except asyncio.CancelledError:
            if transaction.state is TransactionState.COMMITTED and candidate is not None:
                # The authoritative outcome already exists. Finish as success so
                # callers never observe cancellation for a committed mutation.
                if previous_backing is not None:
                    await self._delete_obsolete_backing_after_commit(previous_backing)
                return candidate
            await self._rollback_after_cancellation(transaction)
            if candidate_backing is not None:
                await self._delete_candidate_after_cancellation(candidate_backing)
            raise
        except Exception as exception:
            if transaction.state is TransactionState.OPEN:
                await self._best_effort_rollback(transaction)
            if transaction.state is not TransactionState.COMMITTED:
                if candidate_backing is not None:
                    await self._best_effort_backing_delete(candidate_backing)
                raise _safe_failure(exception) from None
            assert candidate is not None
            if previous_backing is not None:
                await self._delete_obsolete_backing_after_commit(previous_backing)
            return candidate

        assert candidate is not None
        if previous_backing is not None:
            await self._delete_obsolete_backing_after_commit(previous_backing)
        return candidate

    async def read(self, request: ArtifactReadRequest) -> ArtifactReadResult | None:
        if not isinstance(request, ArtifactReadRequest):
            raise TypeError("request must be ArtifactReadRequest")
        self._ensure_open()
        now = _now(self._clock)
        transaction = self._state_store.transaction()
        result: ArtifactReadResult | None = None
        try:
            await transaction.__aenter__()
            stored = await transaction.get(_record_key(request.scope, request.artifact_id))
            if stored is not None:
                record, backing_key = _decode_record(
                    stored.value,
                    limits=self._limits,
                    now=now,
                    expected_scope=request.scope,
                    expected_artifact_id=request.artifact_id,
                )
                _require_state_identity(record, state_key=stored.key)
                if record.status is ArtifactStatus.ACTIVE and record.expires_at > now:
                    await self._require_tracked_identity(
                        transaction,
                        request.scope,
                        request.artifact_id,
                    )
                    assert backing_key is not None
                    content = await self._read_verified_backing(backing_key, record=record)
                    result = ArtifactReadResult(record=record, content=content)
            await transaction.commit()
        except asyncio.CancelledError:
            if transaction.state is TransactionState.COMMITTED:
                return result
            await self._rollback_after_cancellation(transaction)
            raise
        except Exception as exception:
            if transaction.state is TransactionState.OPEN:
                await self._best_effort_rollback(transaction)
            if transaction.state is TransactionState.COMMITTED:
                return result
            raise _safe_failure(exception) from None
        return result

    async def list(self, request: ArtifactListRequest) -> ArtifactListResult:
        if not isinstance(request, ArtifactListRequest):
            raise TypeError("request must be ArtifactListRequest")
        self._ensure_open()
        if request.max_results > self._limits.max_list_results:
            raise ValueError("max_results is outside configured workspace bounds")
        if request.prefix is not None and (
            len(request.prefix.value.encode("utf-8")) > self._limits.max_logical_path_bytes
            or len(request.prefix.segments) > self._limits.max_logical_path_segments
        ):
            raise AgentLimitExceededError()

        now = _now(self._clock)
        transaction = self._state_store.transaction()
        result: ArtifactListResult | None = None
        try:
            await transaction.__aenter__()
            stored_records = await transaction.list(
                namespace=_WORKSPACE_STATE_NAMESPACE,
                prefix=_record_prefix(request.scope),
            )
            stored_ledger = await transaction.get(_ledger_key(request.scope))
            ledger = (
                frozenset()
                if stored_ledger is None
                else _decode_ledger(
                    stored_ledger.value,
                    expected_scope=request.scope,
                    limits=self._limits,
                )
            )

            active: list[ArtifactRecord] = []
            for stored in stored_records:
                record, _ = _decode_record(
                    stored.value,
                    limits=self._limits,
                    now=now,
                    expected_scope=request.scope,
                )
                _require_state_identity(record, state_key=stored.key)
                if record.artifact_id not in ledger:
                    raise AgentCodecError("workspace identity ledger is invalid")
                if record.status is not ArtifactStatus.ACTIVE or record.expires_at <= now:
                    continue
                assert record.logical_path is not None
                if request.prefix is not None and not _path_has_prefix(
                    record.logical_path,
                    request.prefix,
                ):
                    continue
                active.append(record)

            active.sort(
                key=lambda record: (_logical_path_value(record), record.artifact_id.value.int)
            )
            truncated = len(active) > request.max_results
            selected = active[: request.max_results]
            # Listing is intentionally content-free. Persisted metadata, limits,
            # scope, path, ledger, and backing-key identity are validated here;
            # payload existence, byte length, and digest are verified by read and
            # recovery paths so no backing I/O extends this serialized transaction.
            result = ArtifactListResult(
                scope=request.scope,
                artifacts=tuple(selected),
                truncated=truncated,
                created_at=now,
            )
            await transaction.commit()
        except asyncio.CancelledError:
            if transaction.state is TransactionState.COMMITTED and result is not None:
                return result
            await self._rollback_after_cancellation(transaction)
            raise
        except Exception as exception:
            if transaction.state is TransactionState.OPEN:
                await self._best_effort_rollback(transaction)
            if transaction.state is TransactionState.COMMITTED and result is not None:
                return result
            raise _safe_failure(exception) from None
        assert result is not None
        return result

    async def delete(self, request: ArtifactDeleteRequest) -> None:
        if not isinstance(request, ArtifactDeleteRequest):
            raise TypeError("request must be ArtifactDeleteRequest")
        self._ensure_open()
        now = _now(self._clock)
        if request.created_at > now:
            raise AgentStateConflictError()

        transaction = self._state_store.transaction()
        previous_backing: WorkspaceBackingKey | None = None
        try:
            await transaction.__aenter__()
            key = _record_key(request.scope, request.artifact_id)
            stored = await transaction.get(key)
            if stored is None:
                raise AgentStateConflictError()
            current, previous_backing = _decode_record(
                stored.value,
                limits=self._limits,
                now=now,
                expected_scope=request.scope,
                expected_artifact_id=request.artifact_id,
            )
            _require_state_identity(current, state_key=stored.key)
            await self._require_tracked_identity(
                transaction,
                request.scope,
                request.artifact_id,
            )
            if (
                current.status is not ArtifactStatus.ACTIVE
                or current.expires_at <= now
                or current.version != request.expected_version
            ):
                raise AgentStateConflictError()
            tombstone = _tombstone(current, now=now, limits=self._limits)
            await transaction.put(
                key,
                _encode_record(tombstone, None),
                expected_version=stored.version,
                ttl=self._limits.retention.tombstone_retention,
            )
            await transaction.commit()
        except asyncio.CancelledError:
            if transaction.state is not TransactionState.COMMITTED:
                await self._rollback_after_cancellation(transaction)
                raise
        except Exception as exception:
            if transaction.state is TransactionState.OPEN:
                await self._best_effort_rollback(transaction)
            if transaction.state is not TransactionState.COMMITTED:
                raise _safe_failure(exception) from None

        if previous_backing is not None:
            await self._delete_obsolete_backing_after_commit(previous_backing)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_backing:
            try:
                await self._backing.close()
            except Exception:
                pass
        if self._owns_state_store:
            try:
                await self._state_store.close()
            except Exception:
                pass

    async def _require_capacity(
        self,
        transaction: StateTransaction,
        scope: WorkspaceScope,
        candidate: ArtifactRecord,
        *,
        ledger: frozenset[ArtifactId],
        now: datetime,
        replacing: ArtifactId | None,
    ) -> None:
        records = await transaction.list(
            namespace=_WORKSPACE_STATE_NAMESPACE,
            prefix=_record_prefix(scope),
        )
        count = 0
        total_bytes = 0
        for stored in records:
            record, _ = _decode_record(
                stored.value,
                limits=self._limits,
                now=now,
                expected_scope=scope,
            )
            _require_state_identity(record, state_key=stored.key)
            if record.artifact_id not in ledger:
                raise AgentCodecError("workspace identity ledger is invalid")
            if replacing is not None and record.artifact_id == replacing:
                continue
            if record.status is not ArtifactStatus.ACTIVE or record.expires_at <= now:
                continue
            if record.logical_path == candidate.logical_path:
                raise AgentStateConflictError()
            count += 1
            total_bytes += record.byte_length

        if count + 1 > self._limits.max_artifacts_per_scope:
            raise AgentLimitExceededError()
        if total_bytes + candidate.byte_length > self._limits.max_total_bytes_per_scope:
            raise AgentLimitExceededError()

    async def _require_tracked_identity(
        self,
        transaction: StateTransaction,
        scope: WorkspaceScope,
        artifact_id: ArtifactId,
    ) -> None:
        stored = await transaction.get(_ledger_key(scope))
        if stored is None:
            raise AgentCodecError("workspace identity ledger is invalid")
        ledger = _decode_ledger(
            stored.value,
            expected_scope=scope,
            limits=self._limits,
        )
        if artifact_id not in ledger:
            raise AgentCodecError("workspace identity ledger is invalid")

    async def _write_and_verify_backing(
        self,
        key: WorkspaceBackingKey,
        content: bytes,
        *,
        record: ArtifactRecord,
    ) -> None:
        try:
            await self._backing.write(
                key,
                content,
                expected_digest=record.content_digest,
            )
            persisted = await self._backing.read(
                key,
                expected_digest=record.content_digest,
            )
            _validate_backing_bytes(persisted, record=record)
        except Exception as exception:
            raise _safe_backing_failure(exception) from None

    async def _read_verified_backing(
        self,
        key: WorkspaceBackingKey,
        *,
        record: ArtifactRecord,
    ) -> bytes:
        try:
            content = await self._backing.read(
                key,
                expected_digest=record.content_digest,
            )
            return _validate_backing_bytes(content, record=record)
        except Exception as exception:
            raise _safe_backing_failure(exception) from None

    async def _best_effort_backing_delete(self, key: WorkspaceBackingKey) -> None:
        try:
            await self._backing.delete(key)
        except Exception:
            pass

    @staticmethod
    async def _best_effort_rollback(transaction: StateTransaction) -> None:
        try:
            await transaction.rollback()
        except Exception:
            pass

    async def _delete_obsolete_backing_after_commit(self, key: WorkspaceBackingKey) -> None:
        """Best-effort cleanup that preserves an already committed success outcome."""

        try:
            await _finish_despite_cancellation(self._backing.delete(key))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _delete_candidate_after_cancellation(self, key: WorkspaceBackingKey) -> None:
        """Remove pre-commit bytes before propagating cancellation to the caller."""

        try:
            await _finish_despite_cancellation(self._backing.delete(key))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    @staticmethod
    async def _rollback_after_cancellation(transaction: StateTransaction) -> None:
        """Finish pre-commit rollback before propagating cancellation."""

        if transaction.state is not TransactionState.OPEN:
            return
        try:
            await _finish_despite_cancellation(transaction.rollback())
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def _active_physical_ttl(self) -> timedelta:
        return self._limits.retention.artifact_ttl + self._limits.retention.tombstone_retention

    def _ensure_open(self) -> None:
        if self._closed or self._state_store.closed or self._backing.closed:
            raise AgentServiceUnavailableError()


class InMemoryWorkspaceStore(StateStoreWorkspaceStore):
    """Reference authoritative workspace store with in-memory metadata and bytes."""

    def __init__(
        self,
        *,
        limits: WorkspaceLimits | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        state_store = MemoryStateStore(
            clock=clock,
            source="phoenix.agent.workspace.state",
        )
        backing = InMemoryWorkspaceBackingAdapter()
        super().__init__(
            state_store,
            backing,
            limits=limits,
            clock=clock,
            owns_state_store=True,
            owns_backing=True,
        )


def _path_has_prefix(path: ArtifactLogicalPath, prefix: ArtifactLogicalPath) -> bool:
    return path.value == prefix.value or path.value.startswith(f"{prefix.value}/")


def _logical_path_value(record: ArtifactRecord) -> str:
    if record.logical_path is None:
        raise AgentCodecError("workspace authoritative metadata is invalid")
    return record.logical_path.value


def _validate_backing_bytes(content: object, *, record: ArtifactRecord) -> bytes:
    if not isinstance(content, bytes):
        raise AgentCodecError("workspace backing is inconsistent")
    if len(content) != record.byte_length:
        raise AgentCodecError("workspace backing is inconsistent")
    if artifact_content_digest(content) != record.content_digest:
        raise AgentCodecError("workspace backing is inconsistent")
    return content


async def _finish_despite_cancellation(operation: Awaitable[None]) -> None:
    """Finish one finite cleanup operation despite repeated task cancellation."""

    cleanup = asyncio.ensure_future(operation)
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            continue
    cleanup.result()
