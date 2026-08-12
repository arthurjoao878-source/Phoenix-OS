"""Runtime-owned semantic indexing, recovery, and administration for agent memory."""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.errors import AgentCodecError, AgentServiceUnavailableError
from phoenix_os.agent.memory_authorization import MemoryAuthorizer, PolicyEngineMemoryAuthorizer
from phoenix_os.agent.memory_contracts import (
    MAX_MEMORY_SEARCH_RESULTS,
    MemoryContextBlock,
    MemoryDeleteRequest,
    MemoryId,
    MemoryLimits,
    MemoryNamespace,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordStatus,
    MemoryRetrievalCandidate,
    MemoryScope,
    MemoryScopeKind,
    MemorySearchRequest,
    MemorySearchResult,
    MemoryWriteRequest,
)
from phoenix_os.agent.memory_retrieval import (
    AgentMemoryService,
    MemoryRetrievalAdapter,
    ServerOwnedAgentMemoryContextProvider,
)
from phoenix_os.agent.memory_store import (
    InMemoryAgentMemoryStore,
    MemoryStore,
    StateStoreMemoryStore,
)
from phoenix_os.events import EventBus
from phoenix_os.policy import PolicyEngine, SecurityContext
from phoenix_os.runtime import RuntimeContext
from phoenix_os.state import StateStore

MAX_MEMORY_VECTOR_DIMENSION = 4_096
MAX_MEMORY_RUNTIME_SCOPES_PER_CYCLE = 1_024
MAX_MEMORY_RUNTIME_RECORDS_PER_SCOPE_CYCLE = 4_096
MAX_MEMORY_RUNTIME_MAINTENANCE_INTERVAL = timedelta(days=1)
_MAX_MEMORY_RUNTIME_OPERATION_TIMEOUT = timedelta(minutes=5)
_MEMORY_REASON_PATTERN = re.compile(r"^[a-z0-9._-]{1,64}$")

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _normalize_embedding(
    values: Sequence[float],
    *,
    dimension: int,
) -> tuple[float, ...]:
    if isinstance(dimension, bool) or not isinstance(dimension, int):
        raise TypeError("embedding dimension must be an integer")
    if dimension <= 0 or dimension > MAX_MEMORY_VECTOR_DIMENSION:
        raise ValueError("embedding dimension is outside supported bounds")
    try:
        normalized = tuple(float(value) for value in values)
    except (TypeError, ValueError) as exception:
        raise AgentCodecError(
            "memory semantic provider returned an invalid embedding"
        ) from exception
    if len(normalized) != dimension:
        raise AgentCodecError("memory semantic provider returned an invalid embedding")
    if any(not math.isfinite(value) for value in normalized):
        raise AgentCodecError("memory semantic provider returned an invalid embedding")
    norm = math.sqrt(sum(value * value for value in normalized))
    if norm <= 0:
        raise AgentCodecError("memory semantic provider returned an invalid embedding")
    return tuple(value / norm for value in normalized)


@runtime_checkable
class MemoryEmbeddingProvider(Protocol):
    """Provider-neutral semantic embedding boundary with no provider SDK objects."""

    @property
    def provider_id(self) -> str: ...

    @property
    def dimension(self) -> int: ...

    async def embed(self, text: str) -> Sequence[float]: ...


@runtime_checkable
class MemoryDerivedIndex(Protocol):
    """Derived vector index that never becomes authoritative record truth."""

    @property
    def closed(self) -> bool: ...

    @property
    def dimension(self) -> int: ...

    @property
    def entry_count(self) -> int: ...

    async def upsert(
        self,
        candidate: MemoryRetrievalCandidate,
        embedding: Sequence[float],
    ) -> None: ...

    async def delete(self, scope: MemoryScope, memory_id: MemoryId) -> None: ...

    async def clear_scope(self, scope: MemoryScope) -> None: ...

    async def search(
        self,
        scope: MemoryScope,
        embedding: Sequence[float],
        *,
        limit: int,
    ) -> tuple[MemoryRetrievalCandidate, ...]: ...

    async def count_scope(self, scope: MemoryScope) -> int: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _VectorEntry:
    candidate: MemoryRetrievalCandidate
    embedding: tuple[float, ...]


class InMemoryDerivedMemoryIndex:
    """Bounded reference vector index containing no memory content or provenance."""

    def __init__(self, *, dimension: int) -> None:
        if isinstance(dimension, bool) or not isinstance(dimension, int):
            raise TypeError("dimension must be an integer")
        if dimension <= 0 or dimension > MAX_MEMORY_VECTOR_DIMENSION:
            raise ValueError("dimension is outside supported bounds")
        self._dimension = dimension
        self._entries: dict[tuple[MemoryScope, MemoryId], _VectorEntry] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    async def upsert(
        self,
        candidate: MemoryRetrievalCandidate,
        embedding: Sequence[float],
    ) -> None:
        if not isinstance(candidate, MemoryRetrievalCandidate):
            raise TypeError("candidate must be MemoryRetrievalCandidate")
        vector = _normalize_embedding(embedding, dimension=self._dimension)
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            self._entries[(candidate.scope, candidate.memory_id)] = _VectorEntry(
                candidate=candidate,
                embedding=vector,
            )

    async def delete(self, scope: MemoryScope, memory_id: MemoryId) -> None:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if not isinstance(memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            self._entries.pop((scope, memory_id), None)

    async def clear_scope(self, scope: MemoryScope) -> None:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            keys = tuple(key for key in self._entries if key[0] == scope)
            for key in keys:
                self._entries.pop(key, None)

    async def search(
        self,
        scope: MemoryScope,
        embedding: Sequence[float],
        *,
        limit: int,
    ) -> tuple[MemoryRetrievalCandidate, ...]:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0 or limit > MAX_MEMORY_SEARCH_RESULTS:
            raise ValueError("limit is outside supported memory search bounds")
        query = _normalize_embedding(embedding, dimension=self._dimension)
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            entries = tuple(
                entry
                for (entry_scope, _memory_id), entry in self._entries.items()
                if entry_scope == scope
            )

        candidates = [
            MemoryRetrievalCandidate(
                scope=entry.candidate.scope,
                memory_id=entry.candidate.memory_id,
                version=entry.candidate.version,
                content_digest=entry.candidate.content_digest,
                score=sum(
                    query_value * entry_value
                    for query_value, entry_value in zip(
                        query,
                        entry.embedding,
                        strict=True,
                    )
                ),
            )
            for entry in entries
        ]
        candidates.sort(key=lambda candidate: (-candidate.score, candidate.memory_id.value.int))
        return tuple(candidates[:limit])

    async def count_scope(self, scope: MemoryScope) -> int:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            return sum(1 for entry_scope, _memory_id in self._entries if entry_scope == scope)

    async def close(self) -> None:
        if self._closed:
            return
        async with self._lock:
            self._entries.clear()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()


class SemanticMemoryRetrievalAdapter:
    """Select semantic candidates from a derived index; source truth is re-read later."""

    def __init__(
        self,
        *,
        provider: MemoryEmbeddingProvider,
        index: MemoryDerivedIndex,
        adapter_id: str = "semantic-memory",
        operation_timeout: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(provider, MemoryEmbeddingProvider):
            raise TypeError("provider must implement MemoryEmbeddingProvider")
        if not isinstance(index, MemoryDerivedIndex):
            raise TypeError("index must implement MemoryDerivedIndex")
        if provider.dimension != index.dimension:
            raise ValueError("semantic provider and index dimensions must match")
        if provider.dimension <= 0 or provider.dimension > MAX_MEMORY_VECTOR_DIMENSION:
            raise ValueError("semantic provider dimension is outside supported bounds")
        if not isinstance(operation_timeout, timedelta):
            raise TypeError("operation_timeout must be timedelta")
        if (
            operation_timeout <= timedelta(0)
            or operation_timeout > _MAX_MEMORY_RUNTIME_OPERATION_TIMEOUT
        ):
            raise ValueError("operation_timeout is outside supported bounds")
        normalized = adapter_id.strip().lower()
        if not normalized or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in normalized
        ):
            raise ValueError("adapter_id is invalid")
        self._provider = provider
        self._index = index
        self._adapter_id = normalized
        self._operation_timeout = operation_timeout

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    async def search(
        self,
        request: MemorySearchRequest,
    ) -> tuple[MemoryRetrievalCandidate, ...]:
        if not isinstance(request, MemorySearchRequest):
            raise TypeError("request must be MemorySearchRequest")
        vector = await _provider_embedding(
            self._provider,
            request.query,
            operation_timeout=self._operation_timeout,
        )
        candidates = await self._index.search(
            request.scope,
            vector,
            limit=request.max_results,
        )
        return tuple(candidates)


class MemoryRuntimeOperation(StrEnum):
    RECOVERY = "recovery"
    CLEANUP = "cleanup"
    INDEX = "index"
    ADMIN = "admin"
    LIFECYCLE = "lifecycle"


class MemoryRuntimeOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class MemoryRuntimeObservation:
    """Content-free operational observation; memory text/query/vector are impossible fields."""

    operation: MemoryRuntimeOperation
    outcome: MemoryRuntimeOutcome
    scope: MemoryScope | None = None
    memory_id: MemoryId | None = None
    records: int = 0
    total_bytes: int = 0
    reason: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.operation, MemoryRuntimeOperation):
            raise TypeError("operation must be MemoryRuntimeOperation")
        if not isinstance(self.outcome, MemoryRuntimeOutcome):
            raise TypeError("outcome must be MemoryRuntimeOutcome")
        if self.scope is not None and not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope or None")
        if self.memory_id is not None and not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId or None")
        if isinstance(self.records, bool) or not isinstance(self.records, int) or self.records < 0:
            raise ValueError("records must be a non-negative integer")
        if (
            isinstance(self.total_bytes, bool)
            or not isinstance(self.total_bytes, int)
            or self.total_bytes < 0
        ):
            raise ValueError("total_bytes must be a non-negative integer")
        if self.reason is not None:
            normalized = self.reason.strip().lower()
            if _MEMORY_REASON_PATTERN.fullmatch(normalized) is None:
                raise ValueError("reason must be a fixed Phoenix reason code")
            object.__setattr__(self, "reason", normalized)
        _require_aware(self.created_at, label="created_at")


class ContentFreeMemoryObserver:
    """Emit only IDs, counters, statuses, and fixed reason codes."""

    def __init__(
        self,
        events: EventBus | None = None,
        *,
        source: str = "phoenix.agent.memory",
    ) -> None:
        if events is not None and not isinstance(events, EventBus):
            raise TypeError("events must be EventBus or None")
        normalized = source.strip().lower()
        if not normalized:
            raise ValueError("source must not be blank")
        self._events = events
        self._source = normalized

    async def observe(self, observation: MemoryRuntimeObservation) -> None:
        if not isinstance(observation, MemoryRuntimeObservation):
            raise TypeError("observation must be MemoryRuntimeObservation")
        if self._events is None:
            return
        payload: dict[str, object] = {
            "operation": observation.operation.value,
            "outcome": observation.outcome.value,
            "records": observation.records,
            "total_bytes": observation.total_bytes,
        }
        if observation.scope is not None:
            payload.update(
                {
                    "namespace": observation.scope.namespace.value,
                    "scope_kind": observation.scope.kind.value,
                    "scope_id": observation.scope.scope_id.value,
                }
            )
        if observation.memory_id is not None:
            payload["memory_id"] = str(observation.memory_id)
        if observation.reason is not None:
            payload["reason"] = observation.reason
        try:
            await self._events.emit(
                "agent.memory.operation",
                source=self._source,
                payload=payload,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return


@dataclass(frozen=True, slots=True)
class AgentMemoryRuntimeConfiguration:
    """Finite opt-in Runtime configuration for memory ownership and maintenance."""

    namespace: MemoryNamespace
    scope_kind: MemoryScopeKind = MemoryScopeKind.AGENT
    limits: MemoryLimits = field(default_factory=MemoryLimits)
    semantic_enabled: bool = False
    maintenance_interval: timedelta = timedelta(minutes=1)
    operation_timeout: timedelta = timedelta(seconds=30)
    max_scopes_per_cycle: int = 64
    max_records_per_scope_cycle: int = 256

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, MemoryNamespace):
            raise TypeError("namespace must be MemoryNamespace")
        if not isinstance(self.scope_kind, MemoryScopeKind):
            raise TypeError("scope_kind must be MemoryScopeKind")
        if not isinstance(self.limits, MemoryLimits):
            raise TypeError("limits must be MemoryLimits")
        if type(self.semantic_enabled) is not bool:
            raise TypeError("semantic_enabled must be bool")
        if not isinstance(self.maintenance_interval, timedelta):
            raise TypeError("maintenance_interval must be timedelta")
        if (
            self.maintenance_interval <= timedelta(0)
            or self.maintenance_interval > MAX_MEMORY_RUNTIME_MAINTENANCE_INTERVAL
        ):
            raise ValueError("maintenance_interval is outside supported bounds")
        if not isinstance(self.operation_timeout, timedelta):
            raise TypeError("operation_timeout must be timedelta")
        if (
            self.operation_timeout <= timedelta(0)
            or self.operation_timeout > _MAX_MEMORY_RUNTIME_OPERATION_TIMEOUT
        ):
            raise ValueError("operation_timeout is outside supported bounds")
        if (
            isinstance(self.max_scopes_per_cycle, bool)
            or not isinstance(self.max_scopes_per_cycle, int)
            or not 1 <= self.max_scopes_per_cycle <= MAX_MEMORY_RUNTIME_SCOPES_PER_CYCLE
        ):
            raise ValueError("max_scopes_per_cycle is outside supported bounds")
        if (
            isinstance(self.max_records_per_scope_cycle, bool)
            or not isinstance(self.max_records_per_scope_cycle, int)
            or not 1
            <= self.max_records_per_scope_cycle
            <= min(
                MAX_MEMORY_RUNTIME_RECORDS_PER_SCOPE_CYCLE,
                self.limits.max_records_per_scope,
            )
        ):
            raise ValueError("max_records_per_scope_cycle is outside supported bounds")


async def _provider_embedding(
    provider: MemoryEmbeddingProvider,
    text: str,
    *,
    operation_timeout: timedelta,
) -> tuple[float, ...]:
    try:
        async with asyncio.timeout(operation_timeout.total_seconds()):
            values = await provider.embed(text)
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        raise AgentServiceUnavailableError() from None
    except Exception:
        raise AgentServiceUnavailableError() from None
    return _normalize_embedding(values, dimension=provider.dimension)


def _consume_background_task_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


class AgentMemoryRuntimeOwner:
    """Runtime lifecycle owner for recovery, bounded maintenance, index, and store."""

    def __init__(
        self,
        *,
        configuration: AgentMemoryRuntimeConfiguration,
        store: MemoryStore,
        observer: ContentFreeMemoryObserver,
        provider: MemoryEmbeddingProvider | None = None,
        index: MemoryDerivedIndex | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if not isinstance(configuration, AgentMemoryRuntimeConfiguration):
            raise TypeError("configuration must be AgentMemoryRuntimeConfiguration")
        if not isinstance(store, MemoryStore):
            raise TypeError("store must implement MemoryStore")
        if not isinstance(observer, ContentFreeMemoryObserver):
            raise TypeError("observer must be ContentFreeMemoryObserver")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if configuration.semantic_enabled:
            if provider is None or index is None:
                raise ValueError("semantic memory requires provider and index")
            if not isinstance(provider, MemoryEmbeddingProvider):
                raise TypeError("provider must implement MemoryEmbeddingProvider")
            if not isinstance(index, MemoryDerivedIndex):
                raise TypeError("index must implement MemoryDerivedIndex")
        elif provider is not None or index is not None:
            raise ValueError("semantic provider/index require semantic_enabled")
        self._configuration = configuration
        self._store = store
        self._observer = observer
        self._provider = provider
        self._index = index
        self._clock = clock
        self._worker: asyncio.Task[None] | None = None
        self._started = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._started and not self._closed

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._closed:
            raise AgentServiceUnavailableError()
        if self._started:
            return
        try:
            await self.reconcile_once()
        except asyncio.CancelledError:
            await self.close()
            raise
        except Exception:
            await self.close()
            raise
        self._started = True
        self._worker = asyncio.create_task(
            self._maintenance_loop(),
            name="phoenix-agent-memory-maintenance",
        )
        await self._observer.observe(
            MemoryRuntimeObservation(
                operation=MemoryRuntimeOperation.LIFECYCLE,
                outcome=MemoryRuntimeOutcome.SUCCEEDED,
                reason="started",
                created_at=self._now(),
            )
        )

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        worker = self._worker
        self._worker = None
        shutdown_timed_out = False
        if worker is not None:
            worker.cancel()
            done, pending = await asyncio.wait(
                {worker},
                timeout=self._configuration.operation_timeout.total_seconds(),
            )
            if pending:
                shutdown_timed_out = True
                worker.add_done_callback(_consume_background_task_result)
            elif done:
                _consume_background_task_result(worker)
        if self._index is not None:
            await self._index.close()
        await self._store.close()
        await self._observer.observe(
            MemoryRuntimeObservation(
                operation=MemoryRuntimeOperation.LIFECYCLE,
                outcome=(
                    MemoryRuntimeOutcome.FAILED
                    if shutdown_timed_out
                    else MemoryRuntimeOutcome.SUCCEEDED
                ),
                reason="shutdown_timeout" if shutdown_timed_out else "closed",
                created_at=self._now(),
            )
        )

    async def reconcile_once(self) -> int:
        try:
            async with asyncio.timeout(self._configuration.operation_timeout.total_seconds()):
                scopes = await self._store.list_scopes(
                    limit=self._configuration.max_scopes_per_cycle
                )
                reconciled = 0
                for scope in scopes:
                    await self._reconcile_scope(scope)
                    reconciled += 1
                return reconciled
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise AgentServiceUnavailableError() from None

    async def reconcile_scope(self, scope: MemoryScope) -> int:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        try:
            async with asyncio.timeout(self._configuration.operation_timeout.total_seconds()):
                return await self._reconcile_scope(scope)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise AgentServiceUnavailableError() from None

    async def _reconcile_scope(self, scope: MemoryScope) -> int:
        purged = await self._store.purge_expired(scope)
        records = await self._store.list_scope(
            scope,
            limit=self._configuration.max_records_per_scope_cycle,
        )
        if self._index is not None:
            await self._index.clear_scope(scope)
            for record in records:
                await self.index_record(record)
        await self._observer.observe(
            MemoryRuntimeObservation(
                operation=MemoryRuntimeOperation.RECOVERY,
                outcome=MemoryRuntimeOutcome.SUCCEEDED,
                scope=scope,
                records=len(records),
                total_bytes=sum(record.content_bytes for record in records),
                reason="reconciled",
                created_at=self._now(),
            )
        )
        if purged:
            await self._observer.observe(
                MemoryRuntimeObservation(
                    operation=MemoryRuntimeOperation.CLEANUP,
                    outcome=MemoryRuntimeOutcome.SUCCEEDED,
                    scope=scope,
                    records=purged,
                    reason="expired_purged",
                    created_at=self._now(),
                )
            )
        return len(records)

    async def index_record(self, record: MemoryRecord) -> bool:
        if self._index is None or self._provider is None:
            return False
        if not isinstance(record, MemoryRecord):
            raise TypeError("record must be MemoryRecord")
        if record.status is not MemoryRecordStatus.ACTIVE or record.content is None:
            return False
        try:
            vector = await _provider_embedding(
                self._provider,
                record.content,
                operation_timeout=self._configuration.operation_timeout,
            )
            await self._index.upsert(
                MemoryRetrievalCandidate(
                    scope=record.scope,
                    memory_id=record.memory_id,
                    version=record.version,
                    content_digest=record.content_digest,
                    score=0.0,
                ),
                vector,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._observer.observe(
                MemoryRuntimeObservation(
                    operation=MemoryRuntimeOperation.INDEX,
                    outcome=MemoryRuntimeOutcome.FAILED,
                    scope=record.scope,
                    memory_id=record.memory_id,
                    reason="index_update_failed",
                    created_at=self._now(),
                )
            )
            return False
        await self._observer.observe(
            MemoryRuntimeObservation(
                operation=MemoryRuntimeOperation.INDEX,
                outcome=MemoryRuntimeOutcome.SUCCEEDED,
                scope=record.scope,
                memory_id=record.memory_id,
                reason="indexed",
                created_at=self._now(),
            )
        )
        return True

    async def drop_record(self, scope: MemoryScope, memory_id: MemoryId) -> None:
        if self._index is None:
            return
        try:
            await self._index.delete(scope, memory_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._observer.observe(
                MemoryRuntimeObservation(
                    operation=MemoryRuntimeOperation.INDEX,
                    outcome=MemoryRuntimeOutcome.FAILED,
                    scope=scope,
                    memory_id=memory_id,
                    reason="index_delete_failed",
                    created_at=self._now(),
                )
            )

    async def _maintenance_loop(self) -> None:
        interval = self._configuration.maintenance_interval.total_seconds()
        while not self._closed:
            await asyncio.sleep(interval)
            if self._closed:
                return
            try:
                await self.reconcile_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._observer.observe(
                    MemoryRuntimeObservation(
                        operation=MemoryRuntimeOperation.CLEANUP,
                        outcome=MemoryRuntimeOutcome.FAILED,
                        reason="maintenance_failed",
                        created_at=self._now(),
                    )
                )

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, label="clock result")
        return value


class AgentMemoryRuntimeService:
    """Authorized memory service that keeps an optional derived index synchronized."""

    def __init__(
        self,
        core: AgentMemoryService,
        owner: AgentMemoryRuntimeOwner,
    ) -> None:
        if not isinstance(core, AgentMemoryService):
            raise TypeError("core must be AgentMemoryService")
        if not isinstance(owner, AgentMemoryRuntimeOwner):
            raise TypeError("owner must be AgentMemoryRuntimeOwner")
        self._core = core
        self._owner = owner

    @property
    def limits(self) -> MemoryLimits:
        return self._core.limits

    async def search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> MemorySearchResult:
        return await self._core.search(request, context)

    async def search_context(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> MemoryContextBlock | None:
        return await self._core.search_context(request, context)

    async def read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
    ) -> MemoryRecord | None:
        return await self._core.read(request, context)

    async def write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> MemoryRecord:
        record = await self._core.write(request, context)
        await self._owner.index_record(record)
        return record

    async def delete(
        self,
        request: MemoryDeleteRequest,
        context: SecurityContext,
    ) -> None:
        await self._core.delete(request, context)
        await self._owner.drop_record(request.scope, request.memory_id)


@dataclass(frozen=True, slots=True)
class MemoryAdministrationSnapshot:
    """Content-free administrative view for one independently authorized scope."""

    scope: MemoryScope
    active_records: int
    active_bytes: int
    indexed_records: int
    store_closed: bool
    index_closed: bool | None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if self.active_records < 0 or self.active_bytes < 0 or self.indexed_records < 0:
            raise ValueError("memory administration counters must be non-negative")
        _require_aware(self.created_at, label="created_at")


class AgentMemoryAdministration:
    """Fresh `memory.admin` authorization with content-free results only."""

    def __init__(
        self,
        *,
        authorizer: MemoryAuthorizer,
        store: MemoryStore,
        observer: ContentFreeMemoryObserver,
        index: MemoryDerivedIndex | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if not isinstance(authorizer, MemoryAuthorizer):
            raise TypeError("authorizer must implement MemoryAuthorizer")
        if not isinstance(store, MemoryStore):
            raise TypeError("store must implement MemoryStore")
        if index is not None and not isinstance(index, MemoryDerivedIndex):
            raise TypeError("index must implement MemoryDerivedIndex")
        if not isinstance(observer, ContentFreeMemoryObserver):
            raise TypeError("observer must be ContentFreeMemoryObserver")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._authorizer = authorizer
        self._store = store
        self._index = index
        self._observer = observer
        self._clock = clock

    async def snapshot(
        self,
        scope: MemoryScope,
        context: SecurityContext,
    ) -> MemoryAdministrationSnapshot:
        now = self._now()
        await self._authorizer.authorize_admin(
            scope,
            context,
            created_at=now,
        )
        records = await self._store.list_scope(scope)
        indexed = 0 if self._index is None else await self._index.count_scope(scope)
        snapshot = MemoryAdministrationSnapshot(
            scope=scope,
            active_records=len(records),
            active_bytes=sum(record.content_bytes for record in records),
            indexed_records=indexed,
            store_closed=self._store.closed,
            index_closed=None if self._index is None else self._index.closed,
            created_at=now,
        )
        await self._observer.observe(
            MemoryRuntimeObservation(
                operation=MemoryRuntimeOperation.ADMIN,
                outcome=MemoryRuntimeOutcome.SUCCEEDED,
                scope=scope,
                records=snapshot.active_records,
                total_bytes=snapshot.active_bytes,
                reason="snapshot",
                created_at=now,
            )
        )
        return snapshot

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, label="clock result")
        return value


@dataclass(frozen=True, slots=True)
class AgentMemoryRuntimeStack:
    """Reviewed Runtime-owned memory services for one explicitly enabled agent."""

    configuration: AgentMemoryRuntimeConfiguration
    store: MemoryStore
    retrieval: MemoryRetrievalAdapter
    core: AgentMemoryService
    service: AgentMemoryRuntimeService
    context: ServerOwnedAgentMemoryContextProvider
    observer: ContentFreeMemoryObserver
    owner: AgentMemoryRuntimeOwner
    administration: AgentMemoryAdministration
    index: MemoryDerivedIndex | None = None


def create_agent_memory_runtime_stack(
    *,
    configuration: AgentMemoryRuntimeConfiguration,
    policy: PolicyEngine,
    state_store: StateStore | None = None,
    embedding_provider: MemoryEmbeddingProvider | None = None,
    index: MemoryDerivedIndex | None = None,
    events: EventBus | None = None,
    clock: Clock = _utc_now,
) -> AgentMemoryRuntimeStack:
    """Compose memory only when explicitly requested by Runtime configuration."""

    if not isinstance(configuration, AgentMemoryRuntimeConfiguration):
        raise TypeError("configuration must be AgentMemoryRuntimeConfiguration")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    if events is not None and not isinstance(events, EventBus):
        raise TypeError("events must be EventBus or None")
    if not callable(clock):
        raise TypeError("clock must be callable")

    if configuration.semantic_enabled:
        if embedding_provider is None:
            raise ValueError("semantic memory requires an embedding provider")
        if not isinstance(embedding_provider, MemoryEmbeddingProvider):
            raise TypeError("embedding_provider must implement MemoryEmbeddingProvider")
        resolved_index = (
            InMemoryDerivedMemoryIndex(dimension=embedding_provider.dimension)
            if index is None
            else index
        )
        if not isinstance(resolved_index, MemoryDerivedIndex):
            raise TypeError("index must implement MemoryDerivedIndex")
        retrieval: MemoryRetrievalAdapter | None = SemanticMemoryRetrievalAdapter(
            provider=embedding_provider,
            index=resolved_index,
            operation_timeout=configuration.operation_timeout,
        )
    else:
        if embedding_provider is not None or index is not None:
            raise ValueError("semantic provider/index require semantic_enabled")
        resolved_index = None
        retrieval = None

    store: MemoryStore = (
        InMemoryAgentMemoryStore(
            limits=configuration.limits,
            clock=clock,
        )
        if state_store is None
        else StateStoreMemoryStore(
            state_store,
            limits=configuration.limits,
            clock=clock,
            owns_state_store=False,
        )
    )

    if not configuration.semantic_enabled:
        from phoenix_os.agent.memory_retrieval import (
            DeterministicLexicalMemoryRetrievalAdapter,
        )

        retrieval = DeterministicLexicalMemoryRetrievalAdapter(store)

    assert retrieval is not None
    authorizer = PolicyEngineMemoryAuthorizer(policy)
    observer = ContentFreeMemoryObserver(events)
    owner = AgentMemoryRuntimeOwner(
        configuration=configuration,
        store=store,
        observer=observer,
        provider=embedding_provider,
        index=resolved_index,
        clock=clock,
    )
    core = AgentMemoryService(
        store=store,
        authorizer=authorizer,
        retrieval=retrieval,
        limits=configuration.limits,
        clock=clock,
    )
    service = AgentMemoryRuntimeService(core, owner)
    context = ServerOwnedAgentMemoryContextProvider(
        service=core,
        namespace=configuration.namespace,
        scope_kind=configuration.scope_kind,
        clock=clock,
    )
    administration = AgentMemoryAdministration(
        authorizer=authorizer,
        store=store,
        observer=observer,
        index=resolved_index,
        clock=clock,
    )
    return AgentMemoryRuntimeStack(
        configuration=configuration,
        store=store,
        retrieval=retrieval,
        core=core,
        service=service,
        context=context,
        observer=observer,
        owner=owner,
        administration=administration,
        index=resolved_index,
    )
