"""Serializable in-memory implementation of the Phoenix state-store contract."""

from __future__ import annotations

import asyncio
import builtins
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import TypeVar, cast

from phoenix_os.events import BusClosedError, EventBus
from phoenix_os.observability import (
    MetricKind,
    ObservabilityClosedError,
    ObservabilityHub,
    Severity,
)
from phoenix_os.state.codec import JsonStateCodec
from phoenix_os.state.contracts import (
    ABSENT_VERSION,
    RestoreMode,
    StateCodec,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateSnapshot,
    StateStoreStats,
    TransactionState,
    _normalize_name,
)
from phoenix_os.state.errors import (
    StateConflictError,
    StateStoreClosedError,
    StateTransactionError,
    StateTypeError,
)

T = TypeVar("T")
type Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class _StoredValue:
    key: StateKey[object]
    payload: bytes
    version: int
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class _StateSignal:
    name: str
    payload: Mapping[str, object]
    context: StateOperationContext | None
    severity: Severity = Severity.INFO


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _validate_expected_version(expected_version: int | None) -> None:
    if expected_version is not None and expected_version < ABSENT_VERSION:
        raise ValueError("expected_version cannot be negative")


def _validate_ttl(ttl: timedelta | None) -> None:
    if ttl is not None and ttl <= timedelta(0):
        raise ValueError("ttl must be greater than zero")


def _actual_version(stored: _StoredValue | None) -> int | None:
    return None if stored is None else stored.version


def _matches_expected(stored: _StoredValue | None, expected_version: int | None) -> bool:
    if expected_version is None:
        return True
    if expected_version == ABSENT_VERSION:
        return stored is None
    return stored is not None and stored.version == expected_version


class MemoryStateStore:
    """Safe, deterministic and serializable in-memory state store."""

    def __init__(
        self,
        *,
        codec: StateCodec | None = None,
        events: EventBus | None = None,
        observability: ObservabilityHub | None = None,
        clock: Clock = _utc_now,
        source: str = "phoenix.state.memory",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._codec = JsonStateCodec() if codec is None else codec
        self._events = events
        self._observability = observability
        self._clock = clock
        self._source = normalized_source
        self._records: dict[str, _StoredValue] = {}
        self._revision = 0
        self._closed = False
        self._reads = 0
        self._writes = 0
        self._deletes = 0
        self._expirations = 0
        self._conflicts = 0
        self._transactions = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def get(
        self,
        key: StateKey[T],
        *,
        context: StateOperationContext | None = None,
    ) -> StateRecord[T] | None:
        async with self._trace("get", key=key, context=context):
            expired: list[_StateSignal]
            async with self._lock:
                self._ensure_open()
                expired = self._expire_locked(self._clock(), only=key.canonical)
                stored = self._records.get(key.canonical)
                self._reads += 1
                record = None if stored is None else self._decode_record(stored, key)
            await self._emit_signals(expired)
            await self._signal(
                "state.read",
                {
                    "key": key.canonical,
                    "found": record is not None,
                    "version": None if record is None else record.version,
                },
                context,
            )
            return record

    async def put(
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
        context: StateOperationContext | None = None,
    ) -> StateRecord[T]:
        _validate_expected_version(expected_version)
        _validate_ttl(ttl)
        payload = self._codec.encode(value)
        async with self._trace("put", key=key, context=context):
            expired: list[_StateSignal]
            conflict: StateConflictError | None = None
            result: StateRecord[T] | None = None
            async with self._lock:
                self._ensure_open()
                now = self._clock()
                expired = self._expire_locked(now, only=key.canonical)
                current = self._records.get(key.canonical)
                if not _matches_expected(current, expected_version):
                    self._conflicts += 1
                    conflict = StateConflictError(
                        cast(StateKey[object], key),
                        cast(int, expected_version),
                        _actual_version(current),
                    )
                else:
                    self._revision += 1
                    created_at = now if current is None else current.created_at
                    stored = _StoredValue(
                        key=StateKey(key.namespace, key.name),
                        payload=payload,
                        version=self._revision,
                        created_at=created_at,
                        updated_at=now,
                        expires_at=None if ttl is None else now + ttl,
                    )
                    self._records[key.canonical] = stored
                    self._writes += 1
                    result = self._decode_record(stored, key)
            await self._emit_signals(expired)
            if conflict is not None:
                await self._signal(
                    "state.conflict",
                    {
                        "key": key.canonical,
                        "expected_version": expected_version,
                        "actual_version": conflict.actual_version,
                        "operation": "put",
                    },
                    context,
                    severity=Severity.WARNING,
                )
                raise conflict
            assert result is not None
            await self._signal(
                "state.written",
                {
                    "key": key.canonical,
                    "version": result.version,
                    "created": result.created_at == result.updated_at,
                    "expires_at": None
                    if result.expires_at is None
                    else result.expires_at.isoformat(),
                },
                context,
            )
            return result

    async def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
        context: StateOperationContext | None = None,
    ) -> bool:
        _validate_expected_version(expected_version)
        async with self._trace("delete", key=key, context=context):
            expired: list[_StateSignal]
            conflict: StateConflictError | None = None
            deleted_version: int | None = None
            async with self._lock:
                self._ensure_open()
                expired = self._expire_locked(self._clock(), only=key.canonical)
                current = self._records.get(key.canonical)
                if current is None:
                    if expected_version not in {None, ABSENT_VERSION}:
                        self._conflicts += 1
                        conflict = StateConflictError(key, expected_version, None)
                elif not _matches_expected(current, expected_version):
                    self._conflicts += 1
                    conflict = StateConflictError(
                        key,
                        cast(int, expected_version),
                        current.version,
                    )
                else:
                    deleted_version = current.version
                    del self._records[key.canonical]
                    self._revision += 1
                    self._deletes += 1
            await self._emit_signals(expired)
            if conflict is not None:
                await self._signal(
                    "state.conflict",
                    {
                        "key": key.canonical,
                        "expected_version": expected_version,
                        "actual_version": conflict.actual_version,
                        "operation": "delete",
                    },
                    context,
                    severity=Severity.WARNING,
                )
                raise conflict
            deleted = deleted_version is not None
            await self._signal(
                "state.deleted",
                {
                    "key": key.canonical,
                    "deleted": deleted,
                    "previous_version": deleted_version,
                },
                context,
            )
            return deleted

    async def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
        context: StateOperationContext | None = None,
    ) -> tuple[StateRecord[object], ...]:
        normalized_namespace = (
            None if namespace is None else _normalize_name(namespace, label="namespace")
        )
        normalized_prefix = None if prefix is None else prefix.strip().lower()
        if normalized_prefix == "":
            raise ValueError("prefix must not be blank")
        async with self._trace("list", context=context):
            async with self._lock:
                self._ensure_open()
                expired = self._expire_locked(self._clock())
                selected = [
                    stored
                    for stored in self._records.values()
                    if (
                        normalized_namespace is None or stored.key.namespace == normalized_namespace
                    )
                    and (normalized_prefix is None or stored.key.name.startswith(normalized_prefix))
                ]
                selected.sort(key=lambda item: item.key.canonical)
                self._reads += 1
                records = tuple(self._decode_record(stored, stored.key) for stored in selected)
            await self._emit_signals(expired)
            await self._signal(
                "state.listed",
                {
                    "namespace": normalized_namespace,
                    "prefix": normalized_prefix,
                    "records": len(records),
                },
                context,
            )
            return records

    def transaction(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> MemoryStateTransaction:
        self._ensure_open()
        return MemoryStateTransaction(self, context=context)

    async def snapshot(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> StateSnapshot:
        async with self._trace("snapshot", context=context):
            async with self._lock:
                self._ensure_open()
                expired = self._expire_locked(self._clock())
                records = tuple(
                    self._decode_record(stored, stored.key)
                    for stored in sorted(
                        self._records.values(), key=lambda item: item.key.canonical
                    )
                )
                snapshot = StateSnapshot(
                    revision=self._revision,
                    records=records,
                    created_at=self._clock(),
                )
            await self._emit_signals(expired)
            await self._signal(
                "state.snapshot.created",
                {"revision": snapshot.revision, "records": len(snapshot.records)},
                context,
            )
            return snapshot

    async def restore(
        self,
        snapshot: StateSnapshot,
        *,
        mode: RestoreMode = RestoreMode.REPLACE,
        context: StateOperationContext | None = None,
    ) -> int:
        encoded = [(record, self._codec.encode(record.value)) for record in snapshot.records]
        async with self._trace("restore", context=context):
            async with self._lock:
                self._ensure_open()
                now = self._clock()
                expired = self._expire_locked(now)
                if mode is RestoreMode.REPLACE:
                    self._records.clear()
                restored = 0
                for record, payload in encoded:
                    if record.expires_at is not None and record.expires_at <= now:
                        continue
                    self._revision += 1
                    stored = _StoredValue(
                        key=StateKey(record.key.namespace, record.key.name),
                        payload=payload,
                        version=self._revision,
                        created_at=record.created_at,
                        updated_at=now,
                        expires_at=record.expires_at,
                    )
                    self._records[record.key.canonical] = stored
                    restored += 1
                self._writes += restored
            await self._emit_signals(expired)
            await self._signal(
                "state.snapshot.restored",
                {
                    "snapshot_revision": snapshot.revision,
                    "mode": mode.value,
                    "restored": restored,
                },
                context,
            )
            return restored

    async def purge_expired(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> int:
        async with self._trace("purge", context=context):
            async with self._lock:
                self._ensure_open()
                expired = self._expire_locked(self._clock())
            await self._emit_signals(expired)
            await self._signal(
                "state.expiration.purged",
                {"expired": len(expired)},
                context,
            )
            return len(expired)

    async def stats(self) -> StateStoreStats:
        async with self._lock:
            return StateStoreStats(
                closed=self._closed,
                revision=self._revision,
                records=len(self._records),
                reads=self._reads,
                writes=self._writes,
                deletes=self._deletes,
                expirations=self._expirations,
                conflicts=self._conflicts,
                transactions=self._transactions,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            records = len(self._records)
            self._records.clear()
            self._closed = True
        await self._signal("state.closed", {"records_cleared": records}, None)

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    def _decode_record(self, stored: _StoredValue, key: StateKey[T]) -> StateRecord[T]:
        value = self._codec.decode(stored.payload)
        if key.expected_type is not None and not isinstance(value, key.expected_type):
            raise StateTypeError(
                f"state value {key.canonical!r} has type {type(value).__name__}, "
                f"expected {key.expected_type.__name__}"
            )
        return StateRecord(
            key=key,
            value=cast(T, value),
            version=stored.version,
            created_at=stored.created_at,
            updated_at=stored.updated_at,
            expires_at=stored.expires_at,
        )

    def _expire_locked(
        self,
        now: datetime,
        *,
        only: str | None = None,
    ) -> builtins.list[_StateSignal]:
        if now.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        signals: builtins.list[_StateSignal] = []
        candidates = (
            [self._records[only]]
            if only is not None and only in self._records
            else builtins.list(self._records.values())
            if only is None
            else []
        )
        for stored in candidates:
            if stored.expires_at is None or stored.expires_at > now:
                continue
            self._records.pop(stored.key.canonical, None)
            self._revision += 1
            self._expirations += 1
            signals.append(
                _StateSignal(
                    "state.expired",
                    {"key": stored.key.canonical, "version": stored.version},
                    None,
                )
            )
        return signals

    async def _emit_signals(self, signals: builtins.list[_StateSignal]) -> None:
        for signal in signals:
            await self._signal(
                signal.name,
                signal.payload,
                signal.context,
                severity=signal.severity,
            )

    async def _signal(
        self,
        name: str,
        payload: Mapping[str, object],
        context: StateOperationContext | None,
        *,
        severity: Severity = Severity.INFO,
    ) -> None:
        correlation_id = None if context is None else context.correlation_id
        causation_id = None if context is None else context.causation_id
        metadata = {} if context is None else context.metadata
        if self._events is not None:
            try:
                await self._events.emit(
                    name,
                    source=self._source,
                    payload=payload,
                    metadata=metadata,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
            except BusClosedError:
                pass
        if self._observability is not None:
            try:
                await self._observability.log(
                    name,
                    source=self._source,
                    message=name,
                    severity=severity,
                    attributes=payload,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
                await self._observability.metric(
                    "state.operations.total",
                    1,
                    source=self._source,
                    kind=MetricKind.COUNTER,
                    unit="operation",
                    attributes={"operation": name},
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
            except ObservabilityClosedError:
                pass

    @asynccontextmanager
    async def _trace(
        self,
        operation: str,
        *,
        key: StateKey[object] | None = None,
        context: StateOperationContext | None = None,
    ) -> AsyncIterator[None]:
        if self._observability is None or self._observability.closed:
            yield
            return
        attributes: dict[str, object] = {"operation": operation}
        if key is not None:
            attributes["key"] = key.canonical
        async with self._observability.span(
            f"state.{operation}",
            source=self._source,
            attributes=attributes,
            correlation_id=None if context is None else context.correlation_id,
        ):
            yield

    def _ensure_open(self) -> None:
        if self._closed:
            raise StateStoreClosedError("state store is closed")


class MemoryStateTransaction:
    """Serializable transaction that commits atomically or rolls back fully."""

    def __init__(
        self,
        store: MemoryStateStore,
        *,
        context: StateOperationContext | None,
    ) -> None:
        self._store = store
        self._context = context
        self._state = TransactionState.NEW
        self._working: dict[str, _StoredValue] = {}
        self._revision = 0
        self._signals: list[_StateSignal] = []
        self._expired_signals: list[_StateSignal] = []
        self._mutations = 0

    @property
    def state(self) -> TransactionState:
        return self._state

    async def __aenter__(self) -> MemoryStateTransaction:
        if self._state is not TransactionState.NEW:
            raise StateTransactionError("transaction instances cannot be entered more than once")
        await self._store._lock.acquire()
        try:
            self._store._ensure_open()
            self._expired_signals = self._store._expire_locked(self._store._clock())
            self._working = dict(self._store._records)
            self._revision = self._store._revision
            self._state = TransactionState.OPEN
        except BaseException:
            self._store._lock.release()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc, traceback
        if self._state is not TransactionState.OPEN:
            return
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()

    async def get(self, key: StateKey[T]) -> StateRecord[T] | None:
        self._ensure_open()
        self._store._reads += 1
        stored = self._working.get(key.canonical)
        return None if stored is None else self._store._decode_record(stored, key)

    async def put(
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
    ) -> StateRecord[T]:
        self._ensure_open()
        _validate_expected_version(expected_version)
        _validate_ttl(ttl)
        current = self._working.get(key.canonical)
        if not _matches_expected(current, expected_version):
            self._store._conflicts += 1
            raise StateConflictError(
                cast(StateKey[object], key),
                cast(int, expected_version),
                _actual_version(current),
            )
        now = self._store._clock()
        payload = self._store._codec.encode(value)
        self._revision += 1
        stored = _StoredValue(
            key=StateKey(key.namespace, key.name),
            payload=payload,
            version=self._revision,
            created_at=now if current is None else current.created_at,
            updated_at=now,
            expires_at=None if ttl is None else now + ttl,
        )
        self._working[key.canonical] = stored
        self._mutations += 1
        self._signals.append(
            _StateSignal(
                "state.written",
                {
                    "key": key.canonical,
                    "version": stored.version,
                    "transaction": True,
                },
                self._context,
            )
        )
        return self._store._decode_record(stored, key)

    async def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
    ) -> bool:
        self._ensure_open()
        _validate_expected_version(expected_version)
        current = self._working.get(key.canonical)
        if current is None:
            if expected_version not in {None, ABSENT_VERSION}:
                self._store._conflicts += 1
                raise StateConflictError(key, expected_version, None)
            return False
        if not _matches_expected(current, expected_version):
            self._store._conflicts += 1
            raise StateConflictError(key, cast(int, expected_version), current.version)
        del self._working[key.canonical]
        self._revision += 1
        self._mutations += 1
        self._signals.append(
            _StateSignal(
                "state.deleted",
                {
                    "key": key.canonical,
                    "previous_version": current.version,
                    "transaction": True,
                },
                self._context,
            )
        )
        return True

    async def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
    ) -> tuple[StateRecord[object], ...]:
        self._ensure_open()
        normalized_namespace = (
            None if namespace is None else _normalize_name(namespace, label="namespace")
        )
        normalized_prefix = None if prefix is None else prefix.strip().lower()
        if normalized_prefix == "":
            raise ValueError("prefix must not be blank")
        selected = [
            stored
            for stored in self._working.values()
            if (normalized_namespace is None or stored.key.namespace == normalized_namespace)
            and (normalized_prefix is None or stored.key.name.startswith(normalized_prefix))
        ]
        selected.sort(key=lambda item: item.key.canonical)
        self._store._reads += 1
        return tuple(self._store._decode_record(item, item.key) for item in selected)

    async def commit(self) -> None:
        self._ensure_open()
        self._store._records = self._working
        self._store._revision = self._revision
        self._store._writes += sum(signal.name == "state.written" for signal in self._signals)
        self._store._deletes += sum(signal.name == "state.deleted" for signal in self._signals)
        self._store._transactions += 1
        self._state = TransactionState.COMMITTED
        self._store._lock.release()
        await self._store._emit_signals(self._expired_signals)
        await self._store._emit_signals(self._signals)
        await self._store._signal(
            "state.transaction.committed",
            {"mutations": self._mutations, "revision": self._revision},
            self._context,
        )

    async def rollback(self) -> None:
        self._ensure_open()
        self._store._transactions += 1
        self._state = TransactionState.ROLLED_BACK
        self._store._lock.release()
        await self._store._emit_signals(self._expired_signals)
        await self._store._signal(
            "state.transaction.rolled_back",
            {"mutations_discarded": self._mutations},
            self._context,
        )

    def _ensure_open(self) -> None:
        if self._state is not TransactionState.OPEN:
            raise StateTransactionError(f"transaction is not open: {self._state.value}")
