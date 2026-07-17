"""Immutable public contracts for Phoenix state stores."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType, TracebackType
from typing import Protocol, TypeVar
from uuid import UUID

T = TypeVar("T")

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
ABSENT_VERSION = 0


def _normalize_name(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized or _NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid state {label}: {value!r}")
    return normalized


def _freeze_metadata(value: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class StateKey[T]:
    """Typed, namespace-qualified identity for one state value."""

    namespace: str
    name: str
    expected_type: type[T] | None = field(default=None, repr=False, compare=False)
    # Python 3.12 typing assigns __orig_class__ after constructing StateKey[T].
    # Frozen slotted dataclasses otherwise route that assignment through a
    # stale dataclass closure and raise TypeError instead of AttributeError.
    # Reserving the slot makes the generated frozen guard raise
    # FrozenInstanceError (an AttributeError), which typing safely ignores.
    __orig_class__: object = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "namespace", _normalize_name(self.namespace, label="namespace"))
        object.__setattr__(self, "name", _normalize_name(self.name, label="key"))
        if self.expected_type is not None and not isinstance(self.expected_type, type):
            raise TypeError("expected_type must be a concrete type")

    @property
    def canonical(self) -> str:
        """Return the deterministic storage identity for the key."""

        return f"{self.namespace}:{self.name}"


@dataclass(frozen=True, slots=True)
class StateOperationContext:
    """Correlation metadata propagated to state events and diagnostics."""

    correlation_id: str | None = None
    causation_id: UUID | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.correlation_id is not None:
            normalized = self.correlation_id.strip()
            if not normalized:
                raise ValueError("correlation_id must not be blank")
            object.__setattr__(self, "correlation_id", normalized)
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class StateRecord[T]:
    """Immutable decoded state value and its optimistic-concurrency version."""

    key: StateKey[T]
    value: T
    version: int
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    # Keep parameterized construction compatible with Python 3.12 for the
    # same frozen-slots reason documented on StateKey.__orig_class__.
    __orig_class__: object = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValueError("state versions must be positive")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("state timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise ValueError("expires_at must be timezone-aware")
            if self.expires_at <= self.updated_at:
                raise ValueError("expires_at must be later than updated_at")

    @property
    def ttl(self) -> timedelta | None:
        """Return the original TTL interval represented by this record."""

        if self.expires_at is None:
            return None
        return self.expires_at - self.updated_at


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """Portable logical snapshot of non-expired records."""

    revision: int
    records: tuple[StateRecord[object], ...]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.revision < 0:
            raise ValueError("snapshot revision cannot be negative")
        if self.created_at.tzinfo is None:
            raise ValueError("snapshot created_at must be timezone-aware")
        identities = [record.key.canonical for record in self.records]
        if len(identities) != len(set(identities)):
            raise ValueError("snapshot records must have unique keys")


class RestoreMode(StrEnum):
    """How snapshot contents are combined with existing records."""

    REPLACE = "replace"
    MERGE = "merge"


class TransactionState(StrEnum):
    """Observable lifecycle state of a state transaction."""

    NEW = "new"
    OPEN = "open"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class StateStoreStats:
    """Point-in-time counters and storage status."""

    closed: bool
    revision: int
    records: int
    reads: int
    writes: int
    deletes: int
    expirations: int
    conflicts: int
    transactions: int


class StateCodec(Protocol):
    """Safe serializer used by a state store."""

    def encode(self, value: object) -> bytes: ...

    def decode(self, payload: bytes) -> object: ...


class StateTransaction(Protocol):
    """Serializable asynchronous transaction contract."""

    @property
    def state(self) -> TransactionState: ...

    def __aenter__(self) -> Awaitable[StateTransaction]: ...

    def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Awaitable[None]: ...

    def get(self, key: StateKey[T]) -> Awaitable[StateRecord[T] | None]: ...

    def put(
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
    ) -> Awaitable[StateRecord[T]]: ...

    def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
    ) -> Awaitable[bool]: ...

    def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
    ) -> Awaitable[tuple[StateRecord[object], ...]]: ...

    def commit(self) -> Awaitable[None]: ...

    def rollback(self) -> Awaitable[None]: ...


class StateStore(Protocol):
    """Asynchronous persistence boundary used by Phoenix services."""

    @property
    def closed(self) -> bool: ...

    def get(
        self,
        key: StateKey[T],
        *,
        context: StateOperationContext | None = None,
    ) -> Awaitable[StateRecord[T] | None]: ...

    def put(
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
        context: StateOperationContext | None = None,
    ) -> Awaitable[StateRecord[T]]: ...

    def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
        context: StateOperationContext | None = None,
    ) -> Awaitable[bool]: ...

    def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
        context: StateOperationContext | None = None,
    ) -> Awaitable[tuple[StateRecord[object], ...]]: ...

    def transaction(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> StateTransaction: ...

    def snapshot(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> Awaitable[StateSnapshot]: ...

    def restore(
        self,
        snapshot: StateSnapshot,
        *,
        mode: RestoreMode = RestoreMode.REPLACE,
        context: StateOperationContext | None = None,
    ) -> Awaitable[int]: ...

    def purge_expired(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> Awaitable[int]: ...

    def stats(self) -> Awaitable[StateStoreStats]: ...

    def close(self) -> Awaitable[None]: ...

    def start(self, context: object) -> Awaitable[None]: ...

    def stop(self, context: object) -> Awaitable[None]: ...
