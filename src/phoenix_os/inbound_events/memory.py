"""Bounded in-memory repositories for secure inbound event state."""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar
from uuid import UUID

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
    InboundEventAlreadyExistsError,
    InboundEventCapacityError,
    InboundEventConflictError,
    InboundEventNotFoundError,
    InboundEventRepositoryClosedError,
    InboundReplayAlreadyExistsError,
    InboundReplayCapacityError,
    InboundReplayRepositoryClosedError,
    InboundSourceAlreadyExistsError,
    InboundSourceCapacityError,
    InboundSourceConflictError,
    InboundSourceNotFoundError,
    InboundSourceRepositoryClosedError,
)


class InMemoryInboundSourceRepository:
    """Process-local source repository with bounded unique indexes."""

    def __init__(self, *, capacity: int = 256) -> None:
        if not 1 <= capacity <= MAX_INBOUND_SOURCE_CAPACITY:
            raise ValueError(
                f"inbound source capacity must be between 1 and {MAX_INBOUND_SOURCE_CAPACITY}"
            )
        self._capacity = capacity
        self._sources: dict[UUID, InboundEventSource] = {}
        self._name_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, source: InboundEventSource) -> None:
        if not isinstance(source, InboundEventSource):
            raise TypeError("source must be InboundEventSource")
        async with self._lock:
            self._require_open()
            if source.id in self._sources:
                raise InboundSourceAlreadyExistsError("inbound source id already exists")
            if source.name in self._name_index:
                raise InboundSourceAlreadyExistsError("inbound source name already exists")
            if len(self._sources) >= self._capacity:
                raise InboundSourceCapacityError(
                    "inbound source repository capacity has been exhausted"
                )
            self._sources[source.id] = source
            self._name_index[source.name] = source.id

    async def get(self, source_id: UUID) -> InboundEventSource | None:
        async with self._lock:
            self._require_open()
            return self._sources.get(source_id)

    async def get_by_name(self, name: str) -> InboundEventSource | None:
        normalized = _normalize_name(name, label="inbound source")
        async with self._lock:
            self._require_open()
            source_id = self._name_index.get(normalized)
            return None if source_id is None else self._sources[source_id]

    async def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundSourcePage:
        async with self._lock:
            self._require_open()
            ordered = tuple(
                sorted(self._sources.values(), key=lambda item: (item.name, item.id.hex))
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

    async def replace(
        self,
        source: InboundEventSource,
        *,
        expected_revision: int,
    ) -> InboundEventSource:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        async with self._lock:
            self._require_open()
            current = self._sources.get(source.id)
            if current is None:
                raise InboundSourceNotFoundError("inbound source was not found")
            _validate_source_replacement(current, source, expected_revision=expected_revision)
            owner = self._name_index.get(source.name)
            if owner is not None and owner != source.id:
                raise InboundSourceAlreadyExistsError("inbound source name already exists")
            if current.name != source.name:
                del self._name_index[current.name]
                self._name_index[source.name] = source.id
            self._sources[source.id] = source
            return source

    async def snapshot(self) -> InboundSourceRepositorySnapshot:
        async with self._lock:
            statuses = Counter(item.status for item in self._sources.values())
            return InboundSourceRepositorySnapshot(
                closed=self._closed,
                sources=len(self._sources),
                active=statuses[InboundEventSourceStatus.ACTIVE],
                disabled=statuses[InboundEventSourceStatus.DISABLED],
                revoked=statuses[InboundEventSourceStatus.REVOKED],
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise InboundSourceRepositoryClosedError("inbound source repository is closed")


@dataclass(slots=True)
class _InboundMemoryBackend:
    event_capacity: int
    replay_capacity: int
    events: dict[UUID, InboundAcceptedEvent] = field(default_factory=dict, init=False)
    receipts: dict[UUID, InboundEventReceipt] = field(default_factory=dict, init=False)
    source_event_index: dict[tuple[UUID, str], UUID] = field(default_factory=dict, init=False)
    replays: dict[tuple[UUID, InboundReplayKind, str], InboundReplayReservation] = field(
        default_factory=dict, init=False
    )
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)


class InMemoryInboundEventRepository:
    """Process-local accepted-event repository with atomic replay reservations."""

    _ALLOWED_TRANSITIONS: ClassVar[
        dict[InboundPublicationStatus, frozenset[InboundPublicationStatus]]
    ] = {
        InboundPublicationStatus.PENDING: frozenset(
            {InboundPublicationStatus.PUBLISHING, InboundPublicationStatus.DISCARDED}
        ),
        InboundPublicationStatus.PUBLISHING: frozenset(
            {
                InboundPublicationStatus.RETRYING,
                InboundPublicationStatus.PUBLISHED,
                InboundPublicationStatus.DEAD_LETTER,
                InboundPublicationStatus.DISCARDED,
            }
        ),
        InboundPublicationStatus.RETRYING: frozenset(
            {InboundPublicationStatus.PUBLISHING, InboundPublicationStatus.DISCARDED}
        ),
        InboundPublicationStatus.DEAD_LETTER: frozenset({InboundPublicationStatus.RETRYING}),
    }

    def __init__(
        self,
        *,
        capacity: int = 4_096,
        replay_capacity: int = 16_384,
        replay_repository: InMemoryInboundReplayRepository | None = None,
    ) -> None:
        if not 1 <= capacity <= MAX_INBOUND_EVENT_CAPACITY:
            raise ValueError(
                f"inbound event capacity must be between 1 and {MAX_INBOUND_EVENT_CAPACITY}"
            )
        if not 1 <= replay_capacity <= MAX_INBOUND_REPLAY_CAPACITY:
            raise ValueError(
                f"inbound replay capacity must be between 1 and {MAX_INBOUND_REPLAY_CAPACITY}"
            )
        if replay_repository is None:
            self._backend = _InboundMemoryBackend(capacity, replay_capacity)
        else:
            if not isinstance(replay_repository, InMemoryInboundReplayRepository):
                raise TypeError("replay_repository must be InMemoryInboundReplayRepository")
            self._backend = replay_repository._backend
            if self._backend.events:
                raise ValueError("shared inbound replay repository already contains events")
            self._backend.event_capacity = capacity
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def accept(self, acceptance: InboundAcceptance) -> None:
        if not isinstance(acceptance, InboundAcceptance):
            raise TypeError("acceptance must be InboundAcceptance")
        event = acceptance.event
        receipt = acceptance.receipt
        source_reservation = next(
            item
            for item in acceptance.replay_reservations
            if item.kind is InboundReplayKind.SOURCE_EVENT_ID
        )
        source_key = (event.source_id, source_reservation.evidence_digest)
        async with self._backend.lock:
            self._require_open()
            if event.id in self._backend.events:
                raise InboundEventAlreadyExistsError("inbound accepted event id already exists")
            if receipt.id in self._backend.receipts:
                raise InboundEventAlreadyExistsError("inbound receipt id already exists")
            if source_key in self._backend.source_event_index:
                raise InboundEventAlreadyExistsError("inbound source-event identity already exists")
            duplicate = next(
                (
                    reservation
                    for reservation in acceptance.replay_reservations
                    if reservation.key in self._backend.replays
                ),
                None,
            )
            if duplicate is not None:
                raise InboundReplayAlreadyExistsError(
                    f"inbound {duplicate.kind.value} evidence is already reserved"
                )
            if len(self._backend.events) >= self._backend.event_capacity:
                raise InboundEventCapacityError(
                    "inbound event repository capacity has been exhausted"
                )
            if (
                len(self._backend.replays) + len(acceptance.replay_reservations)
                > self._backend.replay_capacity
            ):
                raise InboundReplayCapacityError(
                    "inbound replay repository capacity has been exhausted"
                )

            self._backend.events[event.id] = event
            self._backend.receipts[receipt.id] = receipt
            self._backend.source_event_index[source_key] = event.id
            for reservation in acceptance.replay_reservations:
                self._backend.replays[reservation.key] = reservation

    async def reserve_idempotent_replay(
        self,
        accepted_event_id: UUID,
        reservations: tuple[InboundReplayReservation, InboundReplayReservation],
    ) -> None:
        async with self._backend.lock:
            self._require_open()
            event = self._backend.events.get(accepted_event_id)
            if event is None:
                raise InboundEventNotFoundError("inbound accepted event was not found")
            validated = _validate_idempotent_replay_reservations(event, reservations)
            duplicate = next(
                (
                    reservation
                    for reservation in validated
                    if reservation.key in self._backend.replays
                ),
                None,
            )
            if duplicate is not None:
                raise InboundReplayAlreadyExistsError(
                    f"inbound {duplicate.kind.value} evidence is already reserved"
                )
            if len(self._backend.replays) + len(validated) > self._backend.replay_capacity:
                raise InboundReplayCapacityError(
                    "inbound replay repository capacity has been exhausted"
                )
            for reservation in validated:
                self._backend.replays[reservation.key] = reservation

    async def get(self, accepted_event_id: UUID) -> InboundAcceptedEvent | None:
        async with self._backend.lock:
            self._require_open()
            return self._backend.events.get(accepted_event_id)

    async def get_receipt(self, receipt_id: UUID) -> InboundEventReceipt | None:
        async with self._backend.lock:
            self._require_open()
            return self._backend.receipts.get(receipt_id)

    async def get_by_source_event_digest(
        self,
        source_id: UUID,
        source_event_digest: str,
    ) -> InboundAcceptedEvent | None:
        digest = _normalize_sha256(
            source_event_digest,
            label="inbound source-event digest",
        )
        async with self._backend.lock:
            self._require_open()
            event_id = self._backend.source_event_index.get((source_id, digest))
            return None if event_id is None else self._backend.events[event_id]

    async def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundEventPage:
        async with self._backend.lock:
            self._require_open()
            ordered = tuple(
                sorted(
                    self._backend.events.values(),
                    key=lambda item: (item.accepted_at, item.id.hex),
                )
            )
            items = ordered[request.offset : request.offset + request.limit]
            return InboundEventPage(
                items=items,
                page=InboundPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )

    async def replace(
        self,
        event: InboundAcceptedEvent,
        *,
        expected_revision: int,
    ) -> InboundAcceptedEvent:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        async with self._backend.lock:
            self._require_open()
            current = self._backend.events.get(event.id)
            if current is None:
                raise InboundEventNotFoundError("inbound accepted event was not found")
            _validate_event_replacement(current, event, expected_revision=expected_revision)
            self._backend.events[event.id] = event
            return event

    async def snapshot(self) -> InboundEventRepositorySnapshot:
        async with self._backend.lock:
            statuses = Counter(item.status for item in self._backend.events.values())
            return InboundEventRepositorySnapshot(
                closed=self._closed,
                events=len(self._backend.events),
                pending=statuses[InboundPublicationStatus.PENDING],
                publishing=statuses[InboundPublicationStatus.PUBLISHING],
                retrying=statuses[InboundPublicationStatus.RETRYING],
                published=statuses[InboundPublicationStatus.PUBLISHED],
                dead_letter=statuses[InboundPublicationStatus.DEAD_LETTER],
                discarded=statuses[InboundPublicationStatus.DISCARDED],
                attempts=sum(item.completed_attempts for item in self._backend.events.values()),
                capacity=self._backend.event_capacity,
            )

    async def close(self) -> None:
        async with self._backend.lock:
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise InboundEventRepositoryClosedError("inbound event repository is closed")


def _validate_event_replacement(
    current: InboundAcceptedEvent,
    replacement: InboundAcceptedEvent,
    *,
    expected_revision: int,
) -> None:
    if current.revision != expected_revision:
        raise InboundEventConflictError("inbound event revision conflict")
    if replacement.revision != expected_revision + 1:
        raise InboundEventConflictError(
            "replacement inbound event revision must increment exactly once"
        )
    _validate_event_immutable_metadata(current, replacement)
    if replacement.updated_at < current.updated_at:
        raise InboundEventConflictError(
            "replacement inbound event updated_at cannot move backwards"
        )
    redrive = (
        current.status is InboundPublicationStatus.DEAD_LETTER
        and replacement.status is InboundPublicationStatus.RETRYING
    )
    if current.status.terminal and not redrive:
        raise InboundEventConflictError("terminal inbound event is immutable")
    allowed = InMemoryInboundEventRepository._ALLOWED_TRANSITIONS.get(current.status, frozenset())
    if replacement.status not in allowed:
        raise InboundEventConflictError("inbound event lifecycle transition is not allowed")
    _validate_attempt_history(current, replacement)


class InMemoryInboundReplayRepository:
    """Read and prune source-scoped replay reservations from shared memory state."""

    def __init__(
        self,
        *,
        capacity: int = 16_384,
        _backend: _InboundMemoryBackend | None = None,
    ) -> None:
        if not 1 <= capacity <= MAX_INBOUND_REPLAY_CAPACITY:
            raise ValueError(
                f"inbound replay capacity must be between 1 and {MAX_INBOUND_REPLAY_CAPACITY}"
            )
        self._backend = _backend or _InboundMemoryBackend(4_096, capacity)
        self._backend.replay_capacity = capacity
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
        normalized_kind = InboundReplayKind(kind)
        digest = _normalize_sha256(
            evidence_digest,
            label="inbound replay evidence digest",
        )
        async with self._backend.lock:
            self._require_open()
            return self._backend.replays.get((source_id, normalized_kind, digest))

    async def list(
        self,
        request: InboundPageRequest = DEFAULT_INBOUND_PAGE_REQUEST,
    ) -> InboundReplayPage:
        async with self._backend.lock:
            self._require_open()
            ordered = tuple(
                sorted(
                    self._backend.replays.values(),
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

    async def prune_expired(self, *, now: datetime) -> int:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        async with self._backend.lock:
            self._require_open()
            expired = tuple(
                key
                for key, reservation in self._backend.replays.items()
                if reservation.expires_at <= now
            )
            for key in expired:
                del self._backend.replays[key]
            return len(expired)

    async def snapshot(self) -> InboundReplayRepositorySnapshot:
        async with self._backend.lock:
            kinds = Counter(item.kind for item in self._backend.replays.values())
            return InboundReplayRepositorySnapshot(
                closed=self._closed,
                reservations=len(self._backend.replays),
                request_ids=kinds[InboundReplayKind.REQUEST_ID],
                nonces=kinds[InboundReplayKind.NONCE],
                source_events=kinds[InboundReplayKind.SOURCE_EVENT_ID],
                capacity=self._backend.replay_capacity,
            )

    async def close(self) -> None:
        async with self._backend.lock:
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise InboundReplayRepositoryClosedError("inbound replay repository is closed")


@dataclass(frozen=True, slots=True)
class InMemoryInboundRepositories:
    """Coordinated reference repositories sharing one atomic event/replay backend."""

    sources: InMemoryInboundSourceRepository
    events: InMemoryInboundEventRepository
    replay: InMemoryInboundReplayRepository

    async def close(self) -> None:
        await self.sources.close()
        await self.events.close()
        await self.replay.close()


def create_in_memory_inbound_repositories(
    *,
    source_capacity: int = 256,
    event_capacity: int = 4_096,
    replay_capacity: int = 16_384,
) -> InMemoryInboundRepositories:
    """Create coordinated bounded reference repositories."""

    replay = InMemoryInboundReplayRepository(capacity=replay_capacity)
    events = InMemoryInboundEventRepository(
        capacity=event_capacity,
        replay_capacity=replay_capacity,
        replay_repository=replay,
    )
    return InMemoryInboundRepositories(
        sources=InMemoryInboundSourceRepository(capacity=source_capacity),
        events=events,
        replay=replay,
    )


def _validate_source_replacement(
    current: InboundEventSource,
    replacement: InboundEventSource,
    *,
    expected_revision: int,
) -> None:
    if current.revision != expected_revision:
        raise InboundSourceConflictError("inbound source revision conflict")
    if replacement.revision != expected_revision + 1:
        raise InboundSourceConflictError(
            "replacement inbound source revision must increment exactly once"
        )
    if replacement.id != current.id:
        raise InboundSourceConflictError("replacement inbound source cannot change id")
    if replacement.created_at != current.created_at:
        raise InboundSourceConflictError("replacement inbound source cannot change created_at")
    if replacement.created_by != current.created_by:
        raise InboundSourceConflictError("replacement inbound source cannot change created_by")
    if replacement.schema_version != current.schema_version:
        raise InboundSourceConflictError("replacement inbound source cannot change schema version")
    if replacement.updated_at < current.updated_at:
        raise InboundSourceConflictError(
            "replacement inbound source updated_at cannot move backwards"
        )
    if current.status is InboundEventSourceStatus.REVOKED:
        raise InboundSourceConflictError("revoked inbound source is terminal")


def _validate_event_immutable_metadata(
    current: InboundAcceptedEvent,
    replacement: InboundAcceptedEvent,
) -> None:
    immutable_fields = (
        "receipt_id",
        "source_id",
        "source_event_id",
        "external_event_type",
        "external_schema_version",
        "internal_event_type",
        "occurred_at",
        "accepted_at",
        "normalized_payload",
        "normalized_payload_sha256",
        "correlation_id",
        "schema_version",
    )
    for field_name in immutable_fields:
        if getattr(replacement, field_name) != getattr(current, field_name):
            raise InboundEventConflictError(f"replacement inbound event cannot change {field_name}")


def _validate_attempt_history(
    current: InboundAcceptedEvent,
    replacement: InboundAcceptedEvent,
) -> None:
    completed = len(current.attempts)
    if replacement.attempts[:completed] != current.attempts:
        raise InboundEventConflictError(
            "replacement inbound event cannot rewrite publication history"
        )
    added = len(replacement.attempts) - completed
    if added < 0 or added > 1:
        raise InboundEventConflictError(
            "replacement inbound event may append at most one publication attempt"
        )
    if current.status is InboundPublicationStatus.PUBLISHING:
        if replacement.status is InboundPublicationStatus.DISCARDED:
            if added != 0:
                raise InboundEventConflictError(
                    "discarded inbound event cannot append a publication attempt"
                )
            return
        if added != 1:
            raise InboundEventConflictError(
                "completed publishing event must append one publication attempt"
            )
        if replacement.attempts[-1].number != current.current_attempt:
            raise InboundEventConflictError(
                "completed inbound attempt number does not match publishing state"
            )
        return
    if added != 0:
        raise InboundEventConflictError("inbound event may append attempts only while publishing")
