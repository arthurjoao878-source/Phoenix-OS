"""Bounded in-memory reference repository for durable operator sessions."""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import replace
from datetime import datetime
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
    ControlPlaneDurableSessionNotFoundError,
    ControlPlaneDurableSessionRepositoryClosedError,
)


class InMemoryControlPlaneDurableSessionRepository:
    """Process-local digest-only repository with optimistic lifecycle updates."""

    def __init__(
        self,
        *,
        capacity: int = 4096,
        max_sessions_per_operator: int = DEFAULT_DURABLE_SESSIONS_PER_OPERATOR,
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
        self._capacity = capacity
        self._max_sessions_per_operator = max_sessions_per_operator
        self._records: dict[UUID, ControlPlaneDurableSessionRecord] = {}
        self._token_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneDurableSessionRecord) -> None:
        async with self._lock:
            self._require_open()
            self._require_available_identity(record)
            if len(self._records) >= self._capacity:
                raise ControlPlaneDurableSessionCapacityError(
                    "durable session repository capacity has been exhausted"
                )
            if record.status is ControlPlaneDurableSessionStatus.ACTIVE:
                self._require_operator_capacity(record.operator_id)
            self._records[record.id] = record
            self._token_index[record.token_digest] = record.id

    async def get(self, session_id: UUID) -> ControlPlaneDurableSessionRecord | None:
        async with self._lock:
            self._require_open()
            return self._records.get(session_id)

    async def get_by_token_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneDurableSessionRecord | None:
        normalized = _normalize_digest(token_digest)
        async with self._lock:
            self._require_open()
            session_id = self._token_index.get(normalized)
            return None if session_id is None else self._records[session_id]

    async def list_page(
        self,
        request: ControlPlaneDurableSessionPageRequest = DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    ) -> ControlPlaneDurableSessionPage:
        async with self._lock:
            self._require_open()
            filtered = tuple(
                record
                for record in self._records.values()
                if (request.operator_id is None or record.operator_id == request.operator_id)
                and (request.status is None or record.status is request.status)
            )
            ordered = tuple(
                sorted(
                    filtered,
                    key=lambda item: (-item.issued_at.timestamp(), item.id.hex),
                )
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
        async with self._lock:
            self._require_open()
            active = (
                record
                for record in self._records.values()
                if record.operator_id == operator_id
                and record.status is ControlPlaneDurableSessionStatus.ACTIVE
            )
            return tuple(
                sorted(
                    active,
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
        async with self._lock:
            self._require_open()
            current = self._require_record(session_id)
            self._require_revision(current, expected_revision)
            self._require_active(current)
            if seen_at < current.last_seen_at:
                raise ControlPlaneDurableSessionConflictError(
                    "durable session activity time cannot move backwards"
                )
            if seen_at >= current.absolute_expires_at:
                raise ControlPlaneDurableSessionConflictError(
                    "durable session activity cannot reach or exceed absolute expiry"
                )
            if idle_expires_at <= seen_at or idle_expires_at > current.absolute_expires_at:
                raise ControlPlaneDurableSessionConflictError(
                    "durable session idle expiry is inconsistent"
                )
            updated = replace(
                current,
                last_seen_at=seen_at,
                idle_expires_at=idle_expires_at,
                revision=current.revision + 1,
            )
            self._records[session_id] = updated
            return updated

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
        if normalized_status not in {
            ControlPlaneDurableSessionStatus.REVOKED,
            ControlPlaneDurableSessionStatus.EXPIRED,
        }:
            raise ValueError("durable session terminate requires revoked or expired status")
        if normalized_status is ControlPlaneDurableSessionStatus.EXPIRED:
            if not normalized_reason.expiration:
                raise ValueError("expired durable session requires an expiration reason")
        elif normalized_reason.expiration or (
            normalized_reason is ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED
        ):
            raise ValueError("revoked durable session requires a revocation reason")
        async with self._lock:
            self._require_open()
            current = self._require_record(session_id)
            self._require_revision(current, expected_revision)
            self._require_active(current)
            if terminated_at < current.last_seen_at:
                raise ControlPlaneDurableSessionConflictError(
                    "durable session termination cannot precede last activity"
                )
            updated = replace(
                current,
                status=normalized_status,
                terminated_at=terminated_at,
                termination_reason=normalized_reason,
                revision=current.revision + 1,
            )
            self._records[session_id] = updated
            return updated

    async def rotate(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
        successor: ControlPlaneDurableSessionRecord,
        rotated_at: datetime,
    ) -> ControlPlaneDurableSessionRotation:
        _validate_revision(expected_revision)
        _require_aware(rotated_at, "rotated_at")
        async with self._lock:
            self._require_open()
            current = self._require_record(session_id)
            self._require_revision(current, expected_revision)
            self._require_active(current)
            if len(self._records) >= self._capacity:
                raise ControlPlaneDurableSessionCapacityError(
                    "durable session repository capacity has been exhausted"
                )
            self._require_available_identity(successor)
            self._validate_successor(current, successor, rotated_at)
            previous = replace(
                current,
                status=ControlPlaneDurableSessionStatus.ROTATED,
                terminated_at=rotated_at,
                termination_reason=ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
                successor_session_id=successor.id,
                revision=current.revision + 1,
            )
            self._records[current.id] = previous
            self._records[successor.id] = successor
            self._token_index[successor.token_digest] = successor.id
            return ControlPlaneDurableSessionRotation(previous=previous, successor=successor)

    async def delete_terminal(
        self,
        session_id: UUID,
        *,
        expected_revision: int,
    ) -> None:
        _validate_revision(expected_revision)
        async with self._lock:
            self._require_open()
            current = self._require_record(session_id)
            self._require_revision(current, expected_revision)
            if not current.status.terminal:
                raise ControlPlaneDurableSessionConflictError(
                    "active durable session cannot be deleted"
                )
            del self._records[session_id]
            del self._token_index[current.token_digest]

    async def snapshot(self) -> ControlPlaneDurableSessionSnapshot:
        async with self._lock:
            counts = Counter(record.status for record in self._records.values())
            return ControlPlaneDurableSessionSnapshot(
                closed=self._closed,
                entries=len(self._records),
                active=counts[ControlPlaneDurableSessionStatus.ACTIVE],
                revoked=counts[ControlPlaneDurableSessionStatus.REVOKED],
                expired=counts[ControlPlaneDurableSessionStatus.EXPIRED],
                rotated=counts[ControlPlaneDurableSessionStatus.ROTATED],
                capacity=self._capacity,
                max_sessions_per_operator=self._max_sessions_per_operator,
            )

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._token_index.clear()
            self._closed = True

    def _require_available_identity(self, record: ControlPlaneDurableSessionRecord) -> None:
        if record.id in self._records:
            raise ControlPlaneDurableSessionAlreadyExistsError(
                "durable session identity already exists"
            )
        if record.token_digest in self._token_index:
            raise ControlPlaneDurableSessionAlreadyExistsError(
                "durable session token digest already exists"
            )

    def _require_operator_capacity(self, operator_id: UUID) -> None:
        active = sum(
            record.operator_id == operator_id
            and record.status is ControlPlaneDurableSessionStatus.ACTIVE
            for record in self._records.values()
        )
        if active >= self._max_sessions_per_operator:
            raise ControlPlaneDurableSessionCapacityError(
                "durable session per-operator limit has been reached"
            )

    def _require_record(self, session_id: UUID) -> ControlPlaneDurableSessionRecord:
        record = self._records.get(session_id)
        if record is None:
            raise ControlPlaneDurableSessionNotFoundError("durable session record was not found")
        return record

    @staticmethod
    def _require_revision(
        record: ControlPlaneDurableSessionRecord,
        expected_revision: int,
    ) -> None:
        if record.revision != expected_revision:
            raise ControlPlaneDurableSessionConflictError("durable session revision conflict")

    @staticmethod
    def _require_active(record: ControlPlaneDurableSessionRecord) -> None:
        if record.status is not ControlPlaneDurableSessionStatus.ACTIVE:
            raise ControlPlaneDurableSessionConflictError("durable session record is terminal")

    @staticmethod
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

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneDurableSessionRepositoryClosedError(
                "durable session repository is closed"
            )


def _validate_revision(value: int) -> None:
    if value <= 0:
        raise ValueError("expected_revision must be positive")


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
