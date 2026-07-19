"""Bounded in-memory reference repository for the command journal."""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import replace
from datetime import datetime
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneCommandJournalAlreadyExistsError,
    ControlPlaneCommandJournalCapacityError,
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandJournalNotFoundError,
    ControlPlaneCommandJournalRepositoryClosedError,
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


class InMemoryControlPlaneCommandJournalRepository:
    """Process-local reference implementation with optimistic revisions."""

    def __init__(self, *, capacity: int = 4096) -> None:
        if capacity <= 0 or capacity > MAX_COMMAND_JOURNAL_CAPACITY:
            raise ValueError(
                f"command journal capacity must be between 1 and {MAX_COMMAND_JOURNAL_CAPACITY}"
            )
        self._capacity = capacity
        self._records: dict[UUID, ControlPlaneCommandJournalRecord] = {}
        self._idempotency_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneCommandJournalRecord) -> None:
        async with self._lock:
            self._require_open()
            if len(self._records) >= self._capacity:
                raise ControlPlaneCommandJournalCapacityError(
                    "command journal capacity has been exhausted"
                )
            if record.command_id in self._records:
                raise ControlPlaneCommandJournalAlreadyExistsError(
                    "command journal record already exists"
                )
            if record.idempotency_digest in self._idempotency_index:
                raise ControlPlaneCommandJournalAlreadyExistsError(
                    "command journal idempotency digest already exists"
                )
            self._records[record.command_id] = record
            self._idempotency_index[record.idempotency_digest] = record.command_id

    async def get(self, command_id: UUID) -> ControlPlaneCommandJournalRecord | None:
        async with self._lock:
            self._require_open()
            return self._records.get(command_id)

    async def get_by_idempotency_digest(
        self,
        digest: str,
    ) -> ControlPlaneCommandJournalRecord | None:
        normalized = _normalize_digest(digest)
        async with self._lock:
            self._require_open()
            command_id = self._idempotency_index.get(normalized)
            return None if command_id is None else self._records[command_id]

    async def list_page(
        self,
        request: ControlPlaneCommandJournalPageRequest = DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    ) -> ControlPlaneCommandJournalPage:
        async with self._lock:
            self._require_open()
            ordered = tuple(
                sorted(
                    self._records.values(),
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
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        if updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")
        normalized_status = ControlPlaneCommandJournalStatus(status)
        async with self._lock:
            self._require_open()
            current = self._records.get(command_id)
            if current is None:
                raise ControlPlaneCommandJournalNotFoundError(
                    "command journal record was not found"
                )
            if current.revision != expected_revision:
                raise ControlPlaneCommandJournalConflictError("command journal revision conflict")
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
            self._records[command_id] = updated
            return updated

    async def delete_terminal(
        self,
        command_id: UUID,
        *,
        expected_revision: int,
    ) -> None:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        async with self._lock:
            self._require_open()
            current = self._records.get(command_id)
            if current is None:
                raise ControlPlaneCommandJournalNotFoundError(
                    "command journal record was not found"
                )
            if current.revision != expected_revision:
                raise ControlPlaneCommandJournalConflictError("command journal revision conflict")
            if not current.status.terminal:
                raise ControlPlaneCommandJournalConflictError(
                    "non-terminal command journal record cannot be deleted"
                )
            del self._records[command_id]
            del self._idempotency_index[current.idempotency_digest]

    async def snapshot(self) -> ControlPlaneCommandJournalSnapshot:
        async with self._lock:
            counts = Counter(record.status for record in self._records.values())
            return ControlPlaneCommandJournalSnapshot(
                closed=self._closed,
                entries=len(self._records),
                pending=counts[ControlPlaneCommandJournalStatus.PENDING],
                executing=counts[ControlPlaneCommandJournalStatus.EXECUTING],
                succeeded=counts[ControlPlaneCommandJournalStatus.SUCCEEDED],
                rejected=counts[ControlPlaneCommandJournalStatus.REJECTED],
                failed=counts[ControlPlaneCommandJournalStatus.FAILED],
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._idempotency_index.clear()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneCommandJournalRepositoryClosedError(
                "command journal repository is closed"
            )


def _normalize_digest(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("idempotency digest must be a SHA-256 hexadecimal digest")
    return normalized
