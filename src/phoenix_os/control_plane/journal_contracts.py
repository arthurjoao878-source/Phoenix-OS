"""Immutable contracts for the durable Phoenix control-plane command journal."""

from __future__ import annotations

import re
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.commands import (
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
)

DEFAULT_COMMAND_JOURNAL_PAGE_SIZE = 50
MAX_COMMAND_JOURNAL_PAGE_SIZE = 200
MAX_COMMAND_JOURNAL_CAPACITY = 100_000

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_CODE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class ControlPlaneCommandJournalStatus(StrEnum):
    """Durable lifecycle states for one administrative command."""

    PENDING = "pending"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in {self.SUCCEEDED, self.REJECTED, self.FAILED}


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandJournalRecord:
    """Payload-free durable command record safe for persistence and recovery."""

    command_id: UUID
    action: ControlPlaneCommandAction
    target: str
    principal: str
    idempotency_digest: str = field(repr=False)
    fingerprint: str = field(repr=False)
    status: ControlPlaneCommandJournalStatus
    requested_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    result_code: str | None = None
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        action = ControlPlaneCommandAction(self.action)
        status = ControlPlaneCommandJournalStatus(self.status)
        target = _normalize_text(self.target, label="target", maximum=256)
        principal = _normalize_text(self.principal, label="principal", maximum=128)
        idempotency_digest = _normalize_digest(
            self.idempotency_digest,
            label="idempotency digest",
        )
        fingerprint = _normalize_digest(self.fingerprint, label="fingerprint")
        result_code = _normalize_result_code(self.result_code)

        if self.schema_version != 1:
            raise ValueError("unsupported command journal schema version")
        if self.revision <= 0:
            raise ValueError("command journal revision must be positive")
        _require_aware(self.requested_at, "requested_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.requested_at:
            raise ValueError("updated_at cannot precede requested_at")
        if self.completed_at is not None:
            _require_aware(self.completed_at, "completed_at")
            if self.completed_at < self.updated_at:
                raise ValueError("completed_at cannot precede updated_at")

        if status.terminal:
            if self.completed_at is None or result_code is None:
                raise ValueError("terminal journal record requires completion data")
        elif self.completed_at is not None or result_code is not None:
            raise ValueError("non-terminal journal record cannot contain completion data")

        object.__setattr__(self, "action", action)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "idempotency_digest", idempotency_digest)
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "result_code", result_code)

    @classmethod
    def from_intent(
        cls,
        intent: ControlPlaneCommandIntent,
        *,
        principal: str,
    ) -> ControlPlaneCommandJournalRecord:
        """Create the initial payload-free record for an authenticated command."""

        return cls(
            command_id=intent.id,
            action=intent.action,
            target=intent.target,
            principal=principal,
            idempotency_digest=intent.idempotency_key.digest.hex(),
            fingerprint=intent.fingerprint,
            status=ControlPlaneCommandJournalStatus.PENDING,
            requested_at=intent.requested_at,
            updated_at=intent.requested_at,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandJournalPageRequest:
    """Validated offset pagination for command history."""

    offset: int = 0
    limit: int = DEFAULT_COMMAND_JOURNAL_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("command journal offset cannot be negative")
        if self.limit <= 0 or self.limit > MAX_COMMAND_JOURNAL_PAGE_SIZE:
            raise ValueError(
                f"command journal limit must be between 1 and {MAX_COMMAND_JOURNAL_PAGE_SIZE}"
            )


DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST = ControlPlaneCommandJournalPageRequest()


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandJournalPageInfo:
    """Stable pagination metadata for command-history responses."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.returned < 0 or self.total < 0:
            raise ValueError("command journal page counters cannot be negative")
        if self.limit <= 0 or self.limit > MAX_COMMAND_JOURNAL_PAGE_SIZE:
            raise ValueError(
                f"command journal limit must be between 1 and {MAX_COMMAND_JOURNAL_PAGE_SIZE}"
            )
        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("command journal returned count is inconsistent")
        expected = self.offset + self.returned
        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("command journal page requires next_offset")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("command journal next_offset is inconsistent")

    @classmethod
    def from_slice(
        cls,
        request: ControlPlaneCommandJournalPageRequest,
        *,
        returned: int,
        total: int,
    ) -> ControlPlaneCommandJournalPageInfo:
        next_offset = request.offset + returned
        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=next_offset if next_offset < total else None,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandJournalPage:
    """Deterministically ordered page of payload-free command records."""

    items: tuple[ControlPlaneCommandJournalRecord, ...]
    page: ControlPlaneCommandJournalPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("command journal page count must match items")
        command_ids = tuple(item.command_id for item in self.items)
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("command journal page items must be unique")


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandJournalSnapshot:
    """Non-sensitive counters for the bounded command journal."""

    closed: bool
    entries: int
    pending: int
    executing: int
    succeeded: int
    rejected: int
    failed: int
    capacity: int

    def __post_init__(self) -> None:
        counters = (
            self.entries,
            self.pending,
            self.executing,
            self.succeeded,
            self.rejected,
            self.failed,
        )
        if any(value < 0 for value in counters):
            raise ValueError("command journal counters cannot be negative")
        if self.capacity <= 0 or self.capacity > MAX_COMMAND_JOURNAL_CAPACITY:
            raise ValueError("command journal capacity is outside supported bounds")
        if self.entries > self.capacity:
            raise ValueError("command journal entries cannot exceed capacity")
        states = self.pending + self.executing + self.succeeded + self.rejected + self.failed
        if states != self.entries:
            raise ValueError("command journal status counts must equal entries")


class ControlPlaneCommandJournalSnapshotSource(Protocol):
    """Narrow snapshot source used by the read-only control plane."""

    def snapshot(self) -> Awaitable[ControlPlaneCommandJournalSnapshot]: ...


class ControlPlaneCommandJournalRepository(Protocol):
    """Asynchronous persistence boundary for administrative command history."""

    @property
    def closed(self) -> bool: ...

    def add(self, record: ControlPlaneCommandJournalRecord) -> Awaitable[None]: ...

    def get(self, command_id: UUID) -> Awaitable[ControlPlaneCommandJournalRecord | None]: ...

    def get_by_idempotency_digest(
        self,
        digest: str,
    ) -> Awaitable[ControlPlaneCommandJournalRecord | None]: ...

    def list_page(
        self,
        request: ControlPlaneCommandJournalPageRequest = DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    ) -> Awaitable[ControlPlaneCommandJournalPage]: ...

    def transition(
        self,
        command_id: UUID,
        *,
        expected_revision: int,
        status: ControlPlaneCommandJournalStatus,
        updated_at: datetime,
        result_code: str | None = None,
    ) -> Awaitable[ControlPlaneCommandJournalRecord]: ...

    def delete_terminal(
        self,
        command_id: UUID,
        *,
        expected_revision: int,
    ) -> Awaitable[None]: ...

    def snapshot(self) -> Awaitable[ControlPlaneCommandJournalSnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def _normalize_text(value: str, *, label: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"command journal {label} has an invalid length")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"command journal {label} must not contain control characters")
    return normalized


def _normalize_digest(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"command journal {label} must be a SHA-256 hexadecimal digest")
    return normalized


def _normalize_result_code(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if _RESULT_CODE_PATTERN.fullmatch(normalized) is None:
        raise ValueError("command journal result code contains unsupported characters")
    return normalized


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
