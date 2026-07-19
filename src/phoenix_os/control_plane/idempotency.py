"""Bounded in-memory idempotency storage for Phoenix control-plane commands."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from phoenix_os.control_plane.commands import (
    ControlPlaneCommandIntent,
    ControlPlaneCommandReceipt,
    ControlPlaneCommandStatus,
    ControlPlaneIdempotencyReservation,
    ControlPlaneIdempotencySnapshot,
    IdempotencyKey,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandStateError,
    ControlPlaneIdempotencyCapacityError,
    ControlPlaneIdempotencyConflictError,
    ControlPlaneIdempotencyStoreClosedError,
)

type ControlPlaneCommandClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class _IdempotencyEntry:
    fingerprint: str
    receipt: ControlPlaneCommandReceipt


class InMemoryControlPlaneIdempotencyStore:
    """Reserve and replay commands while retaining only hashed client keys."""

    def __init__(
        self,
        *,
        capacity: int = 1024,
        clock: ControlPlaneCommandClock = _utc_now,
    ) -> None:
        if capacity <= 0 or capacity > 100_000:
            raise ValueError("idempotency capacity must be between 1 and 100000")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._capacity = capacity
        self._clock = clock
        self._entries: dict[bytes, _IdempotencyEntry] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def reserve(
        self,
        intent: ControlPlaneCommandIntent,
    ) -> ControlPlaneIdempotencyReservation:
        async with self._lock:
            self._require_open()
            key = intent.idempotency_key.digest
            existing = self._entries.get(key)
            if existing is not None:
                self._require_matching(existing, intent)
                return ControlPlaneIdempotencyReservation(existing.receipt, replayed=True)

            self._ensure_capacity()
            receipt = ControlPlaneCommandReceipt(
                command_id=intent.id,
                action=intent.action,
                target=intent.target,
                status=ControlPlaneCommandStatus.PENDING,
                created_at=intent.requested_at,
            )
            self._entries[key] = _IdempotencyEntry(intent.fingerprint, receipt)
            return ControlPlaneIdempotencyReservation(receipt, replayed=False)

    async def complete(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        result_code: str,
        completed_at: datetime | None = None,
    ) -> ControlPlaneCommandReceipt:
        return await self._finish(
            intent,
            status=ControlPlaneCommandStatus.SUCCEEDED,
            result_code=result_code,
            completed_at=completed_at,
        )

    async def fail(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        result_code: str,
        completed_at: datetime | None = None,
    ) -> ControlPlaneCommandReceipt:
        return await self._finish(
            intent,
            status=ControlPlaneCommandStatus.FAILED,
            result_code=result_code,
            completed_at=completed_at,
        )

    async def get(self, key: IdempotencyKey) -> ControlPlaneCommandReceipt | None:
        async with self._lock:
            self._require_open()
            entry = self._entries.get(key.digest)
            return None if entry is None else entry.receipt

    async def snapshot(self) -> ControlPlaneIdempotencySnapshot:
        async with self._lock:
            counts = {status: 0 for status in ControlPlaneCommandStatus}
            for entry in self._entries.values():
                counts[entry.receipt.status] += 1
            return ControlPlaneIdempotencySnapshot(
                closed=self._closed,
                entries=len(self._entries),
                pending=counts[ControlPlaneCommandStatus.PENDING],
                succeeded=counts[ControlPlaneCommandStatus.SUCCEEDED],
                failed=counts[ControlPlaneCommandStatus.FAILED],
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._entries.clear()

    async def _finish(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        status: ControlPlaneCommandStatus,
        result_code: str,
        completed_at: datetime | None,
    ) -> ControlPlaneCommandReceipt:
        finished_at = self._clock() if completed_at is None else completed_at
        if finished_at.tzinfo is None:
            raise ValueError("completed_at must be timezone-aware")
        async with self._lock:
            self._require_open()
            entry = self._entries.get(intent.idempotency_key.digest)
            if entry is None:
                raise ControlPlaneCommandStateError("command must be reserved before completion")
            self._require_matching(entry, intent)
            if entry.receipt.status.terminal:
                normalized = result_code.strip().lower()
                if entry.receipt.status is status and entry.receipt.result_code == normalized:
                    return entry.receipt
                raise ControlPlaneCommandStateError("terminal command result cannot be replaced")
            receipt = ControlPlaneCommandReceipt(
                command_id=entry.receipt.command_id,
                action=entry.receipt.action,
                target=entry.receipt.target,
                status=status,
                created_at=entry.receipt.created_at,
                completed_at=finished_at,
                result_code=result_code,
            )
            entry.receipt = receipt
            return receipt

    def _ensure_capacity(self) -> None:
        if len(self._entries) < self._capacity:
            return
        terminal = [
            (key, entry) for key, entry in self._entries.items() if entry.receipt.status.terminal
        ]
        if not terminal:
            raise ControlPlaneIdempotencyCapacityError(
                "idempotency capacity is occupied by pending commands"
            )
        key, _ = min(
            terminal,
            key=lambda item: (
                item[1].receipt.created_at,
                item[1].receipt.command_id.hex,
            ),
        )
        del self._entries[key]

    @staticmethod
    def _require_matching(
        entry: _IdempotencyEntry,
        intent: ControlPlaneCommandIntent,
    ) -> None:
        if entry.fingerprint != intent.fingerprint:
            raise ControlPlaneIdempotencyConflictError(
                "idempotency key is already bound to another command"
            )

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneIdempotencyStoreClosedError("idempotency store is closed")
