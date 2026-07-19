"""Journal-backed restart-safe idempotency for Phoenix control-plane commands."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
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
    ControlPlaneCommandJournalAlreadyExistsError,
    ControlPlaneCommandJournalCapacityError,
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandStateError,
    ControlPlaneIdempotencyCapacityError,
    ControlPlaneIdempotencyConflictError,
    ControlPlaneIdempotencyStoreClosedError,
)
from phoenix_os.control_plane.journal_contracts import (
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalRepository,
    ControlPlaneCommandJournalStatus,
)

type JournalIdempotencyClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class JournalControlPlaneIdempotencyStore:
    """Adapt a durable command journal to the RFC-0018 idempotency boundary."""

    def __init__(
        self,
        repository: ControlPlaneCommandJournalRepository,
        *,
        principal: str,
        clock: JournalIdempotencyClock = _utc_now,
    ) -> None:
        normalized_principal = principal.strip()
        if not normalized_principal:
            raise ValueError("journal idempotency principal must not be blank")
        if len(normalized_principal) > 128:
            raise ValueError("journal idempotency principal is too long")
        if any(ord(character) < 32 or ord(character) == 127 for character in normalized_principal):
            raise ValueError("journal idempotency principal must not contain control characters")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._repository = repository
        self._principal = normalized_principal
        self._clock = clock
        self._closed = False
        self._close_lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def reserve(
        self,
        intent: ControlPlaneCommandIntent,
    ) -> ControlPlaneIdempotencyReservation:
        self._require_open()
        digest = intent.idempotency_key.digest.hex()
        existing = await self._repository.get_by_idempotency_digest(digest)
        if existing is not None:
            self._require_matching(existing, intent)
            return ControlPlaneIdempotencyReservation(
                _record_to_receipt(existing),
                replayed=True,
            )

        record = ControlPlaneCommandJournalRecord.from_intent(
            intent,
            principal=self._principal,
        )
        try:
            await self._repository.add(record)
        except ControlPlaneCommandJournalCapacityError as exception:
            raise ControlPlaneIdempotencyCapacityError(
                "durable idempotency capacity has been exhausted"
            ) from exception
        except ControlPlaneCommandJournalAlreadyExistsError as exception:
            raced = await self._repository.get_by_idempotency_digest(digest)
            if raced is None:
                raise ControlPlaneIdempotencyConflictError(
                    "command identity is already bound to another idempotency key"
                ) from exception
            self._require_matching(raced, intent)
            return ControlPlaneIdempotencyReservation(
                _record_to_receipt(raced),
                replayed=True,
            )

        executing = await self._transition_new_to_executing(record)
        return ControlPlaneIdempotencyReservation(
            _record_to_receipt(executing),
            replayed=False,
        )

    async def complete(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        result_code: str,
        completed_at: datetime | None = None,
    ) -> ControlPlaneCommandReceipt:
        return await self._finish(
            intent,
            status=ControlPlaneCommandJournalStatus.SUCCEEDED,
            receipt_status=ControlPlaneCommandStatus.SUCCEEDED,
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
            status=ControlPlaneCommandJournalStatus.FAILED,
            receipt_status=ControlPlaneCommandStatus.FAILED,
            result_code=result_code,
            completed_at=completed_at,
        )

    async def reject(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        result_code: str,
        completed_at: datetime | None = None,
    ) -> ControlPlaneCommandReceipt:
        """Persist a rejected terminal state and return an RFC-0018 failure receipt."""

        return await self._finish(
            intent,
            status=ControlPlaneCommandJournalStatus.REJECTED,
            receipt_status=ControlPlaneCommandStatus.FAILED,
            result_code=result_code,
            completed_at=completed_at,
        )

    async def get(self, key: IdempotencyKey) -> ControlPlaneCommandReceipt | None:
        self._require_open()
        record = await self._repository.get_by_idempotency_digest(key.digest.hex())
        return None if record is None else _record_to_receipt(record)

    async def snapshot(self) -> ControlPlaneIdempotencySnapshot:
        snapshot = await self._repository.snapshot()
        return ControlPlaneIdempotencySnapshot(
            closed=self._closed,
            entries=snapshot.entries,
            pending=snapshot.pending + snapshot.executing,
            succeeded=snapshot.succeeded,
            failed=snapshot.rejected + snapshot.failed,
            capacity=snapshot.capacity,
        )

    async def close(self) -> None:
        """Close only the adapter; the Runtime retains ownership of the durable repository."""

        async with self._close_lock:
            self._closed = True

    async def _transition_new_to_executing(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandJournalRecord:
        try:
            return await self._repository.transition(
                record.command_id,
                expected_revision=record.revision,
                status=ControlPlaneCommandJournalStatus.EXECUTING,
                updated_at=record.updated_at,
            )
        except ControlPlaneCommandJournalConflictError as exception:
            current = await self._repository.get(record.command_id)
            if current is None:
                raise ControlPlaneCommandStateError(
                    "durable command disappeared during reservation"
                ) from exception
            return current

    async def _finish(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        status: ControlPlaneCommandJournalStatus,
        receipt_status: ControlPlaneCommandStatus,
        result_code: str,
        completed_at: datetime | None,
    ) -> ControlPlaneCommandReceipt:
        self._require_open()
        finished_at = self._clock() if completed_at is None else completed_at
        if finished_at.tzinfo is None:
            raise ValueError("completed_at must be timezone-aware")

        digest = intent.idempotency_key.digest.hex()
        record = await self._repository.get_by_idempotency_digest(digest)
        if record is None:
            raise ControlPlaneCommandStateError("command must be reserved before completion")
        self._require_matching(record, intent)
        if record.status.terminal:
            receipt = _record_to_receipt(record)
            normalized_code = result_code.strip().lower()
            if receipt.status is receipt_status and receipt.result_code == normalized_code:
                return receipt
            raise ControlPlaneCommandStateError("terminal command result cannot be replaced")

        try:
            updated = await self._repository.transition(
                record.command_id,
                expected_revision=record.revision,
                status=status,
                updated_at=finished_at,
                result_code=result_code,
            )
        except ControlPlaneCommandJournalConflictError as exception:
            current = await self._repository.get_by_idempotency_digest(digest)
            if current is None:
                raise ControlPlaneCommandStateError(
                    "durable command disappeared during completion"
                ) from exception
            self._require_matching(current, intent)
            receipt = _record_to_receipt(current)
            normalized_code = result_code.strip().lower()
            if receipt.status is receipt_status and receipt.result_code == normalized_code:
                return receipt
            raise ControlPlaneCommandStateError(
                "terminal command result cannot be replaced"
            ) from exception
        return _record_to_receipt(updated)

    @staticmethod
    def _require_matching(
        record: ControlPlaneCommandJournalRecord,
        intent: ControlPlaneCommandIntent,
    ) -> None:
        if (
            record.idempotency_digest != intent.idempotency_key.digest.hex()
            or record.fingerprint != intent.fingerprint
            or record.action is not intent.action
            or record.target != intent.target
        ):
            raise ControlPlaneIdempotencyConflictError(
                "idempotency key is already bound to another command"
            )

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneIdempotencyStoreClosedError("idempotency store is closed")


def _record_to_receipt(record: ControlPlaneCommandJournalRecord) -> ControlPlaneCommandReceipt:
    if record.status in {
        ControlPlaneCommandJournalStatus.PENDING,
        ControlPlaneCommandJournalStatus.EXECUTING,
    }:
        return ControlPlaneCommandReceipt(
            command_id=record.command_id,
            action=record.action,
            target=record.target,
            status=ControlPlaneCommandStatus.PENDING,
            created_at=record.requested_at,
        )
    status = (
        ControlPlaneCommandStatus.SUCCEEDED
        if record.status is ControlPlaneCommandJournalStatus.SUCCEEDED
        else ControlPlaneCommandStatus.FAILED
    )
    return ControlPlaneCommandReceipt(
        command_id=record.command_id,
        action=record.action,
        target=record.target,
        status=status,
        created_at=record.requested_at,
        completed_at=record.completed_at,
        result_code=record.result_code,
    )
