"""Deterministic in-memory audit store for tests and ephemeral deployments."""

from __future__ import annotations

import asyncio
import inspect
from datetime import datetime
from typing import TYPE_CHECKING

from phoenix_os.audit.codec import compute_audit_digest
from phoenix_os.audit.contracts import (
    AUDIT_GENESIS_DIGEST,
    AuditEvent,
    AuditQuery,
    AuditRecord,
    AuditSeal,
    AuditSigner,
    AuditStoreSnapshot,
    AuditVerification,
)
from phoenix_os.audit.errors import AuditSignerError, AuditStoreClosedError

if TYPE_CHECKING:
    from phoenix_os.secrets import KeyRef


class InMemoryAuditStore:
    """Process-local append-only hash chain with optional external signatures."""

    def __init__(
        self,
        *,
        signer: AuditSigner | None = None,
        signing_key: KeyRef | None = None,
        signing_algorithm: str = "external",
    ) -> None:
        if (signer is None) is not (signing_key is None):
            raise ValueError("signer and signing_key must be configured together")
        algorithm = signing_algorithm.strip().lower()
        if not algorithm:
            raise ValueError("signing_algorithm must not be blank")
        self._signer = signer
        self._signing_key = signing_key
        self._signing_algorithm = algorithm
        self._records: list[AuditRecord] = []
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def append(self, event: AuditEvent, *, recorded_at: datetime) -> AuditRecord:
        self._ensure_open()
        if recorded_at.tzinfo is None:
            raise ValueError("recorded_at must be timezone-aware")
        async with self._lock:
            self._ensure_open()
            sequence = len(self._records) + 1
            previous_digest = (
                AUDIT_GENESIS_DIGEST if not self._records else self._records[-1].digest
            )
            digest = compute_audit_digest(
                event,
                sequence=sequence,
                recorded_at=recorded_at,
                previous_digest=previous_digest,
            )
            seal = await self._seal(digest)
            record = AuditRecord(
                event=event,
                sequence=sequence,
                recorded_at=recorded_at,
                previous_digest=previous_digest,
                digest=digest,
                seal=seal,
            )
            self._records.append(record)
            return record

    async def read(self, query: AuditQuery) -> tuple[AuditRecord, ...]:
        async with self._lock:
            matching = [record for record in self._records if query.matches(record)]
            return tuple(matching[: query.limit])

    async def verify(self) -> AuditVerification:
        async with self._lock:
            records = tuple(self._records)
        if not records:
            return AuditVerification(True, 0, AUDIT_GENESIS_DIGEST)

        previous_digest = AUDIT_GENESIS_DIGEST
        signatures_checked = 0
        for expected_sequence, record in enumerate(records, start=1):
            if record.sequence != expected_sequence:
                return _invalid(
                    records,
                    expected_sequence,
                    record.sequence,
                    f"sequence mismatch: expected {expected_sequence}, found {record.sequence}",
                    signatures_checked,
                    previous_digest,
                )
            if record.previous_digest != previous_digest:
                return _invalid(
                    records,
                    expected_sequence,
                    record.sequence,
                    "previous digest link mismatch",
                    signatures_checked,
                    previous_digest,
                )
            expected_digest = compute_audit_digest(
                record.event,
                sequence=record.sequence,
                recorded_at=record.recorded_at,
                previous_digest=record.previous_digest,
            )
            if record.digest != expected_digest:
                return _invalid(
                    records,
                    expected_sequence,
                    record.sequence,
                    "record digest mismatch",
                    signatures_checked,
                    previous_digest,
                )
            if record.seal is not None:
                if self._signer is None:
                    return _invalid(
                        records,
                        expected_sequence,
                        record.sequence,
                        "signature verifier unavailable",
                        signatures_checked,
                        previous_digest,
                    )
                try:
                    valid = self._signer.verify(
                        bytes.fromhex(record.digest),
                        record.seal.signature,
                        key=record.seal.key,
                    )
                    if inspect.isawaitable(valid):
                        valid = await valid
                except asyncio.CancelledError:
                    raise
                except Exception as exception:
                    raise AuditSignerError("audit signature verification failed") from exception
                if not valid:
                    return _invalid(
                        records,
                        expected_sequence,
                        record.sequence,
                        "external signature mismatch",
                        signatures_checked,
                        previous_digest,
                    )
                signatures_checked += 1
            previous_digest = record.digest

        return AuditVerification(
            valid=True,
            checked_records=len(records),
            first_sequence=records[0].sequence,
            last_sequence=records[-1].sequence,
            head_digest=records[-1].digest,
            signatures_checked=signatures_checked,
        )

    async def snapshot(self) -> AuditStoreSnapshot:
        async with self._lock:
            head = None if not self._records else self._records[-1]
            return AuditStoreSnapshot(
                closed=self._closed,
                records=len(self._records),
                head_sequence=None if head is None else head.sequence,
                head_digest=AUDIT_GENESIS_DIGEST if head is None else head.digest,
                signed_records=sum(record.seal is not None for record in self._records),
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    async def _seal(self, digest: str) -> AuditSeal | None:
        if self._signer is None or self._signing_key is None:
            return None
        try:
            signature = self._signer.sign(bytes.fromhex(digest), key=self._signing_key)
            if inspect.isawaitable(signature):
                signature = await signature
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            raise AuditSignerError("audit signature creation failed") from exception
        return AuditSeal(
            key=self._signing_key,
            algorithm=self._signing_algorithm,
            signature=bytes(signature),
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise AuditStoreClosedError("audit store is closed")


def _invalid(
    records: tuple[AuditRecord, ...],
    checked_records: int,
    failure_sequence: int,
    reason: str,
    signatures_checked: int,
    head_digest: str,
) -> AuditVerification:
    return AuditVerification(
        valid=False,
        checked_records=checked_records,
        first_sequence=records[0].sequence,
        last_sequence=records[-1].sequence,
        head_digest=head_digest,
        failure_sequence=failure_sequence,
        reason=reason,
        signatures_checked=signatures_checked,
    )
