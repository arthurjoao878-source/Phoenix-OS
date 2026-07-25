"""Durable replay admission and stable source-event idempotency."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from phoenix_os.inbound_events.contracts import (
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventReceipt,
    InboundEventRepository,
    InboundEventSource,
    InboundReplayKind,
    InboundReplayRepository,
    InboundReplayReservation,
    InboundRequestEvidence,
    canonical_inbound_json_bytes,
    inbound_evidence_digest,
)
from phoenix_os.inbound_events.errors import (
    InboundCorruptionError,
    InboundEventAlreadyExistsError,
    InboundIdempotencyConflictError,
    InboundReplayAlreadyExistsError,
    InboundReplayRejectedError,
)

type InboundAdmissionClock = Callable[[], datetime]
type InboundUuidFactory = Callable[[], UUID]


@dataclass(frozen=True, slots=True)
class InboundAdmissionResult:
    """Stable receipt plus whether this request created the durable event."""

    receipt: InboundEventReceipt
    idempotent: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, InboundEventReceipt):
            raise TypeError("inbound admission result requires a receipt")
        if type(self.idempotent) is not bool:
            raise TypeError("inbound admission idempotent flag must be bool")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound admission result schema version")

    @property
    def accepted_event_id(self) -> UUID:
        return self.receipt.accepted_event_id


class InboundReplayIdempotencyService:
    """Atomically admit new events and durably reserve all replay evidence."""

    def __init__(
        self,
        events: InboundEventRepository,
        replay: InboundReplayRepository,
        *,
        clock: InboundAdmissionClock | None = None,
        uuid_factory: InboundUuidFactory = uuid4,
    ) -> None:
        resolved_clock = _utc_now if clock is None else clock
        if not callable(resolved_clock):
            raise TypeError("inbound admission clock must be callable")
        if not callable(uuid_factory):
            raise TypeError("inbound admission UUID factory must be callable")
        self._events = events
        self._replay = replay
        self._clock = resolved_clock
        self._uuid_factory = uuid_factory

    async def admit(
        self,
        source: InboundEventSource,
        evidence: InboundRequestEvidence,
        *,
        external_event_type: str,
        external_schema_version: int,
        internal_event_type: str,
        occurred_at: datetime,
        normalized_payload: Mapping[str, object],
    ) -> InboundAdmissionResult:
        """Create one durable acceptance or return its stable idempotent receipt."""

        if not isinstance(source, InboundEventSource):
            raise TypeError("inbound admission source has an invalid type")
        if not isinstance(evidence, InboundRequestEvidence):
            raise TypeError("inbound admission evidence has an invalid type")
        if evidence.source_id != source.id:
            raise ValueError("inbound admission evidence belongs to another source")
        if not source.accepting:
            raise ValueError("inactive inbound source cannot accept events")
        if not isinstance(normalized_payload, Mapping):
            raise TypeError("inbound normalized payload must be a mapping")

        now = self._now()
        payload_digest = _payload_digest(normalized_payload)
        digests = _replay_digests(source.id, evidence)

        await self._replay.prune_expired(now=now)
        await self._reject_used_request_or_nonce(source.id, digests)

        existing = await self._events.get_by_source_event_digest(
            source.id,
            digests[InboundReplayKind.SOURCE_EVENT_ID],
        )
        if existing is not None:
            return await self._return_existing(
                source,
                evidence,
                existing,
                payload_digest=payload_digest,
                digests=digests,
                now=now,
            )

        acceptance = self._new_acceptance(
            source,
            evidence,
            external_event_type=external_event_type,
            external_schema_version=external_schema_version,
            internal_event_type=internal_event_type,
            occurred_at=occurred_at,
            normalized_payload=normalized_payload,
            payload_digest=payload_digest,
            digests=digests,
            now=now,
        )

        try:
            await self._events.accept(acceptance)
        except (InboundEventAlreadyExistsError, InboundReplayAlreadyExistsError) as conflict:
            await self._reject_used_request_or_nonce(source.id, digests)
            existing = await self._events.get_by_source_event_digest(
                source.id,
                digests[InboundReplayKind.SOURCE_EVENT_ID],
            )
            if existing is None:
                raise conflict
            return await self._return_existing(
                source,
                evidence,
                existing,
                payload_digest=payload_digest,
                digests=digests,
                now=now,
            )

        return InboundAdmissionResult(
            receipt=acceptance.receipt,
            idempotent=False,
        )

    async def _return_existing(
        self,
        source: InboundEventSource,
        evidence: InboundRequestEvidence,
        existing: InboundAcceptedEvent,
        *,
        payload_digest: str,
        digests: Mapping[InboundReplayKind, str],
        now: datetime,
    ) -> InboundAdmissionResult:
        if not hmac.compare_digest(existing.normalized_payload_sha256, payload_digest):
            raise InboundIdempotencyConflictError

        receipt = await self._events.get_receipt(existing.receipt_id)
        if receipt is None:
            raise InboundCorruptionError("persisted inbound idempotent event receipt is missing")

        reservations = _request_nonce_reservations(
            source,
            evidence,
            existing.id,
            digests=digests,
            now=now,
        )
        try:
            await self._events.reserve_idempotent_replay(
                existing.id,
                reservations,
            )
        except InboundReplayAlreadyExistsError:
            raise InboundReplayRejectedError from None

        return InboundAdmissionResult(receipt=receipt, idempotent=True)

    async def _reject_used_request_or_nonce(
        self,
        source_id: UUID,
        digests: Mapping[InboundReplayKind, str],
    ) -> None:
        for kind in (InboundReplayKind.REQUEST_ID, InboundReplayKind.NONCE):
            reservation = await self._replay.get(source_id, kind, digests[kind])
            if reservation is not None:
                raise InboundReplayRejectedError

    def _new_acceptance(
        self,
        source: InboundEventSource,
        evidence: InboundRequestEvidence,
        *,
        external_event_type: str,
        external_schema_version: int,
        internal_event_type: str,
        occurred_at: datetime,
        normalized_payload: Mapping[str, object],
        payload_digest: str,
        digests: Mapping[InboundReplayKind, str],
        now: datetime,
    ) -> InboundAcceptance:
        event_id = self._new_uuid("accepted event")
        receipt_id = self._new_uuid("receipt")
        event = InboundAcceptedEvent(
            id=event_id,
            receipt_id=receipt_id,
            source_id=source.id,
            source_event_id=evidence.source_event_id,
            external_event_type=external_event_type,
            external_schema_version=external_schema_version,
            internal_event_type=internal_event_type,
            occurred_at=occurred_at,
            accepted_at=now,
            updated_at=now,
            normalized_payload=normalized_payload,
            normalized_payload_sha256=payload_digest,
            correlation_id=evidence.correlation_id,
            next_attempt_at=now,
        )
        receipt = InboundEventReceipt(
            id=receipt_id,
            accepted_event_id=event_id,
            source_id=source.id,
            source_event_id=evidence.source_event_id,
            external_event_type=external_event_type,
            external_schema_version=external_schema_version,
            accepted_at=now,
            correlation_id=evidence.correlation_id,
        )
        expiry = now + source.replay_retention
        reservations = tuple(
            InboundReplayReservation(
                source_id=source.id,
                kind=kind,
                evidence_digest=digests[kind],
                accepted_event_id=event_id,
                created_at=now,
                expires_at=expiry,
                normalized_payload_sha256=(
                    payload_digest if kind is InboundReplayKind.SOURCE_EVENT_ID else None
                ),
            )
            for kind in InboundReplayKind
        )
        return InboundAcceptance(event, receipt, reservations)

    def _new_uuid(self, label: str) -> UUID:
        value = self._uuid_factory()
        if not isinstance(value, UUID):
            raise TypeError(f"inbound {label} UUID factory must return UUID")
        return value

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("inbound admission clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inbound admission clock must return an aware datetime")
        return value.astimezone(UTC)


def _request_nonce_reservations(
    source: InboundEventSource,
    evidence: InboundRequestEvidence,
    accepted_event_id: UUID,
    *,
    digests: Mapping[InboundReplayKind, str],
    now: datetime,
) -> tuple[InboundReplayReservation, InboundReplayReservation]:
    expiry = now + source.replay_retention
    return (
        InboundReplayReservation(
            source_id=source.id,
            kind=InboundReplayKind.REQUEST_ID,
            evidence_digest=digests[InboundReplayKind.REQUEST_ID],
            accepted_event_id=accepted_event_id,
            created_at=now,
            expires_at=expiry,
        ),
        InboundReplayReservation(
            source_id=source.id,
            kind=InboundReplayKind.NONCE,
            evidence_digest=digests[InboundReplayKind.NONCE],
            accepted_event_id=accepted_event_id,
            created_at=now,
            expires_at=expiry,
        ),
    )


def _replay_digests(
    source_id: UUID,
    evidence: InboundRequestEvidence,
) -> dict[InboundReplayKind, str]:
    return {
        InboundReplayKind.REQUEST_ID: inbound_evidence_digest(
            source_id,
            InboundReplayKind.REQUEST_ID,
            evidence.request_id,
        ),
        InboundReplayKind.NONCE: inbound_evidence_digest(
            source_id,
            InboundReplayKind.NONCE,
            evidence.nonce,
        ),
        InboundReplayKind.SOURCE_EVENT_ID: inbound_evidence_digest(
            source_id,
            InboundReplayKind.SOURCE_EVENT_ID,
            evidence.source_event_id,
        ),
    }


def _payload_digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)
