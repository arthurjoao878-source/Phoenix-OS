"""Action-bound, short-lived, single-use approval for destructive host effects."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.host_automation.authorization import HOST_APPLICATION_CLOSE_ACTION
from phoenix_os.host_automation.contracts import (
    MAX_HOST_OPERATION_TIMEOUT,
    HostApplicationCloseRequest,
    HostApplicationId,
    HostEpoch,
    HostId,
    HostProcessId,
)
from phoenix_os.host_automation.errors import (
    HostAutomationApprovalRejectedError,
    HostAutomationServiceUnavailableError,
)
from phoenix_os.policy import SecurityContext

_MAX_HOST_APPROVAL_CAPACITY = 100_000


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True, order=True)
class HostAutomationApprovalId:
    """Opaque server-owned identity for one host approval record."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("host automation approval id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


class HostAutomationApprovalStatus(StrEnum):
    """Finite lifecycle states for one host approval record."""

    PENDING = "pending"
    APPROVED = "approved"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class HostAutomationApprovalChallenge:
    """Content-free challenge bound to one exact host.app.close invocation."""

    approval_id: HostAutomationApprovalId
    action: str
    host_id: HostId
    host_epoch: HostEpoch
    application_id: HostApplicationId
    process_id: HostProcessId
    request_id: UUID
    requested_at: datetime
    expires_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        _validate_close_binding(
            approval_id=self.approval_id,
            action=self.action,
            host_id=self.host_id,
            host_epoch=self.host_epoch,
            application_id=self.application_id,
            process_id=self.process_id,
            request_id=self.request_id,
        )
        if self.schema_version != 1:
            raise ValueError("unsupported host automation approval challenge schema version")
        _require_aware(self.requested_at, "requested_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.requested_at:
            raise ValueError("host automation approval expiry must follow request time")


@dataclass(frozen=True, slots=True)
class HostAutomationApprovalEvidence:
    """Server-issued evidence bound to one exact host.app.close invocation."""

    approval_id: HostAutomationApprovalId
    action: str
    host_id: HostId
    host_epoch: HostEpoch
    application_id: HostApplicationId
    process_id: HostProcessId
    request_id: UUID
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        _validate_close_binding(
            approval_id=self.approval_id,
            action=self.action,
            host_id=self.host_id,
            host_epoch=self.host_epoch,
            application_id=self.application_id,
            process_id=self.process_id,
            request_id=self.request_id,
        )
        if not isinstance(self.approved_by, str):
            raise TypeError("approved_by must be a string")
        approved_by = self.approved_by.strip()
        if not approved_by or len(approved_by) > 1_024:
            raise ValueError("approved_by is invalid")
        if self.schema_version != 1:
            raise ValueError("unsupported host automation approval evidence schema version")
        _require_aware(self.approved_at, "approved_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("host automation approval expiry must follow approval time")
        object.__setattr__(self, "approved_by", approved_by)


@dataclass(frozen=True, slots=True)
class HostAutomationApprovalVerification:
    """Safe acknowledgement that one approval was consumed exactly once."""

    approval_id: HostAutomationApprovalId
    action: str
    consumed_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, HostAutomationApprovalId):
            raise TypeError("approval_id must be HostAutomationApprovalId")
        if self.action != HOST_APPLICATION_CLOSE_ACTION:
            raise ValueError("unsupported host automation approval action")
        if self.schema_version != 1:
            raise ValueError("unsupported host automation approval verification schema version")
        _require_aware(self.consumed_at, "consumed_at")


@dataclass(frozen=True, slots=True)
class HostAutomationApprovalRecord:
    """Current content-free approval state without consumable authority."""

    challenge: HostAutomationApprovalChallenge
    requester: str
    status: HostAutomationApprovalStatus
    approved_at: datetime | None = None
    consumed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.challenge, HostAutomationApprovalChallenge):
            raise TypeError("challenge must be HostAutomationApprovalChallenge")
        if not isinstance(self.status, HostAutomationApprovalStatus):
            raise TypeError("status must be HostAutomationApprovalStatus")
        if not isinstance(self.requester, str):
            raise TypeError("requester must be a string")
        requester = self.requester.strip()
        if not requester or len(requester) > 1_024:
            raise ValueError("requester is invalid")
        object.__setattr__(self, "requester", requester)

        for label, timestamp in (
            ("approved_at", self.approved_at),
            ("consumed_at", self.consumed_at),
        ):
            if timestamp is not None:
                _require_aware(timestamp, label)

        if self.approved_at is not None and (
            self.approved_at < self.challenge.requested_at
            or self.approved_at >= self.challenge.expires_at
        ):
            raise ValueError("approved_at falls outside the approval lifetime")
        if self.status is HostAutomationApprovalStatus.PENDING:
            if self.approved_at is not None or self.consumed_at is not None:
                raise ValueError("pending host approvals cannot contain terminal timestamps")
        elif self.status is HostAutomationApprovalStatus.APPROVED:
            if self.approved_at is None or self.consumed_at is not None:
                raise ValueError("approved host approvals require only approved_at")
        else:
            if self.approved_at is None or self.consumed_at is None:
                raise ValueError("consumed host approvals require terminal timestamps")
            if self.consumed_at < self.approved_at:
                raise ValueError("consumed_at cannot precede approved_at")
            if self.consumed_at >= self.challenge.expires_at:
                raise ValueError("consumed_at falls outside the approval lifetime")


@dataclass(frozen=True, slots=True)
class HostAutomationApprovalSnapshot:
    closed: bool
    entries: int
    pending: int
    approved: int
    consumed: int
    capacity: int

    def __post_init__(self) -> None:
        if not isinstance(self.closed, bool):
            raise TypeError("closed must be a boolean")
        counters = (self.entries, self.pending, self.approved, self.consumed, self.capacity)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in counters):
            raise TypeError("host automation approval counters must be integers")
        if min(counters) < 0 or self.capacity <= 0:
            raise ValueError("host automation approval counters are invalid")
        if self.entries > self.capacity:
            raise ValueError("host automation approval entries exceed capacity")
        if self.pending + self.approved + self.consumed != self.entries:
            raise ValueError("host automation approval counters are inconsistent")


@runtime_checkable
class HostAutomationApprovalGate(Protocol):
    """Explicit approval boundary for destructive host.app.close effects."""

    @property
    def closed(self) -> bool: ...

    async def request_application_close(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> HostAutomationApprovalChallenge: ...

    async def approve(
        self,
        approval_id: HostAutomationApprovalId,
        approver: SecurityContext,
    ) -> HostAutomationApprovalEvidence: ...

    async def verify_and_consume_application_close(
        self,
        evidence: HostAutomationApprovalEvidence,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> HostAutomationApprovalVerification: ...

    async def lookup(
        self,
        approval_id: HostAutomationApprovalId,
    ) -> HostAutomationApprovalRecord | None: ...

    async def snapshot(self) -> HostAutomationApprovalSnapshot: ...

    async def close(self) -> None: ...


@dataclass(slots=True)
class _ApprovalEntry:
    challenge: HostAutomationApprovalChallenge
    binding_digest: bytes
    requester: str
    status: HostAutomationApprovalStatus = HostAutomationApprovalStatus.PENDING
    approved_by: str | None = None
    approved_at: datetime | None = None
    consumed_at: datetime | None = None


class InMemoryHostAutomationApprovalGate:
    """Store exact host-close approval bindings and reject mutation or replay."""

    def __init__(
        self,
        *,
        capacity: int = 1_024,
        ttl: timedelta = timedelta(minutes=2),
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("host automation approval capacity must be an integer")
        if capacity <= 0 or capacity > _MAX_HOST_APPROVAL_CAPACITY:
            raise ValueError("host automation approval capacity is outside the allowed range")
        if not isinstance(ttl, timedelta):
            raise TypeError("host automation approval TTL must be a timedelta")
        if ttl <= timedelta(0) or ttl > MAX_HOST_OPERATION_TIMEOUT:
            raise ValueError("host automation approval TTL is outside the allowed range")
        if not callable(clock):
            raise TypeError("host automation approval clock must be callable")

        self._capacity = capacity
        self._ttl = ttl
        self._clock = clock
        self._entries: dict[HostAutomationApprovalId, _ApprovalEntry] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def request_application_close(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> HostAutomationApprovalChallenge:
        if not isinstance(request, HostApplicationCloseRequest):
            raise TypeError("request must be HostApplicationCloseRequest")
        _require_authenticated_context(context)

        now = self._now()
        challenge = HostAutomationApprovalChallenge(
            approval_id=HostAutomationApprovalId(),
            action=HOST_APPLICATION_CLOSE_ACTION,
            host_id=request.host_id,
            host_epoch=request.host_epoch,
            application_id=request.application_id,
            process_id=request.process_id,
            request_id=request.request_id,
            requested_at=now,
            expires_at=now + self._ttl,
        )
        binding = _close_binding_digest(request, context)
        async with self._lock:
            self._require_open()
            self._ensure_capacity(now)
            self._entries[challenge.approval_id] = _ApprovalEntry(
                challenge=challenge,
                binding_digest=binding,
                requester=context.principal,
            )
        return challenge

    async def approve(
        self,
        approval_id: HostAutomationApprovalId,
        approver: SecurityContext,
    ) -> HostAutomationApprovalEvidence:
        if not isinstance(approval_id, HostAutomationApprovalId):
            raise TypeError("approval_id must be HostAutomationApprovalId")
        _require_authenticated_context(approver)
        now = self._now()
        async with self._lock:
            self._require_open()
            entry = self._entries.get(approval_id)
            if (
                entry is None
                or entry.status is not HostAutomationApprovalStatus.PENDING
                or now >= entry.challenge.expires_at
            ):
                raise HostAutomationApprovalRejectedError()
            entry.status = HostAutomationApprovalStatus.APPROVED
            entry.approved_by = approver.principal
            entry.approved_at = now
            return _evidence(entry)

    async def verify_and_consume_application_close(
        self,
        evidence: HostAutomationApprovalEvidence,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> HostAutomationApprovalVerification:
        if not isinstance(evidence, HostAutomationApprovalEvidence):
            raise TypeError("evidence must be HostAutomationApprovalEvidence")
        if not isinstance(request, HostApplicationCloseRequest):
            raise TypeError("request must be HostApplicationCloseRequest")
        _require_authenticated_context(context)

        now = self._now()
        binding = _close_binding_digest(request, context)
        async with self._lock:
            self._require_open()
            entry = self._entries.get(evidence.approval_id)
            if (
                entry is None
                or entry.status is not HostAutomationApprovalStatus.APPROVED
                or now >= entry.challenge.expires_at
                or not hmac.compare_digest(entry.binding_digest, binding)
                or not hmac.compare_digest(
                    _evidence_digest(evidence),
                    _evidence_digest(_evidence(entry)),
                )
            ):
                raise HostAutomationApprovalRejectedError()
            entry.status = HostAutomationApprovalStatus.CONSUMED
            entry.consumed_at = now

        return HostAutomationApprovalVerification(
            approval_id=evidence.approval_id,
            action=HOST_APPLICATION_CLOSE_ACTION,
            consumed_at=now,
        )

    async def lookup(
        self,
        approval_id: HostAutomationApprovalId,
    ) -> HostAutomationApprovalRecord | None:
        if not isinstance(approval_id, HostAutomationApprovalId):
            raise TypeError("approval_id must be HostAutomationApprovalId")
        async with self._lock:
            self._require_open()
            entry = self._entries.get(approval_id)
            return None if entry is None else _record(entry)

    async def snapshot(self) -> HostAutomationApprovalSnapshot:
        async with self._lock:
            pending = sum(
                entry.status is HostAutomationApprovalStatus.PENDING
                for entry in self._entries.values()
            )
            approved = sum(
                entry.status is HostAutomationApprovalStatus.APPROVED
                for entry in self._entries.values()
            )
            consumed = sum(
                entry.status is HostAutomationApprovalStatus.CONSUMED
                for entry in self._entries.values()
            )
            return HostAutomationApprovalSnapshot(
                closed=self._closed,
                entries=len(self._entries),
                pending=pending,
                approved=approved,
                consumed=consumed,
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._entries.clear()

    def _ensure_capacity(self, now: datetime) -> None:
        if len(self._entries) < self._capacity:
            return
        removable = [
            (approval_id, entry)
            for approval_id, entry in self._entries.items()
            if entry.status is HostAutomationApprovalStatus.CONSUMED
            or now >= entry.challenge.expires_at
        ]
        if not removable:
            raise HostAutomationApprovalRejectedError()
        approval_id, _ = min(
            removable,
            key=lambda item: (
                item[1].challenge.requested_at,
                str(item[0]),
            ),
        )
        del self._entries[approval_id]

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, "host automation approval clock result")
        return value

    def _require_open(self) -> None:
        if self._closed:
            raise HostAutomationServiceUnavailableError()


def _validate_close_binding(
    *,
    approval_id: HostAutomationApprovalId,
    action: str,
    host_id: HostId,
    host_epoch: HostEpoch,
    application_id: HostApplicationId,
    process_id: HostProcessId,
    request_id: UUID,
) -> None:
    if not isinstance(approval_id, HostAutomationApprovalId):
        raise TypeError("approval_id must be HostAutomationApprovalId")
    if action != HOST_APPLICATION_CLOSE_ACTION:
        raise ValueError("host automation approval is not bound to host.app.close")
    if not isinstance(host_id, HostId):
        raise TypeError("host_id must be HostId")
    if not isinstance(host_epoch, HostEpoch):
        raise TypeError("host_epoch must be HostEpoch")
    if not isinstance(application_id, HostApplicationId):
        raise TypeError("application_id must be HostApplicationId")
    if not isinstance(process_id, HostProcessId):
        raise TypeError("process_id must be HostProcessId")
    if not isinstance(request_id, UUID):
        raise TypeError("request_id must be UUID")


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise HostAutomationApprovalRejectedError()


def _close_binding_digest(
    request: HostApplicationCloseRequest,
    context: SecurityContext,
) -> bytes:
    material = (
        f"phoenix-host-approval-binding:v1:{HOST_APPLICATION_CLOSE_ACTION}:"
        f"{context.principal_type.value}:{context.principal}:"
        f"{request.host_id}:{request.host_epoch}:{request.application_id}:"
        f"{request.process_id}:{request.request_id}"
    ).encode()
    return hashlib.sha256(material).digest()


def _record(entry: _ApprovalEntry) -> HostAutomationApprovalRecord:
    return HostAutomationApprovalRecord(
        challenge=entry.challenge,
        requester=entry.requester,
        status=entry.status,
        approved_at=entry.approved_at,
        consumed_at=entry.consumed_at,
    )


def _evidence(entry: _ApprovalEntry) -> HostAutomationApprovalEvidence:
    approved_by = entry.approved_by
    approved_at = entry.approved_at
    if approved_by is None or approved_at is None:
        raise HostAutomationApprovalRejectedError()
    challenge = entry.challenge
    return HostAutomationApprovalEvidence(
        approval_id=challenge.approval_id,
        action=challenge.action,
        host_id=challenge.host_id,
        host_epoch=challenge.host_epoch,
        application_id=challenge.application_id,
        process_id=challenge.process_id,
        request_id=challenge.request_id,
        approved_by=approved_by,
        approved_at=approved_at,
        expires_at=challenge.expires_at,
    )


def _evidence_digest(evidence: HostAutomationApprovalEvidence) -> bytes:
    material = (
        f"phoenix-host-approval-evidence:v1:{evidence.approval_id}:{evidence.action}:"
        f"{evidence.host_id}:{evidence.host_epoch}:{evidence.application_id}:"
        f"{evidence.process_id}:{evidence.request_id}:{evidence.approved_by}:"
        f"{evidence.approved_at.isoformat()}:{evidence.expires_at.isoformat()}"
    ).encode()
    return hashlib.sha256(material).digest()


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
