"""Action-bound, short-lived, single-use approval records for tool calls."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.authorization import (
    TOOL_INVOKE_ACTION,
    canonical_tool_argument_digest,
    tool_effect_requires_approval,
)
from phoenix_os.agent.contracts import (
    MAX_AGENT_APPROVAL_WAIT_TIMEOUT,
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolApprovalId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
)
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.policy import PrincipalType, SecurityContext

_ARGUMENT_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RESOURCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._:/-]{0,1023})\Z")
_IMPLEMENTATION_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})\Z")
_APPROVAL_V1 = 1
_APPROVAL_V2 = 2


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolApprovalStatus(StrEnum):
    """Bounded lifecycle states for one server-owned approval record."""

    PENDING = "pending"
    APPROVED = "approved"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class ToolApprovalChallenge:
    """Content-free metadata for one exact tool invocation awaiting approval."""

    approval_id: ToolApprovalId
    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    effect: ToolEffect
    resolved_resource: str
    argument_digest: str
    requested_at: datetime
    expires_at: datetime
    schema_version: int = _APPROVAL_V1
    principal_type: PrincipalType | None = None
    principal: str | None = None
    session_id: UUID | None = None
    agent_id: AgentId | None = None
    resolver_id: str | None = None
    adapter_id: str | None = None

    def __post_init__(self) -> None:
        _validate_binding_fields(
            self.approval_id,
            self.run_id,
            self.step_id,
            self.call_id,
            self.tool_id,
            self.effect,
            self.resolved_resource,
            self.argument_digest,
        )
        _validate_subject_binding(
            schema_version=self.schema_version,
            principal_type=self.principal_type,
            principal=self.principal,
            session_id=self.session_id,
            agent_id=self.agent_id,
            resolver_id=self.resolver_id,
            adapter_id=self.adapter_id,
        )
        _require_aware(self.requested_at, "requested_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.requested_at:
            raise ValueError("tool approval expiry must follow request time")


@dataclass(frozen=True, slots=True)
class ToolApprovalEvidence:
    """Server-issued approval evidence bound to one exact tool invocation."""

    approval_id: ToolApprovalId
    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    effect: ToolEffect
    resolved_resource: str
    argument_digest: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    schema_version: int = _APPROVAL_V1
    principal_type: PrincipalType | None = None
    principal: str | None = None
    session_id: UUID | None = None
    agent_id: AgentId | None = None
    resolver_id: str | None = None
    adapter_id: str | None = None

    def __post_init__(self) -> None:
        _validate_binding_fields(
            self.approval_id,
            self.run_id,
            self.step_id,
            self.call_id,
            self.tool_id,
            self.effect,
            self.resolved_resource,
            self.argument_digest,
        )
        _validate_subject_binding(
            schema_version=self.schema_version,
            principal_type=self.principal_type,
            principal=self.principal,
            session_id=self.session_id,
            agent_id=self.agent_id,
            resolver_id=self.resolver_id,
            adapter_id=self.adapter_id,
        )
        approved_by = self.approved_by.strip()
        if not approved_by:
            raise ValueError("approved_by must not be blank")
        _require_aware(self.approved_at, "approved_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("tool approval expiry must follow approval time")
        object.__setattr__(self, "approved_by", approved_by)


@dataclass(frozen=True, slots=True)
class ToolApprovalVerification:
    """Safe result returned after exact evidence is consumed once."""

    approval_id: ToolApprovalId
    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    consumed_at: datetime
    schema_version: int = _APPROVAL_V1

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, ToolApprovalId):
            raise TypeError("approval_id must be ToolApprovalId")
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if self.schema_version not in {_APPROVAL_V1, _APPROVAL_V2}:
            raise ValueError("unsupported tool approval verification schema version")
        _require_aware(self.consumed_at, "consumed_at")


@dataclass(frozen=True, slots=True)
class ToolApprovalRecord:
    """Content-free current record returned without consuming approval authority."""

    challenge: ToolApprovalChallenge
    requester: str
    status: ToolApprovalStatus
    approved_at: datetime | None = None
    consumed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.challenge, ToolApprovalChallenge):
            raise TypeError("challenge must be ToolApprovalChallenge")
        if not isinstance(self.status, ToolApprovalStatus):
            raise TypeError("status must be ToolApprovalStatus")
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

        if self.status is ToolApprovalStatus.PENDING:
            if self.approved_at is not None or self.consumed_at is not None:
                raise ValueError("pending approval records cannot contain terminal timestamps")
        elif self.status is ToolApprovalStatus.APPROVED:
            if self.approved_at is None or self.consumed_at is not None:
                raise ValueError("approved records require only approved_at")
        else:
            if self.approved_at is None or self.consumed_at is None:
                raise ValueError("consumed records require approval and consumption times")
            if self.consumed_at < self.approved_at:
                raise ValueError("consumed_at cannot precede approved_at")
            if self.consumed_at >= self.challenge.expires_at:
                raise ValueError("consumed_at falls outside the approval lifetime")


@dataclass(frozen=True, slots=True)
class ToolApprovalSnapshot:
    """Content-free counters for one bounded approval store."""

    closed: bool
    entries: int
    pending: int
    approved: int
    consumed: int
    capacity: int

    def __post_init__(self) -> None:
        counters = (self.entries, self.pending, self.approved, self.consumed)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in counters):
            raise TypeError("tool approval counters must be integers")
        if min(counters) < 0 or self.capacity <= 0:
            raise ValueError("tool approval counters cannot be negative")
        if self.entries > self.capacity:
            raise ValueError("tool approval entries exceed capacity")
        if self.pending + self.approved + self.consumed != self.entries:
            raise ValueError("tool approval counters are inconsistent")


@runtime_checkable
class ToolApprovalService(Protocol):
    @property
    def closed(self) -> bool: ...

    async def request(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> ToolApprovalChallenge: ...

    async def approve(
        self,
        approval_id: ToolApprovalId,
        approver: SecurityContext,
    ) -> ToolApprovalEvidence: ...

    async def verify_and_consume(
        self,
        evidence: ToolApprovalEvidence,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> ToolApprovalVerification: ...

    async def snapshot(self) -> ToolApprovalSnapshot: ...

    async def close(self) -> None: ...


@runtime_checkable
class ToolApprovalStateService(Protocol):
    """Read-only current-state boundary for durable approval revalidation."""

    async def lookup(
        self,
        approval_id: ToolApprovalId,
    ) -> ToolApprovalRecord | None: ...


@dataclass(slots=True)
class _ApprovalEntry:
    challenge: ToolApprovalChallenge
    binding_digest: bytes
    requester: str
    status: ToolApprovalStatus = ToolApprovalStatus.PENDING
    approved_by: str | None = None
    approved_at: datetime | None = None
    consumed_at: datetime | None = None


def tool_descriptor_requires_approval(descriptor: ToolDescriptor) -> bool:
    """Return the conservative approval requirement for one reviewed descriptor."""

    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    return descriptor.approval_may_be_required or tool_effect_requires_approval(descriptor.effect)


class InMemoryToolApprovalService:
    """Store exact approval bindings and reject expiry, mutation, and replay."""

    def __init__(
        self,
        *,
        capacity: int = 1024,
        ttl: timedelta = timedelta(minutes=2),
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("tool approval capacity must be an integer")
        if capacity <= 0 or capacity > 100_000:
            raise ValueError("tool approval capacity must be between 1 and 100000")
        if not isinstance(ttl, timedelta):
            raise TypeError("tool approval TTL must be a timedelta")
        if ttl <= timedelta(0) or ttl > MAX_AGENT_APPROVAL_WAIT_TIMEOUT:
            raise ValueError("tool approval TTL exceeds the allowed range")
        if not callable(clock):
            raise TypeError("tool approval clock must be callable")
        self._capacity = capacity
        self._ttl = ttl
        self._clock = clock
        self._entries: dict[ToolApprovalId, _ApprovalEntry] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def request(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> ToolApprovalChallenge:
        _validate_request_descriptor_context(request, descriptor, context)
        if not tool_descriptor_requires_approval(descriptor):
            raise AgentApprovalRejectedError()

        now = self._now()
        if now >= request.deadline:
            raise AgentApprovalRejectedError()
        expires_at = min(now + self._ttl, request.deadline)
        if expires_at <= now:
            raise AgentApprovalRejectedError()

        challenge = ToolApprovalChallenge(
            approval_id=ToolApprovalId(),
            schema_version=_APPROVAL_V2,
            principal_type=context.principal_type,
            principal=context.principal,
            session_id=context.session_id,
            agent_id=request.agent_id,
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            effect=descriptor.effect,
            resolver_id=descriptor.resolver_id,
            adapter_id=descriptor.adapter_id,
            resolved_resource=request.resolved_resource,
            argument_digest=canonical_tool_argument_digest(request.arguments),
            requested_at=now,
            expires_at=expires_at,
        )
        binding = _binding_digest(
            request,
            descriptor,
            context,
            expires_at=expires_at,
        )
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
        approval_id: ToolApprovalId,
        approver: SecurityContext,
    ) -> ToolApprovalEvidence:
        if not isinstance(approval_id, ToolApprovalId):
            raise TypeError("approval_id must be ToolApprovalId")
        _require_authenticated_context(approver)
        now = self._now()
        async with self._lock:
            self._require_open()
            entry = self._entries.get(approval_id)
            if (
                entry is None
                or entry.status is not ToolApprovalStatus.PENDING
                or now >= entry.challenge.expires_at
            ):
                raise AgentApprovalRejectedError()
            entry.status = ToolApprovalStatus.APPROVED
            entry.approved_by = approver.principal
            entry.approved_at = now
            return _evidence(entry)

    async def verify_and_consume(
        self,
        evidence: ToolApprovalEvidence,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> ToolApprovalVerification:
        if not isinstance(evidence, ToolApprovalEvidence):
            raise TypeError("evidence must be ToolApprovalEvidence")
        if evidence.schema_version != _APPROVAL_V2:
            raise AgentApprovalRejectedError()
        _validate_request_descriptor_context(request, descriptor, context)
        now = self._now()

        async with self._lock:
            self._require_open()
            entry = self._entries.get(evidence.approval_id)
            if (
                entry is None
                or entry.challenge.schema_version != _APPROVAL_V2
                or entry.status is not ToolApprovalStatus.APPROVED
                or now >= entry.challenge.expires_at
            ):
                raise AgentApprovalRejectedError()
            binding = _binding_digest(
                request,
                descriptor,
                context,
                expires_at=entry.challenge.expires_at,
            )
            if (
                not hmac.compare_digest(entry.binding_digest, binding)
                or not hmac.compare_digest(
                    _evidence_digest(evidence),
                    _evidence_digest(_evidence(entry)),
                )
            ):
                raise AgentApprovalRejectedError()
            entry.status = ToolApprovalStatus.CONSUMED
            entry.consumed_at = now

        return ToolApprovalVerification(
            approval_id=evidence.approval_id,
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            consumed_at=now,
            schema_version=_APPROVAL_V2,
        )

    async def lookup(
        self,
        approval_id: ToolApprovalId,
    ) -> ToolApprovalRecord | None:
        if not isinstance(approval_id, ToolApprovalId):
            raise TypeError("approval_id must be ToolApprovalId")
        async with self._lock:
            self._require_open()
            entry = self._entries.get(approval_id)
            return None if entry is None else _record(entry)

    async def snapshot(self) -> ToolApprovalSnapshot:
        async with self._lock:
            pending = sum(
                entry.status is ToolApprovalStatus.PENDING for entry in self._entries.values()
            )
            approved = sum(
                entry.status is ToolApprovalStatus.APPROVED for entry in self._entries.values()
            )
            consumed = sum(
                entry.status is ToolApprovalStatus.CONSUMED for entry in self._entries.values()
            )
            return ToolApprovalSnapshot(
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
            if entry.status is ToolApprovalStatus.CONSUMED or now >= entry.challenge.expires_at
        ]
        if not removable:
            raise AgentApprovalRejectedError()
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
        _require_aware(value, "tool approval clock result")
        return value

    def _require_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()


def _validate_binding_fields(
    approval_id: ToolApprovalId,
    run_id: AgentRunId,
    step_id: AgentStepId,
    call_id: ToolCallId,
    tool_id: ToolId,
    effect: ToolEffect,
    resolved_resource: str,
    argument_digest: str,
) -> None:
    if not isinstance(approval_id, ToolApprovalId):
        raise TypeError("approval_id must be ToolApprovalId")
    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    if not isinstance(step_id, AgentStepId):
        raise TypeError("step_id must be AgentStepId")
    if not isinstance(call_id, ToolCallId):
        raise TypeError("call_id must be ToolCallId")
    if not isinstance(tool_id, ToolId):
        raise TypeError("tool_id must be ToolId")
    if not isinstance(effect, ToolEffect):
        raise TypeError("effect must be ToolEffect")
    if (
        not isinstance(resolved_resource, str)
        or _RESOURCE_PATTERN.fullmatch(resolved_resource) is None
    ):
        raise ValueError("resolved_resource is invalid")
    if (
        not isinstance(argument_digest, str)
        or _ARGUMENT_DIGEST_PATTERN.fullmatch(argument_digest) is None
    ):
        raise ValueError("argument_digest has an invalid format")


def _validate_subject_binding(
    *,
    schema_version: int,
    principal_type: PrincipalType | None,
    principal: str | None,
    session_id: UUID | None,
    agent_id: AgentId | None,
    resolver_id: str | None,
    adapter_id: str | None,
) -> None:
    if schema_version not in {_APPROVAL_V1, _APPROVAL_V2}:
        raise ValueError("unsupported tool approval schema version")
    v2_fields = (
        principal_type,
        principal,
        session_id,
        agent_id,
        resolver_id,
        adapter_id,
    )
    if schema_version == _APPROVAL_V1:
        if any(value is not None for value in v2_fields):
            raise ValueError("legacy tool approval cannot contain v2 binding fields")
        return
    if not isinstance(principal_type, PrincipalType):
        raise TypeError("principal_type must be PrincipalType")
    if principal_type is PrincipalType.ANONYMOUS:
        raise ValueError("tool approval cannot bind an anonymous principal")
    if not isinstance(principal, str):
        raise TypeError("principal must be a string")
    if not principal or principal != principal.strip() or len(principal) > 1_024:
        raise ValueError("principal is invalid")
    if session_id is not None and not isinstance(session_id, UUID):
        raise TypeError("session_id must be UUID or None")
    if not isinstance(agent_id, AgentId):
        raise TypeError("agent_id must be AgentId")
    for label, value in (("resolver_id", resolver_id), ("adapter_id", adapter_id)):
        if not isinstance(value, str):
            raise TypeError(f"{label} must be a string")
        if _IMPLEMENTATION_ID_PATTERN.fullmatch(value) is None:
            raise ValueError(f"{label} is invalid")


def _validate_request_descriptor_context(
    request: ToolInvocationRequest,
    descriptor: ToolDescriptor,
    context: SecurityContext,
) -> None:
    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    _require_authenticated_context(context)
    if request.agent_id is None:
        raise AgentApprovalRejectedError()
    if descriptor.tool_id != request.tool_id:
        raise AgentApprovalRejectedError()


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentApprovalRejectedError()


def _binding_digest(
    request: ToolInvocationRequest,
    descriptor: ToolDescriptor,
    context: SecurityContext,
    *,
    expires_at: datetime,
) -> bytes:
    agent_id = request.agent_id
    if agent_id is None:
        raise AgentApprovalRejectedError()
    _require_aware(expires_at, "approval binding expiry")
    material = json.dumps(
        [
            "phoenix-agent-approval-binding:v2",
            TOOL_INVOKE_ACTION,
            context.principal_type.value,
            context.principal,
            None if context.session_id is None else str(context.session_id),
            str(agent_id),
            str(request.run_id),
            str(request.step_id),
            str(request.call_id),
            str(request.tool_id),
            descriptor.effect.value,
            descriptor.resolver_id,
            descriptor.adapter_id,
            request.resolved_resource,
            canonical_tool_argument_digest(request.arguments),
            expires_at.isoformat(),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).digest()


def _record(entry: _ApprovalEntry) -> ToolApprovalRecord:
    return ToolApprovalRecord(
        challenge=entry.challenge,
        requester=entry.requester,
        status=entry.status,
        approved_at=entry.approved_at,
        consumed_at=entry.consumed_at,
    )


def _evidence(entry: _ApprovalEntry) -> ToolApprovalEvidence:
    approved_by = entry.approved_by
    approved_at = entry.approved_at
    if approved_by is None or approved_at is None:
        raise AgentApprovalRejectedError()
    challenge = entry.challenge
    if challenge.schema_version != _APPROVAL_V2:
        raise AgentApprovalRejectedError()
    return ToolApprovalEvidence(
        approval_id=challenge.approval_id,
        run_id=challenge.run_id,
        step_id=challenge.step_id,
        call_id=challenge.call_id,
        tool_id=challenge.tool_id,
        effect=challenge.effect,
        resolved_resource=challenge.resolved_resource,
        argument_digest=challenge.argument_digest,
        approved_by=approved_by,
        approved_at=approved_at,
        expires_at=challenge.expires_at,
        schema_version=_APPROVAL_V2,
        principal_type=challenge.principal_type,
        principal=challenge.principal,
        session_id=challenge.session_id,
        agent_id=challenge.agent_id,
        resolver_id=challenge.resolver_id,
        adapter_id=challenge.adapter_id,
    )


def _evidence_digest(evidence: ToolApprovalEvidence) -> bytes:
    principal_type = evidence.principal_type
    principal = evidence.principal
    agent_id = evidence.agent_id
    resolver_id = evidence.resolver_id
    adapter_id = evidence.adapter_id
    if (
        evidence.schema_version != _APPROVAL_V2
        or principal_type is None
        or principal is None
        or agent_id is None
        or resolver_id is None
        or adapter_id is None
    ):
        raise AgentApprovalRejectedError()
    material = json.dumps(
        [
            "phoenix-agent-approval-evidence:v2",
            str(evidence.approval_id),
            principal_type.value,
            principal,
            None if evidence.session_id is None else str(evidence.session_id),
            str(agent_id),
            str(evidence.run_id),
            str(evidence.step_id),
            str(evidence.call_id),
            str(evidence.tool_id),
            evidence.effect.value,
            resolver_id,
            adapter_id,
            evidence.resolved_resource,
            evidence.argument_digest,
            evidence.approved_by,
            evidence.approved_at.isoformat(),
            evidence.expires_at.isoformat(),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).digest()


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
