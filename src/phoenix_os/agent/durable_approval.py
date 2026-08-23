"""Approval-wait checkpoint correlation and current-state revalidation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.approval import (
    ToolApprovalChallenge,
    ToolApprovalRecord,
    ToolApprovalStateService,
    ToolApprovalStatus,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolApprovalId,
    ToolCallId,
    ToolEffect,
    ToolId,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableRunStatus,
)
from phoenix_os.agent.errors import AgentServiceUnavailableError
from phoenix_os.policy import PrincipalType

_APPROVAL_SCHEMA_KEY = "approval.schema"
_APPROVAL_ID_KEY = "approval.id"
_APPROVAL_RUN_KEY = "approval.run"
_APPROVAL_STEP_KEY = "approval.step"
_APPROVAL_CALL_KEY = "approval.call"
_APPROVAL_TOOL_KEY = "approval.tool"
_APPROVAL_EFFECT_KEY = "approval.effect"
_APPROVAL_RESOURCE_KEY = "approval.resource"
_APPROVAL_ARGUMENT_DIGEST_KEY = "approval.argument-digest"
_APPROVAL_REQUESTER_KEY = "approval.requester"
_APPROVAL_REQUESTED_AT_KEY = "approval.requested-at"
_APPROVAL_EXPIRES_AT_KEY = "approval.expires-at"
_APPROVAL_PRINCIPAL_TYPE_KEY = "approval.principal-type"
_APPROVAL_PRINCIPAL_KEY = "approval.principal"
_APPROVAL_SESSION_ID_KEY = "approval.session-id"
_APPROVAL_AGENT_KEY = "approval.agent"
_APPROVAL_RESOLVER_KEY = "approval.resolver"
_APPROVAL_ADAPTER_KEY = "approval.adapter"
_APPROVAL_LEGACY_SCHEMA_VERSION = "1"
_APPROVAL_SCHEMA_VERSION = "2"
_NO_SESSION = "none"

_APPROVAL_WAIT_V1_KEYS = frozenset(
    {
        _APPROVAL_SCHEMA_KEY,
        _APPROVAL_ID_KEY,
        _APPROVAL_RUN_KEY,
        _APPROVAL_STEP_KEY,
        _APPROVAL_CALL_KEY,
        _APPROVAL_TOOL_KEY,
        _APPROVAL_EFFECT_KEY,
        _APPROVAL_RESOURCE_KEY,
        _APPROVAL_ARGUMENT_DIGEST_KEY,
        _APPROVAL_REQUESTER_KEY,
        _APPROVAL_REQUESTED_AT_KEY,
        _APPROVAL_EXPIRES_AT_KEY,
    }
)
_APPROVAL_WAIT_V2_KEYS = frozenset(
    _APPROVAL_WAIT_V1_KEYS
    | {
        _APPROVAL_PRINCIPAL_TYPE_KEY,
        _APPROVAL_PRINCIPAL_KEY,
        _APPROVAL_SESSION_ID_KEY,
        _APPROVAL_AGENT_KEY,
        _APPROVAL_RESOLVER_KEY,
        _APPROVAL_ADAPTER_KEY,
    }
)
_APPROVAL_WAIT_KEYS = frozenset(_APPROVAL_WAIT_V1_KEYS | _APPROVAL_WAIT_V2_KEYS)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _normalize_requester(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("approval requester must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > 1_024:
        raise ValueError("approval requester is invalid")
    return normalized


@dataclass(frozen=True, slots=True)
class ApprovalWaitReference:
    """Exact content-free approval correlation persisted in checkpoint metadata."""

    approval_id: ToolApprovalId
    agent_run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    tool_id: ToolId
    effect: ToolEffect
    resolved_resource: str
    argument_digest: str
    requester: str
    requested_at: datetime
    expires_at: datetime
    principal_type: PrincipalType | None = None
    principal: str | None = None
    session_id: UUID | None = None
    agent_id: AgentId | None = None
    resolver_id: str | None = None
    adapter_id: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        ToolApprovalChallenge(
            approval_id=self.approval_id,
            run_id=self.agent_run_id,
            step_id=self.step_id,
            call_id=self.call_id,
            tool_id=self.tool_id,
            effect=self.effect,
            resolved_resource=self.resolved_resource,
            argument_digest=self.argument_digest,
            requested_at=self.requested_at,
            expires_at=self.expires_at,
            principal_type=self.principal_type,
            principal=self.principal,
            session_id=self.session_id,
            agent_id=self.agent_id,
            resolver_id=self.resolver_id,
            adapter_id=self.adapter_id,
            schema_version=self.schema_version,
        )
        object.__setattr__(self, "requester", _normalize_requester(self.requester))

    @classmethod
    def from_challenge(
        cls,
        challenge: ToolApprovalChallenge,
        *,
        requester: str,
    ) -> ApprovalWaitReference:
        if not isinstance(challenge, ToolApprovalChallenge):
            raise TypeError("challenge must be ToolApprovalChallenge")
        return cls(
            approval_id=challenge.approval_id,
            agent_run_id=challenge.run_id,
            step_id=challenge.step_id,
            call_id=challenge.call_id,
            tool_id=challenge.tool_id,
            effect=challenge.effect,
            resolved_resource=challenge.resolved_resource,
            argument_digest=challenge.argument_digest,
            requester=requester,
            requested_at=challenge.requested_at,
            expires_at=challenge.expires_at,
            principal_type=challenge.principal_type,
            principal=challenge.principal,
            session_id=challenge.session_id,
            agent_id=challenge.agent_id,
            resolver_id=challenge.resolver_id,
            adapter_id=challenge.adapter_id,
            schema_version=challenge.schema_version,
        )

    @classmethod
    def from_checkpoint(cls, checkpoint: CheckpointEnvelope) -> ApprovalWaitReference:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if checkpoint.status is not DurableRunStatus.PAUSED_APPROVAL:
            raise ValueError("checkpoint is not paused for approval")
        if checkpoint.metadata.next_operation is not CheckpointNextOperation.WAIT_APPROVAL:
            raise ValueError("approval checkpoint does not wait for approval")
        if checkpoint.step_id is None:
            raise ValueError("approval checkpoint requires a step id")

        metadata = checkpoint.metadata.metadata
        schema = metadata.get(_APPROVAL_SCHEMA_KEY)
        if schema == _APPROVAL_LEGACY_SCHEMA_VERSION:
            schema_version = 1
            expected_keys = _APPROVAL_WAIT_V1_KEYS
        elif schema == _APPROVAL_SCHEMA_VERSION:
            schema_version = 2
            expected_keys = _APPROVAL_WAIT_V2_KEYS
        else:
            raise ValueError("unsupported approval-wait metadata schema")
        approval_keys = frozenset(key for key in metadata if key.startswith("approval."))
        if approval_keys != expected_keys:
            raise ValueError("approval checkpoint correlation fields are not exact")

        principal_type: PrincipalType | None = None
        principal: str | None = None
        session_id: UUID | None = None
        agent_id: AgentId | None = None
        resolver_id: str | None = None
        adapter_id: str | None = None
        if schema_version == 2:
            principal_type = _metadata_principal_type(metadata, _APPROVAL_PRINCIPAL_TYPE_KEY)
            principal = _metadata_value(metadata, _APPROVAL_PRINCIPAL_KEY)
            session_id = _metadata_session_id(metadata, _APPROVAL_SESSION_ID_KEY)
            agent_id = _metadata_agent_id(metadata, _APPROVAL_AGENT_KEY)
            resolver_id = _metadata_value(metadata, _APPROVAL_RESOLVER_KEY)
            adapter_id = _metadata_value(metadata, _APPROVAL_ADAPTER_KEY)

        reference = cls(
            approval_id=ToolApprovalId(_metadata_uuid(metadata, _APPROVAL_ID_KEY)),
            agent_run_id=AgentRunId(_metadata_uuid(metadata, _APPROVAL_RUN_KEY)),
            step_id=AgentStepId(_metadata_uuid(metadata, _APPROVAL_STEP_KEY)),
            call_id=ToolCallId(_metadata_uuid(metadata, _APPROVAL_CALL_KEY)),
            tool_id=_metadata_tool_id(metadata, _APPROVAL_TOOL_KEY),
            effect=_metadata_effect(metadata, _APPROVAL_EFFECT_KEY),
            resolved_resource=_metadata_value(metadata, _APPROVAL_RESOURCE_KEY),
            argument_digest=_metadata_value(metadata, _APPROVAL_ARGUMENT_DIGEST_KEY),
            requester=_metadata_value(metadata, _APPROVAL_REQUESTER_KEY),
            requested_at=_metadata_datetime(metadata, _APPROVAL_REQUESTED_AT_KEY),
            expires_at=_metadata_datetime(metadata, _APPROVAL_EXPIRES_AT_KEY),
            principal_type=principal_type,
            principal=principal,
            session_id=session_id,
            agent_id=agent_id,
            resolver_id=resolver_id,
            adapter_id=adapter_id,
            schema_version=schema_version,
        )
        if reference.agent_run_id != checkpoint.agent_run_id:
            raise ValueError("approval reference changed agent run identity")
        if reference.step_id != checkpoint.step_id:
            raise ValueError("approval reference changed step identity")
        if reference.requester != checkpoint.metadata.actor_id:
            raise ValueError("approval reference changed requester identity")
        if reference.schema_version == 2 and reference.agent_id != checkpoint.metadata.agent_id:
            raise ValueError("approval reference changed agent identity")
        if reference.requested_at > checkpoint.created_at:
            raise ValueError("approval request cannot follow its checkpoint")
        if checkpoint.created_at >= reference.expires_at:
            raise ValueError("approval checkpoint cannot begin after expiry")
        if reference.expires_at > checkpoint.metadata.budget.deadline:
            raise ValueError("approval expiry exceeds the original run deadline")
        return reference

    def to_metadata(self) -> Mapping[str, str]:
        values = {
            _APPROVAL_SCHEMA_KEY: str(self.schema_version),
            _APPROVAL_ID_KEY: str(self.approval_id),
            _APPROVAL_RUN_KEY: str(self.agent_run_id),
            _APPROVAL_STEP_KEY: str(self.step_id),
            _APPROVAL_CALL_KEY: str(self.call_id),
            _APPROVAL_TOOL_KEY: str(self.tool_id),
            _APPROVAL_EFFECT_KEY: self.effect.value,
            _APPROVAL_RESOURCE_KEY: self.resolved_resource,
            _APPROVAL_ARGUMENT_DIGEST_KEY: self.argument_digest,
            _APPROVAL_REQUESTER_KEY: self.requester,
            _APPROVAL_REQUESTED_AT_KEY: self.requested_at.isoformat(),
            _APPROVAL_EXPIRES_AT_KEY: self.expires_at.isoformat(),
        }
        if self.schema_version == 1:
            return MappingProxyType(values)

        principal_type = self.principal_type
        principal = self.principal
        agent_id = self.agent_id
        resolver_id = self.resolver_id
        adapter_id = self.adapter_id
        if (
            principal_type is None
            or principal is None
            or agent_id is None
            or resolver_id is None
            or adapter_id is None
        ):
            raise ValueError("v2 approval reference is missing authority binding")
        values.update(
            {
                _APPROVAL_PRINCIPAL_TYPE_KEY: principal_type.value,
                _APPROVAL_PRINCIPAL_KEY: principal,
                _APPROVAL_SESSION_ID_KEY: (
                    _NO_SESSION if self.session_id is None else str(self.session_id)
                ),
                _APPROVAL_AGENT_KEY: str(agent_id),
                _APPROVAL_RESOLVER_KEY: resolver_id,
                _APPROVAL_ADAPTER_KEY: adapter_id,
            }
        )
        return MappingProxyType(values)

    def matches_record(self, record: ToolApprovalRecord) -> bool:
        if not isinstance(record, ToolApprovalRecord):
            raise TypeError("record must be ToolApprovalRecord")
        challenge = record.challenge
        return (
            record.requester == self.requester
            and challenge.schema_version == self.schema_version
            and challenge.approval_id == self.approval_id
            and challenge.principal_type is self.principal_type
            and challenge.principal == self.principal
            and challenge.session_id == self.session_id
            and challenge.agent_id == self.agent_id
            and challenge.run_id == self.agent_run_id
            and challenge.step_id == self.step_id
            and challenge.call_id == self.call_id
            and challenge.tool_id == self.tool_id
            and challenge.effect is self.effect
            and challenge.resolver_id == self.resolver_id
            and challenge.adapter_id == self.adapter_id
            and challenge.resolved_resource == self.resolved_resource
            and challenge.argument_digest == self.argument_digest
            and challenge.requested_at == self.requested_at
            and challenge.expires_at == self.expires_at
        )


class DurableApprovalState(StrEnum):
    """Safe current-state categories that grant no tool authority."""

    PENDING = "pending"
    APPROVED = "approved"
    REAPPROVAL_REQUIRED = "reapproval_required"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    MISSING = "missing"
    MISMATCHED = "mismatched"
    UNAVAILABLE = "unavailable"
    INVALID_CHECKPOINT = "invalid_checkpoint"


@dataclass(frozen=True, slots=True)
class DurableApprovalRevalidation:
    """Content-free result of re-reading one trusted approval service."""

    run_id: DurableAgentRunId
    checkpoint_id: CheckpointId
    state: DurableApprovalState
    assessed_at: datetime
    approval_id: ToolApprovalId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id must be CheckpointId")
        if not isinstance(self.state, DurableApprovalState):
            raise TypeError("state must be DurableApprovalState")
        _require_timezone_aware(self.assessed_at, label="assessed_at")
        if self.approval_id is not None and not isinstance(
            self.approval_id,
            ToolApprovalId,
        ):
            raise TypeError("approval_id must be ToolApprovalId or None")
        if self.state is not DurableApprovalState.INVALID_CHECKPOINT and self.approval_id is None:
            raise ValueError("revalidation state requires an approval id")

    @property
    def ready(self) -> bool:
        """Return current readiness without consuming or granting the approval."""

        return self.state is DurableApprovalState.APPROVED


@runtime_checkable
class DurableApprovalRevalidator(Protocol):
    """Re-read current approval state for one paused checkpoint."""

    async def revalidate(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> DurableApprovalRevalidation: ...


class ToolApprovalDurableRevalidator:
    """Compare checkpoint correlation against the trusted live approval record."""

    def __init__(self, service: ToolApprovalStateService) -> None:
        if not isinstance(service, ToolApprovalStateService):
            raise TypeError("service must implement ToolApprovalStateService")
        self._service = service

    async def revalidate(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> DurableApprovalRevalidation:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        _require_timezone_aware(now, label="now")

        try:
            reference = ApprovalWaitReference.from_checkpoint(checkpoint)
        except (TypeError, ValueError, OverflowError):
            return _revalidation(
                checkpoint,
                state=DurableApprovalState.INVALID_CHECKPOINT,
                now=now,
            )

        if now < checkpoint.created_at or now < reference.requested_at:
            return _revalidation(
                checkpoint,
                state=DurableApprovalState.INVALID_CHECKPOINT,
                now=now,
                approval_id=reference.approval_id,
            )
        if reference.schema_version == 1:
            return _revalidation(
                checkpoint,
                state=DurableApprovalState.REAPPROVAL_REQUIRED,
                now=now,
                approval_id=reference.approval_id,
            )

        try:
            record = await self._service.lookup(reference.approval_id)
        except AgentServiceUnavailableError:
            return _revalidation(
                checkpoint,
                state=DurableApprovalState.UNAVAILABLE,
                now=now,
                approval_id=reference.approval_id,
            )

        if record is None:
            return _revalidation(
                checkpoint,
                state=DurableApprovalState.MISSING,
                now=now,
                approval_id=reference.approval_id,
            )
        if not reference.matches_record(record):
            return _revalidation(
                checkpoint,
                state=DurableApprovalState.MISMATCHED,
                now=now,
                approval_id=reference.approval_id,
            )
        if now >= reference.expires_at:
            state = DurableApprovalState.EXPIRED
        elif record.status is ToolApprovalStatus.PENDING:
            state = DurableApprovalState.PENDING
        elif record.status is ToolApprovalStatus.APPROVED:
            state = DurableApprovalState.APPROVED
        else:
            state = DurableApprovalState.CONSUMED
        return _revalidation(
            checkpoint,
            state=state,
            now=now,
            approval_id=reference.approval_id,
        )


def approval_wait_checkpoint_metadata(
    challenge: ToolApprovalChallenge,
    *,
    requester: str,
) -> Mapping[str, str]:
    """Build only the fixed correlation metadata permitted for approval waiting."""

    return ApprovalWaitReference.from_challenge(
        challenge,
        requester=requester,
    ).to_metadata()


def _revalidation(
    checkpoint: CheckpointEnvelope,
    *,
    state: DurableApprovalState,
    now: datetime,
    approval_id: ToolApprovalId | None = None,
) -> DurableApprovalRevalidation:
    return DurableApprovalRevalidation(
        run_id=checkpoint.durable_run_id,
        checkpoint_id=checkpoint.checkpoint_id,
        state=state,
        assessed_at=now,
        approval_id=approval_id,
    )


def _metadata_value(metadata: Mapping[str, str], key: str) -> str:
    if key not in _APPROVAL_WAIT_KEYS:
        raise ValueError("unknown approval-wait metadata key")
    value = metadata.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("approval-wait metadata is incomplete")
    return value


def _metadata_uuid(metadata: Mapping[str, str], key: str) -> UUID:
    raw = _metadata_value(metadata, key)
    value = UUID(raw)
    if str(value) != raw:
        raise ValueError("approval-wait UUID is not canonical")
    return value


def _metadata_datetime(metadata: Mapping[str, str], key: str) -> datetime:
    raw = _metadata_value(metadata, key)
    value = datetime.fromisoformat(raw)
    _require_timezone_aware(value, label="approval-wait timestamp")
    if value.isoformat() != raw:
        raise ValueError("approval-wait timestamp is not canonical")
    return value


def _metadata_principal_type(
    metadata: Mapping[str, str],
    key: str,
) -> PrincipalType:
    raw = _metadata_value(metadata, key)
    value = PrincipalType(raw)
    if value.value != raw:
        raise ValueError("approval-wait principal type is not canonical")
    return value


def _metadata_session_id(
    metadata: Mapping[str, str],
    key: str,
) -> UUID | None:
    raw = _metadata_value(metadata, key)
    if raw == _NO_SESSION:
        return None
    value = UUID(raw)
    if str(value) != raw:
        raise ValueError("approval-wait session id is not canonical")
    return value


def _metadata_agent_id(metadata: Mapping[str, str], key: str) -> AgentId:
    raw = _metadata_value(metadata, key)
    value = AgentId(raw)
    if str(value) != raw:
        raise ValueError("approval-wait agent id is not canonical")
    return value


def _metadata_tool_id(metadata: Mapping[str, str], key: str) -> ToolId:
    raw = _metadata_value(metadata, key)
    value = ToolId(raw)
    if str(value) != raw:
        raise ValueError("approval-wait tool id is not canonical")
    return value


def _metadata_effect(metadata: Mapping[str, str], key: str) -> ToolEffect:
    raw = _metadata_value(metadata, key)
    value = ToolEffect(raw)
    if value.value != raw:
        raise ValueError("approval-wait effect is not canonical")
    return value
