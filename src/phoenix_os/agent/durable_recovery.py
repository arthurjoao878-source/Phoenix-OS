"""Bounded startup recovery admission and fail-closed checkpoint classification."""

from __future__ import annotations

import re
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from typing import Final, Protocol, runtime_checkable

from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityAssessment,
    DurableCompatibilityValidator,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    CheckpointSequence,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    FencingGeneration,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError

_OWNER_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")

_RESUMABLE_NEXT_OPERATIONS: Final[frozenset[CheckpointNextOperation]] = frozenset(
    {
        CheckpointNextOperation.MODEL_TURN,
        CheckpointNextOperation.VALIDATE_PROPOSAL,
        CheckpointNextOperation.AUTHORIZE_TOOL,
        CheckpointNextOperation.TOOL_INVOCATION,
        CheckpointNextOperation.VALIDATE_RESULT,
        CheckpointNextOperation.COMPLETE,
    }
)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_owner_id(owner_id: str) -> None:
    if not isinstance(owner_id, str):
        raise TypeError("owner_id must be a string")
    if not _OWNER_ID_PATTERN.fullmatch(owner_id.strip()):
        raise ValueError("owner_id is invalid")


@dataclass(frozen=True, slots=True)
class DurableRecoveryAssessment:
    """Content-free startup assessment that grants no continuing lease authority."""

    run_id: DurableAgentRunId
    checkpoint_id: CheckpointId
    checkpoint_digest: CheckpointDigest
    sequence: CheckpointSequence
    run_version: DurableRunVersion
    status: DurableRunStatus
    point: RecoveryPoint
    disposition: RecoveryDisposition
    compatibility: DurableCompatibilityAssessment
    generation: FencingGeneration
    assessed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id must be CheckpointId")
        if not isinstance(self.checkpoint_digest, CheckpointDigest):
            raise TypeError("checkpoint_digest must be CheckpointDigest")
        if not isinstance(self.sequence, CheckpointSequence):
            raise TypeError("sequence must be CheckpointSequence")
        if not isinstance(self.run_version, DurableRunVersion):
            raise TypeError("run_version must be DurableRunVersion")
        if not isinstance(self.status, DurableRunStatus):
            raise TypeError("status must be DurableRunStatus")
        if not isinstance(self.point, RecoveryPoint):
            raise TypeError("point must be RecoveryPoint")
        if not isinstance(self.disposition, RecoveryDisposition):
            raise TypeError("disposition must be RecoveryDisposition")
        if not isinstance(self.compatibility, DurableCompatibilityAssessment):
            raise TypeError("compatibility must be DurableCompatibilityAssessment")
        if not isinstance(self.generation, FencingGeneration):
            raise TypeError("generation must be FencingGeneration")
        _require_timezone_aware(self.assessed_at, label="assessed_at")

        if self.disposition is RecoveryDisposition.RESUME and not self.compatibility.compatible:
            raise ValueError("resume disposition requires compatible current configuration")

        if self.disposition is RecoveryDisposition.MARK_INDETERMINATE_MODEL:
            if self.point is not RecoveryPoint.ACTIVE_MODEL_ATTEMPT:
                raise ValueError("model indeterminate disposition requires a model attempt")
        elif self.disposition is RecoveryDisposition.MARK_INDETERMINATE_TOOL:
            if self.point is not RecoveryPoint.ACTIVE_TOOL_ATTEMPT:
                raise ValueError("tool indeterminate disposition requires a tool attempt")
        elif self.disposition is RecoveryDisposition.TERMINATE_EXPIRED:
            if self.point is not RecoveryPoint.EXPIRED:
                raise ValueError("expired disposition requires an expired recovery point")
        elif self.disposition is RecoveryDisposition.RESUME:
            if self.point not in {
                RecoveryPoint.SAFE_BOUNDARY,
                RecoveryPoint.SHUTDOWN_PAUSE,
            }:
                raise ValueError("resume disposition requires a reviewed resumable point")


@runtime_checkable
class DurableRecoveryCoordinator(Protocol):
    """Bounded startup assessment boundary for existing durable runs."""

    @property
    def closed(self) -> bool: ...

    def assess_candidate(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> Awaitable[DurableRecoveryAssessment]: ...

    def assess_page(
        self,
        *,
        owner_id: str,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> Awaitable[tuple[DurableRecoveryAssessment, ...]]: ...

    def close(self) -> Awaitable[None]: ...


class StartupDurableRecoveryCoordinator(DurableRecoveryCoordinator):
    """Acquire, re-read, validate, classify, and release bounded startup candidates."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
        compatibility_validator: DurableCompatibilityValidator,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must be DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must be DurableLeaseManager")
        if not isinstance(compatibility_validator, DurableCompatibilityValidator):
            raise TypeError("compatibility_validator must be DurableCompatibilityValidator")
        self._store = store
        self._lease_manager = lease_manager
        self._compatibility_validator = compatibility_validator
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def assess_candidate(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableRecoveryAssessment:
        """Assess one authoritative post-acquisition checkpoint and release its lease."""

        self._ensure_open()
        self._require_run_id(run_id)
        _require_owner_id(owner_id)
        _require_timezone_aware(now, label="now")

        lease = await self._lease_manager.acquire(
            run_id,
            owner_id=owner_id.strip(),
            now=now,
        )
        try:
            self._ensure_open()
            checkpoint = await self._store.get_current(run_id)
            if checkpoint is None or checkpoint.status.terminal:
                raise AgentStateConflictError()

            history = await self._store.list_history(
                run_id,
                limit=checkpoint.sequence.value,
            )
            _validate_authoritative_history(checkpoint, history)
            compatibility = self._compatibility_validator.validate(checkpoint)
            _validate_compatibility_assessment(checkpoint, compatibility)
            point, disposition = classify_recovery_checkpoint(checkpoint, now=now)
            if not compatibility.compatible and disposition is RecoveryDisposition.RESUME:
                point = RecoveryPoint.UNSAFE_STATE
                disposition = RecoveryDisposition.PAUSE_OPERATOR
            return _assessment(
                checkpoint=checkpoint,
                lease=lease,
                point=point,
                disposition=disposition,
                compatibility=compatibility,
                now=now,
            )
        finally:
            await self._lease_manager.release(lease, now=now)

    async def assess_page(
        self,
        *,
        owner_id: str,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableRecoveryAssessment, ...]:
        """Assess one bounded deterministic page without retaining lease authority."""

        self._ensure_open()
        _require_owner_id(owner_id)
        _require_timezone_aware(now, label="now")
        if after is not None:
            self._require_run_id(after)

        candidates = await self._store.list_recovery_candidates(
            limit=limit,
            after=after,
        )
        _validate_candidate_page(candidates, limit=limit, after=after)

        assessments: list[DurableRecoveryAssessment] = []
        for run_id in candidates:
            self._ensure_open()
            assessments.append(
                await self.assess_candidate(
                    run_id,
                    owner_id=owner_id,
                    now=now,
                )
            )
        return tuple(assessments)

    async def close(self) -> None:
        """Stop new startup assessments without closing composed dependencies."""

        self._closed = True

    @staticmethod
    def _require_run_id(run_id: DurableAgentRunId) -> None:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("durable recovery coordinator is closed")


def classify_recovery_checkpoint(
    checkpoint: CheckpointEnvelope,
    *,
    now: datetime,
) -> tuple[RecoveryPoint, RecoveryDisposition]:
    """Classify one validated checkpoint without granting execution authority."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    _require_timezone_aware(now, label="now")
    if checkpoint.status.terminal:
        raise AgentStateConflictError()
    if now < checkpoint.created_at:
        raise AgentStateConflictError()

    if now >= checkpoint.metadata.retention_deadline or now >= checkpoint.metadata.budget.deadline:
        return RecoveryPoint.EXPIRED, RecoveryDisposition.TERMINATE_EXPIRED

    attempt = checkpoint.metadata.active_attempt
    if attempt is not None:
        if attempt.status is ExecutionAttemptStatus.STARTED:
            if attempt.kind is ExecutionAttemptKind.MODEL_TURN:
                return (
                    RecoveryPoint.ACTIVE_MODEL_ATTEMPT,
                    RecoveryDisposition.MARK_INDETERMINATE_MODEL,
                )
            return (
                RecoveryPoint.ACTIVE_TOOL_ATTEMPT,
                RecoveryDisposition.MARK_INDETERMINATE_TOOL,
            )
        if attempt.status is ExecutionAttemptStatus.INDETERMINATE:
            if (
                checkpoint.status is DurableRunStatus.INDETERMINATE_MODEL
                and attempt.kind is ExecutionAttemptKind.MODEL_TURN
            ):
                return (
                    RecoveryPoint.ACTIVE_MODEL_ATTEMPT,
                    RecoveryDisposition.PAUSE_OPERATOR,
                )
            if (
                checkpoint.status is DurableRunStatus.INDETERMINATE_TOOL
                and attempt.kind is ExecutionAttemptKind.TOOL_INVOCATION
            ):
                return (
                    RecoveryPoint.ACTIVE_TOOL_ATTEMPT,
                    RecoveryDisposition.PAUSE_OPERATOR,
                )
            return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED

    if checkpoint.status.indeterminate:
        return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED

    next_operation = checkpoint.metadata.next_operation
    if checkpoint.status is DurableRunStatus.PAUSED_APPROVAL:
        if next_operation is not CheckpointNextOperation.WAIT_APPROVAL:
            return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED
        return RecoveryPoint.AWAITING_APPROVAL, RecoveryDisposition.PAUSE_OPERATOR

    if checkpoint.status is DurableRunStatus.PAUSED_OPERATOR:
        if next_operation is not CheckpointNextOperation.OPERATOR_REVIEW:
            return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED
        return RecoveryPoint.OPERATOR_PAUSE, RecoveryDisposition.PAUSE_OPERATOR

    if checkpoint.status is DurableRunStatus.PAUSED_SHUTDOWN:
        if next_operation is CheckpointNextOperation.NONE:
            return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED
        return RecoveryPoint.SHUTDOWN_PAUSE, RecoveryDisposition.RESUME

    if checkpoint.status in {
        DurableRunStatus.CHECKPOINTING,
        DurableRunStatus.RECOVERING,
        DurableRunStatus.RECONCILING,
    }:
        return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.PAUSE_OPERATOR

    if checkpoint.status is DurableRunStatus.CREATED and attempt is not None:
        return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED

    if checkpoint.status in {
        DurableRunStatus.CREATED,
        DurableRunStatus.ACTIVE,
    }:
        if next_operation in _RESUMABLE_NEXT_OPERATIONS:
            return RecoveryPoint.SAFE_BOUNDARY, RecoveryDisposition.RESUME
        return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED

    return RecoveryPoint.UNSAFE_STATE, RecoveryDisposition.TERMINATE_FAILED


def _validate_compatibility_assessment(
    checkpoint: CheckpointEnvelope,
    assessment: DurableCompatibilityAssessment,
) -> None:
    if not isinstance(assessment, DurableCompatibilityAssessment):
        raise TypeError("compatibility validator must return DurableCompatibilityAssessment")
    if assessment.agent_id != checkpoint.metadata.agent_id:
        raise AgentStateConflictError()


def _assessment(
    *,
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
    point: RecoveryPoint,
    disposition: RecoveryDisposition,
    compatibility: DurableCompatibilityAssessment,
    now: datetime,
) -> DurableRecoveryAssessment:
    if lease.run_id != checkpoint.durable_run_id:
        raise AgentStateConflictError()
    return DurableRecoveryAssessment(
        run_id=checkpoint.durable_run_id,
        checkpoint_id=checkpoint.checkpoint_id,
        checkpoint_digest=checkpoint.digest,
        sequence=checkpoint.sequence,
        run_version=checkpoint.run_version,
        status=checkpoint.status,
        point=point,
        disposition=disposition,
        compatibility=compatibility,
        generation=lease.generation,
        assessed_at=now,
    )


def _validate_candidate_page(
    candidates: tuple[DurableAgentRunId, ...],
    *,
    limit: int,
    after: DurableAgentRunId | None,
) -> None:
    if not isinstance(candidates, tuple):
        raise TypeError("recovery candidate page must be a tuple")
    if len(candidates) > limit:
        raise AgentCodecError("recovery candidate page exceeds its requested limit")

    previous = after
    seen: set[DurableAgentRunId] = set()
    for run_id in candidates:
        if not isinstance(run_id, DurableAgentRunId):
            raise AgentCodecError("recovery candidate page contains an invalid run id")
        if run_id in seen:
            raise AgentCodecError("recovery candidate page contains a duplicate run id")
        if previous is not None and run_id <= previous:
            raise AgentCodecError("recovery candidate page is not strictly ordered")
        seen.add(run_id)
        previous = run_id


def _validate_authoritative_history(
    current: CheckpointEnvelope,
    history: tuple[CheckpointEnvelope, ...],
) -> None:
    if not isinstance(history, tuple):
        raise TypeError("checkpoint history must be a tuple")
    if not history:
        raise AgentCodecError("authoritative checkpoint history is empty")
    if len(history) != current.sequence.value:
        raise AgentCodecError("authoritative checkpoint history is incomplete")
    if history[-1] != current:
        raise AgentCodecError("authoritative checkpoint changed during validation")

    first = history[0]
    if (
        first.sequence.value != 1
        or first.run_version.value != 1
        or first.previous_digest is not None
    ):
        raise AgentCodecError("authoritative checkpoint history has an invalid root")

    for expected_sequence, checkpoint in enumerate(history, start=1):
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise AgentCodecError("authoritative history contains an invalid checkpoint")
        if checkpoint.durable_run_id != current.durable_run_id:
            raise AgentCodecError("authoritative history changed durable run identity")
        if checkpoint.agent_run_id != current.agent_run_id:
            raise AgentCodecError("authoritative history changed agent run identity")
        if checkpoint.schema_version != current.schema_version:
            raise AgentCodecError("authoritative history changed checkpoint schema")
        if checkpoint.sequence.value != expected_sequence:
            raise AgentCodecError("authoritative history has a sequence gap")
        if checkpoint.run_version.value != expected_sequence:
            raise AgentCodecError("authoritative history has a version gap")

    for previous, checkpoint in pairwise(history):
        if checkpoint.previous_digest != previous.digest:
            raise AgentCodecError("authoritative history has a broken digest chain")
