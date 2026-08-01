"""Fenced durable checkpoint records for model and tool execution attempts."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentStepId, ToolCallId, ToolEffect
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.errors import AgentStateConflictError

_ALLOWED_TERMINAL_STATUSES = frozenset(
    {
        ExecutionAttemptStatus.SUCCEEDED,
        ExecutionAttemptStatus.FAILED,
        ExecutionAttemptStatus.CANCELLED,
        ExecutionAttemptStatus.TIMED_OUT,
    }
)
_MODEL_SUCCESS_OPERATIONS = frozenset(
    {
        CheckpointNextOperation.VALIDATE_PROPOSAL,
        CheckpointNextOperation.COMPLETE,
    }
)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@runtime_checkable
class DurableExecutionAttemptRecorder(Protocol):
    """Persist one reviewed attempt transition per fenced checkpoint."""

    def prepare_model_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        external_request_digest: CheckpointDigest,
        now: datetime,
    ) -> Awaitable[CheckpointEnvelope]: ...

    def prepare_tool_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        tool_call_id: ToolCallId,
        tool_effect: ToolEffect,
        external_request_digest: CheckpointDigest,
        now: datetime,
    ) -> Awaitable[CheckpointEnvelope]: ...

    def mark_started(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[CheckpointEnvelope]: ...

    def mark_indeterminate(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        reason: IndeterminateReason,
        now: datetime,
    ) -> Awaitable[CheckpointEnvelope]: ...

    def mark_terminal(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        status: ExecutionAttemptStatus,
        now: datetime,
        next_operation: CheckpointNextOperation | None = None,
        error_code: str | None = None,
    ) -> Awaitable[CheckpointEnvelope]: ...


class StoreBackedDurableExecutionAttemptRecorder(DurableExecutionAttemptRecorder):
    """Record exact attempt transitions through the configured durable store."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        attempt_id_factory: Callable[[], ExecutionAttemptId] = ExecutionAttemptId,
        checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must be DurableRunStore")
        if not callable(attempt_id_factory):
            raise TypeError("attempt_id_factory must be callable")
        if not callable(checkpoint_id_factory):
            raise TypeError("checkpoint_id_factory must be callable")
        self._store = store
        self._attempt_id_factory = attempt_id_factory
        self._checkpoint_id_factory = checkpoint_id_factory

    async def prepare_model_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        external_request_digest: CheckpointDigest,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Persist PREPARED before one model request may be submitted."""

        current = await self._load_current(
            run_id,
            expected_version=expected_version,
            lease=lease,
            now=now,
            require_budget_open=True,
        )
        self._require_prepare_boundary(
            current,
            expected_operation=CheckpointNextOperation.MODEL_TURN,
        )
        self._require_digest(external_request_digest)
        attempt_id = await self._new_attempt_id(current)
        attempt = ExecutionAttempt(
            attempt_id=attempt_id,
            kind=ExecutionAttemptKind.MODEL_TURN,
            status=ExecutionAttemptStatus.PREPARED,
            agent_run_id=current.agent_run_id,
            step_id=self._require_step_id(current),
            prepared_at=now,
            external_request_digest=external_request_digest,
        )
        return await self._append(
            current,
            lease=lease,
            now=now,
            status=DurableRunStatus.ACTIVE,
            next_operation=CheckpointNextOperation.MODEL_TURN,
            attempt=attempt,
        )

    async def prepare_tool_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        tool_call_id: ToolCallId,
        tool_effect: ToolEffect,
        external_request_digest: CheckpointDigest,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Persist PREPARED before one exact tool request may be submitted."""

        if not isinstance(tool_call_id, ToolCallId):
            raise TypeError("tool_call_id must be ToolCallId")
        if not isinstance(tool_effect, ToolEffect):
            raise TypeError("tool_effect must be ToolEffect")
        current = await self._load_current(
            run_id,
            expected_version=expected_version,
            lease=lease,
            now=now,
            require_budget_open=True,
        )
        self._require_prepare_boundary(
            current,
            expected_operation=CheckpointNextOperation.TOOL_INVOCATION,
        )
        self._require_digest(external_request_digest)
        attempt_id = await self._new_attempt_id(current)
        attempt = ExecutionAttempt(
            attempt_id=attempt_id,
            kind=ExecutionAttemptKind.TOOL_INVOCATION,
            status=ExecutionAttemptStatus.PREPARED,
            agent_run_id=current.agent_run_id,
            step_id=self._require_step_id(current),
            prepared_at=now,
            tool_call_id=tool_call_id,
            tool_effect=tool_effect,
            external_request_digest=external_request_digest,
        )
        return await self._append(
            current,
            lease=lease,
            now=now,
            status=DurableRunStatus.ACTIVE,
            next_operation=CheckpointNextOperation.TOOL_INVOCATION,
            attempt=attempt,
        )

    async def mark_started(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Persist STARTED immediately before handing control to an adapter."""

        self._require_attempt_id(attempt_id)
        current = await self._load_current(
            run_id,
            expected_version=expected_version,
            lease=lease,
            now=now,
            require_budget_open=True,
        )
        attempt = self._require_current_attempt(
            current,
            attempt_id=attempt_id,
            allowed_statuses=frozenset({ExecutionAttemptStatus.PREPARED}),
        )
        self._require_attempt_time(attempt, now=now)
        started = replace(
            attempt,
            status=ExecutionAttemptStatus.STARTED,
            started_at=now,
        )
        return await self._append(
            current,
            lease=lease,
            now=now,
            status=DurableRunStatus.ACTIVE,
            next_operation=current.metadata.next_operation,
            attempt=started,
        )

    async def mark_indeterminate(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        reason: IndeterminateReason,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Persist one fail-closed unknown external outcome without retry."""

        self._require_attempt_id(attempt_id)
        if not isinstance(reason, IndeterminateReason):
            raise TypeError("reason must be IndeterminateReason")
        current = await self._load_current(
            run_id,
            expected_version=expected_version,
            lease=lease,
            now=now,
            require_budget_open=False,
        )
        attempt = self._require_current_attempt(
            current,
            attempt_id=attempt_id,
            allowed_statuses=frozenset({ExecutionAttemptStatus.STARTED}),
        )
        self._require_attempt_time(attempt, now=now)
        try:
            indeterminate = replace(
                attempt,
                status=ExecutionAttemptStatus.INDETERMINATE,
                completed_at=now,
                indeterminate_reason=reason,
            )
        except (TypeError, ValueError) as exception:
            raise AgentStateConflictError() from exception
        durable_status = (
            DurableRunStatus.INDETERMINATE_MODEL
            if attempt.kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        )
        return await self._append(
            current,
            lease=lease,
            now=now,
            status=durable_status,
            next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
            attempt=indeterminate,
        )

    async def mark_terminal(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        status: ExecutionAttemptStatus,
        now: datetime,
        next_operation: CheckpointNextOperation | None = None,
        error_code: str | None = None,
    ) -> CheckpointEnvelope:
        """Persist one reviewed terminal outcome without transparent repetition."""

        self._require_attempt_id(attempt_id)
        if not isinstance(status, ExecutionAttemptStatus):
            raise TypeError("status must be ExecutionAttemptStatus")
        if status not in _ALLOWED_TERMINAL_STATUSES:
            raise AgentStateConflictError()

        current = await self._load_current(
            run_id,
            expected_version=expected_version,
            lease=lease,
            now=now,
            require_budget_open=False,
        )
        allowed_sources = frozenset(
            {ExecutionAttemptStatus.STARTED}
            if status is ExecutionAttemptStatus.SUCCEEDED
            else {
                ExecutionAttemptStatus.PREPARED,
                ExecutionAttemptStatus.STARTED,
            }
        )
        attempt = self._require_current_attempt(
            current,
            attempt_id=attempt_id,
            allowed_statuses=allowed_sources,
        )
        self._require_attempt_time(attempt, now=now)
        resulting_status, resulting_operation = self._terminal_boundary(
            attempt,
            status=status,
            next_operation=next_operation,
            error_code=error_code,
        )
        try:
            terminal = replace(
                attempt,
                status=status,
                completed_at=now,
                error_code=error_code,
            )
        except (TypeError, ValueError) as exception:
            raise AgentStateConflictError() from exception
        return await self._append(
            current,
            lease=lease,
            now=now,
            status=resulting_status,
            next_operation=resulting_operation,
            attempt=terminal,
        )

    async def _load_current(
        self,
        run_id: DurableAgentRunId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
        require_budget_open: bool,
    ) -> CheckpointEnvelope:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        _require_timezone_aware(now, label="now")
        if lease.run_id != run_id or not lease.active_at(now):
            raise AgentStateConflictError()

        current = await self._store.get_current(run_id)
        if current is None:
            raise AgentStateConflictError()
        if (
            current.durable_run_id != run_id
            or current.run_version != expected_version
            or current.status is not DurableRunStatus.ACTIVE
            or current.status.terminal
            or now < current.created_at
            or now >= current.metadata.retention_deadline
        ):
            raise AgentStateConflictError()
        if require_budget_open and now >= current.metadata.budget.deadline:
            raise AgentStateConflictError()
        self._require_step_id(current)
        return current

    @staticmethod
    def _require_prepare_boundary(
        current: CheckpointEnvelope,
        *,
        expected_operation: CheckpointNextOperation,
    ) -> None:
        active = current.metadata.active_attempt
        if current.metadata.next_operation is not expected_operation:
            raise AgentStateConflictError()
        if active is not None and not active.status.terminal:
            raise AgentStateConflictError()

    async def _new_attempt_id(
        self,
        current: CheckpointEnvelope,
    ) -> ExecutionAttemptId:
        attempt_id = self._attempt_id_factory()
        self._require_attempt_id(attempt_id)
        history = await self._store.list_history(
            current.durable_run_id,
            limit=current.sequence.value,
        )
        if len(history) != current.sequence.value or not history or history[-1] != current:
            raise AgentStateConflictError()
        if any(
            checkpoint.metadata.active_attempt is not None
            and checkpoint.metadata.active_attempt.attempt_id == attempt_id
            for checkpoint in history
        ):
            raise AgentStateConflictError()
        return attempt_id

    @staticmethod
    def _require_current_attempt(
        current: CheckpointEnvelope,
        *,
        attempt_id: ExecutionAttemptId,
        allowed_statuses: frozenset[ExecutionAttemptStatus],
    ) -> ExecutionAttempt:
        attempt = current.metadata.active_attempt
        if (
            attempt is None
            or attempt.attempt_id != attempt_id
            or attempt.status not in allowed_statuses
            or attempt.agent_run_id != current.agent_run_id
            or current.step_id is None
            or attempt.step_id != current.step_id
        ):
            raise AgentStateConflictError()
        expected_operation = (
            CheckpointNextOperation.MODEL_TURN
            if attempt.kind is ExecutionAttemptKind.MODEL_TURN
            else CheckpointNextOperation.TOOL_INVOCATION
        )
        if current.metadata.next_operation is not expected_operation:
            raise AgentStateConflictError()
        return attempt

    @staticmethod
    def _require_attempt_time(
        attempt: ExecutionAttempt,
        *,
        now: datetime,
    ) -> None:
        if now < attempt.prepared_at:
            raise AgentStateConflictError()
        if attempt.started_at is not None and now < attempt.started_at:
            raise AgentStateConflictError()

    @staticmethod
    def _terminal_boundary(
        attempt: ExecutionAttempt,
        *,
        status: ExecutionAttemptStatus,
        next_operation: CheckpointNextOperation | None,
        error_code: str | None,
    ) -> tuple[DurableRunStatus, CheckpointNextOperation]:
        if status is ExecutionAttemptStatus.SUCCEEDED:
            if error_code is not None or not isinstance(
                next_operation,
                CheckpointNextOperation,
            ):
                raise AgentStateConflictError()
            if attempt.kind is ExecutionAttemptKind.MODEL_TURN:
                if next_operation not in _MODEL_SUCCESS_OPERATIONS:
                    raise AgentStateConflictError()
            elif next_operation is not CheckpointNextOperation.VALIDATE_RESULT:
                raise AgentStateConflictError()
            return DurableRunStatus.ACTIVE, next_operation

        if next_operation is not None:
            raise AgentStateConflictError()
        if status in {
            ExecutionAttemptStatus.FAILED,
            ExecutionAttemptStatus.TIMED_OUT,
        }:
            if not isinstance(error_code, str) or not error_code.strip():
                raise AgentStateConflictError()
        elif error_code is not None:
            raise AgentStateConflictError()
        return (
            DurableRunStatus.PAUSED_OPERATOR,
            CheckpointNextOperation.OPERATOR_REVIEW,
        )

    async def _append(
        self,
        current: CheckpointEnvelope,
        *,
        lease: DurableLease,
        now: datetime,
        status: DurableRunStatus,
        next_operation: CheckpointNextOperation,
        attempt: ExecutionAttempt,
    ) -> CheckpointEnvelope:
        checkpoint_id = self._checkpoint_id_factory()
        if not isinstance(checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id_factory must return CheckpointId")
        metadata = replace(
            current.metadata,
            next_operation=next_operation,
            active_attempt=attempt,
        )
        candidate = seal_checkpoint_envelope(
            replace(
                current,
                checkpoint_id=checkpoint_id,
                sequence=current.sequence.next(),
                previous_digest=current.digest,
                run_version=current.run_version.next(),
                status=status,
                metadata=metadata,
                created_at=now,
                digest=CheckpointDigest("0" * 64),
            )
        )
        return await self._store.append(
            candidate,
            expected_version=current.run_version,
            lease=lease,
            now=now,
        )

    @staticmethod
    def _require_step_id(current: CheckpointEnvelope) -> AgentStepId:
        step_id = current.step_id
        if step_id is None:
            raise AgentStateConflictError()
        return step_id

    @staticmethod
    def _require_attempt_id(attempt_id: ExecutionAttemptId) -> None:
        if not isinstance(attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")

    @staticmethod
    def _require_digest(digest: CheckpointDigest) -> None:
        if not isinstance(digest, CheckpointDigest):
            raise TypeError("external_request_digest must be CheckpointDigest")
