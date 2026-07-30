"""Reviewed durable-run transitions and safe checkpoint-boundary enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableRunStatus,
    ExecutionAttemptKind,
)
from phoenix_os.agent.errors import AgentStateConflictError


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_boolean(value: bool, *, label: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a bool")


@dataclass(frozen=True, slots=True)
class DurableCheckpointBoundary:
    """Content-free evidence that checkpoint creation is currently safe."""

    next_operation: CheckpointNextOperation
    model_call_active: bool = False
    tool_call_active: bool = False
    result_stream_open: bool = False
    approval_consumption_active: bool = False
    transition_complete: bool = True
    budgets_known: bool = True
    continuation_available: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.next_operation, CheckpointNextOperation):
            raise TypeError("next_operation must be CheckpointNextOperation")
        boolean_fields = (
            ("model_call_active", self.model_call_active),
            ("tool_call_active", self.tool_call_active),
            ("result_stream_open", self.result_stream_open),
            ("approval_consumption_active", self.approval_consumption_active),
            ("transition_complete", self.transition_complete),
            ("budgets_known", self.budgets_known),
            ("continuation_available", self.continuation_available),
        )
        for label, value in boolean_fields:
            _require_boolean(value, label=label)

    @property
    def safe(self) -> bool:
        """Return whether every RFC-0028 safe-boundary condition is satisfied."""

        return (
            not self.model_call_active
            and not self.tool_call_active
            and not self.result_stream_open
            and not self.approval_consumption_active
            and self.transition_complete
            and self.budgets_known
            and self.continuation_available
        )

    def require_safe(self) -> None:
        """Fail closed when checkpoint creation would cross active work."""

        if not self.safe:
            raise AgentStateConflictError()


_TERMINAL_STATUSES: Final[frozenset[DurableRunStatus]] = frozenset(
    {
        DurableRunStatus.COMPLETED,
        DurableRunStatus.FAILED,
        DurableRunStatus.CANCELLED,
        DurableRunStatus.EXPIRED,
    }
)

_ALLOWED_TRANSITIONS: Final[dict[DurableRunStatus, frozenset[DurableRunStatus]]] = {
    DurableRunStatus.CREATED: frozenset(
        {
            DurableRunStatus.ACTIVE,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.ACTIVE: frozenset(
        {
            DurableRunStatus.CHECKPOINTING,
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.PAUSED_SHUTDOWN,
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.CHECKPOINTING: frozenset(
        {
            DurableRunStatus.ACTIVE,
            DurableRunStatus.PAUSED_APPROVAL,
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.PAUSED_SHUTDOWN,
            DurableRunStatus.COMPLETED,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.PAUSED_APPROVAL: frozenset(
        {
            DurableRunStatus.RECOVERING,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.PAUSED_OPERATOR: frozenset(
        {
            DurableRunStatus.RECOVERING,
            DurableRunStatus.RECONCILING,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.PAUSED_SHUTDOWN: frozenset(
        {
            DurableRunStatus.RECOVERING,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.RECOVERING: frozenset(
        {
            DurableRunStatus.ACTIVE,
            DurableRunStatus.PAUSED_APPROVAL,
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.PAUSED_SHUTDOWN,
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.RECONCILING: frozenset(
        {
            DurableRunStatus.ACTIVE,
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
            DurableRunStatus.COMPLETED,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.INDETERMINATE_MODEL: frozenset(
        {
            DurableRunStatus.RECONCILING,
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.INDETERMINATE_TOOL: frozenset(
        {
            DurableRunStatus.RECONCILING,
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.FAILED,
            DurableRunStatus.CANCELLED,
            DurableRunStatus.EXPIRED,
        }
    ),
    DurableRunStatus.COMPLETED: frozenset(),
    DurableRunStatus.FAILED: frozenset(),
    DurableRunStatus.CANCELLED: frozenset(),
    DurableRunStatus.EXPIRED: frozenset(),
}

_ACTIVE_NEXT_OPERATIONS: Final[frozenset[CheckpointNextOperation]] = frozenset(
    {
        CheckpointNextOperation.MODEL_TURN,
        CheckpointNextOperation.VALIDATE_PROPOSAL,
        CheckpointNextOperation.AUTHORIZE_TOOL,
        CheckpointNextOperation.TOOL_INVOCATION,
        CheckpointNextOperation.VALIDATE_RESULT,
        CheckpointNextOperation.COMPLETE,
    }
)


def durable_transition_allowed(
    source: DurableRunStatus,
    target: DurableRunStatus,
) -> bool:
    """Return whether one reviewed durable transition is structurally permitted."""

    if not isinstance(source, DurableRunStatus):
        raise TypeError("source must be DurableRunStatus")
    if not isinstance(target, DurableRunStatus):
        raise TypeError("target must be DurableRunStatus")
    return target in _ALLOWED_TRANSITIONS[source]


class DurableRunStateMachine:
    """Permit only reviewed durable transitions and safe checkpoint creation."""

    def __init__(
        self,
        run_id: DurableAgentRunId,
        *,
        created_at: datetime,
    ) -> None:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        _require_timezone_aware(created_at, label="created_at")
        self._run_id = run_id
        self._status = DurableRunStatus.CREATED
        self._updated_at = created_at
        self._checkpoint_boundary: DurableCheckpointBoundary | None = None

    @classmethod
    def from_checkpoint(cls, checkpoint: CheckpointEnvelope) -> DurableRunStateMachine:
        """Restore reviewed state from an already validated checkpoint envelope."""

        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        machine = cls(
            checkpoint.durable_run_id,
            created_at=checkpoint.created_at,
        )
        machine._status = checkpoint.status
        machine._updated_at = checkpoint.created_at
        return machine

    @property
    def run_id(self) -> DurableAgentRunId:
        return self._run_id

    @property
    def status(self) -> DurableRunStatus:
        return self._status

    @property
    def terminal(self) -> bool:
        return self._status in _TERMINAL_STATUSES

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def checkpoint_boundary(self) -> DurableCheckpointBoundary | None:
        return self._checkpoint_boundary

    def transition(
        self,
        target: DurableRunStatus,
        *,
        now: datetime,
        boundary: DurableCheckpointBoundary | None = None,
        active_attempt_kind: ExecutionAttemptKind | None = None,
    ) -> None:
        """Apply one reviewed transition or fail closed without changing state."""

        if not isinstance(target, DurableRunStatus):
            raise TypeError("target must be DurableRunStatus")
        _require_timezone_aware(now, label="now")
        if now < self._updated_at:
            raise AgentStateConflictError()
        if self.terminal:
            raise AgentStateConflictError()
        if not durable_transition_allowed(self._status, target):
            raise AgentStateConflictError()

        self._validate_boundary_argument(target=target, boundary=boundary)
        self._validate_attempt_argument(
            target=target,
            active_attempt_kind=active_attempt_kind,
        )
        self._validate_checkpoint_result(target)

        previous = self._status
        self._status = target
        self._updated_at = now

        if target is DurableRunStatus.CHECKPOINTING:
            self._checkpoint_boundary = boundary
        elif previous is DurableRunStatus.CHECKPOINTING:
            self._checkpoint_boundary = None

    def _validate_boundary_argument(
        self,
        *,
        target: DurableRunStatus,
        boundary: DurableCheckpointBoundary | None,
    ) -> None:
        if target is DurableRunStatus.CHECKPOINTING:
            if not isinstance(boundary, DurableCheckpointBoundary):
                raise AgentStateConflictError()
            boundary.require_safe()
            return
        if boundary is not None:
            raise AgentStateConflictError()

    def _validate_attempt_argument(
        self,
        *,
        target: DurableRunStatus,
        active_attempt_kind: ExecutionAttemptKind | None,
    ) -> None:
        expected: ExecutionAttemptKind | None = None
        if target is DurableRunStatus.INDETERMINATE_MODEL:
            expected = ExecutionAttemptKind.MODEL_TURN
        elif target is DurableRunStatus.INDETERMINATE_TOOL:
            expected = ExecutionAttemptKind.TOOL_INVOCATION

        if expected is None:
            if active_attempt_kind is not None:
                raise AgentStateConflictError()
            return
        if active_attempt_kind is not expected:
            raise AgentStateConflictError()

    def _validate_checkpoint_result(self, target: DurableRunStatus) -> None:
        if self._status is not DurableRunStatus.CHECKPOINTING:
            return
        boundary = self._checkpoint_boundary
        if boundary is None:
            raise AgentStateConflictError()

        next_operation = boundary.next_operation
        if target is DurableRunStatus.ACTIVE:
            if next_operation not in _ACTIVE_NEXT_OPERATIONS:
                raise AgentStateConflictError()
            return
        if target is DurableRunStatus.PAUSED_APPROVAL:
            if next_operation is not CheckpointNextOperation.WAIT_APPROVAL:
                raise AgentStateConflictError()
            return
        if target is DurableRunStatus.PAUSED_OPERATOR:
            if next_operation is not CheckpointNextOperation.OPERATOR_REVIEW:
                raise AgentStateConflictError()
            return
        if target is DurableRunStatus.PAUSED_SHUTDOWN:
            return
        if target in _TERMINAL_STATUSES:
            if next_operation is not CheckpointNextOperation.NONE:
                raise AgentStateConflictError()
            return
        raise AgentStateConflictError()
