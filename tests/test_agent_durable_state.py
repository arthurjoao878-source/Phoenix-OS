from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptKind,
)
from phoenix_os.agent.durable_state import (
    DurableCheckpointBoundary,
    DurableRunStateMachine,
    durable_transition_allowed,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 7, 29, 20, tzinfo=UTC)
RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-0000-0000-000000000004"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=128,
        tool_result_bytes=0,
        input_tokens=32,
        output_tokens=16,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _metadata(
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=AgentId("assistant"),
        actor_id="worker-1",
        next_operation=next_operation,
        budget=_budget(),
        compatibility=_compatibility(),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
        retention_deadline=NOW + timedelta(days=7),
    )


def _checkpoint(
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
) -> CheckpointEnvelope:
    return CheckpointEnvelope(
        schema_version=CheckpointSchemaVersion(),
        durable_run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=CheckpointSequence(1),
        previous_digest=None,
        run_version=DurableRunVersion(1),
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        metadata=_metadata(next_operation),
        created_at=NOW + timedelta(seconds=1),
        digest=_digest("e"),
    )


def _active_machine() -> DurableRunStateMachine:
    machine = DurableRunStateMachine(RUN_ID, created_at=NOW)
    machine.transition(DurableRunStatus.ACTIVE, now=NOW + timedelta(seconds=1))
    return machine


def _checkpointing_machine(
    next_operation: CheckpointNextOperation,
) -> DurableRunStateMachine:
    machine = _active_machine()
    machine.transition(
        DurableRunStatus.CHECKPOINTING,
        now=NOW + timedelta(seconds=2),
        boundary=DurableCheckpointBoundary(next_operation),
    )
    return machine


def test_boundary_defaults_are_safe_and_content_free() -> None:
    boundary = DurableCheckpointBoundary(CheckpointNextOperation.MODEL_TURN)

    assert boundary.safe
    assert boundary.next_operation is CheckpointNextOperation.MODEL_TURN
    assert not boundary.model_call_active
    assert not boundary.tool_call_active
    assert not boundary.result_stream_open
    assert not boundary.approval_consumption_active
    assert boundary.transition_complete
    assert boundary.budgets_known
    assert boundary.continuation_available
    boundary.require_safe()


@pytest.mark.parametrize(
    "boundary",
    [
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            model_call_active=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            tool_call_active=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            result_stream_open=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            approval_consumption_active=True,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            transition_complete=False,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            budgets_known=False,
        ),
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            continuation_available=False,
        ),
    ],
)
def test_boundary_fails_closed_when_any_safety_condition_is_missing(
    boundary: DurableCheckpointBoundary,
) -> None:
    assert not boundary.safe

    with pytest.raises(AgentStateConflictError):
        boundary.require_safe()


def test_boundary_rejects_wrong_runtime_types() -> None:
    with pytest.raises(TypeError, match="next_operation"):
        DurableCheckpointBoundary(
            cast(CheckpointNextOperation, "model_turn"),
        )

    with pytest.raises(TypeError, match="model_call_active"):
        DurableCheckpointBoundary(
            CheckpointNextOperation.MODEL_TURN,
            model_call_active=cast(bool, 1),
        )


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (DurableRunStatus.CREATED, DurableRunStatus.ACTIVE),
        (DurableRunStatus.ACTIVE, DurableRunStatus.CHECKPOINTING),
        (DurableRunStatus.CHECKPOINTING, DurableRunStatus.ACTIVE),
        (DurableRunStatus.CHECKPOINTING, DurableRunStatus.PAUSED_APPROVAL),
        (DurableRunStatus.PAUSED_APPROVAL, DurableRunStatus.RECOVERING),
        (DurableRunStatus.RECOVERING, DurableRunStatus.ACTIVE),
        (DurableRunStatus.INDETERMINATE_MODEL, DurableRunStatus.RECONCILING),
        (DurableRunStatus.RECONCILING, DurableRunStatus.ACTIVE),
        (DurableRunStatus.CHECKPOINTING, DurableRunStatus.COMPLETED),
    ],
)
def test_reviewed_transition_table_allows_expected_edges(
    source: DurableRunStatus,
    target: DurableRunStatus,
) -> None:
    assert durable_transition_allowed(source, target)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (DurableRunStatus.CREATED, DurableRunStatus.COMPLETED),
        (DurableRunStatus.ACTIVE, DurableRunStatus.COMPLETED),
        (DurableRunStatus.PAUSED_APPROVAL, DurableRunStatus.ACTIVE),
        (DurableRunStatus.INDETERMINATE_MODEL, DurableRunStatus.ACTIVE),
        (DurableRunStatus.INDETERMINATE_TOOL, DurableRunStatus.ACTIVE),
        (DurableRunStatus.COMPLETED, DurableRunStatus.ACTIVE),
        (DurableRunStatus.FAILED, DurableRunStatus.RECOVERING),
    ],
)
def test_reviewed_transition_table_rejects_unreviewed_edges(
    source: DurableRunStatus,
    target: DurableRunStatus,
) -> None:
    assert not durable_transition_allowed(source, target)


def test_transition_table_rejects_wrong_runtime_types() -> None:
    with pytest.raises(TypeError, match="source"):
        durable_transition_allowed(
            cast(DurableRunStatus, "active"),
            DurableRunStatus.CHECKPOINTING,
        )

    with pytest.raises(TypeError, match="target"):
        durable_transition_allowed(
            DurableRunStatus.ACTIVE,
            cast(DurableRunStatus, "checkpointing"),
        )


def test_state_machine_starts_created_with_stable_identity() -> None:
    machine = DurableRunStateMachine(RUN_ID, created_at=NOW)

    assert machine.run_id == RUN_ID
    assert machine.status is DurableRunStatus.CREATED
    assert not machine.terminal
    assert machine.updated_at == NOW
    assert machine.checkpoint_boundary is None


def test_state_machine_constructor_rejects_invalid_identity_and_time() -> None:
    with pytest.raises(TypeError, match="run_id"):
        DurableRunStateMachine(
            cast(DurableAgentRunId, object()),
            created_at=NOW,
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        DurableRunStateMachine(
            RUN_ID,
            created_at=NOW.replace(tzinfo=None),
        )


def test_normal_checkpoint_lifecycle_reaches_completion() -> None:
    machine = _active_machine()
    model_boundary = DurableCheckpointBoundary(CheckpointNextOperation.MODEL_TURN)

    machine.transition(
        DurableRunStatus.CHECKPOINTING,
        now=NOW + timedelta(seconds=2),
        boundary=model_boundary,
    )

    assert machine.status.value == DurableRunStatus.CHECKPOINTING.value
    assert machine.checkpoint_boundary == model_boundary

    machine.transition(
        DurableRunStatus.ACTIVE,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is DurableRunStatus.ACTIVE
    assert machine.checkpoint_boundary is None

    machine.transition(
        DurableRunStatus.CHECKPOINTING,
        now=NOW + timedelta(seconds=4),
        boundary=DurableCheckpointBoundary(CheckpointNextOperation.NONE),
    )
    machine.transition(
        DurableRunStatus.COMPLETED,
        now=NOW + timedelta(seconds=5),
    )

    assert machine.status is DurableRunStatus.COMPLETED
    assert machine.terminal
    assert machine.checkpoint_boundary is None


def test_from_checkpoint_restores_only_reviewed_identity_state_and_time() -> None:
    checkpoint = _checkpoint(status=DurableRunStatus.ACTIVE)

    machine = DurableRunStateMachine.from_checkpoint(checkpoint)

    assert machine.run_id == checkpoint.durable_run_id
    assert machine.status is DurableRunStatus.ACTIVE
    assert machine.updated_at == checkpoint.created_at
    assert machine.checkpoint_boundary is None


def test_from_checkpoint_rejects_wrong_runtime_type() -> None:
    with pytest.raises(TypeError, match="checkpoint"):
        DurableRunStateMachine.from_checkpoint(
            cast(CheckpointEnvelope, object()),
        )


def test_invalid_direct_transition_fails_without_mutating_state() -> None:
    machine = DurableRunStateMachine(RUN_ID, created_at=NOW)

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.COMPLETED,
            now=NOW + timedelta(seconds=1),
        )

    assert machine.status is DurableRunStatus.CREATED
    assert machine.updated_at == NOW


def test_transition_rejects_time_rollback_without_mutating_state() -> None:
    machine = _active_machine()

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.CHECKPOINTING,
            now=NOW,
            boundary=DurableCheckpointBoundary(CheckpointNextOperation.MODEL_TURN),
        )

    assert machine.status is DurableRunStatus.ACTIVE
    assert machine.updated_at == NOW + timedelta(seconds=1)


def test_transition_accepts_equal_trusted_timestamp() -> None:
    machine = DurableRunStateMachine(RUN_ID, created_at=NOW)

    machine.transition(DurableRunStatus.ACTIVE, now=NOW)

    assert machine.status is DurableRunStatus.ACTIVE
    assert machine.updated_at == NOW


def test_transition_rejects_invalid_target_and_naive_time() -> None:
    machine = DurableRunStateMachine(RUN_ID, created_at=NOW)

    with pytest.raises(TypeError, match="target"):
        machine.transition(
            cast(DurableRunStatus, "active"),
            now=NOW + timedelta(seconds=1),
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        machine.transition(
            DurableRunStatus.ACTIVE,
            now=NOW.replace(tzinfo=None),
        )


def test_checkpointing_requires_a_safe_boundary() -> None:
    machine = _active_machine()

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.CHECKPOINTING,
            now=NOW + timedelta(seconds=2),
        )

    unsafe = DurableCheckpointBoundary(
        CheckpointNextOperation.MODEL_TURN,
        model_call_active=True,
    )
    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.CHECKPOINTING,
            now=NOW + timedelta(seconds=2),
            boundary=unsafe,
        )

    assert machine.status is DurableRunStatus.ACTIVE
    assert machine.checkpoint_boundary is None


def test_boundary_argument_is_rejected_for_non_checkpoint_transition() -> None:
    machine = DurableRunStateMachine(RUN_ID, created_at=NOW)

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.ACTIVE,
            now=NOW + timedelta(seconds=1),
            boundary=DurableCheckpointBoundary(CheckpointNextOperation.MODEL_TURN),
        )

    assert machine.status is DurableRunStatus.CREATED


@pytest.mark.parametrize(
    "next_operation",
    [
        CheckpointNextOperation.MODEL_TURN,
        CheckpointNextOperation.VALIDATE_PROPOSAL,
        CheckpointNextOperation.AUTHORIZE_TOOL,
        CheckpointNextOperation.TOOL_INVOCATION,
        CheckpointNextOperation.VALIDATE_RESULT,
        CheckpointNextOperation.COMPLETE,
    ],
)
def test_checkpoint_can_return_active_for_executable_next_operations(
    next_operation: CheckpointNextOperation,
) -> None:
    machine = _checkpointing_machine(next_operation)

    machine.transition(
        DurableRunStatus.ACTIVE,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is DurableRunStatus.ACTIVE


@pytest.mark.parametrize(
    "next_operation",
    [
        CheckpointNextOperation.NONE,
        CheckpointNextOperation.WAIT_APPROVAL,
        CheckpointNextOperation.OPERATOR_REVIEW,
    ],
)
def test_checkpoint_cannot_return_active_for_non_executable_next_operations(
    next_operation: CheckpointNextOperation,
) -> None:
    machine = _checkpointing_machine(next_operation)

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.ACTIVE,
            now=NOW + timedelta(seconds=3),
        )

    assert machine.status is DurableRunStatus.CHECKPOINTING


def test_approval_pause_requires_wait_approval_boundary() -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.WAIT_APPROVAL)

    machine.transition(
        DurableRunStatus.PAUSED_APPROVAL,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is DurableRunStatus.PAUSED_APPROVAL

    invalid = _checkpointing_machine(CheckpointNextOperation.MODEL_TURN)
    with pytest.raises(AgentStateConflictError):
        invalid.transition(
            DurableRunStatus.PAUSED_APPROVAL,
            now=NOW + timedelta(seconds=3),
        )


def test_operator_pause_requires_operator_review_boundary() -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.OPERATOR_REVIEW)

    machine.transition(
        DurableRunStatus.PAUSED_OPERATOR,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is DurableRunStatus.PAUSED_OPERATOR

    invalid = _checkpointing_machine(CheckpointNextOperation.WAIT_APPROVAL)
    with pytest.raises(AgentStateConflictError):
        invalid.transition(
            DurableRunStatus.PAUSED_OPERATOR,
            now=NOW + timedelta(seconds=3),
        )


def test_shutdown_pause_preserves_a_deterministic_continuation_boundary() -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.MODEL_TURN)

    machine.transition(
        DurableRunStatus.PAUSED_SHUTDOWN,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is DurableRunStatus.PAUSED_SHUTDOWN


@pytest.mark.parametrize(
    "terminal_status",
    [
        DurableRunStatus.COMPLETED,
        DurableRunStatus.FAILED,
        DurableRunStatus.CANCELLED,
        DurableRunStatus.EXPIRED,
    ],
)
def test_terminal_checkpoint_requires_no_next_operation(
    terminal_status: DurableRunStatus,
) -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.NONE)

    machine.transition(
        terminal_status,
        now=NOW + timedelta(seconds=3),
    )

    assert machine.status is terminal_status
    assert machine.terminal


def test_terminal_checkpoint_rejects_remaining_work() -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.MODEL_TURN)

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.FAILED,
            now=NOW + timedelta(seconds=3),
        )

    assert machine.status is DurableRunStatus.CHECKPOINTING


@pytest.mark.parametrize(
    ("target", "attempt_kind"),
    [
        (
            DurableRunStatus.INDETERMINATE_MODEL,
            ExecutionAttemptKind.MODEL_TURN,
        ),
        (
            DurableRunStatus.INDETERMINATE_TOOL,
            ExecutionAttemptKind.TOOL_INVOCATION,
        ),
    ],
)
def test_indeterminate_transition_requires_matching_attempt_kind(
    target: DurableRunStatus,
    attempt_kind: ExecutionAttemptKind,
) -> None:
    machine = _active_machine()

    machine.transition(
        target,
        now=NOW + timedelta(seconds=2),
        active_attempt_kind=attempt_kind,
    )

    assert machine.status is target


@pytest.mark.parametrize(
    ("target", "attempt_kind"),
    [
        (DurableRunStatus.INDETERMINATE_MODEL, None),
        (
            DurableRunStatus.INDETERMINATE_MODEL,
            ExecutionAttemptKind.TOOL_INVOCATION,
        ),
        (DurableRunStatus.INDETERMINATE_TOOL, None),
        (
            DurableRunStatus.INDETERMINATE_TOOL,
            ExecutionAttemptKind.MODEL_TURN,
        ),
    ],
)
def test_indeterminate_transition_rejects_missing_or_mismatched_attempt(
    target: DurableRunStatus,
    attempt_kind: ExecutionAttemptKind | None,
) -> None:
    machine = _active_machine()

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            target,
            now=NOW + timedelta(seconds=2),
            active_attempt_kind=attempt_kind,
        )

    assert machine.status is DurableRunStatus.ACTIVE


def test_attempt_kind_is_rejected_for_non_indeterminate_transition() -> None:
    machine = _active_machine()

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.CHECKPOINTING,
            now=NOW + timedelta(seconds=2),
            boundary=DurableCheckpointBoundary(CheckpointNextOperation.MODEL_TURN),
            active_attempt_kind=ExecutionAttemptKind.MODEL_TURN,
        )

    assert machine.status is DurableRunStatus.ACTIVE


def test_indeterminate_run_cannot_return_directly_to_execution() -> None:
    machine = _active_machine()
    machine.transition(
        DurableRunStatus.INDETERMINATE_MODEL,
        now=NOW + timedelta(seconds=2),
        active_attempt_kind=ExecutionAttemptKind.MODEL_TURN,
    )

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.ACTIVE,
            now=NOW + timedelta(seconds=3),
        )

    assert machine.status is DurableRunStatus.INDETERMINATE_MODEL


def test_indeterminate_run_can_reconcile_before_reviewed_resume() -> None:
    machine = _active_machine()
    machine.transition(
        DurableRunStatus.INDETERMINATE_TOOL,
        now=NOW + timedelta(seconds=2),
        active_attempt_kind=ExecutionAttemptKind.TOOL_INVOCATION,
    )
    machine.transition(
        DurableRunStatus.RECONCILING,
        now=NOW + timedelta(seconds=3),
    )
    machine.transition(
        DurableRunStatus.ACTIVE,
        now=NOW + timedelta(seconds=4),
    )

    assert machine.status is DurableRunStatus.ACTIVE


def test_approval_recovery_requires_recovering_state() -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.WAIT_APPROVAL)
    machine.transition(
        DurableRunStatus.PAUSED_APPROVAL,
        now=NOW + timedelta(seconds=3),
    )

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.ACTIVE,
            now=NOW + timedelta(seconds=4),
        )

    machine.transition(
        DurableRunStatus.RECOVERING,
        now=NOW + timedelta(seconds=4),
    )
    machine.transition(
        DurableRunStatus.ACTIVE,
        now=NOW + timedelta(seconds=5),
    )

    assert machine.status is DurableRunStatus.ACTIVE


def test_terminal_state_rejects_duplicate_or_later_work() -> None:
    machine = _checkpointing_machine(CheckpointNextOperation.NONE)
    machine.transition(
        DurableRunStatus.CANCELLED,
        now=NOW + timedelta(seconds=3),
    )

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.CANCELLED,
            now=NOW + timedelta(seconds=4),
        )

    with pytest.raises(AgentStateConflictError):
        machine.transition(
            DurableRunStatus.RECOVERING,
            now=NOW + timedelta(seconds=4),
        )

    assert machine.status is DurableRunStatus.CANCELLED
    assert machine.updated_at == NOW + timedelta(seconds=3)
