from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
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
    DurableExecutionAttemptRecorder,
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    StoreBackedDurableExecutionAttemptRecorder,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    IndeterminateReason,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import classify_recovery_checkpoint
from phoenix_os.agent.durable_reliability import (
    ReliabilityFaultInjector,
    ReliabilityFaultPoint,
)
from phoenix_os.agent.durable_reliability_fake import (
    DeterministicReliabilityFaultInjector,
    InjectedReliabilityFault,
    ReliabilityFaultTrigger,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 1, 0, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
PREPARE_TIME = NOW + timedelta(seconds=2)
START_TIME = NOW + timedelta(seconds=3)
COMPLETE_TIME = NOW + timedelta(seconds=4)

DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000004"))
ATTEMPT_ID = ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000005"))
OTHER_ATTEMPT_ID = ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000006"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget(
    *,
    deadline: datetime | None = None,
) -> AgentBudgetSnapshot:
    resolved_deadline = NOW + timedelta(hours=1) if deadline is None else deadline
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=16,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=resolved_deadline,
    )


def _attempt(
    status: ExecutionAttemptStatus,
    *,
    attempt_id: ExecutionAttemptId = ATTEMPT_ID,
    kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN,
    prepared_at: datetime = PREPARE_TIME,
) -> ExecutionAttempt:
    started_at = (
        None if status is ExecutionAttemptStatus.PREPARED else prepared_at + timedelta(seconds=1)
    )
    completed_at = prepared_at + timedelta(seconds=2) if status.terminal else None
    return ExecutionAttempt(
        attempt_id=attempt_id,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=prepared_at,
        tool_call_id=CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None,
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=started_at,
        completed_at=completed_at,
        external_request_digest=_digest("e"),
        error_code=(
            "attempt-failed"
            if status
            in {
                ExecutionAttemptStatus.FAILED,
                ExecutionAttemptStatus.TIMED_OUT,
            }
            else None
        ),
    )


def _checkpoint(
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
    step_id: AgentStepId | None = STEP_ID,
    deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
    created_at: datetime = NOW,
) -> CheckpointEnvelope:
    resolved_retention = (
        NOW + timedelta(days=7) if retention_deadline is None else retention_deadline
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("60000000-0000-0000-0000-000000000001")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=step_id,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=next_operation,
                budget=_budget(deadline=deadline),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=resolved_retention,
                active_attempt=active_attempt,
                metadata={"tenant": "demo"},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _checkpoint_ids(count: int = 12) -> tuple[CheckpointId, ...]:
    return tuple(
        CheckpointId(UUID(int=0x70000000000000000000000000000000 + index))
        for index in range(1, count + 1)
    )


def _recorder(
    store: InMemoryDurableRunStore,
    *,
    attempt_ids: tuple[ExecutionAttemptId, ...] = (ATTEMPT_ID,),
    checkpoint_ids: tuple[CheckpointId, ...] | None = None,
    fault_injector: ReliabilityFaultInjector | None = None,
) -> StoreBackedDurableExecutionAttemptRecorder:
    attempts = iter(attempt_ids)
    checkpoints = iter(_checkpoint_ids() if checkpoint_ids is None else checkpoint_ids)

    def next_attempt_id() -> ExecutionAttemptId:
        try:
            return next(attempts)
        except StopIteration as exception:
            raise AssertionError("attempt id factory exhausted") from exception

    def next_checkpoint_id() -> CheckpointId:
        try:
            return next(checkpoints)
        except StopIteration as exception:
            raise AssertionError("checkpoint id factory exhausted") from exception

    return StoreBackedDurableExecutionAttemptRecorder(
        store=store,
        attempt_id_factory=next_attempt_id,
        checkpoint_id_factory=next_checkpoint_id,
        fault_injector=fault_injector,
    )


async def _created(
    *,
    checkpoint: CheckpointEnvelope | None = None,
    attempt_ids: tuple[ExecutionAttemptId, ...] = (ATTEMPT_ID,),
) -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
    CheckpointEnvelope,
]:
    current = _checkpoint() if checkpoint is None else checkpoint
    store = InMemoryDurableRunStore()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        current.durable_run_id,
        owner_id="attempt-worker",
        now=LEASE_TIME,
    )
    return store, lease, _recorder(store, attempt_ids=attempt_ids), current


async def _prepared_model() -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
    CheckpointEnvelope,
]:
    store, lease, recorder, current = await _created()
    prepared = await recorder.prepare_model_attempt(
        DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=PREPARE_TIME,
    )
    return store, lease, recorder, prepared


async def _prepared_tool() -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
    CheckpointEnvelope,
]:
    current = _checkpoint(next_operation=CheckpointNextOperation.TOOL_INVOCATION)
    store, lease, recorder, _ = await _created(checkpoint=current)
    prepared = await recorder.prepare_tool_attempt(
        DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
        external_request_digest=_digest("f"),
        now=PREPARE_TIME,
    )
    return store, lease, recorder, prepared


def test_recorder_implements_public_protocol() -> None:
    store = InMemoryDurableRunStore()
    recorder = _recorder(store)

    assert isinstance(recorder, DurableExecutionAttemptRecorder)


@pytest.mark.asyncio
async def test_prepare_model_records_exact_content_free_checkpoint() -> None:
    store, _lease, _recorder_instance, prepared = await _prepared_model()
    attempt = prepared.metadata.active_attempt

    assert attempt is not None
    assert attempt.attempt_id == ATTEMPT_ID
    assert attempt.kind is ExecutionAttemptKind.MODEL_TURN
    assert attempt.status is ExecutionAttemptStatus.PREPARED
    assert attempt.external_request_digest == _digest("e")
    assert attempt.started_at is None
    assert attempt.completed_at is None
    assert prepared.sequence == CheckpointSequence(2)
    assert prepared.run_version == DurableRunVersion(2)
    assert prepared.status is DurableRunStatus.ACTIVE
    assert prepared.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
    assert await store.get_current(DURABLE_RUN_ID) == prepared
    serialized = repr(prepared)
    assert "TOP-SECRET-REQUEST" not in serialized
    assert "prompt" not in serialized


@pytest.mark.asyncio
async def test_prepare_tool_records_exact_call_effect_and_digest() -> None:
    _store, _lease, _recorder_instance, prepared = await _prepared_tool()
    attempt = prepared.metadata.active_attempt

    assert attempt is not None
    assert attempt.kind is ExecutionAttemptKind.TOOL_INVOCATION
    assert attempt.tool_call_id == CALL_ID
    assert attempt.tool_effect is ToolEffect.IRREVERSIBLE_WRITE
    assert attempt.external_request_digest == _digest("f")
    assert prepared.metadata.next_operation is CheckpointNextOperation.TOOL_INVOCATION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "model"),
    [
        (CheckpointNextOperation.TOOL_INVOCATION, True),
        (CheckpointNextOperation.MODEL_TURN, False),
    ],
)
async def test_prepare_requires_the_exact_external_operation(
    operation: CheckpointNextOperation,
    model: bool,
) -> None:
    current = _checkpoint(next_operation=operation)
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        if model:
            await recorder.prepare_model_attempt(
                DURABLE_RUN_ID,
                expected_version=current.run_version,
                lease=lease,
                external_request_digest=_digest("e"),
                now=PREPARE_TIME,
            )
        else:
            await recorder.prepare_tool_attempt(
                DURABLE_RUN_ID,
                expected_version=current.run_version,
                lease=lease,
                tool_call_id=CALL_ID,
                tool_effect=ToolEffect.READ_ONLY,
                external_request_digest=_digest("e"),
                now=PREPARE_TIME,
            )


@pytest.mark.asyncio
async def test_prepare_rejects_one_nonterminal_active_attempt() -> None:
    current = _checkpoint(active_attempt=_attempt(ExecutionAttemptStatus.PREPARED))
    _store, lease, recorder, _ = await _created(
        checkpoint=current,
        attempt_ids=(OTHER_ATTEMPT_ID,),
    )

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("f"),
            now=COMPLETE_TIME,
        )


@pytest.mark.asyncio
async def test_prepare_can_replace_one_terminal_attempt_with_a_fresh_identity() -> None:
    current = _checkpoint(
        active_attempt=_attempt(ExecutionAttemptStatus.SUCCEEDED),
    )
    _store, lease, recorder, _ = await _created(
        checkpoint=current,
        attempt_ids=(OTHER_ATTEMPT_ID,),
    )

    prepared = await recorder.prepare_model_attempt(
        DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("f"),
        now=COMPLETE_TIME + timedelta(seconds=1),
    )

    attempt = prepared.metadata.active_attempt
    assert attempt is not None
    assert attempt.attempt_id == OTHER_ATTEMPT_ID
    assert attempt.status is ExecutionAttemptStatus.PREPARED


@pytest.mark.asyncio
async def test_attempt_identity_cannot_be_reused_from_history() -> None:
    store, lease, recorder, prepared = await _prepared_model()
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )
    completed = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=started.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.SUCCEEDED,
        now=COMPLETE_TIME,
        next_operation=CheckpointNextOperation.COMPLETE,
    )
    cleared = seal_checkpoint_envelope(
        replace(
            completed,
            checkpoint_id=CheckpointId(UUID("70000000-0000-0000-0000-000000000099")),
            sequence=completed.sequence.next(),
            previous_digest=completed.digest,
            run_version=completed.run_version.next(),
            metadata=replace(
                completed.metadata,
                next_operation=CheckpointNextOperation.MODEL_TURN,
                active_attempt=None,
            ),
            created_at=COMPLETE_TIME + timedelta(seconds=1),
            digest=_digest("0"),
        )
    )
    await store.append(
        cleared,
        expected_version=completed.run_version,
        lease=lease,
        now=COMPLETE_TIME + timedelta(seconds=1),
    )
    duplicate_recorder = _recorder(
        store,
        attempt_ids=(ATTEMPT_ID,),
        checkpoint_ids=(CheckpointId(UUID("70000000-0000-0000-0000-000000000100")),),
    )

    with pytest.raises(AgentStateConflictError):
        await duplicate_recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=cleared.run_version,
            lease=lease,
            external_request_digest=_digest("9"),
            now=COMPLETE_TIME + timedelta(seconds=2),
        )


@pytest.mark.asyncio
async def test_mark_started_preserves_exact_attempt_identity() -> None:
    _store, lease, recorder, prepared = await _prepared_tool()
    before = prepared.metadata.active_attempt
    assert before is not None

    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )
    attempt = started.metadata.active_attempt

    assert attempt is not None
    assert attempt.status is ExecutionAttemptStatus.STARTED
    assert attempt.started_at == START_TIME
    assert attempt.attempt_id == before.attempt_id
    assert attempt.kind is before.kind
    assert attempt.tool_call_id == before.tool_call_id
    assert attempt.tool_effect is before.tool_effect
    assert attempt.external_request_digest == before.external_request_digest


@pytest.mark.asyncio
async def test_mark_started_rejects_wrong_attempt_identity() -> None:
    _store, lease, recorder, prepared = await _prepared_model()

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_started(
            DURABLE_RUN_ID,
            OTHER_ATTEMPT_ID,
            expected_version=prepared.run_version,
            lease=lease,
            now=START_TIME,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        ExecutionAttemptStatus.STARTED,
        ExecutionAttemptStatus.SUCCEEDED,
        ExecutionAttemptStatus.FAILED,
    ],
)
async def test_mark_started_requires_prepared_state(
    status: ExecutionAttemptStatus,
) -> None:
    current = _checkpoint(active_attempt=_attempt(status))
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_started(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=current.run_version,
            lease=lease,
            now=COMPLETE_TIME + timedelta(seconds=1),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "next_operation",
    [
        CheckpointNextOperation.VALIDATE_PROPOSAL,
        CheckpointNextOperation.COMPLETE,
    ],
)
async def test_successful_model_attempt_moves_to_reviewed_next_boundary(
    next_operation: CheckpointNextOperation,
) -> None:
    _store, lease, recorder, prepared = await _prepared_model()
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )

    completed = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=started.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.SUCCEEDED,
        now=COMPLETE_TIME,
        next_operation=next_operation,
    )

    attempt = completed.metadata.active_attempt
    assert attempt is not None
    assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
    assert attempt.completed_at == COMPLETE_TIME
    assert completed.status is DurableRunStatus.ACTIVE
    assert completed.metadata.next_operation is next_operation


@pytest.mark.asyncio
async def test_successful_tool_attempt_moves_only_to_result_validation() -> None:
    _store, lease, recorder, prepared = await _prepared_tool()
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )

    completed = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=started.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.SUCCEEDED,
        now=COMPLETE_TIME,
        next_operation=CheckpointNextOperation.VALIDATE_RESULT,
    )

    assert completed.status is DurableRunStatus.ACTIVE
    assert completed.metadata.next_operation is CheckpointNextOperation.VALIDATE_RESULT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "next_operation"),
    [
        (False, CheckpointNextOperation.MODEL_TURN),
        (False, CheckpointNextOperation.VALIDATE_RESULT),
        (True, CheckpointNextOperation.COMPLETE),
        (True, CheckpointNextOperation.TOOL_INVOCATION),
    ],
)
async def test_success_rejects_a_boundary_that_could_repeat_external_work(
    tool: bool,
    next_operation: CheckpointNextOperation,
) -> None:
    if tool:
        _store, lease, recorder, prepared = await _prepared_tool()
    else:
        _store, lease, recorder, prepared = await _prepared_model()
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=started.run_version,
            lease=lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            now=COMPLETE_TIME,
            next_operation=next_operation,
        )


@pytest.mark.asyncio
async def test_success_requires_started_state() -> None:
    _store, lease, recorder, prepared = await _prepared_model()

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=prepared.run_version,
            lease=lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            now=COMPLETE_TIME,
            next_operation=CheckpointNextOperation.COMPLETE,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error_code"),
    [
        (ExecutionAttemptStatus.FAILED, "provider-failed"),
        (ExecutionAttemptStatus.CANCELLED, None),
        (ExecutionAttemptStatus.TIMED_OUT, "provider-timeout"),
    ],
)
@pytest.mark.parametrize("started_first", [False, True])
async def test_non_success_terminal_outcomes_pause_without_retry(
    status: ExecutionAttemptStatus,
    error_code: str | None,
    started_first: bool,
) -> None:
    _store, lease, recorder, prepared = await _prepared_model()
    current = prepared
    now = START_TIME
    if started_first:
        current = await recorder.mark_started(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=prepared.run_version,
            lease=lease,
            now=START_TIME,
        )
        now = COMPLETE_TIME

    terminal = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=current.run_version,
        lease=lease,
        status=status,
        now=now,
        error_code=error_code,
    )

    attempt = terminal.metadata.active_attempt
    assert attempt is not None
    assert attempt.status is status
    assert attempt.error_code == error_code
    assert terminal.status is DurableRunStatus.PAUSED_OPERATOR
    assert terminal.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        ExecutionAttemptStatus.FAILED,
        ExecutionAttemptStatus.TIMED_OUT,
    ],
)
async def test_failed_or_timed_out_attempt_requires_safe_error_code(
    status: ExecutionAttemptStatus,
) -> None:
    _store, lease, recorder, prepared = await _prepared_model()

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=prepared.run_version,
            lease=lease,
            status=status,
            now=START_TIME,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "next_operation", "error_code"),
    [
        (
            ExecutionAttemptStatus.SUCCEEDED,
            CheckpointNextOperation.COMPLETE,
            "unexpected-error",
        ),
        (ExecutionAttemptStatus.CANCELLED, None, "unexpected-error"),
        (
            ExecutionAttemptStatus.FAILED,
            CheckpointNextOperation.COMPLETE,
            "provider-failed",
        ),
    ],
)
async def test_terminal_outcome_rejects_ambiguous_fields(
    status: ExecutionAttemptStatus,
    next_operation: CheckpointNextOperation | None,
    error_code: str | None,
) -> None:
    _store, lease, recorder, prepared = await _prepared_model()
    current = prepared
    if status is ExecutionAttemptStatus.SUCCEEDED:
        current = await recorder.mark_started(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=prepared.run_version,
            lease=lease,
            now=START_TIME,
        )

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=current.run_version,
            lease=lease,
            status=status,
            now=COMPLETE_TIME,
            next_operation=next_operation,
            error_code=error_code,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        ExecutionAttemptStatus.PREPARED,
        ExecutionAttemptStatus.STARTED,
        ExecutionAttemptStatus.INDETERMINATE,
    ],
)
async def test_mark_terminal_rejects_non_reviewed_target_status(
    status: ExecutionAttemptStatus,
) -> None:
    _store, lease, recorder, prepared = await _prepared_model()

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=prepared.run_version,
            lease=lease,
            status=status,
            now=START_TIME,
        )


@pytest.mark.asyncio
async def test_one_attempt_cannot_be_completed_twice() -> None:
    _store, lease, recorder, prepared = await _prepared_model()
    terminal = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.CANCELLED,
        now=START_TIME,
    )

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=terminal.run_version,
            lease=lease,
            status=ExecutionAttemptStatus.CANCELLED,
            now=COMPLETE_TIME,
        )


@pytest.mark.asyncio
async def test_stale_expected_version_cannot_append_attempt_state() -> None:
    _store, lease, recorder, prepared = await _prepared_model()

    with pytest.raises(AgentStateConflictError):
        await recorder.mark_started(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=DurableRunVersion(1),
            lease=lease,
            now=START_TIME,
        )

    assert prepared.run_version == DurableRunVersion(2)


@pytest.mark.asyncio
async def test_lease_for_another_run_grants_no_attempt_authority() -> None:
    store = InMemoryDurableRunStore()
    current = _checkpoint()
    await store.create(current)
    other_checkpoint = replace(
        current,
        durable_run_id=OTHER_DURABLE_RUN_ID,
        checkpoint_id=CheckpointId(UUID("60000000-0000-0000-0000-000000000002")),
        digest=_digest("0"),
    )
    other_checkpoint = seal_checkpoint_envelope(other_checkpoint)
    await store.create(other_checkpoint)
    other_lease = await store.lease_manager.acquire(
        OTHER_DURABLE_RUN_ID,
        owner_id="other-worker",
        now=LEASE_TIME,
    )
    recorder = _recorder(store)

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=other_lease,
            external_request_digest=_digest("e"),
            now=PREPARE_TIME,
        )


@pytest.mark.asyncio
async def test_expired_lease_cannot_append_attempt_state() -> None:
    current = _checkpoint()
    _store, lease, recorder, _ = await _created(checkpoint=current)
    expired_at = lease.expires_at

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=expired_at,
        )


@pytest.mark.asyncio
async def test_stale_fencing_generation_loses_to_new_lease() -> None:
    current = _checkpoint()
    store, old_lease, recorder, _ = await _created(checkpoint=current)
    new_time = old_lease.expires_at
    new_lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="replacement-worker",
        now=new_time,
    )

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=old_lease,
            external_request_digest=_digest("e"),
            now=new_time,
        )

    replacement = _recorder(
        store,
        attempt_ids=(OTHER_ATTEMPT_ID,),
        checkpoint_ids=(CheckpointId(UUID("70000000-0000-0000-0000-000000000200")),),
    )
    prepared = await replacement.prepare_model_attempt(
        DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=new_lease,
        external_request_digest=_digest("f"),
        now=new_time,
    )
    assert prepared.metadata.active_attempt is not None
    assert prepared.metadata.active_attempt.attempt_id == OTHER_ATTEMPT_ID


@pytest.mark.asyncio
async def test_concurrent_prepare_allows_only_one_version_winner() -> None:
    current = _checkpoint()
    store, lease, _recorder_instance, _ = await _created(checkpoint=current)
    first = _recorder(
        store,
        attempt_ids=(ATTEMPT_ID,),
        checkpoint_ids=(CheckpointId(UUID("70000000-0000-0000-0000-000000000301")),),
    )
    second = _recorder(
        store,
        attempt_ids=(OTHER_ATTEMPT_ID,),
        checkpoint_ids=(CheckpointId(UUID("70000000-0000-0000-0000-000000000302")),),
    )

    outcomes = await asyncio.gather(
        first.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=PREPARE_TIME,
        ),
        second.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("f"),
            now=PREPARE_TIME,
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(item, CheckpointEnvelope) for item in outcomes) == 1
    assert sum(isinstance(item, AgentStateConflictError) for item in outcomes) == 1
    persisted = await store.get_current(DURABLE_RUN_ID)
    assert persisted is not None
    assert persisted.run_version == DurableRunVersion(2)


@pytest.mark.asyncio
async def test_attempt_time_cannot_move_before_current_checkpoint() -> None:
    current = _checkpoint(created_at=PREPARE_TIME)
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=LEASE_TIME,
        )


@pytest.mark.asyncio
async def test_prepare_and_start_require_original_budget_to_remain_open() -> None:
    deadline = PREPARE_TIME
    current = _checkpoint(deadline=deadline)
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=deadline,
        )


@pytest.mark.asyncio
async def test_terminal_timeout_can_be_recorded_at_original_budget_deadline() -> None:
    deadline = COMPLETE_TIME
    current = _checkpoint(deadline=deadline)
    store, lease, recorder, _ = await _created(checkpoint=current)
    prepared = await recorder.prepare_model_attempt(
        DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=PREPARE_TIME,
    )
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )

    terminal = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=started.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.TIMED_OUT,
        now=deadline,
        error_code="provider-timeout",
    )

    assert terminal.status is DurableRunStatus.PAUSED_OPERATOR
    assert await store.get_current(DURABLE_RUN_ID) == terminal


@pytest.mark.asyncio
async def test_retention_deadline_rejects_new_attempt_checkpoint() -> None:
    retention_deadline = PREPARE_TIME
    current = _checkpoint(retention_deadline=retention_deadline)
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=retention_deadline,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        DurableRunStatus.PAUSED_APPROVAL,
        DurableRunStatus.PAUSED_OPERATOR,
        DurableRunStatus.RECOVERING,
        DurableRunStatus.COMPLETED,
    ],
)
async def test_attempt_mutation_requires_active_durable_run(
    status: DurableRunStatus,
) -> None:
    operation = (
        CheckpointNextOperation.NONE
        if status is DurableRunStatus.COMPLETED
        else (
            CheckpointNextOperation.WAIT_APPROVAL
            if status is DurableRunStatus.PAUSED_APPROVAL
            else CheckpointNextOperation.OPERATOR_REVIEW
        )
    )
    current = _checkpoint(status=status, next_operation=operation)
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=PREPARE_TIME,
        )


@pytest.mark.asyncio
async def test_attempt_checkpoint_requires_one_exact_step_identity() -> None:
    current = _checkpoint(step_id=None)
    _store, lease, recorder, _ = await _created(checkpoint=current)

    with pytest.raises(AgentStateConflictError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=PREPARE_TIME,
        )


def test_factories_must_be_callable() -> None:
    store = InMemoryDurableRunStore()

    with pytest.raises(TypeError, match="attempt_id_factory"):
        StoreBackedDurableExecutionAttemptRecorder(
            store=store,
            attempt_id_factory=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="checkpoint_id_factory"):
        StoreBackedDurableExecutionAttemptRecorder(
            store=store,
            checkpoint_id_factory=object(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("broken_factory", ["attempt", "checkpoint"])
async def test_factory_results_must_have_phoenix_owned_types(
    broken_factory: str,
) -> None:
    current = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(current)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=LEASE_TIME,
    )

    def valid_attempt_id() -> ExecutionAttemptId:
        return ATTEMPT_ID

    def invalid_attempt_id() -> ExecutionAttemptId:
        return object()  # type: ignore[return-value]

    def valid_checkpoint_id() -> CheckpointId:
        return CheckpointId(UUID("70000000-0000-0000-0000-000000000401"))

    def invalid_checkpoint_id() -> CheckpointId:
        return object()  # type: ignore[return-value]

    recorder = StoreBackedDurableExecutionAttemptRecorder(
        store=store,
        attempt_id_factory=(
            invalid_attempt_id if broken_factory == "attempt" else valid_attempt_id
        ),
        checkpoint_id_factory=(
            invalid_checkpoint_id if broken_factory == "checkpoint" else valid_checkpoint_id
        ),
    )

    with pytest.raises(TypeError):
        await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=current.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=PREPARE_TIME,
        )


@pytest.mark.asyncio
async def test_full_attempt_history_is_monotonic_and_digest_linked() -> None:
    store, lease, recorder, prepared = await _prepared_model()
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )
    terminal = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        expected_version=started.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.SUCCEEDED,
        now=COMPLETE_TIME,
        next_operation=CheckpointNextOperation.COMPLETE,
    )

    history = await store.list_history(DURABLE_RUN_ID, limit=4)
    assert tuple(item.sequence.value for item in history) == (1, 2, 3, 4)
    assert tuple(item.run_version.value for item in history) == (1, 2, 3, 4)
    assert history[1].previous_digest == history[0].digest
    assert history[2].previous_digest == history[1].digest
    assert history[3].previous_digest == history[2].digest
    assert terminal == history[-1]


@pytest.mark.asyncio
async def test_attempt_checkpoints_preserve_immutable_run_metadata_and_budgets() -> None:
    current = _checkpoint()
    _store, lease, recorder, _ = await _created(checkpoint=current)

    prepared = await recorder.prepare_model_attempt(
        DURABLE_RUN_ID,
        expected_version=current.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=PREPARE_TIME,
    )

    assert prepared.agent_run_id == current.agent_run_id
    assert prepared.metadata.agent_id == current.metadata.agent_id
    assert prepared.metadata.actor_id == current.metadata.actor_id
    assert prepared.metadata.payload_profile is current.metadata.payload_profile
    assert prepared.metadata.compatibility == current.metadata.compatibility
    assert prepared.metadata.budget == current.metadata.budget
    assert prepared.metadata.retention_deadline == current.metadata.retention_deadline
    assert prepared.metadata.metadata == current.metadata.metadata


async def _prepare_crash_boundary_attempt(
    recorder: StoreBackedDurableExecutionAttemptRecorder,
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
    kind: ExecutionAttemptKind,
) -> CheckpointEnvelope:
    if kind is ExecutionAttemptKind.MODEL_TURN:
        return await recorder.prepare_model_attempt(
            DURABLE_RUN_ID,
            expected_version=checkpoint.run_version,
            lease=lease,
            external_request_digest=_digest("e"),
            now=PREPARE_TIME,
        )
    return await recorder.prepare_tool_attempt(
        DURABLE_RUN_ID,
        expected_version=checkpoint.run_version,
        lease=lease,
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
        external_request_digest=_digest("f"),
        now=PREPARE_TIME,
    )


def _crash_boundary_checkpoint(kind: ExecutionAttemptKind) -> CheckpointEnvelope:
    return _checkpoint(
        next_operation=(
            CheckpointNextOperation.MODEL_TURN
            if kind is ExecutionAttemptKind.MODEL_TURN
            else CheckpointNextOperation.TOOL_INVOCATION
        )
    )


def _recovery_after_started(
    kind: ExecutionAttemptKind,
) -> tuple[RecoveryPoint, RecoveryDisposition]:
    return (
        (
            RecoveryPoint.ACTIVE_MODEL_ATTEMPT
            if kind is ExecutionAttemptKind.MODEL_TURN
            else RecoveryPoint.ACTIVE_TOOL_ATTEMPT
        ),
        (
            RecoveryDisposition.MARK_INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else RecoveryDisposition.MARK_INDETERMINATE_TOOL
        ),
    )


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_crash_after_prepared_is_durable_but_cannot_transparently_reprepare(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _crash_boundary_checkpoint(kind)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=LEASE_TIME,
    )
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(ReliabilityFaultPoint.ATTEMPT_AFTER_PREPARED),),
        max_total_hits=16,
    )
    recorder = _recorder(
        store,
        attempt_ids=(ATTEMPT_ID, OTHER_ATTEMPT_ID),
        fault_injector=injector,
    )

    with pytest.raises(InjectedReliabilityFault) as crash:
        await _prepare_crash_boundary_attempt(recorder, checkpoint, lease, kind)

    assert crash.value.point is ReliabilityFaultPoint.ATTEMPT_AFTER_PREPARED
    authoritative = await store.get_current(DURABLE_RUN_ID)
    assert authoritative is not None
    attempt = authoritative.metadata.active_attempt
    assert attempt is not None
    assert attempt.attempt_id == ATTEMPT_ID
    assert attempt.kind is kind
    assert attempt.status is ExecutionAttemptStatus.PREPARED
    assert attempt.started_at is None
    assert authoritative.run_version == checkpoint.run_version.next()
    assert await store.list_history(DURABLE_RUN_ID, limit=4) == (
        checkpoint,
        authoritative,
    )

    point, disposition = classify_recovery_checkpoint(
        authoritative,
        now=START_TIME,
    )
    assert point is RecoveryPoint.SAFE_BOUNDARY
    assert disposition is RecoveryDisposition.RESUME

    with pytest.raises(AgentStateConflictError):
        await _prepare_crash_boundary_attempt(
            recorder,
            authoritative,
            lease,
            kind,
        )


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_crash_after_started_never_allows_transparent_model_or_tool_replay(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _crash_boundary_checkpoint(kind)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=LEASE_TIME,
    )
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(ReliabilityFaultPoint.ATTEMPT_AFTER_STARTED),),
        max_total_hits=16,
    )
    recorder = _recorder(
        store,
        attempt_ids=(ATTEMPT_ID, OTHER_ATTEMPT_ID),
        fault_injector=injector,
    )
    prepared = await _prepare_crash_boundary_attempt(
        recorder,
        checkpoint,
        lease,
        kind,
    )
    attempt = prepared.metadata.active_attempt
    assert attempt is not None

    with pytest.raises(InjectedReliabilityFault) as crash:
        await recorder.mark_started(
            DURABLE_RUN_ID,
            attempt.attempt_id,
            expected_version=prepared.run_version,
            lease=lease,
            now=START_TIME,
        )

    assert crash.value.point is ReliabilityFaultPoint.ATTEMPT_AFTER_STARTED
    authoritative = await store.get_current(DURABLE_RUN_ID)
    assert authoritative is not None
    active = authoritative.metadata.active_attempt
    assert active is not None
    assert active.status is ExecutionAttemptStatus.STARTED
    assert active.started_at == START_TIME
    assert await store.list_history(DURABLE_RUN_ID, limit=4) == (
        checkpoint,
        prepared,
        authoritative,
    )

    expected_point, expected_disposition = _recovery_after_started(kind)
    point, disposition = classify_recovery_checkpoint(
        authoritative,
        now=COMPLETE_TIME,
    )
    assert point is expected_point
    assert disposition is expected_disposition

    with pytest.raises(AgentStateConflictError):
        await _prepare_crash_boundary_attempt(
            recorder,
            authoritative,
            lease,
            kind,
        )


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_external_return_crash_leaves_started_attempt_for_fail_closed_recovery(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _crash_boundary_checkpoint(kind)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=LEASE_TIME,
    )
    injector = DeterministicReliabilityFaultInjector(
        (
            ReliabilityFaultTrigger(
                ReliabilityFaultPoint.ATTEMPT_AFTER_EXTERNAL_RETURN_BEFORE_TERMINAL_RECORD
            ),
        ),
        max_total_hits=16,
    )
    recorder = _recorder(
        store,
        attempt_ids=(ATTEMPT_ID, OTHER_ATTEMPT_ID),
        fault_injector=injector,
    )
    prepared = await _prepare_crash_boundary_attempt(
        recorder,
        checkpoint,
        lease,
        kind,
    )
    attempt = prepared.metadata.active_attempt
    assert attempt is not None
    started = await recorder.mark_started(
        DURABLE_RUN_ID,
        attempt.attempt_id,
        expected_version=prepared.run_version,
        lease=lease,
        now=START_TIME,
    )

    with pytest.raises(InjectedReliabilityFault) as crash:
        await recorder.mark_terminal(
            DURABLE_RUN_ID,
            attempt.attempt_id,
            expected_version=started.run_version,
            lease=lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            next_operation=(
                CheckpointNextOperation.VALIDATE_PROPOSAL
                if kind is ExecutionAttemptKind.MODEL_TURN
                else CheckpointNextOperation.VALIDATE_RESULT
            ),
            now=COMPLETE_TIME,
        )

    assert (
        crash.value.point
        is ReliabilityFaultPoint.ATTEMPT_AFTER_EXTERNAL_RETURN_BEFORE_TERMINAL_RECORD
    )
    authoritative = await store.get_current(DURABLE_RUN_ID)
    assert authoritative == started
    assert authoritative.metadata.active_attempt is not None
    assert authoritative.metadata.active_attempt.status is ExecutionAttemptStatus.STARTED
    assert await store.list_history(DURABLE_RUN_ID, limit=5) == (
        checkpoint,
        prepared,
        started,
    )

    with pytest.raises(AgentStateConflictError):
        await _prepare_crash_boundary_attempt(
            recorder,
            authoritative,
            lease,
            kind,
        )

    indeterminate = await recorder.mark_indeterminate(
        DURABLE_RUN_ID,
        attempt.attempt_id,
        expected_version=authoritative.run_version,
        lease=lease,
        reason=IndeterminateReason.PROCESS_LOSS,
        now=COMPLETE_TIME + timedelta(seconds=1),
    )
    assert indeterminate.status is (
        DurableRunStatus.INDETERMINATE_MODEL
        if kind is ExecutionAttemptKind.MODEL_TURN
        else DurableRunStatus.INDETERMINATE_TOOL
    )
    assert indeterminate.metadata.active_attempt is not None
    assert indeterminate.metadata.active_attempt.status is ExecutionAttemptStatus.INDETERMINATE


async def test_prepared_cancellation_does_not_claim_external_return_boundary() -> None:
    checkpoint = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="attempt-worker",
        now=LEASE_TIME,
    )
    injector = DeterministicReliabilityFaultInjector(
        (
            ReliabilityFaultTrigger(
                ReliabilityFaultPoint.ATTEMPT_AFTER_EXTERNAL_RETURN_BEFORE_TERMINAL_RECORD
            ),
        ),
        max_total_hits=8,
    )
    recorder = _recorder(store, fault_injector=injector)
    prepared = await recorder.prepare_model_attempt(
        DURABLE_RUN_ID,
        expected_version=checkpoint.run_version,
        lease=lease,
        external_request_digest=_digest("e"),
        now=PREPARE_TIME,
    )
    attempt = prepared.metadata.active_attempt
    assert attempt is not None

    cancelled = await recorder.mark_terminal(
        DURABLE_RUN_ID,
        attempt.attempt_id,
        expected_version=prepared.run_version,
        lease=lease,
        status=ExecutionAttemptStatus.CANCELLED,
        now=START_TIME,
    )

    assert cancelled.status is DurableRunStatus.PAUSED_OPERATOR
    assert injector.pending_trigger_count == 1
    assert all(
        observation.point
        is not ReliabilityFaultPoint.ATTEMPT_AFTER_EXTERNAL_RETURN_BEFORE_TERMINAL_RECORD
        for observation in injector.observations
    )
