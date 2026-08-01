from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from itertools import product
from typing import Literal, cast
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentRunId,
    AgentStateConflictError,
    AgentStepId,
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
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
    DurableAttemptStatusLookupResult,
    DurableAttemptStatusObservation,
    DurableAttemptStatusQuery,
    DurableExecutionAttemptRecorder,
    DurableLease,
    DurableReconciliationAuthorizer,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    InMemoryDurableRunStore,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
    RecoveryDisposition,
    ReviewedDurableAttemptStatusLookup,
    StartupDurableRecoveryCoordinator,
    StoreBackedDurableExecutionAttemptRecorder,
    StoreBackedDurableReconciliationDispositionApplier,
    ToolCallId,
    ToolEffect,
    reconciliation_disposition_record,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 1, 4, tzinfo=UTC)
LOOKUP_TIME = NOW + timedelta(seconds=4)
OBSERVED_TIME = NOW + timedelta(seconds=5)
REQUEST_TIME = NOW + timedelta(seconds=6)
APPLY_TIME = NOW + timedelta(seconds=7)
RECOVERY_TIME = NOW + timedelta(seconds=8)

DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000005"))
CHECKPOINT_ID = CheckpointId(UUID("60000000-0000-0000-0000-000000000006"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _validator() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=AgentId("assistant"),
                current=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind,
    status: ExecutionAttemptStatus,
    *,
    tool_effect: ToolEffect = ToolEffect.IRREVERSIBLE_WRITE,
) -> ExecutionAttempt:
    prepared_at = NOW + timedelta(seconds=1)
    started_at = None if status is ExecutionAttemptStatus.PREPARED else NOW + timedelta(seconds=2)
    completed_at = NOW + timedelta(seconds=3) if status.terminal else None
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=prepared_at,
        tool_call_id=(TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None),
        tool_effect=(tool_effect if kind is ExecutionAttemptKind.TOOL_INVOCATION else None),
        started_at=started_at,
        completed_at=completed_at,
        external_request_digest=_digest("e"),
        indeterminate_reason=(
            IndeterminateReason.PROCESS_LOSS
            if status is ExecutionAttemptStatus.INDETERMINATE
            else None
        ),
    )


def _checkpoint(
    kind: ExecutionAttemptKind,
    attempt_status: ExecutionAttemptStatus,
    *,
    tool_effect: ToolEffect = ToolEffect.IRREVERSIBLE_WRITE,
) -> CheckpointEnvelope:
    if attempt_status is ExecutionAttemptStatus.INDETERMINATE:
        durable_status = (
            DurableRunStatus.INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        )
        next_operation = CheckpointNextOperation.OPERATOR_REVIEW
    else:
        durable_status = DurableRunStatus.ACTIVE
        next_operation = (
            CheckpointNextOperation.MODEL_TURN
            if kind is ExecutionAttemptKind.MODEL_TURN
            else CheckpointNextOperation.TOOL_INVOCATION
        )

    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=durable_status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=next_operation,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=7),
                active_attempt=_attempt(
                    kind,
                    attempt_status,
                    tool_effect=tool_effect,
                ),
                metadata={"tenant": "demo"},
            ),
            created_at=NOW + timedelta(seconds=3),
            digest=_digest("0"),
        )
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        attributes={"durable_actor_id": "operator-1"},
    )


class _AllowAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del request, checkpoint, lease, context
        self.calls += 1


class _GuardedRecorder:
    def __init__(self, store: InMemoryDurableRunStore) -> None:
        self._delegate = StoreBackedDurableExecutionAttemptRecorder(store=store)
        self.prepare_model_calls = 0
        self.prepare_tool_calls = 0
        self.mark_started_calls = 0
        self.mark_indeterminate_calls = 0
        self.mark_terminal_calls = 0

    async def prepare_model_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        external_request_digest: CheckpointDigest,
        now: datetime,
    ) -> CheckpointEnvelope:
        del run_id, expected_version, lease, external_request_digest, now
        self.prepare_model_calls += 1
        raise AssertionError("recovery must not prepare a replacement model attempt")

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
        del (
            run_id,
            expected_version,
            lease,
            tool_call_id,
            tool_effect,
            external_request_digest,
            now,
        )
        self.prepare_tool_calls += 1
        raise AssertionError("recovery must not prepare a replacement tool attempt")

    async def mark_started(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        del run_id, attempt_id, expected_version, lease, now
        self.mark_started_calls += 1
        raise AssertionError("recovery must not start external work")

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
        self.mark_indeterminate_calls += 1
        return await self._delegate.mark_indeterminate(
            run_id,
            attempt_id,
            expected_version=expected_version,
            lease=lease,
            reason=reason,
            now=now,
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
        del (
            run_id,
            attempt_id,
            expected_version,
            lease,
            status,
            now,
            next_operation,
            error_code,
        )
        self.mark_terminal_calls += 1
        raise AssertionError("recovery must not invent a terminal external result")

    @property
    def forbidden_calls(self) -> int:
        return (
            self.prepare_model_calls
            + self.prepare_tool_calls
            + self.mark_started_calls
            + self.mark_terminal_calls
        )


_LookupBehavior = Literal["observed", "error", "invalid"]


class _ModelBoundary:
    adapter_id = "reviewed-model-status"

    def __init__(
        self,
        *,
        status: DurableAttemptExternalStatus,
        behavior: _LookupBehavior = "observed",
    ) -> None:
        self.status = status
        self.behavior = behavior
        self.lookup_calls = 0
        self.execution_calls = 0

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        self.lookup_calls += 1
        if self.behavior == "error":
            raise RuntimeError("provider status lookup failed")
        if self.behavior == "invalid":
            return cast(DurableAttemptStatusObservation, object())
        return _observation(
            query,
            adapter_id=self.adapter_id,
            status=self.status,
        )

    async def infer(self, request: object) -> object:
        del request
        self.execution_calls += 1
        raise AssertionError("status lookup or reconciliation invoked model inference")


class _ToolBoundary:
    adapter_id = "reviewed-tool-status"

    def __init__(
        self,
        *,
        status: DurableAttemptExternalStatus,
        behavior: _LookupBehavior = "observed",
    ) -> None:
        self.status = status
        self.behavior = behavior
        self.lookup_calls = 0
        self.execution_calls = 0

    async def lookup_tool_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        self.lookup_calls += 1
        if self.behavior == "error":
            raise RuntimeError("tool status lookup failed")
        if self.behavior == "invalid":
            return cast(DurableAttemptStatusObservation, object())
        return _observation(
            query,
            adapter_id=self.adapter_id,
            status=self.status,
        )

    async def invoke(self, request: object) -> object:
        del request
        self.execution_calls += 1
        raise AssertionError("status lookup or reconciliation invoked the tool")


def _observation(
    query: DurableAttemptStatusQuery,
    *,
    adapter_id: str,
    status: DurableAttemptExternalStatus,
) -> DurableAttemptStatusObservation:
    evidence = (
        None
        if status is DurableAttemptExternalStatus.UNKNOWN
        else ReconciliationEvidence(
            evidence_type="adapter-receipt",
            evidence_digest=_digest("9"),
            observed_at=OBSERVED_TIME,
        )
    )
    return DurableAttemptStatusObservation(
        lookup_id=query.lookup_id,
        durable_run_id=query.durable_run_id,
        attempt_id=query.attempt_id,
        external_request_digest=query.external_request_digest,
        adapter_id=adapter_id,
        status=status,
        observed_at=OBSERVED_TIME,
        evidence=evidence,
    )


async def _store_with_checkpoint(
    checkpoint: CheckpointEnvelope,
) -> InMemoryDurableRunStore:
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    return store


async def _recovery_harness(
    checkpoint: CheckpointEnvelope,
) -> tuple[
    InMemoryDurableRunStore,
    _GuardedRecorder,
    StartupDurableRecoveryCoordinator,
]:
    store = await _store_with_checkpoint(checkpoint)
    recorder = _GuardedRecorder(store)
    assert isinstance(recorder, DurableExecutionAttemptRecorder)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        attempt_recorder=recorder,
    )
    return store, recorder, coordinator


async def _lookup_result(
    checkpoint: CheckpointEnvelope,
    kind: ExecutionAttemptKind,
    *,
    status: DurableAttemptExternalStatus,
    behavior: _LookupBehavior = "observed",
) -> tuple[
    DurableAttemptStatusLookupResult,
    _ModelBoundary | _ToolBoundary,
]:
    boundary: _ModelBoundary | _ToolBoundary
    if kind is ExecutionAttemptKind.MODEL_TURN:
        model_boundary = _ModelBoundary(
            status=status,
            behavior=behavior,
        )
        boundary = model_boundary
        service = ReviewedDurableAttemptStatusLookup(
            model_adapter=model_boundary,
        )
    else:
        tool_boundary = _ToolBoundary(
            status=status,
            behavior=behavior,
        )
        boundary = tool_boundary
        service = ReviewedDurableAttemptStatusLookup(
            tool_adapter=tool_boundary,
        )
    result = await service.lookup(
        checkpoint,
        requested_at=LOOKUP_TIME,
    )
    return result, boundary


def _external_status(
    decision: ReconciliationDecision,
) -> DurableAttemptExternalStatus | None:
    if decision is ReconciliationDecision.CONFIRM_SUCCEEDED:
        return DurableAttemptExternalStatus.SUCCEEDED
    if decision is ReconciliationDecision.CONFIRM_FAILED:
        return DurableAttemptExternalStatus.FAILED
    if decision is ReconciliationDecision.CONFIRM_NOT_STARTED:
        return DurableAttemptExternalStatus.NOT_STARTED
    return None


def _request(
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
    decision: ReconciliationDecision,
    lookup_result: DurableAttemptStatusLookupResult | None,
) -> ReconciliationRequest:
    attempt = checkpoint.metadata.active_attempt
    if attempt is None:
        raise AssertionError("reconciliation source must contain an attempt")
    return ReconciliationRequest(
        run_id=checkpoint.durable_run_id,
        attempt_id=attempt.attempt_id,
        actor_id="operator-1",
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        decision=decision,
        evidence=(lookup_result.evidence if lookup_result is not None else None),
        requested_at=REQUEST_TIME,
    )


async def _reconciliation_harness(
    kind: ExecutionAttemptKind,
    decision: ReconciliationDecision,
) -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    _AllowAuthorizer,
    StoreBackedDurableReconciliationDispositionApplier,
    ReconciliationRequest,
    DurableAttemptStatusLookupResult | None,
    _ModelBoundary | _ToolBoundary,
]:
    checkpoint = _checkpoint(
        kind,
        ExecutionAttemptStatus.INDETERMINATE,
    )
    store = await _store_with_checkpoint(checkpoint)
    lease = await store.lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id="reconcile-worker",
        now=NOW + timedelta(seconds=3, microseconds=1),
    )
    authorizer = _AllowAuthorizer()
    assert isinstance(authorizer, DurableReconciliationAuthorizer)
    applier = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=authorizer,
    )

    status = _external_status(decision)
    if status is None:
        lookup_result = None
        boundary: _ModelBoundary | _ToolBoundary
        if kind is ExecutionAttemptKind.MODEL_TURN:
            boundary = _ModelBoundary(
                status=DurableAttemptExternalStatus.UNKNOWN,
            )
        else:
            boundary = _ToolBoundary(
                status=DurableAttemptExternalStatus.UNKNOWN,
            )
    else:
        lookup_result, boundary = await _lookup_result(
            checkpoint,
            kind,
            status=status,
        )

    request = _request(
        checkpoint,
        lease,
        decision,
        lookup_result,
    )
    return (
        store,
        lease,
        authorizer,
        applier,
        request,
        lookup_result,
        boundary,
    )


def _assert_reconciliation_result(
    before: CheckpointEnvelope,
    after: CheckpointEnvelope,
    decision: ReconciliationDecision,
) -> None:
    before_attempt = before.metadata.active_attempt
    assert before_attempt is not None
    assert after.sequence == before.sequence.next()
    assert after.run_version == before.run_version.next()
    assert after.previous_digest == before.digest

    if decision is ReconciliationDecision.REMAIN_INDETERMINATE:
        assert after.status is before.status
        assert after.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
        assert after.metadata.active_attempt == before_attempt
    elif decision is ReconciliationDecision.CANCEL_RUN:
        assert after.status is DurableRunStatus.CANCELLED
        assert after.metadata.next_operation is CheckpointNextOperation.NONE
        assert after.metadata.active_attempt is None
    elif decision is ReconciliationDecision.FAIL_RUN:
        assert after.status is DurableRunStatus.FAILED
        assert after.metadata.next_operation is CheckpointNextOperation.NONE
        assert after.metadata.active_attempt is None
    else:
        attempt = after.metadata.active_attempt
        assert after.status is DurableRunStatus.PAUSED_OPERATOR
        assert attempt is not None
        assert attempt.attempt_id == before_attempt.attempt_id
        assert attempt.status not in {
            ExecutionAttemptStatus.PREPARED,
            ExecutionAttemptStatus.STARTED,
            ExecutionAttemptStatus.INDETERMINATE,
        }
        if decision is ReconciliationDecision.CONFIRM_SUCCEEDED:
            assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
            assert after.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
        elif decision is ReconciliationDecision.CONFIRM_FAILED:
            assert attempt.status is ExecutionAttemptStatus.FAILED
            assert after.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
        else:
            expected_operation = (
                CheckpointNextOperation.MODEL_TURN
                if before_attempt.kind is ExecutionAttemptKind.MODEL_TURN
                else CheckpointNextOperation.TOOL_INVOCATION
            )
            assert attempt.status is ExecutionAttemptStatus.CANCELLED
            assert after.metadata.next_operation is expected_operation


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_read_only_recovery_assessment_never_calls_attempt_recorder(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind, ExecutionAttemptStatus.STARTED)
    store, recorder, coordinator = await _recovery_harness(checkpoint)

    assessment = await coordinator.assess_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )

    assert await store.get_current(checkpoint.durable_run_id) == checkpoint
    assert assessment.disposition in {
        RecoveryDisposition.MARK_INDETERMINATE_MODEL,
        RecoveryDisposition.MARK_INDETERMINATE_TOOL,
    }
    assert recorder.mark_indeterminate_calls == 0
    assert recorder.forbidden_calls == 0
    assert len(await store.list_history(checkpoint.durable_run_id, limit=1)) == 1


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_process_loss_persists_only_one_indeterminate_transition(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind, ExecutionAttemptStatus.STARTED)
    store, recorder, coordinator = await _recovery_harness(checkpoint)

    await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    current = await store.get_current(checkpoint.durable_run_id)

    assert current is not None
    assert current.status is (
        DurableRunStatus.INDETERMINATE_MODEL
        if kind is ExecutionAttemptKind.MODEL_TURN
        else DurableRunStatus.INDETERMINATE_TOOL
    )
    assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert current.metadata.active_attempt is not None
    assert current.metadata.active_attempt.status is ExecutionAttemptStatus.INDETERMINATE
    assert recorder.mark_indeterminate_calls == 1
    assert recorder.forbidden_calls == 0
    assert len(await store.list_history(checkpoint.durable_run_id, limit=2)) == 2


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_repeated_process_loss_recovery_does_not_repeat_transition(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind, ExecutionAttemptStatus.STARTED)
    store, recorder, coordinator = await _recovery_harness(checkpoint)

    first = await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )
    second = await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=RECOVERY_TIME + timedelta(seconds=1),
    )

    assert first.checkpoint_id == second.checkpoint_id
    assert recorder.mark_indeterminate_calls == 1
    assert recorder.forbidden_calls == 0
    assert len(await store.list_history(checkpoint.durable_run_id, limit=2)) == 2


@pytest.mark.parametrize("effect", tuple(ToolEffect))
async def test_tool_effect_never_weakens_the_no_retry_rule(
    effect: ToolEffect,
) -> None:
    checkpoint = _checkpoint(
        ExecutionAttemptKind.TOOL_INVOCATION,
        ExecutionAttemptStatus.STARTED,
        tool_effect=effect,
    )
    store, recorder, coordinator = await _recovery_harness(checkpoint)

    await coordinator.persist_indeterminate_candidate(
        checkpoint.durable_run_id,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )

    assert recorder.mark_indeterminate_calls == 1
    assert recorder.forbidden_calls == 0
    current = await store.get_current(checkpoint.durable_run_id)
    assert current is not None
    assert current.status is DurableRunStatus.INDETERMINATE_TOOL


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_status_lookup_calls_only_the_reviewed_lookup_boundary(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind, ExecutionAttemptStatus.INDETERMINATE)

    result, boundary = await _lookup_result(
        checkpoint,
        kind,
        status=DurableAttemptExternalStatus.SUCCEEDED,
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.OBSERVED
    assert boundary.lookup_calls == 1
    assert boundary.execution_calls == 0


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_status_lookup_adapter_error_is_not_retried(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind, ExecutionAttemptStatus.INDETERMINATE)

    result, boundary = await _lookup_result(
        checkpoint,
        kind,
        status=DurableAttemptExternalStatus.SUCCEEDED,
        behavior="error",
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.ADAPTER_ERROR
    assert boundary.lookup_calls == 1
    assert boundary.execution_calls == 0


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_invalid_status_response_is_not_retried(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind, ExecutionAttemptStatus.INDETERMINATE)

    result, boundary = await _lookup_result(
        checkpoint,
        kind,
        status=DurableAttemptExternalStatus.SUCCEEDED,
        behavior="invalid",
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.INVALID_RESPONSE
    assert boundary.lookup_calls == 1
    assert boundary.execution_calls == 0


@pytest.mark.parametrize(
    ("kind", "decision"),
    tuple(product(tuple(ExecutionAttemptKind), tuple(ReconciliationDecision))),
)
async def test_each_reconciliation_disposition_appends_once_without_execution(
    kind: ExecutionAttemptKind,
    decision: ReconciliationDecision,
) -> None:
    (
        store,
        lease,
        authorizer,
        applier,
        request,
        lookup_result,
        boundary,
    ) = await _reconciliation_harness(kind, decision)
    before = await store.get_current(request.run_id)
    assert before is not None

    after = await applier.apply(
        request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
        lookup_result=lookup_result,
    )
    history = await store.list_history(request.run_id, limit=2)

    assert len(history) == 2
    assert history[-1] == after
    assert authorizer.calls == 1
    assert boundary.execution_calls == 0
    assert boundary.lookup_calls == (1 if lookup_result is not None else 0)
    _assert_reconciliation_result(before, after, decision)
    record = reconciliation_disposition_record(after)
    assert record.decision is decision
    assert record.attempt_id == ATTEMPT_ID


@pytest.mark.parametrize(
    ("kind", "decision"),
    tuple(product(tuple(ExecutionAttemptKind), tuple(ReconciliationDecision))),
)
async def test_replayed_reconciliation_request_cannot_append_twice(
    kind: ExecutionAttemptKind,
    decision: ReconciliationDecision,
) -> None:
    (
        store,
        lease,
        authorizer,
        applier,
        request,
        lookup_result,
        boundary,
    ) = await _reconciliation_harness(kind, decision)

    first = await applier.apply(
        request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
        lookup_result=lookup_result,
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME + timedelta(seconds=1),
            lookup_result=lookup_result,
        )

    current = await store.get_current(request.run_id)
    history = await store.list_history(request.run_id, limit=2)
    assert current == first
    assert len(history) == 2
    assert authorizer.calls == 1
    assert boundary.execution_calls == 0
    assert boundary.lookup_calls == (1 if lookup_result is not None else 0)


@pytest.mark.parametrize(
    ("kind", "decision"),
    tuple(
        product(
            tuple(ExecutionAttemptKind),
            (
                ReconciliationDecision.REMAIN_INDETERMINATE,
                ReconciliationDecision.CONFIRM_NOT_STARTED,
            ),
        )
    ),
)
async def test_concurrent_duplicate_reconciliation_has_one_winner(
    kind: ExecutionAttemptKind,
    decision: ReconciliationDecision,
) -> None:
    (
        store,
        lease,
        _,
        applier,
        request,
        lookup_result,
        boundary,
    ) = await _reconciliation_harness(kind, decision)

    results = await asyncio.gather(
        applier.apply(
            request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
            lookup_result=lookup_result,
        ),
        applier.apply(
            request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
            lookup_result=lookup_result,
        ),
        return_exceptions=True,
    )

    successes = [item for item in results if isinstance(item, CheckpointEnvelope)]
    conflicts = [item for item in results if isinstance(item, AgentStateConflictError)]
    assert len(successes) == 1
    assert len(conflicts) == 1
    assert len(await store.list_history(request.run_id, limit=2)) == 2
    assert boundary.execution_calls == 0
    assert boundary.lookup_calls == (1 if lookup_result is not None else 0)
