from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.agent import (
    DEFAULT_DURABLE_RECONCILIATION_ATTEMPTS,
    MAX_RECONCILIATION_ATTEMPTS,
    AgentAuthorizationRejectedError,
    AgentId,
    AgentLimitExceededError,
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
    DurableLease,
    DurableLeaseId,
    DurableReconciliationAuthorizer,
    DurableReconciliationDispositionApplier,
    DurableReconciliationDispositionRecord,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    FencingGeneration,
    IndeterminateReason,
    InMemoryDurableLeaseManager,
    InMemoryDurableRunStore,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
    StoreBackedDurableReconciliationDispositionApplier,
    ToolCallId,
    ToolEffect,
    durable_attempt_status_query,
    reconciliation_disposition_record,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 1, 3, tzinfo=UTC)
LOOKUP_TIME = NOW + timedelta(seconds=2)
OBSERVED_TIME = NOW + timedelta(seconds=4)
REQUEST_TIME = NOW + timedelta(seconds=5)
APPLY_TIME = NOW + timedelta(seconds=6)

DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
OTHER_AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000003"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
OTHER_STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000004"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004"))
OTHER_ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000005"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000005"))
OTHER_TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000006"))
CHECKPOINT_ID = CheckpointId(UUID("60000000-0000-0000-0000-000000000006"))
LEASE_ID = DurableLeaseId(UUID("70000000-0000-0000-0000-000000000007"))
LOOKUP_ID = UUID("80000000-0000-0000-0000-000000000008")
RECONCILIATION_ID = UUID("90000000-0000-0000-0000-000000000009")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget(*, deadline: datetime | None = None) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=deadline or NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN,
    *,
    attempt_id: ExecutionAttemptId = ATTEMPT_ID,
) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=attempt_id,
        kind=kind,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=3),
        tool_call_id=(TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None),
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=NOW - timedelta(seconds=2),
        completed_at=NOW,
        external_request_digest=_digest("e"),
        indeterminate_reason=IndeterminateReason.PROCESS_LOSS,
    )


def _checkpoint(
    kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN,
    *,
    run_id: DurableAgentRunId = DURABLE_RUN_ID,
    status: DurableRunStatus | None = None,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.OPERATOR_REVIEW,
    attempt: ExecutionAttempt | None = None,
    version: int = 1,
    created_at: datetime = NOW,
    budget_deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
    metadata: dict[str, str] | None = None,
) -> CheckpointEnvelope:
    selected_status = status
    if selected_status is None:
        selected_status = (
            DurableRunStatus.INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        )
    selected_attempt = _attempt(kind) if attempt is None else attempt
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=run_id,
            checkpoint_id=CHECKPOINT_ID,
            sequence=CheckpointSequence(version),
            previous_digest=_digest("f") if version > 1 else None,
            run_version=DurableRunVersion(version),
            status=selected_status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=next_operation,
                budget=_budget(deadline=budget_deadline),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=retention_deadline or NOW + timedelta(days=7),
                active_attempt=selected_attempt,
                metadata=metadata or {"tenant": "demo"},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _context(
    *,
    actor_id: str = "operator-1",
    authenticated: bool = True,
) -> SecurityContext:
    return SecurityContext(
        principal=actor_id,
        principal_type=(PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS),
        authenticated=authenticated,
        attributes={"durable_actor_id": actor_id},
    )


def _lease(
    *,
    run_id: DurableAgentRunId = DURABLE_RUN_ID,
    generation: int = 1,
    acquired_at: datetime = NOW + timedelta(seconds=1),
    expires_at: datetime = NOW + timedelta(minutes=1),
) -> DurableLease:
    return DurableLease(
        run_id=run_id,
        lease_id=LEASE_ID,
        owner_id="reconcile-worker",
        generation=FencingGeneration(generation),
        acquired_at=acquired_at,
        expires_at=expires_at,
    )


def _lookup_result(
    checkpoint: CheckpointEnvelope,
    status: DurableAttemptExternalStatus,
    *,
    observed_at: datetime = OBSERVED_TIME,
    adapter_id: str = "reviewed.status",
) -> DurableAttemptStatusLookupResult:
    query = replace(
        durable_attempt_status_query(
            checkpoint,
            requested_at=LOOKUP_TIME,
        ),
        lookup_id=LOOKUP_ID,
    )
    evidence = (
        None
        if status is DurableAttemptExternalStatus.UNKNOWN
        else ReconciliationEvidence(
            evidence_type="adapter-receipt",
            evidence_digest=_digest("9"),
            observed_at=observed_at,
        )
    )
    observation = DurableAttemptStatusObservation(
        lookup_id=query.lookup_id,
        durable_run_id=query.durable_run_id,
        attempt_id=query.attempt_id,
        external_request_digest=query.external_request_digest,
        adapter_id=adapter_id,
        status=status,
        observed_at=observed_at,
        evidence=evidence,
    )
    return DurableAttemptStatusLookupResult(
        query=query,
        outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
        adapter_id=adapter_id,
        observation=observation,
    )


def _empty_lookup_result(
    checkpoint: CheckpointEnvelope,
    outcome: DurableAttemptStatusLookupOutcome,
) -> DurableAttemptStatusLookupResult:
    query = replace(
        durable_attempt_status_query(
            checkpoint,
            requested_at=LOOKUP_TIME,
        ),
        lookup_id=LOOKUP_ID,
    )
    adapter_id = (
        None if outcome is DurableAttemptStatusLookupOutcome.UNSUPPORTED else "reviewed.status"
    )
    return DurableAttemptStatusLookupResult(
        query=query,
        outcome=outcome,
        adapter_id=adapter_id,
    )


def _request(
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
    decision: ReconciliationDecision,
    *,
    lookup_result: DurableAttemptStatusLookupResult | None = None,
    evidence: ReconciliationEvidence | None = None,
    use_lookup_evidence: bool = True,
    requested_at: datetime = REQUEST_TIME,
    run_id: DurableAgentRunId | None = None,
    attempt_id: ExecutionAttemptId | None = None,
    version: DurableRunVersion | None = None,
    generation: FencingGeneration | None = None,
) -> ReconciliationRequest:
    selected_evidence = evidence
    if use_lookup_evidence and lookup_result is not None:
        selected_evidence = lookup_result.evidence
    attempt = checkpoint.metadata.active_attempt
    if attempt is None:
        raise AssertionError("request helper requires an active attempt")
    return ReconciliationRequest(
        run_id=checkpoint.durable_run_id if run_id is None else run_id,
        attempt_id=attempt.attempt_id if attempt_id is None else attempt_id,
        actor_id="operator-1",
        expected_version=checkpoint.run_version if version is None else version,
        generation=lease.generation if generation is None else generation,
        decision=decision,
        evidence=selected_evidence,
        requested_at=requested_at,
    )


def _invalid_checkpoint_id_factory() -> CheckpointId:
    return object()  # type: ignore[return-value]


def _invalid_reconciliation_id_factory() -> UUID:
    return object()  # type: ignore[return-value]


class _RecordingAuthorizer:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[
            tuple[
                ReconciliationRequest,
                CheckpointEnvelope,
                DurableLease,
                SecurityContext,
            ]
        ] = []

    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        self.calls.append((request, checkpoint, lease, context))
        if self.error is not None:
            raise self.error


async def _store_and_lease(
    checkpoint: CheckpointEnvelope,
) -> tuple[InMemoryDurableRunStore, InMemoryDurableLeaseManager, DurableLease]:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    manager = InMemoryDurableLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(
        limits=limits,
        lease_manager=manager,
    )
    await store.create(checkpoint)
    lease = await manager.acquire(
        checkpoint.durable_run_id,
        owner_id="reconcile-worker",
        now=NOW + timedelta(seconds=1),
    )
    return store, manager, lease


def _applier(
    store: InMemoryDurableRunStore,
    authorizer: _RecordingAuthorizer,
    *,
    max_reconciliation_attempts: int = DEFAULT_DURABLE_RECONCILIATION_ATTEMPTS,
) -> StoreBackedDurableReconciliationDispositionApplier:
    return StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=authorizer,
        max_reconciliation_attempts=max_reconciliation_attempts,
    )


def _forged_lookup(
    original: DurableAttemptStatusLookupResult,
    query: DurableAttemptStatusQuery,
) -> DurableAttemptStatusLookupResult:
    observation = original.observation
    if observation is None:
        return DurableAttemptStatusLookupResult(
            query=query,
            outcome=original.outcome,
            adapter_id=original.adapter_id,
        )
    rebound = DurableAttemptStatusObservation(
        lookup_id=query.lookup_id,
        durable_run_id=query.durable_run_id,
        attempt_id=query.attempt_id,
        external_request_digest=query.external_request_digest,
        adapter_id=observation.adapter_id,
        status=observation.status,
        observed_at=observation.observed_at,
        evidence=observation.evidence,
    )
    return DurableAttemptStatusLookupResult(
        query=query,
        outcome=original.outcome,
        adapter_id=original.adapter_id,
        observation=rebound,
    )


def test_default_reconciliation_limit_is_bounded() -> None:
    assert DEFAULT_DURABLE_RECONCILIATION_ATTEMPTS == 4
    assert DEFAULT_DURABLE_RECONCILIATION_ATTEMPTS <= MAX_RECONCILIATION_ATTEMPTS


async def test_public_applier_implements_protocol() -> None:
    checkpoint = _checkpoint()
    store, _, _ = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    assert isinstance(applier, DurableReconciliationDispositionApplier)
    assert isinstance(_RecordingAuthorizer(), DurableReconciliationAuthorizer)


@pytest.mark.parametrize(
    "dependency",
    (
        "store",
        "authorizer",
        "checkpoint_id_factory",
        "reconciliation_id_factory",
    ),
)
def test_constructor_rejects_invalid_dependencies(
    dependency: str,
) -> None:
    store = InMemoryDurableRunStore()
    authorizer = _RecordingAuthorizer()
    with pytest.raises(TypeError):
        if dependency == "store":
            StoreBackedDurableReconciliationDispositionApplier(
                store=object(),  # type: ignore[arg-type]
                authorizer=authorizer,
            )
        elif dependency == "authorizer":
            StoreBackedDurableReconciliationDispositionApplier(
                store=store,
                authorizer=object(),  # type: ignore[arg-type]
            )
        elif dependency == "checkpoint_id_factory":
            StoreBackedDurableReconciliationDispositionApplier(
                store=store,
                authorizer=authorizer,
                checkpoint_id_factory=None,  # type: ignore[arg-type]
            )
        else:
            StoreBackedDurableReconciliationDispositionApplier(
                store=store,
                authorizer=authorizer,
                reconciliation_id_factory=None,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize(
    "maximum",
    (False, 0, MAX_RECONCILIATION_ATTEMPTS + 1),
)
def test_constructor_rejects_invalid_reconciliation_limits(
    maximum: object,
) -> None:
    store = InMemoryDurableRunStore()
    authorizer = _RecordingAuthorizer()
    expected = TypeError if maximum is False else ValueError
    with pytest.raises(expected):
        StoreBackedDurableReconciliationDispositionApplier(
            store=store,
            authorizer=authorizer,
            max_reconciliation_attempts=maximum,  # type: ignore[arg-type]
        )


async def test_apply_rejects_wrong_public_argument_types() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    with pytest.raises(TypeError):
        await applier.apply(
            cast(Any, object()),
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )
    with pytest.raises(TypeError):
        await applier.apply(
            reconciliation_request,
            lease=object(),  # type: ignore[arg-type]
            context=_context(),
            now=APPLY_TIME,
        )
    with pytest.raises(TypeError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=object(),  # type: ignore[arg-type]
            now=APPLY_TIME,
        )
    with pytest.raises(TypeError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
            lookup_result=object(),  # type: ignore[arg-type]
        )


async def test_apply_rejects_naive_now() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME.replace(tzinfo=None),
        )


async def test_apply_rejects_clock_before_request() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=REQUEST_TIME - timedelta(microseconds=1),
        )


async def test_apply_rejects_foreign_or_expired_lease() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    foreign = _lease(run_id=OTHER_RUN_ID)
    expired = _lease(expires_at=APPLY_TIME)

    for invalid_lease in (foreign, expired):
        with pytest.raises(AgentStateConflictError):
            await applier.apply(
                reconciliation_request,
                lease=invalid_lease,
                context=_context(),
                now=APPLY_TIME,
            )


async def test_apply_rejects_generation_mismatch() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
        generation=FencingGeneration(lease.generation.value + 1),
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


async def test_apply_rejects_missing_run() -> None:
    checkpoint = _checkpoint()
    store = InMemoryDurableRunStore()
    lease = _lease()
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


async def test_apply_rejects_stale_expected_version() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
        version=DurableRunVersion(checkpoint.run_version.value + 1),
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "source",
    (
        _checkpoint(status=DurableRunStatus.PAUSED_OPERATOR),
        _checkpoint(next_operation=CheckpointNextOperation.MODEL_TURN),
    ),
)
async def test_apply_rejects_non_reconcilable_source(
    source: CheckpointEnvelope,
) -> None:
    store, _, lease = await _store_and_lease(source)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        source,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


async def test_apply_rejects_wrong_attempt_identity() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
        attempt_id=OTHER_ATTEMPT_ID,
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


async def test_apply_rejects_retention_expiry_between_request_and_mutation() -> None:
    checkpoint = _checkpoint(retention_deadline=REQUEST_TIME + timedelta(milliseconds=500))
    store, _, lease = await _store_and_lease(checkpoint)
    applier = _applier(store, _RecordingAuthorizer())
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


async def test_authorization_denial_preserves_current_checkpoint() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    authorizer = _RecordingAuthorizer(AgentAuthorizationRejectedError())
    applier = _applier(store, authorizer)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )

    assert await store.get_current(checkpoint.durable_run_id) == checkpoint
    assert len(authorizer.calls) == 1


async def test_authorizer_receives_exact_current_state_before_append() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    authorizer = _RecordingAuthorizer()
    applier = _applier(store, authorizer)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    context = _context()

    result = await applier.apply(
        reconciliation_request,
        lease=lease,
        context=context,
        now=APPLY_TIME,
    )

    assert authorizer.calls == [(reconciliation_request, checkpoint, lease, context)]
    assert result.run_version == checkpoint.run_version.next()


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_confirm_succeeded_records_safe_operator_pause(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind)
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.SUCCEEDED,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=lookup,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        lookup_result=lookup,
        now=APPLY_TIME,
    )

    attempt = result.metadata.active_attempt
    assert result.status is DurableRunStatus.PAUSED_OPERATOR
    assert result.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert attempt is not None
    assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
    assert attempt.completed_at == OBSERVED_TIME
    assert attempt.indeterminate_reason is None
    assert attempt.error_code is None


@pytest.mark.parametrize(
    ("external_status", "attempt_status", "error_code"),
    (
        (
            DurableAttemptExternalStatus.FAILED,
            ExecutionAttemptStatus.FAILED,
            "reconciled-failed",
        ),
        (
            DurableAttemptExternalStatus.CANCELLED,
            ExecutionAttemptStatus.CANCELLED,
            None,
        ),
        (
            DurableAttemptExternalStatus.TIMED_OUT,
            ExecutionAttemptStatus.TIMED_OUT,
            "reconciled-timed-out",
        ),
    ),
)
async def test_confirm_failed_preserves_external_terminal_category(
    external_status: DurableAttemptExternalStatus,
    attempt_status: ExecutionAttemptStatus,
    error_code: str | None,
) -> None:
    checkpoint = _checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(checkpoint, external_status)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_FAILED,
        lookup_result=lookup,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        lookup_result=lookup,
        now=APPLY_TIME,
    )

    attempt = result.metadata.active_attempt
    assert result.status is DurableRunStatus.PAUSED_OPERATOR
    assert result.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert attempt is not None
    assert attempt.status is attempt_status
    assert attempt.error_code == error_code
    assert attempt.indeterminate_reason is None


@pytest.mark.parametrize(
    ("kind", "next_operation"),
    (
        (ExecutionAttemptKind.MODEL_TURN, CheckpointNextOperation.MODEL_TURN),
        (
            ExecutionAttemptKind.TOOL_INVOCATION,
            CheckpointNextOperation.TOOL_INVOCATION,
        ),
    ),
)
async def test_confirm_not_started_only_prepares_later_fresh_attempt(
    kind: ExecutionAttemptKind,
    next_operation: CheckpointNextOperation,
) -> None:
    checkpoint = _checkpoint(kind)
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.NOT_STARTED,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
        lookup_result=lookup,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        lookup_result=lookup,
        now=APPLY_TIME,
    )

    attempt = result.metadata.active_attempt
    assert result.status is DurableRunStatus.PAUSED_OPERATOR
    assert result.metadata.next_operation is next_operation
    assert attempt is not None
    assert attempt.status is ExecutionAttemptStatus.CANCELLED
    assert attempt.indeterminate_reason is None


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_remain_indeterminate_checkpoints_without_external_work(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(kind)
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )

    assert result.status is checkpoint.status
    assert result.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    assert result.metadata.active_attempt == checkpoint.metadata.active_attempt


@pytest.mark.parametrize(
    ("decision", "status"),
    (
        (ReconciliationDecision.CANCEL_RUN, DurableRunStatus.CANCELLED),
        (ReconciliationDecision.FAIL_RUN, DurableRunStatus.FAILED),
    ),
)
async def test_terminal_operator_dispositions_clear_active_attempt(
    decision: ReconciliationDecision,
    status: DurableRunStatus,
) -> None:
    checkpoint = _checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(checkpoint, lease, decision)

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )

    assert result.status is status
    assert result.metadata.next_operation is CheckpointNextOperation.NONE
    assert result.metadata.active_attempt is None


async def test_reconciliation_remains_available_after_execution_budget_expiry() -> None:
    checkpoint = _checkpoint(budget_deadline=NOW + timedelta(seconds=1))
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )

    assert result.status is checkpoint.status


@pytest.mark.parametrize(
    "decision",
    (
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        ReconciliationDecision.CONFIRM_FAILED,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
    ),
)
async def test_confirmation_dispositions_require_reviewed_lookup(
    decision: ReconciliationDecision,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    evidence = ReconciliationEvidence(
        evidence_type="manual-receipt",
        evidence_digest=_digest("8"),
        observed_at=OBSERVED_TIME,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        decision,
        evidence=evidence,
        use_lookup_evidence=False,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "status",
    (
        DurableAttemptExternalStatus.NOT_STARTED,
        DurableAttemptExternalStatus.FAILED,
        DurableAttemptExternalStatus.IN_PROGRESS,
    ),
)
async def test_confirm_succeeded_rejects_other_external_statuses(
    status: DurableAttemptExternalStatus,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(checkpoint, status)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=lookup,
    )
    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "status",
    (
        DurableAttemptExternalStatus.SUCCEEDED,
        DurableAttemptExternalStatus.NOT_STARTED,
        DurableAttemptExternalStatus.IN_PROGRESS,
    ),
)
async def test_confirm_failed_rejects_non_failed_external_statuses(
    status: DurableAttemptExternalStatus,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(checkpoint, status)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_FAILED,
        lookup_result=lookup,
    )
    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "status",
    (
        DurableAttemptExternalStatus.SUCCEEDED,
        DurableAttemptExternalStatus.FAILED,
        DurableAttemptExternalStatus.IN_PROGRESS,
    ),
)
async def test_confirm_not_started_rejects_other_external_statuses(
    status: DurableAttemptExternalStatus,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(checkpoint, status)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
        lookup_result=lookup,
    )
    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "outcome",
    (
        DurableAttemptStatusLookupOutcome.UNSUPPORTED,
        DurableAttemptStatusLookupOutcome.TIMED_OUT,
        DurableAttemptStatusLookupOutcome.ADAPTER_ERROR,
        DurableAttemptStatusLookupOutcome.INVALID_RESPONSE,
    ),
)
async def test_confirmations_reject_non_observed_lookup_outcomes(
    outcome: DurableAttemptStatusLookupOutcome,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _empty_lookup_result(checkpoint, outcome)
    evidence = ReconciliationEvidence(
        evidence_type="manual-receipt",
        evidence_digest=_digest("8"),
        observed_at=OBSERVED_TIME,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=lookup,
        evidence=evidence,
        use_lookup_evidence=False,
    )
    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "field",
    (
        "durable_run_id",
        "checkpoint_id",
        "checkpoint_digest",
        "run_version",
        "attempt_id",
        "agent_run_id",
        "step_id",
        "external_request_digest",
        "requested_at",
    ),
)
async def test_lookup_query_must_bind_exact_current_checkpoint(
    field: str,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    original = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.SUCCEEDED,
    )
    replacements: dict[str, object] = {
        "durable_run_id": OTHER_RUN_ID,
        "checkpoint_id": CheckpointId(UUID("60000000-0000-0000-0000-000000000007")),
        "checkpoint_digest": _digest("7"),
        "run_version": DurableRunVersion(2),
        "attempt_id": OTHER_ATTEMPT_ID,
        "agent_run_id": OTHER_AGENT_RUN_ID,
        "step_id": OTHER_STEP_ID,
        "external_request_digest": _digest("8"),
        "requested_at": NOW - timedelta(seconds=1),
    }
    forged_query = replace(
        original.query,
        **cast(Any, {field: replacements[field]}),
    )
    forged = _forged_lookup(original, forged_query)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=forged,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=forged,
            now=APPLY_TIME,
        )


@pytest.mark.parametrize(
    "field",
    ("tool_call_id", "tool_effect"),
)
async def test_tool_lookup_query_must_bind_exact_tool_identity(
    field: str,
) -> None:
    checkpoint = _checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    store, _, lease = await _store_and_lease(checkpoint)
    original = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.SUCCEEDED,
    )
    replacement: object = OTHER_TOOL_CALL_ID if field == "tool_call_id" else ToolEffect.READ_ONLY
    forged_query = replace(
        original.query,
        **cast(Any, {field: replacement}),
    )
    forged = _forged_lookup(original, forged_query)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=forged,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=forged,
            now=APPLY_TIME,
        )


async def test_request_evidence_must_equal_lookup_evidence() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.SUCCEEDED,
    )
    other_evidence = ReconciliationEvidence(
        evidence_type="adapter-receipt",
        evidence_digest=_digest("8"),
        observed_at=OBSERVED_TIME,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=lookup,
        evidence=other_evidence,
        use_lookup_evidence=False,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME,
        )


async def test_evidence_cannot_follow_operator_request() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.SUCCEEDED,
        observed_at=REQUEST_TIME + timedelta(seconds=1),
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        lookup_result=lookup,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME + timedelta(seconds=1),
        )


async def test_non_confirmation_lookup_evidence_is_still_exactly_bound() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.IN_PROGRESS,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
        lookup_result=lookup,
        use_lookup_evidence=False,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            lookup_result=lookup,
            now=APPLY_TIME,
        )


async def test_applied_checkpoint_has_one_step_digest_and_version_progression() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )

    assert result.sequence == checkpoint.sequence.next()
    assert result.run_version == checkpoint.run_version.next()
    assert result.previous_digest == checkpoint.digest
    assert result.created_at == APPLY_TIME
    history = await store.list_history(checkpoint.durable_run_id, limit=2)
    assert history == (checkpoint, result)


async def test_disposition_record_round_trips_exact_audit_metadata() -> None:
    checkpoint = _checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    store, _, lease = await _store_and_lease(checkpoint)
    lookup = _lookup_result(
        checkpoint,
        DurableAttemptExternalStatus.NOT_STARTED,
    )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
        lookup_result=lookup,
    )
    applier = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=_RecordingAuthorizer(),
        checkpoint_id_factory=lambda: CheckpointId(UUID("60000000-0000-0000-0000-000000000008")),
        reconciliation_id_factory=lambda: RECONCILIATION_ID,
    )

    result = await applier.apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        lookup_result=lookup,
        now=APPLY_TIME,
    )
    record = reconciliation_disposition_record(result)

    assert record.reconciliation_id == RECONCILIATION_ID
    assert record.run_id == checkpoint.durable_run_id
    assert record.source_checkpoint_id == checkpoint.checkpoint_id
    assert record.source_checkpoint_digest == checkpoint.digest
    assert record.source_version == checkpoint.run_version
    assert record.source_status is checkpoint.status
    assert record.attempt_id == ATTEMPT_ID
    assert record.actor_id == "operator-1"
    assert record.generation == lease.generation
    assert record.decision is ReconciliationDecision.CONFIRM_NOT_STARTED
    assert record.lookup_id == LOOKUP_ID
    assert record.lookup_outcome is DurableAttemptStatusLookupOutcome.OBSERVED
    assert record.lookup_adapter_id == "reviewed.status"
    assert record.external_status is DurableAttemptExternalStatus.NOT_STARTED
    assert record.external_request_digest == _digest("e")
    assert record.evidence_type == "adapter-receipt"
    assert record.evidence_digest == _digest("9")
    assert record.evidence_observed_at == OBSERVED_TIME
    assert record.requested_at == REQUEST_TIME
    assert record.applied_at == APPLY_TIME
    assert record.result_status is DurableRunStatus.PAUSED_OPERATOR
    assert record.result_attempt_status is ExecutionAttemptStatus.CANCELLED
    assert DurableReconciliationDispositionRecord.from_metadata(result.metadata.metadata) == record


async def test_record_parser_rejects_unknown_reconciliation_field() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )
    metadata = dict(result.metadata.metadata)
    metadata["reconciliation.unknown"] = "value"
    with pytest.raises(ValueError, match="fields"):
        DurableReconciliationDispositionRecord.from_metadata(metadata)


async def test_checkpoint_record_parser_rejects_rebinding() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )
    rebound = replace(
        result,
        created_at=result.created_at + timedelta(microseconds=1),
    )
    with pytest.raises(ValueError, match="bind"):
        reconciliation_disposition_record(rebound)


async def test_unknown_source_reconciliation_metadata_fails_closed() -> None:
    checkpoint = _checkpoint(
        metadata={
            "tenant": "demo",
            "reconciliation.unknown": "value",
        }
    )
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )


async def test_reconciliation_metadata_growth_fails_closed() -> None:
    checkpoint = _checkpoint(metadata={f"safe.{index}": "value" for index in range(42)})
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    with pytest.raises(AgentStateConflictError):
        await _applier(store, _RecordingAuthorizer()).apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )
    assert await store.get_current(checkpoint.durable_run_id) == checkpoint


async def test_reconciliation_attempt_limit_counts_distinct_records() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    authorizer = _RecordingAuthorizer()
    applier = _applier(
        store,
        authorizer,
        max_reconciliation_attempts=1,
    )
    first_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    first = await applier.apply(
        first_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )
    second_request = _request(
        first,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
        requested_at=APPLY_TIME + timedelta(seconds=1),
    )

    with pytest.raises(AgentLimitExceededError):
        await applier.apply(
            second_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME + timedelta(seconds=2),
        )

    assert await store.get_current(checkpoint.durable_run_id) == first


async def test_repeated_stale_request_does_not_append_twice() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    authorizer = _RecordingAuthorizer()
    applier = _applier(store, authorizer)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    first = await applier.apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )

    with pytest.raises(AgentStateConflictError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME + timedelta(seconds=1),
        )

    history = await store.list_history(checkpoint.durable_run_id, limit=2)
    assert history == (checkpoint, first)


@pytest.mark.parametrize(
    "factory_name",
    ("checkpoint_id_factory", "reconciliation_id_factory"),
)
async def test_factory_return_types_fail_before_store_mutation(
    factory_name: str,
) -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    if factory_name == "checkpoint_id_factory":
        applier = StoreBackedDurableReconciliationDispositionApplier(
            store=store,
            authorizer=_RecordingAuthorizer(),
            checkpoint_id_factory=_invalid_checkpoint_id_factory,
        )
    else:
        applier = StoreBackedDurableReconciliationDispositionApplier(
            store=store,
            authorizer=_RecordingAuthorizer(),
            reconciliation_id_factory=_invalid_reconciliation_id_factory,
        )
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    with pytest.raises(TypeError):
        await applier.apply(
            reconciliation_request,
            lease=lease,
            context=_context(),
            now=APPLY_TIME,
        )
    assert await store.get_current(checkpoint.durable_run_id) == checkpoint


async def test_existing_generic_metadata_is_preserved() -> None:
    checkpoint = _checkpoint(metadata={"tenant": "demo", "safe.category": "durable"})
    store, _, lease = await _store_and_lease(checkpoint)
    reconciliation_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )

    result = await _applier(store, _RecordingAuthorizer()).apply(
        reconciliation_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )

    assert result.metadata.metadata["tenant"] == "demo"
    assert result.metadata.metadata["safe.category"] == "durable"


async def test_second_reconciliation_replaces_only_current_record_metadata() -> None:
    checkpoint = _checkpoint()
    store, _, lease = await _store_and_lease(checkpoint)
    applier = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=_RecordingAuthorizer(),
        reconciliation_id_factory=iter(
            (
                UUID("90000000-0000-0000-0000-000000000010"),
                UUID("90000000-0000-0000-0000-000000000011"),
            )
        ).__next__,
    )
    first_request = _request(
        checkpoint,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
    )
    first = await applier.apply(
        first_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME,
    )
    first_record = reconciliation_disposition_record(first)
    second_request = _request(
        first,
        lease,
        ReconciliationDecision.REMAIN_INDETERMINATE,
        requested_at=APPLY_TIME + timedelta(seconds=1),
    )
    second = await applier.apply(
        second_request,
        lease=lease,
        context=_context(),
        now=APPLY_TIME + timedelta(seconds=2),
    )
    second_record = reconciliation_disposition_record(second)

    assert first_record.reconciliation_id != second_record.reconciliation_id
    assert second.metadata.metadata["tenant"] == "demo"
    history = await store.list_history(checkpoint.durable_run_id, limit=3)
    assert history == (checkpoint, first, second)
