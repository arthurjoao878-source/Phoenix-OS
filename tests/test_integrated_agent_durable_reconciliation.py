from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_authorization import DurableReconciliationAuthorizer
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
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
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_reconciliation import (
    StoreBackedDurableReconciliationDispositionApplier,
    reconciliation_disposition_record,
)
from phoenix_os.agent.durable_status_lookup import (
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
    DurableAttemptStatusLookupResult,
    DurableAttemptStatusObservation,
    durable_attempt_status_query,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
    IntegratedWaitingReason,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 28, 20, 0, tzinfo=UTC)
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=501))
_AGENT_RUN_ID = AgentRunId(UUID(int=502))
_STEP_ID = AgentStepId(UUID(int=503))
_ATTEMPT_ID = ExecutionAttemptId(UUID(int=504))
_SAFE_CHECKPOINT_ID = CheckpointId(UUID(int=505))
_INDETERMINATE_CHECKPOINT_ID = CheckpointId(UUID(int=506))
_RESULT_CHECKPOINT_ID = CheckpointId(UUID(int=507))
_LOOKUP_ID = UUID(int=508)


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=_NOW - timedelta(minutes=1),
        deadline=_NOW + timedelta(hours=1),
    )


def _projection(
    *,
    phase: IntegratedOrchestrationPhase,
    last_safe_boundary: CheckpointId,
    attempt_id: ExecutionAttemptId | None = None,
    waiting_reason: IntegratedWaitingReason | None = None,
) -> IntegratedOrchestrationCheckpointProjection:
    return IntegratedOrchestrationCheckpointProjection(
        task_id=IntegratedTaskId(UUID(int=1)),
        task_digest=IntegratedTaskDigest("sha256:" + "1" * 64),
        execution_profile_id=IntegratedExecutionProfileId("default"),
        execution_profile_generation=IntegratedExecutionProfileGeneration(1),
        budget_extension_usage=IntegratedBudgetUsage(integrated_steps=1),
        orchestration_phase=phase,
        current_agent_step_id=_STEP_ID,
        current_attempt_id=attempt_id,
        last_safe_boundary=last_safe_boundary,
        waiting_reason=waiting_reason,
    )


def _safe_checkpoint(*, integrated: bool) -> CheckpointEnvelope:
    metadata_values: dict[str, str] = {"tenant": "demo"}
    if integrated:
        metadata_values = dict(
            merge_integrated_durable_projection(
                metadata_values,
                _projection(
                    phase=IntegratedOrchestrationPhase.EXECUTING,
                    last_safe_boundary=_SAFE_CHECKPOINT_ID,
                ),
            )
        )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_SAFE_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata=metadata_values,
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


def _indeterminate_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=_ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=_AGENT_RUN_ID,
        step_id=_STEP_ID,
        prepared_at=_NOW,
        started_at=_NOW + timedelta(seconds=1),
        completed_at=_NOW + timedelta(seconds=2),
        external_request_digest=_digest("e"),
        indeterminate_reason=IndeterminateReason.PROCESS_LOSS,
    )


def _indeterminate_checkpoint(
    previous: CheckpointEnvelope,
    *,
    integrated: bool,
) -> CheckpointEnvelope:
    attempt = _indeterminate_attempt()
    metadata_values = dict(previous.metadata.metadata)
    if integrated:
        metadata_values = dict(
            merge_integrated_durable_projection(
                {"tenant": "demo"},
                _projection(
                    phase=IntegratedOrchestrationPhase.WAITING,
                    last_safe_boundary=_SAFE_CHECKPOINT_ID,
                    attempt_id=_ATTEMPT_ID,
                    waiting_reason=IntegratedWaitingReason.RECONCILIATION,
                ),
            )
        )
    return seal_checkpoint_envelope(
        replace(
            previous,
            checkpoint_id=_INDETERMINATE_CHECKPOINT_ID,
            sequence=previous.sequence.next(),
            previous_digest=previous.digest,
            run_version=previous.run_version.next(),
            status=DurableRunStatus.INDETERMINATE_MODEL,
            metadata=replace(
                previous.metadata,
                next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
                active_attempt=attempt,
                metadata=metadata_values,
            ),
            created_at=_NOW + timedelta(seconds=2),
            digest=_digest("0"),
        )
    )


class _AllowReconciliation:
    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del request, checkpoint, lease, context


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        attributes={"durable_actor_id": "operator-1"},
    )


async def _indeterminate_store(
    *,
    integrated: bool,
) -> tuple[InMemoryDurableRunStore, DurableLease, CheckpointEnvelope]:
    initial = _safe_checkpoint(integrated=integrated)
    store = InMemoryDurableRunStore()
    await store.create(initial)
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="reconcile-worker",
        now=_NOW + timedelta(seconds=1),
    )
    current = _indeterminate_checkpoint(initial, integrated=integrated)
    current = await store.append(
        current,
        expected_version=initial.run_version,
        lease=lease,
        now=_NOW + timedelta(seconds=2),
    )
    return store, lease, current


def _request(
    current: CheckpointEnvelope,
    lease: DurableLease,
    decision: ReconciliationDecision,
    *,
    evidence: ReconciliationEvidence | None = None,
) -> ReconciliationRequest:
    return ReconciliationRequest(
        run_id=current.durable_run_id,
        attempt_id=_ATTEMPT_ID,
        actor_id="operator-1",
        expected_version=current.run_version,
        generation=lease.generation,
        decision=decision,
        evidence=evidence,
        requested_at=_NOW + timedelta(seconds=4),
    )


def _not_started_lookup(current: CheckpointEnvelope) -> DurableAttemptStatusLookupResult:
    query = replace(
        durable_attempt_status_query(
            current,
            requested_at=_NOW + timedelta(seconds=3),
        ),
        lookup_id=_LOOKUP_ID,
    )
    evidence = ReconciliationEvidence(
        evidence_type="adapter-receipt",
        evidence_digest=_digest("9"),
        observed_at=_NOW + timedelta(seconds=3),
    )
    observation = DurableAttemptStatusObservation(
        lookup_id=query.lookup_id,
        durable_run_id=query.durable_run_id,
        attempt_id=query.attempt_id,
        external_request_digest=query.external_request_digest,
        adapter_id="reviewed.status",
        status=DurableAttemptExternalStatus.NOT_STARTED,
        observed_at=_NOW + timedelta(seconds=3),
        evidence=evidence,
    )
    return DurableAttemptStatusLookupResult(
        query=query,
        outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
        adapter_id="reviewed.status",
        observation=observation,
    )


def _applier(
    store: InMemoryDurableRunStore,
) -> StoreBackedDurableReconciliationDispositionApplier:
    authorizer = _AllowReconciliation()
    assert isinstance(authorizer, DurableReconciliationAuthorizer)
    return StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=authorizer,
        checkpoint_id_factory=lambda: _RESULT_CHECKPOINT_ID,
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
    )


@pytest.mark.asyncio
async def test_reconciliation_projector_leaves_generic_rfc0028_run_generic() -> None:
    store, lease, current = await _indeterminate_store(integrated=False)
    result = await _applier(store).apply(
        _request(current, lease, ReconciliationDecision.REMAIN_INDETERMINATE),
        lease=lease,
        context=_context(),
        now=_NOW + timedelta(seconds=5),
    )

    assert decode_integrated_durable_projection(result) is None
    assert result.metadata.metadata["tenant"] == "demo"
    assert reconciliation_disposition_record(result).decision is (
        ReconciliationDecision.REMAIN_INDETERMINATE
    )


@pytest.mark.asyncio
async def test_confirm_not_started_stays_waiting_until_explicit_resume() -> None:
    store, lease, current = await _indeterminate_store(integrated=True)
    lookup = _not_started_lookup(current)
    result = await _applier(store).apply(
        _request(
            current,
            lease,
            ReconciliationDecision.CONFIRM_NOT_STARTED,
            evidence=lookup.evidence,
        ),
        lease=lease,
        context=_context(),
        now=_NOW + timedelta(seconds=5),
        lookup_result=lookup,
    )

    assert result.status is DurableRunStatus.PAUSED_OPERATOR
    assert result.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
    assert result.metadata.active_attempt is not None
    assert result.metadata.active_attempt.status is ExecutionAttemptStatus.CANCELLED
    projection = decode_integrated_durable_projection(result)
    assert projection is not None
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
    assert projection.waiting_reason is IntegratedWaitingReason.RECONCILIATION
    assert projection.current_attempt_id == _ATTEMPT_ID
    assert projection.last_safe_boundary == _SAFE_CHECKPOINT_ID

    history = await store.list_history(_DURABLE_RUN_ID, limit=result.sequence.value)
    IntegratedDurableRecoveryHistoryValidator().validate_history(result, history)


@pytest.mark.asyncio
async def test_terminal_reconciliation_clears_attempt_without_moving_safe_boundary() -> None:
    store, lease, current = await _indeterminate_store(integrated=True)
    result = await _applier(store).apply(
        _request(current, lease, ReconciliationDecision.CANCEL_RUN),
        lease=lease,
        context=_context(),
        now=_NOW + timedelta(seconds=5),
    )

    assert result.status is DurableRunStatus.CANCELLED
    assert result.metadata.next_operation is CheckpointNextOperation.NONE
    assert result.metadata.active_attempt is None
    projection = decode_integrated_durable_projection(result)
    assert projection is not None
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.TERMINAL
    assert projection.waiting_reason is None
    assert projection.current_attempt_id is None
    assert projection.last_safe_boundary == _SAFE_CHECKPOINT_ID
