from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
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
    DurableLeaseId,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunTombstone,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    FencingGeneration,
    IndeterminateReason,
    ProtectedPayloadReference,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
    ResumeReason,
    ResumeRequest,
    RetentionPolicy,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 7, 29, 12, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000004"))
CHECKPOINT_ID = CheckpointId(UUID("50000000-0000-0000-0000-000000000005"))
ATTEMPT_ID = ExecutionAttemptId(UUID("60000000-0000-0000-0000-000000000006"))
LEASE_ID = DurableLeaseId(UUID("70000000-0000-0000-0000-000000000007"))


def _digest(character: str = "a") -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=2,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=128,
        tool_result_bytes=64,
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
    *,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.METADATA_ONLY,
    payload_reference: ProtectedPayloadReference | None = None,
    active_attempt: ExecutionAttempt | None = None,
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=AgentId("assistant"),
        actor_id="worker-1",
        next_operation=next_operation,
        budget=_budget(),
        compatibility=_compatibility(),
        payload_profile=payload_profile,
        retention_deadline=NOW + timedelta(days=7),
        payload_reference=payload_reference,
        active_attempt=active_attempt,
        metadata={"tenant": "demo"},
    )


def _envelope(
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    sequence: CheckpointSequence | None = None,
    previous_digest: CheckpointDigest | None = None,
    step_id: AgentStepId | None = STEP_ID,
    metadata: CheckpointMetadata | None = None,
) -> CheckpointEnvelope:
    resolved_sequence = sequence or CheckpointSequence(1)
    return CheckpointEnvelope(
        schema_version=CheckpointSchemaVersion(),
        durable_run_id=DURABLE_RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=resolved_sequence,
        previous_digest=previous_digest,
        run_version=DurableRunVersion(resolved_sequence.value),
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=step_id,
        metadata=metadata or _metadata(),
        created_at=NOW + timedelta(seconds=resolved_sequence.value),
        digest=_digest("e"),
    )


def test_identifiers_versions_sequences_and_digests_are_strict() -> None:
    assert str(DURABLE_RUN_ID) == "10000000-0000-0000-0000-000000000001"
    assert DurableRunVersion(3).next() == DurableRunVersion(4)
    assert CheckpointSequence(3).next() == CheckpointSequence(4)
    assert FencingGeneration(3).next() == FencingGeneration(4)

    with pytest.raises(ValueError, match="greater than zero"):
        DurableRunVersion(0)
    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        CheckpointDigest("A" * 64)


def test_durable_limits_are_finite_and_lease_renewal_precedes_expiry() -> None:
    limits = DurableRunLimits(
        lease_duration=timedelta(seconds=30),
        lease_renewal_interval=timedelta(seconds=10),
    )

    assert limits.max_checkpoints == 256

    with pytest.raises(ValueError, match="shorter than lease duration"):
        DurableRunLimits(
            lease_duration=timedelta(seconds=30),
            lease_renewal_interval=timedelta(seconds=30),
        )


def test_checkpoint_metadata_is_content_free_by_default_and_immutable() -> None:
    metadata = _metadata()

    assert metadata.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
    assert metadata.payload_reference is None
    assert metadata.metadata == {"tenant": "demo"}

    with pytest.raises(TypeError):
        metadata.metadata["tenant"] = "other"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        metadata.actor_id = "other"  # type: ignore[misc]


def test_metadata_only_profile_rejects_protected_payload_reference() -> None:
    reference = ProtectedPayloadReference(
        reference="payload:run-1/checkpoint-1",
        key_version="key-v1",
        plaintext_bytes=128,
        ciphertext_bytes=160,
        ciphertext_digest=_digest("f"),
        created_at=NOW,
    )

    with pytest.raises(ValueError, match="metadata-only"):
        _metadata(payload_reference=reference)

    protected = _metadata(
        payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
        payload_reference=reference,
    )
    assert protected.payload_reference == reference


def test_execution_attempts_enforce_kind_and_status_specific_fields() -> None:
    model_attempt = ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW,
        started_at=NOW + timedelta(seconds=1),
        external_request_digest=_digest("1"),
    )
    assert not model_attempt.status.terminal

    with pytest.raises(ValueError, match="cannot contain tool"):
        replace(model_attempt, tool_call_id=CALL_ID)

    tool_attempt = ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
        prepared_at=NOW,
        started_at=NOW + timedelta(seconds=1),
        completed_at=NOW + timedelta(seconds=2),
        indeterminate_reason=IndeterminateReason.PROCESS_LOSS,
    )
    assert tool_attempt.status.terminal

    with pytest.raises(ValueError, match="indeterminate_reason"):
        replace(tool_attempt, indeterminate_reason=None)


def test_checkpoint_sequence_requires_a_digest_chain() -> None:
    first = _envelope()
    second = _envelope(
        sequence=CheckpointSequence(2),
        previous_digest=first.digest,
    )

    assert first.previous_digest is None
    assert second.previous_digest == first.digest

    with pytest.raises(ValueError, match="first checkpoint"):
        _envelope(previous_digest=_digest("9"))
    with pytest.raises(ValueError, match="later checkpoints"):
        _envelope(sequence=CheckpointSequence(2))


def test_terminal_and_approval_pause_checkpoints_have_bounded_next_operations() -> None:
    terminal = _envelope(
        status=DurableRunStatus.COMPLETED,
        metadata=_metadata(next_operation=CheckpointNextOperation.NONE),
    )
    assert terminal.status.terminal

    with pytest.raises(ValueError, match="terminal checkpoints"):
        _envelope(status=DurableRunStatus.COMPLETED)

    paused = _envelope(
        status=DurableRunStatus.PAUSED_APPROVAL,
        metadata=_metadata(next_operation=CheckpointNextOperation.WAIT_APPROVAL),
    )
    assert paused.status is DurableRunStatus.PAUSED_APPROVAL

    with pytest.raises(ValueError, match="wait for approval"):
        _envelope(status=DurableRunStatus.PAUSED_APPROVAL)


def test_indeterminate_checkpoint_requires_matching_attempt_and_run_identity() -> None:
    attempt = ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW,
        started_at=NOW + timedelta(seconds=1),
        completed_at=NOW + timedelta(seconds=2),
        indeterminate_reason=IndeterminateReason.PROVIDER_STATUS_UNKNOWN,
    )
    checkpoint = _envelope(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        metadata=_metadata(
            next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
            active_attempt=attempt,
        ),
    )

    assert checkpoint.status.indeterminate

    mismatched = replace(
        attempt,
        agent_run_id=AgentRunId(UUID("90000000-0000-0000-0000-000000000009")),
    )
    with pytest.raises(ValueError, match="does not belong"):
        _envelope(
            status=DurableRunStatus.INDETERMINATE_MODEL,
            metadata=_metadata(
                next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
                active_attempt=mismatched,
            ),
        )


def test_durable_lease_is_time_bounded_and_generation_fenced() -> None:
    lease = DurableLease(
        run_id=DURABLE_RUN_ID,
        lease_id=LEASE_ID,
        owner_id="worker-1",
        generation=FencingGeneration(7),
        acquired_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )

    assert lease.active_at(NOW)
    assert lease.active_at(NOW + timedelta(seconds=29))
    assert not lease.active_at(lease.expires_at)


def test_resume_request_carries_expected_version_but_no_authority() -> None:
    request = ResumeRequest(
        run_id=DURABLE_RUN_ID,
        actor_id="operator-1",
        reason=ResumeReason.OPERATOR_REQUEST,
        expected_version=DurableRunVersion(4),
        requested_at=NOW,
    )

    assert request.expected_version == DurableRunVersion(4)
    assert request.reason is ResumeReason.OPERATOR_REQUEST


def test_reconciliation_requires_evidence_for_positive_external_claims() -> None:
    evidence = ReconciliationEvidence(
        evidence_type="provider-status",
        evidence_digest=_digest("8"),
        observed_at=NOW,
        metadata={"provider": "deterministic"},
    )
    request = ReconciliationRequest(
        run_id=DURABLE_RUN_ID,
        attempt_id=ATTEMPT_ID,
        actor_id="operator-1",
        expected_version=DurableRunVersion(4),
        generation=FencingGeneration(7),
        decision=ReconciliationDecision.CONFIRM_SUCCEEDED,
        evidence=evidence,
        requested_at=NOW,
    )

    assert request.evidence == evidence

    with pytest.raises(ValueError, match="requires evidence"):
        replace(request, evidence=None)


def test_retention_policy_and_tombstones_are_fail_closed() -> None:
    policy = RetentionPolicy(
        metadata_retention=timedelta(days=30),
        payload_retention=timedelta(days=7),
        tombstone_retention=timedelta(days=90),
    )
    assert policy.payload_retention < policy.metadata_retention

    with pytest.raises(ValueError, match="payload retention"):
        RetentionPolicy(
            metadata_retention=timedelta(days=7),
            payload_retention=timedelta(days=30),
            tombstone_retention=timedelta(days=90),
        )

    tombstone = DurableRunTombstone(
        run_id=DURABLE_RUN_ID,
        terminal_status=DurableRunStatus.FAILED,
        terminal_version=DurableRunVersion(5),
        final_checkpoint_digest=_digest("7"),
        deletion_generation=FencingGeneration(8),
        terminal_at=NOW,
        retain_until=NOW + timedelta(days=90),
    )
    assert tombstone.terminal_status.terminal

    with pytest.raises(ValueError, match="terminal durable status"):
        replace(tombstone, terminal_status=DurableRunStatus.ACTIVE)
