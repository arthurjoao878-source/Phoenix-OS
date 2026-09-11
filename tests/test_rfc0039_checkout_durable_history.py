from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_durable_evidence import (
    CheckoutReadDurableEvidenceHistoryValidator,
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.errors import AgentCodecError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 9, 7, 4, tzinfo=UTC)
RUN_ID = AgentRunId(UUID("10000000-0000-0000-0000-000000000039"))
DURABLE_RUN_ID = DurableAgentRunId(UUID(str(RUN_ID)))
STEP_1 = AgentStepId(UUID("20000000-0000-0000-0000-000000000039"))
STEP_2 = AgentStepId(UUID("30000000-0000-0000-0000-000000000039"))
CALL_1 = ToolCallId(UUID("40000000-0000-0000-0000-000000000039"))
CALL_2 = ToolCallId(UUID("50000000-0000-0000-0000-000000000039"))
WORKSPACE_ID = "60000000-0000-0000-0000-000000000039"


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _checkpoint_digest(char: str) -> CheckpointDigest:
    return CheckpointDigest(char * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_checkpoint_digest("1"),
        tool_registry=_checkpoint_digest("2"),
        model_provider=_checkpoint_digest("3"),
        checkpoint_codec=_checkpoint_digest("4"),
    )


def _attempt(
    *,
    step_id: AgentStepId,
    call_id: ToolCallId,
    attempt_uuid: str,
) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(UUID(attempt_uuid)),
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.SUCCEEDED,
        agent_run_id=RUN_ID,
        step_id=step_id,
        prepared_at=NOW,
        started_at=NOW + timedelta(seconds=1),
        completed_at=NOW + timedelta(seconds=2),
        tool_call_id=call_id,
        tool_effect=ToolEffect.READ_ONLY,
        external_request_digest=_checkpoint_digest("e"),
    )


def _evidence(
    *,
    count: int,
    total_bytes: int,
    last_byte_length: int,
    suffix: bytes,
) -> dict[str, str]:
    return {
        "rfc0039.checkout.read.count": str(count),
        "rfc0039.checkout.read.bytes": str(total_bytes),
        "rfc0039.checkout.read.last.workspace_id": WORKSPACE_ID,
        "rfc0039.checkout.read.last.registration_generation": "7",
        "rfc0039.checkout.read.last.root_identity": _digest(b"root"),
        "rfc0039.checkout.read.last.file_identity": _digest(b"file-" + suffix),
        "rfc0039.checkout.read.last.content_digest": _digest(b"content-" + suffix),
        "rfc0039.checkout.read.last.byte_length": str(last_byte_length),
    }


def _checkpoint(
    *,
    sequence: int,
    previous: CheckpointEnvelope | None,
    step_id: AgentStepId | None,
    next_operation: CheckpointNextOperation,
    active_attempt: ExecutionAttempt | None,
    evidence: dict[str, str] | None,
) -> CheckpointEnvelope:
    metadata = {"fixture": "base"}
    if evidence is not None:
        metadata.update(evidence)
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID(int=sequence)),
            sequence=CheckpointSequence(sequence),
            previous_digest=None if previous is None else previous.digest,
            run_version=DurableRunVersion(sequence),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=RUN_ID,
            step_id=step_id,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="rfc0039-checkout-durable-history-test",
                next_operation=next_operation,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=active_attempt,
                metadata=metadata,
            ),
            created_at=NOW + timedelta(seconds=sequence + 3),
            digest=_checkpoint_digest("0"),
        )
    )


def _valid_history() -> tuple[CheckpointEnvelope, ...]:
    root = _checkpoint(
        sequence=1,
        previous=None,
        step_id=STEP_1,
        next_operation=CheckpointNextOperation.TOOL_INVOCATION,
        active_attempt=None,
        evidence=None,
    )
    first = _checkpoint(
        sequence=2,
        previous=root,
        step_id=STEP_1,
        next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        active_attempt=_attempt(
            step_id=STEP_1,
            call_id=CALL_1,
            attempt_uuid="70000000-0000-0000-0000-000000000039",
        ),
        evidence=_evidence(count=1, total_bytes=6, last_byte_length=6, suffix=b"one"),
    )
    stable = _checkpoint(
        sequence=3,
        previous=first,
        step_id=STEP_2,
        next_operation=CheckpointNextOperation.TOOL_INVOCATION,
        active_attempt=None,
        evidence=_evidence(count=1, total_bytes=6, last_byte_length=6, suffix=b"one"),
    )
    second = _checkpoint(
        sequence=4,
        previous=stable,
        step_id=STEP_2,
        next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        active_attempt=_attempt(
            step_id=STEP_2,
            call_id=CALL_2,
            attempt_uuid="80000000-0000-0000-0000-000000000039",
        ),
        evidence=_evidence(count=2, total_bytes=11, last_byte_length=5, suffix=b"two"),
    )
    return root, first, stable, second


def test_history_validator_accepts_valid_monotonic_checkout_read_evidence() -> None:
    history = _valid_history()
    CheckoutReadDurableEvidenceHistoryValidator().validate_history(history[-1], history)


def test_history_validator_accepts_history_without_checkout_read_evidence() -> None:
    root = _checkpoint(
        sequence=1,
        previous=None,
        step_id=STEP_1,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        evidence=None,
    )
    CheckoutReadDurableEvidenceHistoryValidator().validate_history(root, (root,))


def test_history_validator_rejects_evidence_appearing_outside_successful_tool_result() -> None:
    root, first, *_ = _valid_history()
    invalid = _checkpoint(
        sequence=2,
        previous=root,
        step_id=STEP_1,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        evidence=dict(first.metadata.metadata),
    )
    with pytest.raises(AgentCodecError):
        CheckoutReadDurableEvidenceHistoryValidator().validate_history(
            invalid,
            (root, invalid),
        )


@pytest.mark.parametrize(
    ("count", "total_bytes"),
    (
        (3, 11),
        (2, 12),
    ),
)
def test_history_validator_rejects_counter_or_byte_jump(
    count: int,
    total_bytes: int,
) -> None:
    root, first, stable, _second = _valid_history()
    invalid = _checkpoint(
        sequence=4,
        previous=stable,
        step_id=STEP_2,
        next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        active_attempt=_attempt(
            step_id=STEP_2,
            call_id=CALL_2,
            attempt_uuid="90000000-0000-0000-0000-000000000039",
        ),
        evidence=_evidence(
            count=count,
            total_bytes=total_bytes,
            last_byte_length=5,
            suffix=b"two",
        ),
    )
    with pytest.raises(AgentCodecError):
        CheckoutReadDurableEvidenceHistoryValidator().validate_history(
            invalid,
            (root, first, stable, invalid),
        )


def test_history_validator_rejects_disappearance_or_identity_mutation_without_increment() -> None:
    root, first, _stable, _second = _valid_history()
    disappeared = _checkpoint(
        sequence=3,
        previous=first,
        step_id=STEP_2,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        evidence=None,
    )
    with pytest.raises(AgentCodecError):
        CheckoutReadDurableEvidenceHistoryValidator().validate_history(
            disappeared,
            (root, first, disappeared),
        )

    changed = _checkpoint(
        sequence=3,
        previous=first,
        step_id=STEP_2,
        next_operation=CheckpointNextOperation.MODEL_TURN,
        active_attempt=None,
        evidence=_evidence(
            count=1,
            total_bytes=6,
            last_byte_length=6,
            suffix=b"changed",
        ),
    )
    with pytest.raises(AgentCodecError):
        CheckoutReadDurableEvidenceHistoryValidator().validate_history(
            changed,
            (root, first, changed),
        )


def test_history_validator_rejects_partial_or_non_authoritative_history() -> None:
    root, first, *_ = _valid_history()
    partial = dict(first.metadata.metadata)
    partial.pop("rfc0039.checkout.read.last.content_digest")
    invalid = _checkpoint(
        sequence=2,
        previous=root,
        step_id=STEP_1,
        next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        active_attempt=_attempt(
            step_id=STEP_1,
            call_id=CALL_1,
            attempt_uuid="a0000000-0000-0000-0000-000000000039",
        ),
        evidence=partial,
    )
    with pytest.raises(AgentCodecError):
        CheckoutReadDurableEvidenceHistoryValidator().validate_history(
            invalid,
            (root, invalid),
        )
    with pytest.raises(AgentCodecError):
        CheckoutReadDurableEvidenceHistoryValidator().validate_history(
            first,
            (root,),
        )
