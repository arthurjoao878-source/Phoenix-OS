from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
    IntegratedWaitingReason,
    PlanDigest,
    PlanRevision,
)
from phoenix_os.integrated_agent.durable_projection import (
    RFC0036_DURABLE_METADATA_PREFIX,
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    encode_integrated_durable_projection,
    integrated_data_flow_context_digest,
    merge_integrated_durable_projection,
    require_integrated_durable_projection,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError

_NOW = datetime(2026, 8, 28, 18, 0, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=101))
_STEP_ID = AgentStepId(UUID(int=102))
_CHECKPOINT_ID = CheckpointId(UUID(int=103))
_ATTEMPT_ID = ExecutionAttemptId(UUID(int=104))


def _projection(
    *,
    phase: IntegratedOrchestrationPhase = IntegratedOrchestrationPhase.EXECUTING,
    waiting_reason: IntegratedWaitingReason | None = None,
    step_id: AgentStepId | None = _STEP_ID,
    attempt_id: ExecutionAttemptId | None = None,
    last_safe_boundary: CheckpointId = _CHECKPOINT_ID,
) -> IntegratedOrchestrationCheckpointProjection:
    return IntegratedOrchestrationCheckpointProjection(
        task_id=IntegratedTaskId(UUID(int=1)),
        task_digest=IntegratedTaskDigest("sha256:" + "1" * 64),
        execution_profile_id=IntegratedExecutionProfileId("default"),
        execution_profile_generation=IntegratedExecutionProfileGeneration(7),
        plan_revision=PlanRevision(3),
        plan_digest=PlanDigest("sha256:" + "2" * 64),
        budget_extension_usage=IntegratedBudgetUsage(
            plan_revisions=3,
            integrated_steps=9,
            browser_operations=1,
            network_operations=2,
            memory_operations=3,
            workspace_operations=4,
            workspace_mutation_bytes=512,
            host_operations=1,
        ),
        data_flow_context_digest="sha256:" + "3" * 64,
        orchestration_phase=phase,
        current_agent_step_id=step_id,
        current_attempt_id=attempt_id,
        last_safe_boundary=last_safe_boundary,
        waiting_reason=waiting_reason,
    )


def _attempt(
    *,
    attempt_id: ExecutionAttemptId = _ATTEMPT_ID,
    step_id: AgentStepId = _STEP_ID,
) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=attempt_id,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=_RUN_ID,
        step_id=step_id,
        prepared_at=_NOW,
        started_at=_NOW,
    )


def _checkpoint(
    metadata: dict[str, str] | None = None,
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    step_id: AgentStepId | None = _STEP_ID,
    active_attempt: ExecutionAttempt | None = None,
    checkpoint_id: CheckpointId = _CHECKPOINT_ID,
) -> CheckpointEnvelope:
    budget = AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=_NOW,
        deadline=_NOW + timedelta(minutes=30),
    )
    digest = CheckpointDigest("a" * 64)
    return CheckpointEnvelope(
        schema_version=CheckpointSchemaVersion(),
        durable_run_id=DurableAgentRunId(UUID(int=105)),
        checkpoint_id=checkpoint_id,
        sequence=CheckpointSequence(),
        previous_digest=None,
        run_version=DurableRunVersion(),
        status=status,
        agent_run_id=_RUN_ID,
        step_id=step_id,
        metadata=CheckpointMetadata(
            agent_id=AgentId("agent"),
            actor_id="actor",
            next_operation=next_operation,
            budget=budget,
            compatibility=CompatibilityDigests(
                configuration=digest,
                tool_registry=digest,
                model_provider=digest,
                checkpoint_codec=digest,
            ),
            payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            retention_deadline=_NOW + timedelta(hours=1),
            active_attempt=active_attempt,
            metadata={} if metadata is None else metadata,
        ),
        created_at=_NOW + timedelta(minutes=1),
        digest=CheckpointDigest("b" * 64),
    )


def _encoded(
    projection: IntegratedOrchestrationCheckpointProjection | None = None,
) -> dict[str, str]:
    return dict(encode_integrated_durable_projection(projection or _projection()))


def test_projection_round_trips_through_existing_checkpoint_metadata_only_contract() -> None:
    projection = _projection()
    encoded = _encoded(projection)

    assert all(key.startswith(RFC0036_DURABLE_METADATA_PREFIX) for key in encoded)
    assert all(isinstance(value, str) for value in encoded.values())
    assert not any("provenance." in key for key in encoded)
    assert len(encoded) < 64

    checkpoint = _checkpoint(encoded)
    assert checkpoint.metadata.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
    assert decode_integrated_durable_projection(checkpoint) == projection
    assert require_integrated_durable_projection(checkpoint) == projection


def test_absent_projection_is_valid_for_generic_rfc0028_but_require_fails_closed() -> None:
    checkpoint = _checkpoint({})

    assert decode_integrated_durable_projection(checkpoint) is None
    with pytest.raises(IntegratedAgentCodecError, match="missing"):
        require_integrated_durable_projection(checkpoint)


def test_reserved_metadata_cannot_be_supplied_or_overwritten_by_caller_metadata() -> None:
    with pytest.raises(IntegratedAgentCodecError, match="server-owned"):
        merge_integrated_durable_projection(
            {"rfc0036.task_id": str(IntegratedTaskId(UUID(int=99)))},
            _projection(),
        )

    merged = merge_integrated_durable_projection({"other.key": "safe"}, _projection())
    assert merged["other.key"] == "safe"
    assert merged["rfc0036.task_id"] == str(IntegratedTaskId(UUID(int=1)))


def test_unknown_and_partial_reserved_projection_fail_closed() -> None:
    unknown = _encoded()
    unknown["rfc0036.future_field"] = "1"
    with pytest.raises(IntegratedAgentCodecError, match="unknown"):
        decode_integrated_durable_projection(_checkpoint(unknown))

    partial = _encoded()
    partial.pop("rfc0036.budget.host_operations")
    with pytest.raises(IntegratedAgentCodecError, match="incomplete"):
        decode_integrated_durable_projection(_checkpoint(partial))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("rfc0036.schema_version", "2"),
        ("rfc0036.execution_profile_generation", "01"),
        ("rfc0036.plan_revision", "+3"),
        ("rfc0036.budget.integrated_steps", "-1"),
        ("rfc0036.budget.browser_operations", "1.0"),
    ],
)
def test_noncanonical_or_invalid_numeric_metadata_fails_closed(key: str, value: str) -> None:
    encoded = _encoded()
    encoded[key] = value

    with pytest.raises(IntegratedAgentCodecError):
        decode_integrated_durable_projection(_checkpoint(encoded))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("rfc0036.task_id", "not-a-uuid"),
        ("rfc0036.current_agent_step_id", "00000000-0000-0000-0000-0000000000AA"),
        ("rfc0036.last_safe_boundary", "{00000000-0000-0000-0000-000000000067}"),
    ],
)
def test_invalid_or_noncanonical_uuid_metadata_fails_closed(key: str, value: str) -> None:
    encoded = _encoded()
    encoded[key] = value

    with pytest.raises(IntegratedAgentCodecError):
        decode_integrated_durable_projection(_checkpoint(encoded))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("rfc0036.task_digest", "4" * 64),
        ("rfc0036.plan_digest", "sha256:" + "A" * 64),
        ("rfc0036.data_flow_context_digest", "sha256:" + "g" * 64),
    ],
)
def test_invalid_digest_metadata_fails_closed(key: str, value: str) -> None:
    encoded = _encoded()
    encoded[key] = value

    with pytest.raises(IntegratedAgentCodecError):
        decode_integrated_durable_projection(_checkpoint(encoded))


def test_plan_revision_and_digest_are_atomic_projection_pair() -> None:
    encoded = _encoded()
    encoded.pop("rfc0036.plan_digest")
    with pytest.raises(IntegratedAgentCodecError, match="plan"):
        decode_integrated_durable_projection(_checkpoint(encoded))

    encoded = _encoded()
    encoded.pop("rfc0036.plan_revision")
    with pytest.raises(IntegratedAgentCodecError, match="plan"):
        decode_integrated_durable_projection(_checkpoint(encoded))


def test_projection_step_and_attempt_must_match_authoritative_checkpoint() -> None:
    wrong_step = _encoded(replace(_projection(), current_agent_step_id=AgentStepId(UUID(int=999))))
    with pytest.raises(IntegratedAgentCodecError, match="step"):
        decode_integrated_durable_projection(_checkpoint(wrong_step))

    attempt = _attempt()
    wrong_attempt = _encoded(
        replace(
            _projection(attempt_id=ExecutionAttemptId(UUID(int=998))),
            current_agent_step_id=_STEP_ID,
        )
    )
    with pytest.raises(IntegratedAgentCodecError, match="attempt"):
        decode_integrated_durable_projection(_checkpoint(wrong_attempt, active_attempt=attempt))


def test_projection_requires_attempt_presence_to_match_checkpoint_presence() -> None:
    attempt = _attempt()
    without_attempt = _encoded(_projection())
    with pytest.raises(IntegratedAgentCodecError, match="attempt"):
        decode_integrated_durable_projection(_checkpoint(without_attempt, active_attempt=attempt))

    with_attempt = _encoded(_projection(attempt_id=_ATTEMPT_ID))
    with pytest.raises(IntegratedAgentCodecError, match="attempt"):
        decode_integrated_durable_projection(_checkpoint(with_attempt))


def test_waiting_and_terminal_phase_must_match_authoritative_next_operation() -> None:
    approval = _encoded(
        _projection(
            phase=IntegratedOrchestrationPhase.WAITING,
            waiting_reason=IntegratedWaitingReason.APPROVAL,
        )
    )
    with pytest.raises(IntegratedAgentCodecError, match="approval wait"):
        decode_integrated_durable_projection(_checkpoint(approval))

    active = _encoded(_projection())
    with pytest.raises(IntegratedAgentCodecError, match="WAITING"):
        decode_integrated_durable_projection(
            _checkpoint(
                active,
                next_operation=CheckpointNextOperation.WAIT_APPROVAL,
            )
        )

    terminal = _encoded(
        _projection(
            phase=IntegratedOrchestrationPhase.TERMINAL,
            step_id=None,
        )
    )
    with pytest.raises(IntegratedAgentCodecError, match="terminal"):
        decode_integrated_durable_projection(
            _checkpoint(
                terminal,
                step_id=None,
                next_operation=CheckpointNextOperation.NONE,
            )
        )


def test_valid_waiting_and_terminal_projection_combinations_decode() -> None:
    approval_projection = _projection(
        phase=IntegratedOrchestrationPhase.WAITING,
        waiting_reason=IntegratedWaitingReason.APPROVAL,
    )
    approval_checkpoint = _checkpoint(
        _encoded(approval_projection),
        status=DurableRunStatus.PAUSED_APPROVAL,
        next_operation=CheckpointNextOperation.WAIT_APPROVAL,
    )
    assert decode_integrated_durable_projection(approval_checkpoint) == approval_projection

    operator_projection = _projection(
        phase=IntegratedOrchestrationPhase.WAITING,
        waiting_reason=IntegratedWaitingReason.CONTEXT_RESUPPLY,
    )
    operator_checkpoint = _checkpoint(
        _encoded(operator_projection),
        status=DurableRunStatus.PAUSED_OPERATOR,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
    )
    assert decode_integrated_durable_projection(operator_checkpoint) == operator_projection

    terminal_projection = _projection(
        phase=IntegratedOrchestrationPhase.TERMINAL,
        step_id=None,
    )
    terminal_checkpoint = _checkpoint(
        _encoded(terminal_projection),
        status=DurableRunStatus.COMPLETED,
        next_operation=CheckpointNextOperation.NONE,
        step_id=None,
    )
    assert decode_integrated_durable_projection(terminal_checkpoint) == terminal_projection


def test_budget_values_are_revalidated_through_integrated_budget_usage() -> None:
    encoded = _encoded()
    encoded["rfc0036.budget.host_operations"] = "1000001"

    with pytest.raises(IntegratedAgentCodecError):
        decode_integrated_durable_projection(_checkpoint(encoded))


def test_data_flow_context_digest_is_canonical_deterministic_and_content_free() -> None:
    first = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.WORKSPACE,
        source_binding="workspace:team/report",
        freshness_bindings=("version:7",),
    )
    second = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.NETWORK,
        source_binding="network:response/42",
        freshness_bindings=("profile:3",),
    )
    left = IntegratedDataProvenance((first, second))
    right = IntegratedDataProvenance((second, first))

    left_digest = integrated_data_flow_context_digest(left)
    right_digest = integrated_data_flow_context_digest(right)

    assert left_digest == right_digest
    assert left_digest.startswith("sha256:")
    assert len(left_digest) == 71
    assert "workspace" not in left_digest
    assert "network" not in left_digest


def test_operator_waiting_reason_is_optional_but_approval_stays_exact() -> None:
    operator_projection = _projection(
        phase=IntegratedOrchestrationPhase.WAITING,
        waiting_reason=None,
    )
    operator_checkpoint = _checkpoint(
        _encoded(operator_projection),
        status=DurableRunStatus.PAUSED_OPERATOR,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
    )
    assert decode_integrated_durable_projection(operator_checkpoint) == operator_projection

    approval_without_reason = _checkpoint(
        _encoded(operator_projection),
        status=DurableRunStatus.PAUSED_APPROVAL,
        next_operation=CheckpointNextOperation.WAIT_APPROVAL,
    )
    with pytest.raises(IntegratedAgentCodecError):
        decode_integrated_durable_projection(approval_without_reason)
