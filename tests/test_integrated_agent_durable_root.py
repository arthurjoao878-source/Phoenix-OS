from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentStepId,
)
from phoenix_os.agent.durable_codec import (
    checkpoint_envelope_digest,
    seal_checkpoint_envelope,
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
    DurableRunStatus,
    DurableRunVersion,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedAgentAdmissionLease,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_projection import (
    decode_integrated_durable_projection,
    integrated_data_flow_context_digest,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)
from phoenix_os.integrated_agent.durable_root import (
    create_integrated_durable_root,
    project_integrated_durable_root,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentValidationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 8, 28, 21, 0, tzinfo=UTC)
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=901))
_AGENT_RUN_ID = AgentRunId(UUID(int=902))
_STEP_ID = AgentStepId(UUID(int=903))
_CHECKPOINT_ID = CheckpointId(UUID(int=904))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(3),
        agent_id=AgentId("assistant"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="user-model",
                    source_kind=IntegratedDataSourceKind.USER_TASK,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                ),
            )
        ),
    )


def _admission(profile: IntegratedExecutionProfile) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        AgentServiceConfiguration(
            agent_id=AgentId("assistant"),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
        ),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=905)),
        objective="Persist an exact integrated durable root.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_AGENT_RUN_ID,
        created_at=_NOW - timedelta(minutes=1),
        deadline=_NOW + timedelta(minutes=19),
    )


async def _live_binding() -> tuple[
    IntegratedExecutionProfile,
    IntegratedTaskRequest,
    IntegratedAgentAdmissionLease,
    IntegratedDataProvenance,
]:
    profile = _profile()
    task = _task()
    admission = _admission(profile)
    lease = await admission.admit(task, _request())
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    guard.begin_run(task, lease.request)
    provenance = guard.current_provenance(lease.request.run_id)
    assert provenance is not None
    guard.release_run(lease.request.run_id)
    return profile, task, lease, provenance


def _root(request: AgentRunRequest) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=request.created_at,
                    deadline=request.deadline,
                ),
                compatibility=CompatibilityDigests(
                    configuration=_digest("a"),
                    tool_registry=_digest("b"),
                    model_provider=_digest("c"),
                    checkpoint_codec=_digest("d"),
                ),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata={"tenant": "demo"},
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


@pytest.mark.asyncio
async def test_projected_root_is_sequence_one_safe_and_exactly_bound() -> None:
    profile, task, lease, provenance = await _live_binding()
    root = _root(lease.request)

    projected = project_integrated_durable_root(
        root,
        lease.binding,
        provenance=provenance,
    )
    projection = decode_integrated_durable_projection(projected)

    assert projection is not None
    assert projected.sequence == CheckpointSequence(1)
    assert projected.previous_digest is None
    assert projected.digest == checkpoint_envelope_digest(projected)
    assert projected.digest != root.digest
    assert projected.metadata.metadata["tenant"] == "demo"
    assert projection.task_id == task.task_id
    assert projection.task_digest == task.digest
    assert projection.execution_profile_id == profile.profile_id
    assert projection.execution_profile_generation == profile.generation
    assert projection.budget_extension_usage.integrated_steps == 0
    assert projection.data_flow_context_digest == integrated_data_flow_context_digest(provenance)
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.PLANNING
    assert projection.current_agent_step_id == _STEP_ID
    assert projection.current_attempt_id is None
    assert projection.last_safe_boundary == _CHECKPOINT_ID

    IntegratedDurableRecoveryHistoryValidator().validate_history(
        projected,
        (projected,),
    )
    await lease.release()


@pytest.mark.asyncio
async def test_create_integrated_durable_root_publishes_projection_at_sequence_one() -> None:
    _profile_value, _task_value, lease, provenance = await _live_binding()
    store = InMemoryDurableRunStore()

    created = await create_integrated_durable_root(
        store,
        _root(lease.request),
        lease.binding,
        provenance=provenance,
    )

    assert await store.get_current(_DURABLE_RUN_ID) == created
    history = await store.list_history(_DURABLE_RUN_ID, limit=1)
    assert history == (created,)
    assert decode_integrated_durable_projection(history[0]) is not None
    IntegratedDurableRecoveryHistoryValidator().validate_history(created, history)
    await lease.release()


@pytest.mark.asyncio
async def test_root_projection_is_idempotent_but_rejects_reserved_substitution() -> None:
    _profile_value, _task_value, lease, provenance = await _live_binding()
    projected = project_integrated_durable_root(
        _root(lease.request),
        lease.binding,
        provenance=provenance,
    )

    assert (
        project_integrated_durable_root(
            projected,
            lease.binding,
            provenance=provenance,
        )
        == projected
    )

    substituted_values = dict(projected.metadata.metadata)
    substituted_values["rfc0036.task_digest"] = "sha256:" + "9" * 64
    substituted = seal_checkpoint_envelope(
        replace(
            projected,
            metadata=replace(
                projected.metadata,
                metadata=substituted_values,
            ),
        )
    )
    with pytest.raises(IntegratedAgentValidationError, match="different RFC-0036 projection"):
        project_integrated_durable_root(
            substituted,
            lease.binding,
            provenance=provenance,
        )
    await lease.release()


@pytest.mark.asyncio
async def test_root_projection_rejects_nonroot_or_mismatched_reviewed_context() -> None:
    _profile_value, _task_value, lease, provenance = await _live_binding()
    root = _root(lease.request)
    later = seal_checkpoint_envelope(
        replace(
            root,
            sequence=CheckpointSequence(2),
            previous_digest=root.digest,
            run_version=DurableRunVersion(2),
        )
    )
    with pytest.raises(IntegratedAgentValidationError, match="sequence one"):
        project_integrated_durable_root(
            later,
            lease.binding,
            provenance=provenance,
        )

    wrong_provenance = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MEMORY,
                source_binding="agent-memory:research/scope:agent",
            ),
        )
    )
    with pytest.raises(IntegratedAgentValidationError, match="does not match"):
        project_integrated_durable_root(
            root,
            lease.binding,
            provenance=wrong_provenance,
        )
    await lease.release()
