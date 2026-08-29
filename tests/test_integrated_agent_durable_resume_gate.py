from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
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
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
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
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryResumeGate,
    StartupDurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedAgentAdmissionLease,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    integrated_data_flow_context_digest,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
    IntegratedDurableRecoveryResumeGate,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 8, 28, 21, 30, tzinfo=UTC)
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=701))
_AGENT_RUN_ID = AgentRunId(UUID(int=702))
_STEP_ID = AgentStepId(UUID(int=703))
_CHECKPOINT_ID = CheckpointId(UUID(int=704))


class _AllowLiveRevalidator:
    async def revalidate_run(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True

    async def revalidate_context(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True


class _DenyContextLiveRevalidator(_AllowLiveRevalidator):
    async def revalidate_context(self, *args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _compatibility_validator() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=AgentId("assistant"),
                current=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(3),
        agent_id=AgentId("assistant"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id="integrated.plan.update",
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
        task_id=IntegratedTaskId(UUID(int=705)),
        objective="Resume only with the exact reviewed context.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_AGENT_RUN_ID,
        created_at=_NOW - timedelta(minutes=2),
        deadline=_NOW + timedelta(minutes=18),
    )


def _projection(
    task: IntegratedTaskRequest,
    profile: IntegratedExecutionProfile,
    *,
    context_digest: str | None,
) -> IntegratedOrchestrationCheckpointProjection:
    return IntegratedOrchestrationCheckpointProjection(
        task_id=task.task_id,
        task_digest=task.digest,
        execution_profile_id=profile.profile_id,
        execution_profile_generation=profile.generation,
        budget_extension_usage=IntegratedBudgetUsage(),
        data_flow_context_digest=context_digest,
        orchestration_phase=IntegratedOrchestrationPhase.EXECUTING,
        current_agent_step_id=_STEP_ID,
        last_safe_boundary=_CHECKPOINT_ID,
    )


def _checkpoint(
    projection: IntegratedOrchestrationCheckpointProjection | None,
) -> CheckpointEnvelope:
    metadata_values: dict[str, str] = {"tenant": "demo"}
    if projection is not None:
        metadata_values = dict(merge_integrated_durable_projection(metadata_values, projection))
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_CHECKPOINT_ID,
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
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=_NOW - timedelta(minutes=2),
                    deadline=_NOW + timedelta(hours=1),
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata=metadata_values,
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


async def _live_state() -> tuple[
    IntegratedAgentAdmission,
    IntegratedAgentExecutionGuard,
    IntegratedAgentAdmissionLease,
    IntegratedTaskRequest,
    IntegratedExecutionProfile,
]:
    profile = _profile()
    admission = _admission(profile)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    task = _task()
    lease = await admission.admit(task, _request())
    guard.begin_run(task, lease.request)
    return admission, guard, lease, task, profile


def test_integrated_resume_gate_structurally_implements_generic_protocol() -> None:
    profile = _profile()
    gate = IntegratedDurableRecoveryResumeGate(
        _admission(profile),
        IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW),
    )
    assert isinstance(gate, DurableRecoveryResumeGate)


@pytest.mark.asyncio
async def test_generic_checkpoint_is_not_restricted_by_integrated_resume_gate() -> None:
    profile = _profile()
    gate = IntegratedDurableRecoveryResumeGate(
        _admission(profile),
        IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW),
    )

    assert await gate.revalidate_resume(_checkpoint(None), now=_NOW) is True


@pytest.mark.asyncio
async def test_integrated_resume_requires_live_binding_and_reviewed_context() -> None:
    admission, guard, lease, task, profile = await _live_state()
    provenance = guard.current_provenance(_AGENT_RUN_ID)
    assert provenance is not None
    projection = _projection(
        task,
        profile,
        context_digest=integrated_data_flow_context_digest(provenance),
    )
    checkpoint = _checkpoint(projection)
    without_live = IntegratedDurableRecoveryResumeGate(admission, guard)
    assert await without_live.revalidate_resume(checkpoint, now=_NOW) is False

    gate = IntegratedDurableRecoveryResumeGate(
        admission,
        guard,
        live_revalidator=_AllowLiveRevalidator(),
    )

    assert await gate.revalidate_resume(checkpoint, now=_NOW) is True

    without_digest = _checkpoint(replace(projection, data_flow_context_digest=None))
    assert await gate.revalidate_resume(without_digest, now=_NOW) is False

    mismatched_task = _checkpoint(
        replace(
            projection,
            task_digest=IntegratedTaskDigest("sha256:" + "9" * 64),
        )
    )
    assert await gate.revalidate_resume(mismatched_task, now=_NOW) is False

    guard.release_run(_AGENT_RUN_ID)
    assert await gate.revalidate_resume(checkpoint, now=_NOW) is False

    await lease.release()


@pytest.mark.asyncio
async def test_missing_live_admission_binding_denies_integrated_resume() -> None:
    admission, guard, lease, task, profile = await _live_state()
    provenance = guard.current_provenance(_AGENT_RUN_ID)
    assert provenance is not None
    checkpoint = _checkpoint(
        _projection(
            task,
            profile,
            context_digest=integrated_data_flow_context_digest(provenance),
        )
    )
    gate = IntegratedDurableRecoveryResumeGate(
        admission,
        guard,
        live_revalidator=_AllowLiveRevalidator(),
    )
    await lease.release()

    assert await gate.revalidate_resume(checkpoint, now=_NOW) is False


@pytest.mark.asyncio
async def test_runtime_factory_wires_all_durable_extension_hooks_once() -> None:
    admission, guard, lease, _task_value, _profile_value = await _live_state()
    projector = IntegratedDurableCheckpointMetadataProjector()
    history_validator = IntegratedDurableRecoveryHistoryValidator()
    resume_gate = IntegratedDurableRecoveryResumeGate(admission, guard)
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        metadata_projector=projector,
        history_validator=history_validator,
        resume_gate=resume_gate,
    )
    coordinator = cast(
        StartupDurableRecoveryCoordinator,
        stack.recovery_coordinator,
    )

    assert coordinator._metadata_projector is projector
    assert coordinator._history_validator is history_validator
    assert coordinator._resume_gate is resume_gate

    await stack.close()
    guard.release_run(_AGENT_RUN_ID)
    await lease.release()
