from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentLimits, AgentRunId
from phoenix_os.agent.durable_cancellation import StoreBackedDurableCancellationCoordinator
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
    DurableCancellationRequest,
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    load_operator_configuration,
)
from phoenix_os.control_plane.task_runtime_bridge import (
    TaskExecutionAuthority,
    TaskRuntimeBridgeValidationError,
    TaskStatusSummary,
    cancel_authorized_durable_task,
    project_authorized_durable_task_status,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
)
from phoenix_os.integrated_agent.durable_projection import (
    IntegratedOrchestrationCheckpointProjection,
    decode_integrated_durable_projection,
    merge_integrated_durable_projection,
)
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRequest,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
_AGENT_ID = AgentId("task-bridge-agent")
_AGENT_RUN_ID = AgentRunId(UUID("10000000-0000-4000-8000-000000000001"))
_DURABLE_RUN_ID = integrated_durable_run_id(_AGENT_RUN_ID)
_CHECKPOINT_ID = CheckpointId(UUID("20000000-0000-4000-8000-000000000002"))
_TASK_ID = IntegratedTaskId(UUID("30000000-0000-4000-8000-000000000003"))
_PROFILE_ID = IntegratedExecutionProfileId("development")
_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(1)


class _AllowCancellation:
    def __init__(self) -> None:
        self.request: DurableCancellationRequest | None = None

    async def authorize(
        self,
        request: DurableCancellationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del checkpoint, lease, context
        self.request = request


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _execution_profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(),
        limits=AgentLimits(max_model_turns=4, max_tool_calls=2),
    )


def _checkpoint() -> CheckpointEnvelope:
    projection = IntegratedOrchestrationCheckpointProjection(
        task_id=_TASK_ID,
        task_digest=IntegratedTaskDigest("sha256:" + "1" * 64),
        execution_profile_id=_PROFILE_ID,
        execution_profile_generation=_PROFILE_GENERATION,
        budget_extension_usage=IntegratedBudgetUsage(),
        orchestration_phase=IntegratedOrchestrationPhase.PLANNING,
        last_safe_boundary=_CHECKPOINT_ID,
    )
    budget = AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=_NOW - timedelta(minutes=1),
        deadline=_NOW + timedelta(minutes=10),
    )
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
            step_id=None,
            metadata=CheckpointMetadata(
                agent_id=_AGENT_ID,
                actor_id="task-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=budget,
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(hours=1),
                metadata=merge_integrated_durable_projection({}, projection),
            ),
            created_at=_NOW - timedelta(seconds=30),
            digest=_digest("0"),
        )
    )


def _configuration(tmp_path: Path) -> OperatorConfiguration:
    root = tmp_path / "checkout"
    root.mkdir(parents=True)
    config = tmp_path / "phoenix.toml"
    config.write_text(
        f"""
schema_version = 1

[providers.ollama-local]
kind = "ollama-local"

[models.dev]
provider = "ollama-local"
provider_model_name = "qwen3:4b-instruct"

[workspaces.project]
kind = "development-checkout"
root = "{root.as_posix()}"
read_prefixes = ["src"]
patch_prefixes = []

[profiles.development]
model = "dev"
workspace = "project"
context_paths = []
allow_workspace_patch = false
""".lstrip(),
        encoding="utf-8",
    )
    return load_operator_configuration(config)


def _task_authority_context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(
            {
                "agent.run",
                "model.infer",
                "tool.invoke",
                "workspace.list",
                "workspace.read",
            }
        ),
    )


@pytest.mark.asyncio
async def test_task_execution_authority_preserves_exact_caller_owned_objects() -> None:
    policy = PolicyEngine()
    context = _task_authority_context()
    try:
        authority = TaskExecutionAuthority(policy=policy, context=context)

        assert authority.policy is policy
        assert authority.context is context
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_task_execution_authority_rejects_untrusted_or_closed_authority() -> None:
    policy = PolicyEngine()
    try:
        with pytest.raises(TaskRuntimeBridgeValidationError):
            TaskExecutionAuthority(policy=policy, context=SecurityContext())
        with pytest.raises(TaskRuntimeBridgeValidationError):
            TaskExecutionAuthority(
                policy=policy,
                context=SecurityContext(
                    principal="operator-1",
                    principal_type=PrincipalType.USER,
                    authenticated=False,
                ),
            )
    finally:
        await policy.close()

    with pytest.raises(TaskRuntimeBridgeValidationError):
        TaskExecutionAuthority(policy=policy, context=_task_authority_context())


@pytest.mark.asyncio
async def test_task_execution_authority_does_not_create_policy_grants() -> None:
    policy = PolicyEngine()
    try:
        authority = TaskExecutionAuthority(
            policy=policy,
            context=_task_authority_context(),
        )
        decision = await authority.policy.evaluate(
            PolicyRequest(
                action="agent.run",
                resource=f"agent:{_AGENT_ID}",
                context=authority.context,
            )
        )

        assert decision.effect is PolicyEffect.DENY
    finally:
        await policy.close()


def test_status_projection_uses_only_exact_persisted_or_configured_facts(
    tmp_path: Path,
) -> None:
    configuration = _configuration(tmp_path)
    operator_profile = configuration.profiles[0]

    summary = project_authorized_durable_task_status(
        configuration=configuration,
        operator_profile=operator_profile,
        execution_profile=_execution_profile(),
        checkpoint=_checkpoint(),
        now=_NOW,
    )

    assert isinstance(summary, TaskStatusSummary)
    assert summary.task_id == str(_TASK_ID)
    assert summary.run_id == str(_AGENT_RUN_ID)
    assert summary.profile_name == "development"
    assert summary.provider_id == "ollama-local"
    assert summary.model_id == "dev"
    assert summary.run_state == "active"
    assert summary.current_step_category == "model_turn"
    assert summary.model_turns_used == 0
    assert summary.model_turns_max == 4
    assert summary.tool_calls_used == 0
    assert summary.tool_calls_max == 2
    assert summary.accepted_tool_proposals is None
    assert summary.rejected_tool_proposals is None
    assert summary.deadline_state == "remaining"
    assert summary.cancellation_state == "not_recorded"
    assert summary.provider_failure_category is None
    assert summary.durable_recovery_disposition == "resume"
    assert summary.terminal_category is None


def test_status_projection_rejects_profile_substitution(tmp_path: Path) -> None:
    configuration = _configuration(tmp_path)
    substituted = replace(
        _execution_profile(),
        generation=IntegratedExecutionProfileGeneration(2),
    )

    with pytest.raises(TaskRuntimeBridgeValidationError):
        project_authorized_durable_task_status(
            configuration=configuration,
            operator_profile=configuration.profiles[0],
            execution_profile=substituted,
            checkpoint=_checkpoint(),
            now=_NOW,
        )


@pytest.mark.asyncio
async def test_cancel_uses_caller_owned_lease_context_and_coordinator(
    tmp_path: Path,
) -> None:
    checkpoint = _checkpoint()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(checkpoint)
    lease = await lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id="task-control",
        now=_NOW,
    )
    authorizer = _AllowCancellation()
    coordinator = StoreBackedDurableCancellationCoordinator(
        store=store,
        lease_manager=lease_manager,
        authorizer=authorizer,
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
    )
    context = SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        correlation_id="task-cancel",
    )

    result = await cancel_authorized_durable_task(
        checkpoint=checkpoint,
        cancellation=coordinator,
        lease=lease,
        context=context,
        actor_id="operator-1",
        now=_NOW,
    )

    assert result.status is DurableRunStatus.CANCELLED
    assert authorizer.request is not None
    assert authorizer.request.run_id == checkpoint.durable_run_id
    assert authorizer.request.expected_version == checkpoint.run_version
    assert authorizer.request.generation == lease.generation
    projection = decode_integrated_durable_projection(result)
    assert projection is not None
    assert projection.orchestration_phase is IntegratedOrchestrationPhase.TERMINAL

    configuration = _configuration(tmp_path / "status")
    summary = project_authorized_durable_task_status(
        configuration=configuration,
        operator_profile=configuration.profiles[0],
        execution_profile=_execution_profile(),
        checkpoint=result,
        now=_NOW,
    )
    assert summary.cancellation_state == "cancelled"
    assert summary.terminal_category == "cancelled"
    assert summary.durable_recovery_disposition is None

    await lease_manager.release(lease, now=_NOW)
    await store.close()
    await lease_manager.close()


@pytest.mark.asyncio
async def test_cancel_never_acquires_or_substitutes_a_lease() -> None:
    checkpoint = _checkpoint()
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(checkpoint)
    lease = await lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id="task-control",
        now=_NOW,
    )
    wrong = replace(lease, run_id=integrated_durable_run_id(AgentRunId()))
    authorizer = _AllowCancellation()
    coordinator = StoreBackedDurableCancellationCoordinator(
        store=store,
        lease_manager=lease_manager,
        authorizer=authorizer,
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
    )

    with pytest.raises(TaskRuntimeBridgeValidationError):
        await cancel_authorized_durable_task(
            checkpoint=checkpoint,
            cancellation=coordinator,
            lease=wrong,
            context=SecurityContext(
                principal="operator-1",
                principal_type=PrincipalType.USER,
                authenticated=True,
            ),
            actor_id="operator-1",
            now=_NOW,
        )

    assert authorizer.request is None
    current = await lease_manager.get_current(checkpoint.durable_run_id, now=_NOW)
    assert current == lease

    await lease_manager.release(lease, now=_NOW)
    await store.close()
    await lease_manager.close()
