from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.authorization import AGENT_RUN_ACTION
from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_authorization import (
    AGENT_RESUME_ACTION,
    durable_agent_run_resource,
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
    DurableRunStatus,
    DurableRunVersion,
    ResumeReason,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.control_plane.task_policy_binding import (
    TaskExecutionPolicyBinding,
    TaskExecutionPolicyTargets,
)
from phoenix_os.control_plane.task_runtime_bridge import (
    TaskExecutionAuthority,
    authorize_operator_durable_task_resume,
)
from phoenix_os.inference.authorization import INFERENCE_MODEL_ACTION
from phoenix_os.inference.contracts import ModelId, ModelProviderId
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

_NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
_AGENT_ID = AgentId("task-resume-agent")
_RUN_ID = AgentRunId(UUID("10000000-0000-4000-8000-000000000001"))
_STEP_ID = AgentStepId(UUID("20000000-0000-4000-8000-000000000002"))
_DURABLE_RUN_ID = integrated_durable_run_id(_RUN_ID)
_PROVIDER_ID = ModelProviderId("ollama-local")
_MODEL_ID = ModelId("dev")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _checkpoint() -> CheckpointEnvelope:
    created_at = _NOW - timedelta(minutes=2)
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("30000000-0000-4000-8000-000000000003")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.PAUSED_SHUTDOWN,
            agent_run_id=_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=_AGENT_ID,
                actor_id="origin-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=1,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=8,
                    output_tokens=0,
                    started_at=created_at,
                    deadline=_NOW + timedelta(hours=1),
                ),
                compatibility=CompatibilityDigests(
                    configuration=_digest("a"),
                    tool_registry=_digest("b"),
                    model_provider=_digest("c"),
                    checkpoint_codec=_digest("d"),
                ),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=7),
                metadata={},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _context(*, allow_resume: bool) -> SecurityContext:
    permissions = {
        AGENT_RUN_ACTION,
        INFERENCE_MODEL_ACTION,
    }
    if allow_resume:
        permissions.add(AGENT_RESUME_ACTION)
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
    )


def _targets() -> TaskExecutionPolicyTargets:
    return TaskExecutionPolicyTargets(
        run_id=_RUN_ID,
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
    )


@pytest.mark.asyncio
async def test_operator_resume_uses_explicit_permission_and_caller_owned_current_lease() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine()
    context = _context(allow_resume=True)
    authority = TaskExecutionAuthority(policy=policy, context=context)
    binding = await TaskExecutionPolicyBinding.open(authority, _targets())
    lease_manager = InMemoryDurableLeaseManager()
    lease = await lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id="task-control",
        now=_NOW,
    )

    try:
        request = await authorize_operator_durable_task_resume(
            checkpoint=checkpoint,
            lease_manager=lease_manager,
            lease=lease,
            authority=authority,
            actor_id=context.principal,
            now=_NOW,
        )

        assert request.run_id == checkpoint.durable_run_id
        assert request.actor_id == context.principal
        assert request.reason is ResumeReason.OPERATOR_REQUEST
        assert request.expected_version == checkpoint.run_version
        assert request.generation == lease.generation
        assert request.requested_at == _NOW
        assert await lease_manager.require_current(lease, now=_NOW) == lease

        rules = await policy.list_rules()
        resume_rules = tuple(rule for rule in rules if AGENT_RESUME_ACTION in rule.actions)
        assert len(resume_rules) == 1
        resume_rule = resume_rules[0]
        assert resume_rule.actions == frozenset({AGENT_RESUME_ACTION})
        assert resume_rule.resources == frozenset(
            {durable_agent_run_resource(checkpoint.durable_run_id)}
        )
        assert resume_rule.required_permissions == frozenset({AGENT_RESUME_ACTION})
        assert resume_rule.principals == frozenset({context.principal})
        assert resume_rule.authenticated is True
        assert resume_rule.attribute_equals == {
            "agent_id": str(_AGENT_ID),
            "agent_run_id": str(_RUN_ID),
            "actor_id": context.principal,
            "run_id": str(checkpoint.durable_run_id),
        }
    finally:
        await binding.close()
        await lease_manager.release(lease, now=_NOW)
        await lease_manager.close()
        await policy.close()


@pytest.mark.asyncio
async def test_operator_resume_is_denied_without_explicit_resume_permission() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine()
    context = _context(allow_resume=False)
    authority = TaskExecutionAuthority(policy=policy, context=context)
    binding = await TaskExecutionPolicyBinding.open(authority, _targets())
    lease_manager = InMemoryDurableLeaseManager()
    lease = await lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id="task-control",
        now=_NOW,
    )

    try:
        assert all(AGENT_RESUME_ACTION not in rule.actions for rule in await policy.list_rules())
        with pytest.raises(AgentAuthorizationRejectedError):
            await authorize_operator_durable_task_resume(
                checkpoint=checkpoint,
                lease_manager=lease_manager,
                lease=lease,
                authority=authority,
                actor_id=context.principal,
                now=_NOW,
            )
        assert await lease_manager.require_current(lease, now=_NOW) == lease
    finally:
        await binding.close()
        await lease_manager.release(lease, now=_NOW)
        await lease_manager.close()
        await policy.close()
