from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
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
    DurableLease,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunVersion,
    RecoveryDisposition,
    RecoveryPoint,
    ResumeReason,
    ResumeRequest,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryResumeGate,
    StartupDurableRecoveryCoordinator,
    classify_recovery_checkpoint,
)
from phoenix_os.agent.durable_reliability import DurableRecoveryAttemptStore
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentLimitExceededError,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 28, 21, 0, tzinfo=UTC)
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=601))
_AGENT_RUN_ID = AgentRunId(UUID(int=602))
_STEP_ID = AgentStepId(UUID(int=603))


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


def _checkpoint(
    *,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID(int=604)),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=status,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=next_operation,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=_NOW - timedelta(minutes=1),
                    deadline=_NOW + timedelta(hours=1),
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata={"tenant": "demo"},
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


@dataclass
class _ResumeGate:
    allowed: bool
    calls: int = 0

    async def revalidate_resume(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> bool:
        del checkpoint, now
        self.calls += 1
        return self.allowed


@dataclass
class _ResumeAuthorizer:
    allowed: bool = True
    requests: list[ResumeRequest] = field(default_factory=list)

    async def authorize(
        self,
        request: ResumeRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del checkpoint, lease, context
        self.requests.append(request)
        if not self.allowed:
            raise AgentAuthorizationRejectedError()


def _resume_context() -> SecurityContext:
    return SecurityContext(
        principal="recovery-worker",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def test_resume_gate_structurally_implements_generic_protocol() -> None:
    assert isinstance(_ResumeGate(True), DurableRecoveryResumeGate)


def test_paused_operator_with_resumable_next_operation_remains_operator_pause() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.PAUSED_OPERATOR,
        next_operation=CheckpointNextOperation.MODEL_TURN,
    )

    point, disposition = classify_recovery_checkpoint(
        checkpoint,
        now=_NOW + timedelta(minutes=1),
    )

    assert point is RecoveryPoint.OPERATOR_PAUSE
    assert disposition is RecoveryDisposition.PAUSE_OPERATOR


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("allowed", "expected"),
    (
        (True, RecoveryDisposition.RESUME),
        (False, RecoveryDisposition.PAUSE_OPERATOR),
    ),
)
async def test_startup_resume_gate_can_only_restrict_structural_resume(
    allowed: bool,
    expected: RecoveryDisposition,
) -> None:
    checkpoint = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    gate = _ResumeGate(allowed)
    authorizer = _ResumeAuthorizer()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        resume_gate=gate,
        resume_authorizer=authorizer,
        resume_context=_resume_context(),
    )

    assessment = await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=1),
    )

    assert assessment.point is RecoveryPoint.SAFE_BOUNDARY
    assert assessment.disposition is expected
    assert gate.calls == 1
    if allowed:
        assert len(authorizer.requests) == 1
        request = authorizer.requests[0]
        assert request.run_id == _DURABLE_RUN_ID
        assert request.actor_id == "recovery-worker"
        assert request.reason is ResumeReason.STARTUP_RECOVERY
        assert request.expected_version == checkpoint.run_version
        assert request.generation == assessment.generation
    else:
        assert authorizer.requests == []


@pytest.mark.asyncio
async def test_startup_resume_fails_closed_without_current_resume_authority() -> None:
    checkpoint = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    gate = _ResumeGate(True)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        resume_gate=gate,
    )

    assessment = await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=1),
    )

    assert assessment.point is RecoveryPoint.SAFE_BOUNDARY
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert gate.calls == 1


@pytest.mark.asyncio
async def test_startup_resume_denial_from_current_policy_pauses_operator() -> None:
    checkpoint = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    gate = _ResumeGate(True)
    authorizer = _ResumeAuthorizer(allowed=False)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        resume_gate=gate,
        resume_authorizer=authorizer,
        resume_context=_resume_context(),
    )

    assessment = await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=1),
    )

    assert assessment.point is RecoveryPoint.SAFE_BOUNDARY
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert len(authorizer.requests) == 1
    assert authorizer.requests[0].reason is ResumeReason.STARTUP_RECOVERY


@pytest.mark.asyncio
async def test_indeterminate_entrypoint_applies_resume_gate_at_safe_boundary() -> None:
    checkpoint = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    gate = _ResumeGate(False)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        resume_gate=gate,
    )

    assessment = await coordinator.persist_indeterminate_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=1),
    )

    assert assessment.point is RecoveryPoint.SAFE_BOUNDARY
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert gate.calls == 1


def test_in_memory_store_implements_recovery_attempt_bookkeeping() -> None:
    store = InMemoryDurableRunStore()
    assert isinstance(store, DurableRecoveryAttemptStore)


@pytest.mark.asyncio
async def test_recovery_attempt_exhaustion_removes_in_memory_candidate() -> None:
    limits = replace(DurableRunLimits(), max_recovery_attempts=2)
    store = InMemoryDurableRunStore(limits=limits)
    checkpoint = _checkpoint()
    await store.create(checkpoint)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
    )

    assert await store.list_recovery_candidates(limit=1) == (_DURABLE_RUN_ID,)

    await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=1),
    )
    assert await store.get_recovery_attempt_count(_DURABLE_RUN_ID) == 1
    assert await store.list_recovery_candidates(limit=1) == (_DURABLE_RUN_ID,)

    await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=2),
    )
    assert await store.get_recovery_attempt_count(_DURABLE_RUN_ID) == 2
    assert await store.list_recovery_candidates(limit=1) == ()

    with pytest.raises(AgentLimitExceededError):
        await coordinator.assess_candidate(
            _DURABLE_RUN_ID,
            owner_id="recovery-worker",
            now=_NOW + timedelta(minutes=3),
        )

    assert await store.get_recovery_attempt_count(_DURABLE_RUN_ID) == 2


@pytest.mark.asyncio
async def test_final_recovery_attempt_cannot_resume_new_protected_work() -> None:
    limits = replace(DurableRunLimits(), max_recovery_attempts=2)
    store = InMemoryDurableRunStore(limits=limits)
    checkpoint = _checkpoint()
    await store.create(checkpoint)
    gate = _ResumeGate(True)
    authorizer = _ResumeAuthorizer()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        resume_gate=gate,
        resume_authorizer=authorizer,
        resume_context=_resume_context(),
    )

    first = await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=1),
    )
    assert first.disposition is RecoveryDisposition.RESUME
    assert len(authorizer.requests) == 1
    assert await store.get_recovery_attempt_count(_DURABLE_RUN_ID) == 1

    final = await coordinator.assess_candidate(
        _DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=_NOW + timedelta(minutes=2),
    )
    assert final.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert gate.calls == 2
    assert len(authorizer.requests) == 1
    assert await store.get_recovery_attempt_count(_DURABLE_RUN_ID) == 2
    assert await store.list_recovery_candidates(limit=1) == ()
    assert await store.get_current(_DURABLE_RUN_ID) == checkpoint
