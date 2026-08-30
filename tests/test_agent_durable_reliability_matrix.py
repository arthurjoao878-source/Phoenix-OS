from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId, ToolCallId, ToolEffect
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    RecoveryDisposition,
    ResumeReason,
    ResumeRequest,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryAssessment,
    StartupDurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_reliability import (
    DurableStoreFreshnessCategory,
    ReliabilityFaultPoint,
)
from phoenix_os.agent.durable_reliability_fake import (
    DeterministicReliabilityFaultInjector,
    InjectedReliabilityFault,
    ReliabilityFaultTrigger,
)
from phoenix_os.agent.durable_sqlite import SQLiteDurableRunStore
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 30, 18, tzinfo=UTC)
RECOVERY_TIME = NOW + timedelta(minutes=10)
RUN_ID = DurableAgentRunId(UUID("71000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("72000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("73000000-0000-0000-0000-000000000003"))
CHECKPOINT_ID = CheckpointId(UUID("74000000-0000-0000-0000-000000000004"))
ATTEMPT_ID = ExecutionAttemptId(UUID("75000000-0000-0000-0000-000000000005"))
TOOL_CALL_ID = ToolCallId(UUID("76000000-0000-0000-0000-000000000006"))


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


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=2,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=64,
        tool_result_bytes=32,
        input_tokens=128,
        output_tokens=16,
        started_at=NOW,
        deadline=NOW + timedelta(hours=3),
    )


def _started_tool_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW + timedelta(seconds=1),
        tool_call_id=TOOL_CALL_ID,
        tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
        started_at=NOW + timedelta(seconds=2),
        external_request_digest=_digest("e"),
    )


def _checkpoint(*, started_tool: bool = False) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=(
                    CheckpointNextOperation.TOOL_INVOCATION
                    if started_tool
                    else CheckpointNextOperation.MODEL_TURN
                ),
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=30),
                active_attempt=_started_tool_attempt() if started_tool else None,
                metadata={},
            ),
            created_at=NOW + timedelta(seconds=3),
            digest=_digest("0"),
        )
    )


class _ResumeGate:
    def __init__(self) -> None:
        self.calls = 0

    async def revalidate_resume(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        now: datetime,
    ) -> bool:
        del checkpoint, now
        self.calls += 1
        return True


class _ResumeAuthorizer:
    def __init__(self) -> None:
        self.requests: list[ResumeRequest] = []

    async def authorize(
        self,
        request: ResumeRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del checkpoint, lease, context
        self.requests.append(request)


def _resume_context() -> SecurityContext:
    return SecurityContext(
        principal="recovery-worker",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


async def _assess_once(
    store: InMemoryDurableRunStore | SQLiteDurableRunStore,
    *,
    owner_id: str,
    now: datetime,
) -> DurableRecoveryAssessment:
    gate = _ResumeGate()
    authorizer = _ResumeAuthorizer()
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        resume_gate=gate,
        resume_authorizer=authorizer,
        resume_context=_resume_context(),
    )
    try:
        assessment = await coordinator.assess_candidate(
            RUN_ID,
            owner_id=owner_id,
            now=now,
        )
        assert gate.calls == 1
        if assessment.disposition is RecoveryDisposition.RESUME:
            assert len(authorizer.requests) == 1
            request = authorizer.requests[0]
            assert request.run_id == RUN_ID
            assert request.actor_id == owner_id
            assert request.reason is ResumeReason.STARTUP_RECOVERY
            assert request.generation == assessment.generation
        else:
            assert authorizer.requests == []
        return assessment
    finally:
        await coordinator.close()


@pytest.mark.asyncio
async def test_inmemory_recovery_epoch_soak_is_finite_without_checkpoint_reset() -> None:
    limits = DurableRunLimits(max_recovery_attempts=4)
    store = InMemoryDurableRunStore(limits=limits)
    original = _checkpoint()
    await store.create(original)

    for occurrence in range(1, limits.max_recovery_attempts + 1):
        assessment = await _assess_once(
            store,
            owner_id=f"recoverer-{occurrence}",
            now=RECOVERY_TIME + timedelta(seconds=occurrence),
        )
        expected = (
            RecoveryDisposition.RESUME
            if occurrence < limits.max_recovery_attempts
            else RecoveryDisposition.PAUSE_OPERATOR
        )
        assert assessment.disposition is expected
        assert assessment.generation.value == occurrence
        assert await store.get_recovery_attempt_count(RUN_ID) == occurrence
        assert await store.get_current(RUN_ID) == original

    assert await store.list_recovery_candidates(limit=8) == ()
    assert await store.get_current(RUN_ID) == original
    await store.close()


@pytest.mark.asyncio
async def test_sqlite_repeated_process_reopen_exhausts_recovery_budget_once(
    tmp_path: Path,
) -> None:
    limits = DurableRunLimits(max_recovery_attempts=4)
    path = tmp_path / "recovery-soak.sqlite3"
    original = _checkpoint()

    seed = SQLiteDurableRunStore(path, limits=limits)
    await seed.create(original)
    await seed.close()

    for occurrence in range(1, limits.max_recovery_attempts + 1):
        store = SQLiteDurableRunStore(path, limits=limits)
        assessment = await _assess_once(
            store,
            owner_id=f"restart-{occurrence}",
            now=RECOVERY_TIME + timedelta(minutes=occurrence),
        )
        expected = (
            RecoveryDisposition.RESUME
            if occurrence < limits.max_recovery_attempts
            else RecoveryDisposition.PAUSE_OPERATOR
        )
        assert assessment.disposition is expected
        assert assessment.generation.value == occurrence
        assert await store.get_recovery_attempt_count(RUN_ID) == occurrence
        assert await store.get_current(RUN_ID) == original
        await store.close()

    reopened = SQLiteDurableRunStore(path, limits=limits)
    assert await reopened.list_recovery_candidates(limit=8) == ()
    assert await reopened.get_recovery_attempt_count(RUN_ID) == limits.max_recovery_attempts
    assert await reopened.get_current(RUN_ID) == original
    freshness = await reopened.get_store_freshness()
    assert freshness.category is DurableStoreFreshnessCategory.CURRENT
    await reopened.close()


@pytest.mark.asyncio
async def test_sqlite_started_tool_transition_crash_reopen_never_replays_effect(
    tmp_path: Path,
) -> None:
    path = tmp_path / "started-tool-crash.sqlite3"
    original = _checkpoint(started_tool=True)
    injector = DeterministicReliabilityFaultInjector(
        (
            ReliabilityFaultTrigger(
                point=ReliabilityFaultPoint.RECOVERY_AFTER_TRANSITION_COMMIT,
            ),
        ),
        max_total_hits=32,
    )
    store = SQLiteDurableRunStore(path)
    await store.create(original)
    crashing = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(),
        fault_injector=injector,
    )

    with pytest.raises(InjectedReliabilityFault):
        await crashing.persist_indeterminate_candidate(
            RUN_ID,
            owner_id="crashing-recoverer",
            now=RECOVERY_TIME,
        )

    committed = await store.get_current(RUN_ID)
    assert committed is not None
    assert committed.status is DurableRunStatus.INDETERMINATE_TOOL
    assert committed.sequence.value == 2
    assert committed.metadata.active_attempt is not None
    assert committed.metadata.active_attempt.status is ExecutionAttemptStatus.INDETERMINATE
    assert len(await store.list_history(RUN_ID, limit=8)) == 2
    assert await store.get_recovery_attempt_count(RUN_ID) == 1
    await crashing.close()
    await store.close()

    reopened = SQLiteDurableRunStore(path)
    successor = StartupDurableRecoveryCoordinator(
        store=reopened,
        lease_manager=reopened.lease_manager,
        compatibility_validator=_validator(),
    )
    assessment = await successor.persist_indeterminate_candidate(
        RUN_ID,
        owner_id="successor-recoverer",
        now=RECOVERY_TIME + timedelta(minutes=1),
    )

    assert assessment.status is DurableRunStatus.INDETERMINATE_TOOL
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert await reopened.get_current(RUN_ID) == committed
    assert len(await reopened.list_history(RUN_ID, limit=8)) == 2
    assert await reopened.get_recovery_attempt_count(RUN_ID) == 2

    await successor.close()
    await reopened.close()
