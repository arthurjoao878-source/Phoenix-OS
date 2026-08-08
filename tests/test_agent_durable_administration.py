from dataclasses import fields
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_administration import (
    AGENT_DURABLE_HEALTH_READ_ACTION,
    AGENT_DURABLE_READ_ACTION,
    DURABLE_ADMINISTRATION_HEALTH_RESOURCE,
    MAX_DURABLE_ADMINISTRATION_AGE_SECONDS,
    MAX_DURABLE_ADMINISTRATION_COUNT,
    DurableAdministrationConfiguration,
    DurableIndeterminateCategory,
    DurableMachineAdministrationGuard,
    DurablePauseCategory,
    DurableRetentionCategory,
    DurableRunAdministration,
)
from phoenix_os.agent.durable_authorization import durable_agent_run_resource
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityAssessment,
    DurableCompatibilityCategory,
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_observer import NullDurableRunObserver
from phoenix_os.agent.durable_retention_worker import (
    DurableRetentionWorkerReport,
    DurableRetentionWorkerSnapshot,
    DurableRetentionWorkerState,
)
from phoenix_os.agent.durable_worker import (
    DurableRecoveryWorkerReport,
    DurableRecoveryWorkerSnapshot,
    DurableRecoveryWorkerState,
)
from phoenix_os.agent.errors import (
    AgentAdministrationAccessDeniedError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 7, 12, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-0000-0000-000000000004"))
ATTEMPT_ID = ExecutionAttemptId(UUID("50000000-0000-0000-0000-000000000005"))
AGENT_ID = AgentId("assistant")
SECRET = "PRIVATE-DURABLE-CONTENT-MUST-NOT-LEAK"


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget(*, started_at: datetime) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=2,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=128,
        tool_result_bytes=0,
        input_tokens=32,
        output_tokens=16,
        started_at=started_at,
        deadline=NOW + timedelta(hours=2),
    )


def _indeterminate_model_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(minutes=2),
        started_at=NOW - timedelta(minutes=1, seconds=30),
        completed_at=NOW - timedelta(minutes=1),
        indeterminate_reason=IndeterminateReason.PROCESS_LOSS,
    )


def _checkpoint(
    *,
    status: DurableRunStatus = DurableRunStatus.PAUSED_OPERATOR,
    retention_deadline: datetime | None = None,
    created_at: datetime | None = None,
    run_started_at: datetime | None = None,
) -> CheckpointEnvelope:
    resolved_created_at = NOW - timedelta(minutes=1) if created_at is None else created_at
    resolved_started_at = (
        resolved_created_at - timedelta(minutes=4) if run_started_at is None else run_started_at
    )
    attempt = (
        _indeterminate_model_attempt() if status is DurableRunStatus.INDETERMINATE_MODEL else None
    )
    metadata = CheckpointMetadata(
        agent_id=AGENT_ID,
        actor_id="durable-worker",
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        budget=_budget(started_at=resolved_started_at),
        compatibility=_compatibility(),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
        retention_deadline=(
            NOW + timedelta(days=1) if retention_deadline is None else retention_deadline
        ),
        active_attempt=attempt,
        metadata={"private": SECRET},
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=metadata,
            created_at=resolved_created_at,
            digest=_digest("0"),
        )
    )


def _validator() -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=AGENT_ID,
                current=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )


class _ExplodingCompatibilityValidator:
    def validate(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> DurableCompatibilityAssessment:
        raise RuntimeError(SECRET)


def _maintainer_context(
    *permissions: str,
) -> SecurityContext:
    return SecurityContext(
        principal="operator:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
        correlation_id="durable-administration-test",
    )


def _service_context(
    *,
    scopes: frozenset[str],
) -> SecurityContext:
    return SecurityContext(
        principal="service:durable-administration",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        scopes=scopes,
        correlation_id="durable-machine-administration-test",
    )


class _ExactMachineGuard:
    def __init__(self, allowed: frozenset[tuple[str, str]]) -> None:
        self._allowed = allowed
        self.calls: list[tuple[str, str]] = []

    async def authorize(
        self,
        context: SecurityContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        self.calls.append((action, resource))
        if (action, resource) not in self._allowed:
            raise AgentAdministrationAccessDeniedError()


class _ExplodingMachineGuard:
    async def authorize(
        self,
        context: SecurityContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        raise RuntimeError(SECRET)


class _RecoveryWorker:
    @property
    def state(self) -> DurableRecoveryWorkerState:
        return DurableRecoveryWorkerState.CREATED

    async def start(self) -> None:
        return None

    async def run_once(self) -> DurableRecoveryWorkerReport:
        raise AssertionError("run_once must not be called by administration")

    async def snapshot(self) -> DurableRecoveryWorkerSnapshot:
        return DurableRecoveryWorkerSnapshot(
            state=DurableRecoveryWorkerState.CREATED,
            active=0,
            passes_started=2,
            passes_completed=1,
            passes_failed=0,
            passes_timed_out=1,
            passes_stopped=0,
            candidates_admitted=3,
            assessed=2,
            conflicts=0,
            failed=1,
            forced_cancellations=0,
            last_started_at=NOW - timedelta(minutes=2),
            last_completed_at=NOW - timedelta(minutes=1),
        )

    async def close(self) -> None:
        return None


class _HugeRecoveryWorker(_RecoveryWorker):
    async def snapshot(self) -> DurableRecoveryWorkerSnapshot:
        huge = MAX_DURABLE_ADMINISTRATION_COUNT + 10
        return DurableRecoveryWorkerSnapshot(
            state=DurableRecoveryWorkerState.RUNNING,
            active=huge,
            passes_started=huge,
            passes_completed=huge,
            passes_failed=0,
            passes_timed_out=0,
            passes_stopped=0,
            candidates_admitted=huge,
            assessed=huge,
            conflicts=0,
            failed=0,
            forced_cancellations=0,
            last_started_at=NOW - timedelta(minutes=2),
            last_completed_at=NOW - timedelta(minutes=1),
        )


class _RetentionWorker:
    @property
    def state(self) -> DurableRetentionWorkerState:
        return DurableRetentionWorkerState.CREATED

    async def start(self) -> None:
        return None

    async def run_once(self) -> DurableRetentionWorkerReport:
        raise AssertionError("run_once must not be called by administration")

    async def snapshot(self) -> DurableRetentionWorkerSnapshot:
        return DurableRetentionWorkerSnapshot(
            state=DurableRetentionWorkerState.CREATED,
            passes_started=3,
            passes_completed=2,
            passes_timed_out=0,
            last_started_at=NOW - timedelta(minutes=3),
            last_completed_at=NOW - timedelta(minutes=1),
            passes_failed=1,
            passes_stopped=0,
        )

    async def close(self) -> None:
        return None


def _administration(
    *,
    store: InMemoryDurableRunStore,
    lease_manager: InMemoryDurableLeaseManager,
    configuration: DurableAdministrationConfiguration | None = None,
    machine_guard: DurableMachineAdministrationGuard | None = None,
    recovery_worker: _RecoveryWorker | None = None,
    retention_worker: _RetentionWorker | None = None,
) -> DurableRunAdministration:
    return DurableRunAdministration(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=_validator(),
        configuration=configuration,
        recovery_worker=recovery_worker,
        retention_worker=retention_worker,
        observer=NullDurableRunObserver(),
        machine_guard=machine_guard,
        clock=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_run_view_matches_rfc_surface_and_exposes_only_safe_metadata() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    lease = await lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="recovery-worker",
        now=NOW,
    )
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
    )

    view = await administration.run(
        DURABLE_RUN_ID,
        _maintainer_context(AGENT_DURABLE_READ_ACTION),
    )

    assert view is not None
    assert {item.name for item in fields(view)} == {
        "run_id",
        "status",
        "pause_category",
        "checkpoint_sequence",
        "age_seconds",
        "retention_category",
        "payload_profile",
        "lease_present",
        "fencing_generation",
        "indeterminate_category",
        "compatibility_category",
        "schema_version",
    }
    assert view.run_id == DURABLE_RUN_ID
    assert view.status is DurableRunStatus.PAUSED_OPERATOR
    assert view.pause_category is DurablePauseCategory.OPERATOR
    assert view.checkpoint_sequence == 1
    assert view.age_seconds == 300
    assert view.retention_category is DurableRetentionCategory.RETAINED
    assert view.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
    assert view.lease_present is True
    assert view.fencing_generation == lease.generation.value
    assert view.indeterminate_category is DurableIndeterminateCategory.NONE
    assert view.compatibility_category is DurableCompatibilityCategory.EXACT
    assert SECRET not in repr(view)
    assert "durable-worker" not in repr(view)
    assert str(AGENT_ID) not in repr(view)


@pytest.mark.asyncio
async def test_run_lookup_authorizes_before_revealing_existence() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
    )
    unknown = DurableAgentRunId(UUID("90000000-0000-0000-0000-000000000009"))

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.run(
            unknown,
            _maintainer_context(),
        )

    assert (
        await administration.run(
            unknown,
            _maintainer_context(AGENT_DURABLE_READ_ACTION),
        )
        is None
    )


@pytest.mark.asyncio
async def test_machine_administration_is_disabled_by_default() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
    )

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.run(
            DURABLE_RUN_ID,
            _service_context(
                scopes=frozenset({AGENT_DURABLE_READ_ACTION}),
            ),
        )


@pytest.mark.asyncio
async def test_enabled_machine_administration_uses_exact_scope_and_guarded_resource() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    run_resource = durable_agent_run_resource(DURABLE_RUN_ID)
    allowed = frozenset(
        {
            (AGENT_DURABLE_READ_ACTION, run_resource),
            (
                AGENT_DURABLE_HEALTH_READ_ACTION,
                DURABLE_ADMINISTRATION_HEALTH_RESOURCE,
            ),
        }
    )
    guard = _ExactMachineGuard(allowed)
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
        configuration=DurableAdministrationConfiguration(
            machine_administration_enabled=True,
        ),
        machine_guard=guard,
    )

    view = await administration.run(
        DURABLE_RUN_ID,
        _service_context(
            scopes=frozenset({AGENT_DURABLE_READ_ACTION}),
        ),
    )
    snapshot = await administration.snapshot(
        _service_context(
            scopes=frozenset({AGENT_DURABLE_HEALTH_READ_ACTION}),
        )
    )

    assert view is not None
    assert snapshot.store_open is True
    assert guard.calls == [
        (AGENT_DURABLE_READ_ACTION, run_resource),
        (
            AGENT_DURABLE_HEALTH_READ_ACTION,
            DURABLE_ADMINISTRATION_HEALTH_RESOURCE,
        ),
    ]


@pytest.mark.asyncio
async def test_machine_boundary_rejects_inexact_scope_and_resource_before_exposure() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    run_resource = durable_agent_run_resource(DURABLE_RUN_ID)
    guard = _ExactMachineGuard(frozenset({(AGENT_DURABLE_READ_ACTION, run_resource)}))
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
        configuration=DurableAdministrationConfiguration(
            machine_administration_enabled=True,
        ),
        machine_guard=guard,
    )

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.run(
            DURABLE_RUN_ID,
            _service_context(scopes=frozenset({"agent.durable.other"})),
        )
    assert guard.calls == []

    unknown = DurableAgentRunId(UUID("90000000-0000-0000-0000-000000000009"))
    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.run(
            unknown,
            _service_context(scopes=frozenset({AGENT_DURABLE_READ_ACTION})),
        )
    assert guard.calls == [(AGENT_DURABLE_READ_ACTION, durable_agent_run_resource(unknown))]


@pytest.mark.asyncio
async def test_machine_guard_failures_do_not_expose_raw_exception() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
        configuration=DurableAdministrationConfiguration(
            machine_administration_enabled=True,
        ),
        machine_guard=_ExplodingMachineGuard(),
    )

    with pytest.raises(AgentAdministrationAccessDeniedError) as captured:
        await administration.run(
            DURABLE_RUN_ID,
            _service_context(scopes=frozenset({AGENT_DURABLE_READ_ACTION})),
        )

    assert captured.value.__cause__ is None
    assert SECRET not in repr(captured.value)
    assert SECRET not in str(captured.value)


@pytest.mark.asyncio
async def test_non_user_non_service_principal_cannot_use_maintainer_permissions() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
    )
    plugin_context = SecurityContext(
        principal="plugin:admin",
        principal_type=PrincipalType.PLUGIN,
        authenticated=True,
        permissions=frozenset({AGENT_DURABLE_READ_ACTION}),
    )

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.run(DURABLE_RUN_ID, plugin_context)


@pytest.mark.asyncio
async def test_internal_read_failures_are_sanitized() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(_checkpoint())
    administration = DurableRunAdministration(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=_ExplodingCompatibilityValidator(),
        observer=NullDurableRunObserver(),
        clock=lambda: NOW,
    )

    with pytest.raises(AgentServiceUnavailableError) as captured:
        await administration.run(
            DURABLE_RUN_ID,
            _maintainer_context(AGENT_DURABLE_READ_ACTION),
        )

    assert captured.value.__cause__ is None
    assert SECRET not in repr(captured.value)
    assert SECRET not in str(captured.value)


@pytest.mark.asyncio
async def test_snapshot_projects_bounded_health_without_worker_timestamps() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
        recovery_worker=_RecoveryWorker(),
        retention_worker=_RetentionWorker(),
    )

    snapshot = await administration.snapshot(_maintainer_context(AGENT_DURABLE_HEALTH_READ_ACTION))

    assert snapshot.store_open is True
    assert snapshot.lease_manager_open is True
    assert snapshot.recovery is not None
    assert snapshot.recovery.passes_started == 2
    assert snapshot.recovery.passes_timed_out == 1
    assert "last_started_at" not in {item.name for item in fields(snapshot.recovery)}
    assert "last_completed_at" not in {item.name for item in fields(snapshot.recovery)}
    assert snapshot.retention is not None
    assert snapshot.retention.passes_started == 3
    assert snapshot.retention.passes_failed == 1
    assert "last_started_at" not in {item.name for item in fields(snapshot.retention)}
    assert "last_completed_at" not in {item.name for item in fields(snapshot.retention)}
    assert snapshot.observer is not None
    assert snapshot.observer.observations == 0
    assert snapshot.degraded is True
    assert SECRET not in repr(snapshot)


@pytest.mark.asyncio
async def test_snapshot_clamps_cumulative_counts() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
        recovery_worker=_HugeRecoveryWorker(),
    )

    snapshot = await administration.snapshot(_maintainer_context(AGENT_DURABLE_HEALTH_READ_ACTION))

    assert snapshot.recovery is not None
    assert snapshot.recovery.active == MAX_DURABLE_ADMINISTRATION_COUNT
    assert snapshot.recovery.passes_started == MAX_DURABLE_ADMINISTRATION_COUNT
    assert snapshot.recovery.candidates_admitted == MAX_DURABLE_ADMINISTRATION_COUNT


@pytest.mark.asyncio
async def test_closed_store_marks_administration_degraded() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
    )
    context = _maintainer_context(AGENT_DURABLE_HEALTH_READ_ACTION)

    initial = await administration.snapshot(context)
    assert initial.degraded is False

    await store.close()
    degraded = await administration.snapshot(context)

    assert degraded.store_open is False
    assert degraded.lease_manager_open is True
    assert degraded.degraded is True


@pytest.mark.asyncio
async def test_run_view_classifies_expired_retention_and_indeterminate_model() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    checkpoint = _checkpoint(status=DurableRunStatus.INDETERMINATE_MODEL)
    await store.create(checkpoint)
    administration = DurableRunAdministration(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=_validator(),
        observer=NullDurableRunObserver(),
        clock=lambda: NOW + timedelta(days=2),
    )

    view = await administration.run(
        DURABLE_RUN_ID,
        _maintainer_context(AGENT_DURABLE_READ_ACTION),
    )

    assert view is not None
    assert view.status is DurableRunStatus.INDETERMINATE_MODEL
    assert view.indeterminate_category is DurableIndeterminateCategory.MODEL
    assert view.pause_category is DurablePauseCategory.NONE
    assert view.retention_category is DurableRetentionCategory.EXPIRED
    assert view.lease_present is False
    assert view.fencing_generation is None


@pytest.mark.asyncio
async def test_run_age_is_bounded_from_original_run_start() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)
    await store.create(
        _checkpoint(
            run_started_at=NOW - timedelta(days=400),
        )
    )
    administration = _administration(
        store=store,
        lease_manager=lease_manager,
    )

    view = await administration.run(
        DURABLE_RUN_ID,
        _maintainer_context(AGENT_DURABLE_READ_ACTION),
    )

    assert view is not None
    assert view.age_seconds == MAX_DURABLE_ADMINISTRATION_AGE_SECONDS


def test_enabling_machine_administration_without_guard_fails_closed() -> None:
    lease_manager = InMemoryDurableLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=lease_manager)

    with pytest.raises(ValueError, match="machine guard"):
        DurableRunAdministration(
            store=store,
            lease_manager=lease_manager,
            compatibility_validator=_validator(),
            configuration=DurableAdministrationConfiguration(
                machine_administration_enabled=True,
            ),
            clock=lambda: NOW,
        )
