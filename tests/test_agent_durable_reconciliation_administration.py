from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AGENT_RECONCILE_ACTION,
    AgentAdministrationAccessDeniedError,
    AgentId,
    AgentRunId,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentStepId,
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
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
    DurableAttemptStatusLookupResult,
    DurableAttemptStatusObservation,
    DurableLease,
    DurableReconciliationAdministration,
    DurableReconciliationAdministrationPreparation,
    DurableReconciliationAdministrationResult,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    InMemoryDurableLeaseManager,
    InMemoryDurableRunStore,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
    StaticDurableCompatibilityValidator,
    StoreBackedDurableReconciliationDispositionApplier,
    ToolCallId,
    ToolEffect,
    create_durable_agent_runtime_stack,
    durable_attempt_status_query,
    reconciliation_disposition_record,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_observer import DurableRunObservation, DurableRunObserverSnapshot
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.audit import AuditLedger
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 8, 18, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-4000-8000-000000000028"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000028"))
STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000028"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-4000-8000-000000000028"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-4000-8000-000000000028"))
CHECKPOINT_ID = CheckpointId(UUID("60000000-0000-4000-8000-000000000028"))
PREPARATION_ID = UUID("70000000-0000-4000-8000-000000000028")
LOOKUP_ID = UUID("80000000-0000-4000-8000-000000000028")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=4,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(hours=1),
    )


def _attempt(kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=kind,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=3),
        started_at=NOW - timedelta(seconds=2),
        completed_at=NOW - timedelta(seconds=1),
        tool_call_id=(TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None),
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        external_request_digest=_digest("e"),
        indeterminate_reason=IndeterminateReason.PROCESS_LOSS,
    )


def _checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.INDETERMINATE_MODEL,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=7),
                active_attempt=_attempt(),
                metadata={"tenant": "demo"},
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


def _context(
    *permissions: str,
    principal: str = "maintainer",
) -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
        correlation_id="reconciliation-administration-test",
    )


class _AllowAuthorizer:
    def __init__(self) -> None:
        self.requests: list[ReconciliationRequest] = []

    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        del checkpoint, lease
        assert context.authenticated
        self.requests.append(request)


class _Lookup:
    def __init__(
        self,
        status: DurableAttemptExternalStatus = DurableAttemptExternalStatus.SUCCEEDED,
    ) -> None:
        self.status = status
        self.calls = 0

    async def lookup(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        requested_at: datetime,
    ) -> DurableAttemptStatusLookupResult:
        self.calls += 1
        query = replace(
            durable_attempt_status_query(checkpoint, requested_at=requested_at),
            lookup_id=LOOKUP_ID,
        )
        evidence = ReconciliationEvidence(
            evidence_type="adapter-receipt",
            evidence_digest=_digest("9"),
            observed_at=requested_at,
        )
        observation = DurableAttemptStatusObservation(
            lookup_id=query.lookup_id,
            durable_run_id=query.durable_run_id,
            attempt_id=query.attempt_id,
            external_request_digest=query.external_request_digest,
            adapter_id="reviewed.status",
            status=self.status,
            observed_at=requested_at,
            evidence=evidence,
        )
        return DurableAttemptStatusLookupResult(
            query=query,
            outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
            adapter_id="reviewed.status",
            observation=observation,
        )


class _BlockingApplier:
    def __init__(self, delegate: StoreBackedDurableReconciliationDispositionApplier) -> None:
        self._delegate = delegate
        self.started = asyncio.Event()
        self.proceed = asyncio.Event()

    async def apply(
        self,
        request: ReconciliationRequest,
        *,
        lease: DurableLease,
        context: SecurityContext,
        now: datetime,
        lookup_result: DurableAttemptStatusLookupResult | None = None,
    ) -> CheckpointEnvelope:
        self.started.set()
        await self.proceed.wait()
        return await self._delegate.apply(
            request,
            lease=lease,
            context=context,
            now=now,
            lookup_result=lookup_result,
        )


class _FailingApplier:
    async def apply(
        self,
        request: ReconciliationRequest,
        *,
        lease: DurableLease,
        context: SecurityContext,
        now: datetime,
        lookup_result: DurableAttemptStatusLookupResult | None = None,
    ) -> CheckpointEnvelope:
        del request, lease, context, now, lookup_result
        raise RuntimeError("RAW-INTERNAL-FAILURE")


class _BlockingReleaseLeaseManager(InMemoryDurableLeaseManager):
    def __init__(self, *, limits: DurableRunLimits) -> None:
        super().__init__(limits=limits)
        self.release_started = asyncio.Event()
        self.release_proceed = asyncio.Event()

    async def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> None:
        self.release_started.set()
        await self.release_proceed.wait()
        await super().release(lease, now=now)


class _BlockingObserver:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def record(
        self,
        observation: DurableRunObservation,
        context: SecurityContext,
    ) -> None:
        del observation, context
        self.started.set()
        await asyncio.Event().wait()

    async def snapshot(self) -> DurableRunObserverSnapshot:
        return DurableRunObserverSnapshot()


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


async def _services(
    *,
    lookup: _Lookup | None = None,
    audit: AuditLedger | None = None,
    clock: _Clock | None = None,
) -> tuple[
    InMemoryDurableRunStore,
    InMemoryDurableLeaseManager,
    _AllowAuthorizer,
    AuditLedger,
    DurableReconciliationAdministration,
]:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    leases = InMemoryDurableLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(limits=limits, lease_manager=leases)
    await store.create(_checkpoint())
    authorizer = _AllowAuthorizer()
    applier = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=authorizer,
    )
    selected_audit = AuditLedger() if audit is None else audit
    selected_clock = _Clock(NOW + timedelta(seconds=5)) if clock is None else clock
    administration = DurableReconciliationAdministration(
        store=store,
        lease_manager=leases,
        applier=applier,
        audit=selected_audit,
        status_lookup=lookup,
        clock=selected_clock,
        preparation_id_factory=lambda: PREPARATION_ID,
    )
    return store, leases, authorizer, selected_audit, administration


@pytest.mark.asyncio
async def test_prepare_confirm_succeeded_uses_only_reviewed_lookup_evidence() -> None:
    lookup = _Lookup()
    _store, _leases, _authorizer, _audit, administration = await _services(lookup=lookup)

    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        _context(AGENT_RECONCILE_ACTION),
    )

    assert isinstance(preparation, DurableReconciliationAdministrationPreparation)
    assert preparation.id == PREPARATION_ID
    assert preparation.requested_at == NOW + timedelta(seconds=5)
    assert preparation.prepared_at == preparation.requested_at
    assert preparation.expires_at == preparation.requested_at + timedelta(minutes=1)
    assert not hasattr(preparation, "evidence")
    assert not hasattr(preparation, "lookup_result")
    assert preparation.evidence_type == "adapter-receipt"
    assert preparation.evidence_digest == _digest("9")
    assert preparation.evidence_observed_at == NOW + timedelta(seconds=5)
    assert lookup.calls == 1


@pytest.mark.asyncio
async def test_prepare_rejects_wrong_external_status_for_selected_decision() -> None:
    lookup = _Lookup(DurableAttemptExternalStatus.FAILED)
    _store, _leases, _authorizer, _audit, administration = await _services(lookup=lookup)

    with pytest.raises(AgentStateConflictError):
        await administration.prepare(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            DurableRunVersion(1),
            ReconciliationDecision.CONFIRM_SUCCEEDED,
            _context(AGENT_RECONCILE_ACTION),
        )


@pytest.mark.asyncio
async def test_prepare_requires_exact_human_reconciliation_permission() -> None:
    _store, _leases, _authorizer, _audit, administration = await _services()

    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.prepare(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            DurableRunVersion(1),
            ReconciliationDecision.CANCEL_RUN,
            _context(),
        )


@pytest.mark.asyncio
async def test_apply_uses_server_fencing_and_persists_exact_disposition() -> None:
    lookup = _Lookup()
    store, leases, authorizer, audit, administration = await _services(lookup=lookup)
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        context,
    )

    reserved = await leases.get_current(
        DURABLE_RUN_ID,
        now=preparation.requested_at,
    )
    assert reserved is not None
    assert reserved.owner_id == "reconciliation-admin"
    assert reserved.generation.value == 1
    assert reserved.acquired_at == preparation.requested_at
    assert reserved.expires_at == preparation.expires_at

    result = await administration.apply(preparation, context)

    assert isinstance(result, DurableReconciliationAdministrationResult)
    assert result.status is DurableRunStatus.PAUSED_OPERATOR
    assert result.run_version == DurableRunVersion(2)
    assert result.fencing_generation.value == 1
    assert result.decision is ReconciliationDecision.CONFIRM_SUCCEEDED
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=NOW + timedelta(seconds=5),
        )
        is None
    )

    current = await store.get_current(DURABLE_RUN_ID)
    assert current is not None
    record = reconciliation_disposition_record(current)
    assert record.attempt_id == ATTEMPT_ID
    assert record.actor_id == "maintainer"
    assert record.generation.value == 1
    assert record.decision is ReconciliationDecision.CONFIRM_SUCCEEDED
    assert len(authorizer.requests) == 1
    assert authorizer.requests[0].generation.value == 1
    assert authorizer.requests[0].requested_at == preparation.requested_at
    assert authorizer.requests[0].evidence is not None
    assert authorizer.requests[0].evidence.evidence_digest == _digest("9")
    assert authorizer.requests[0].evidence.metadata == {}

    snapshot = await audit.snapshot()
    assert snapshot.records == 1
    assert snapshot.appended == 1


@pytest.mark.asyncio
async def test_apply_preserves_the_confirmable_requested_at_after_clock_advances() -> None:
    clock = _Clock(NOW + timedelta(seconds=5))
    store, _leases, authorizer, _audit, administration = await _services(clock=clock)
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    assert preparation.requested_at == NOW + timedelta(seconds=5)
    clock.value = NOW + timedelta(seconds=15)

    result = await administration.apply(preparation, context)

    assert result.status is DurableRunStatus.CANCELLED
    assert len(authorizer.requests) == 1
    assert authorizer.requests[0].requested_at == preparation.requested_at
    current = await store.get_current(DURABLE_RUN_ID)
    assert current is not None
    record = reconciliation_disposition_record(current)
    assert record.requested_at == preparation.requested_at
    assert record.applied_at == NOW + timedelta(seconds=15)


@pytest.mark.asyncio
async def test_required_audit_failure_prevents_reconciliation_mutation() -> None:
    audit = AuditLedger()
    store, leases, authorizer, _audit, administration = await _services(audit=audit)
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )
    await audit.close()

    with pytest.raises(AgentServiceUnavailableError):
        await administration.apply(preparation, context)

    current = await store.get_current(DURABLE_RUN_ID)
    assert current is not None
    assert current.run_version == DurableRunVersion(1)
    assert current.status is DurableRunStatus.INDETERMINATE_MODEL
    assert authorizer.requests == []
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=NOW + timedelta(seconds=5),
        )
        is None
    )


@pytest.mark.asyncio
async def test_server_preparation_is_one_time_and_rejects_forged_copy() -> None:
    _store, _leases, _authorizer, _audit, administration = await _services()
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )
    forged = replace(preparation, decision=ReconciliationDecision.FAIL_RUN)

    with pytest.raises(AgentStateConflictError):
        await administration.apply(forged, context)

    result = await administration.apply(preparation, context)
    assert result.status is DurableRunStatus.CANCELLED

    with pytest.raises(AgentStateConflictError):
        await administration.apply(preparation, context)


@pytest.mark.asyncio
async def test_cancel_disposition_never_performs_external_lookup() -> None:
    lookup = _Lookup()
    store, _leases, _authorizer, _audit, administration = await _services(lookup=lookup)
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    assert not hasattr(preparation, "evidence")
    assert not hasattr(preparation, "lookup_result")
    assert preparation.evidence_type is None
    assert preparation.evidence_digest is None
    assert preparation.evidence_observed_at is None
    assert lookup.calls == 0

    result = await administration.apply(preparation, context)
    assert result.status is DurableRunStatus.CANCELLED
    current = await store.get_current(DURABLE_RUN_ID)
    assert current is not None
    assert current.status is DurableRunStatus.CANCELLED


@pytest.mark.asyncio
async def test_preparation_is_bound_to_the_preparing_actor_without_consuming_on_mismatch() -> None:
    _store, _leases, _authorizer, _audit, administration = await _services()
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        _context(AGENT_RECONCILE_ACTION),
    )

    with pytest.raises(AgentStateConflictError):
        await administration.apply(
            preparation,
            _context(AGENT_RECONCILE_ACTION, principal="other-maintainer"),
        )

    result = await administration.apply(
        preparation,
        _context(AGENT_RECONCILE_ACTION),
    )
    assert result.status is DurableRunStatus.CANCELLED


@pytest.mark.asyncio
async def test_expired_preparation_releases_reservation_and_cannot_apply() -> None:
    clock = _Clock(NOW + timedelta(seconds=5))
    _store, leases, _authorizer, _audit, administration = await _services(clock=clock)
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    clock.value = preparation.expires_at
    with pytest.raises(AgentStateConflictError):
        await administration.apply(preparation, context)

    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.expires_at,
        )
        is None
    )


@pytest.mark.asyncio
async def test_discard_releases_the_reserved_reconciliation_lease() -> None:
    _store, leases, _authorizer, _audit, administration = await _services()
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.requested_at,
        )
        is not None
    )

    await administration.discard(preparation.id)

    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.requested_at,
        )
        is None
    )
    with pytest.raises(AgentStateConflictError):
        await administration.apply(preparation, context)


@pytest.mark.asyncio
async def test_close_releases_unused_reserved_reconciliation_lease() -> None:
    _store, leases, _authorizer, _audit, administration = await _services()
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        _context(AGENT_RECONCILE_ACTION),
    )

    await administration.close()

    assert administration.closed
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.requested_at,
        )
        is None
    )


@pytest.mark.asyncio
async def test_close_waits_for_in_flight_reconciliation_before_storage_can_close() -> None:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    leases = InMemoryDurableLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(limits=limits, lease_manager=leases)
    await store.create(_checkpoint())
    authorizer = _AllowAuthorizer()
    delegate = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=authorizer,
    )
    blocking = _BlockingApplier(delegate)
    administration = DurableReconciliationAdministration(
        store=store,
        lease_manager=leases,
        applier=blocking,
        audit=AuditLedger(),
        clock=lambda: NOW + timedelta(seconds=5),
    )
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    apply_task = asyncio.create_task(administration.apply(preparation, context))
    await blocking.started.wait()
    close_task = asyncio.create_task(administration.close())
    await asyncio.sleep(0)
    assert not close_task.done()

    blocking.proceed.set()
    result = await apply_task
    await close_task

    assert result.status is DurableRunStatus.CANCELLED
    assert administration.closed


@pytest.mark.asyncio
async def test_close_cancellation_waits_for_in_flight_reconciliation_before_raising() -> None:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    leases = InMemoryDurableLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(limits=limits, lease_manager=leases)
    await store.create(_checkpoint())
    authorizer = _AllowAuthorizer()
    delegate = StoreBackedDurableReconciliationDispositionApplier(
        store=store,
        authorizer=authorizer,
    )
    blocking = _BlockingApplier(delegate)
    administration = DurableReconciliationAdministration(
        store=store,
        lease_manager=leases,
        applier=blocking,
        audit=AuditLedger(),
        clock=lambda: NOW + timedelta(seconds=5),
    )
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    apply_task = asyncio.create_task(administration.apply(preparation, context))
    await blocking.started.wait()
    close_task = asyncio.create_task(administration.close())
    await asyncio.sleep(0)
    close_task.cancel()
    await asyncio.sleep(0)

    assert not close_task.done()
    assert not apply_task.done()

    blocking.proceed.set()
    result = await apply_task
    with pytest.raises(asyncio.CancelledError):
        await close_task

    assert result.status is DurableRunStatus.CANCELLED
    assert administration.closed
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.requested_at,
        )
        is None
    )


@pytest.mark.asyncio
async def test_unexpected_applier_failure_is_sanitized_and_releases_the_lease() -> None:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    leases = InMemoryDurableLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(limits=limits, lease_manager=leases)
    await store.create(_checkpoint())
    administration = DurableReconciliationAdministration(
        store=store,
        lease_manager=leases,
        applier=_FailingApplier(),
        audit=AuditLedger(),
        clock=lambda: NOW + timedelta(seconds=5),
    )
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    with pytest.raises(AgentServiceUnavailableError) as captured:
        await administration.apply(preparation, context)

    assert captured.value.__cause__ is None
    assert "RAW-INTERNAL-FAILURE" not in str(captured.value)
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=NOW + timedelta(seconds=5),
        )
        is None
    )


@pytest.mark.asyncio
async def test_post_commit_release_cancellation_cannot_turn_success_into_failure() -> None:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    leases = _BlockingReleaseLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(limits=limits, lease_manager=leases)
    await store.create(_checkpoint())
    authorizer = _AllowAuthorizer()
    administration = DurableReconciliationAdministration(
        store=store,
        lease_manager=leases,
        applier=StoreBackedDurableReconciliationDispositionApplier(
            store=store,
            authorizer=authorizer,
        ),
        audit=AuditLedger(),
        clock=lambda: NOW + timedelta(seconds=5),
    )
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    apply_task = asyncio.create_task(administration.apply(preparation, context))
    await leases.release_started.wait()
    apply_task.cancel()
    await asyncio.sleep(0)

    assert not apply_task.done()

    leases.release_proceed.set()
    result = await apply_task

    assert result.status is DurableRunStatus.CANCELLED
    current = await store.get_current(DURABLE_RUN_ID)
    assert current is not None
    assert current.status is DurableRunStatus.CANCELLED
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.requested_at,
        )
        is None
    )


@pytest.mark.asyncio
async def test_post_commit_observer_cancellation_cannot_turn_success_into_failure() -> None:
    limits = DurableRunLimits(
        lease_duration=timedelta(minutes=1),
        lease_renewal_interval=timedelta(seconds=20),
    )
    leases = InMemoryDurableLeaseManager(limits=limits)
    store = InMemoryDurableRunStore(limits=limits, lease_manager=leases)
    await store.create(_checkpoint())
    authorizer = _AllowAuthorizer()
    observer = _BlockingObserver()
    administration = DurableReconciliationAdministration(
        store=store,
        lease_manager=leases,
        applier=StoreBackedDurableReconciliationDispositionApplier(
            store=store,
            authorizer=authorizer,
        ),
        audit=AuditLedger(),
        observer=observer,
        clock=lambda: NOW + timedelta(seconds=5),
    )
    context = _context(AGENT_RECONCILE_ACTION)
    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.CANCEL_RUN,
        context,
    )

    apply_task = asyncio.create_task(administration.apply(preparation, context))
    await observer.started.wait()
    apply_task.cancel()
    result = await apply_task

    assert result.status is DurableRunStatus.CANCELLED
    current = await store.get_current(DURABLE_RUN_ID)
    assert current is not None
    assert current.status is DurableRunStatus.CANCELLED
    assert (
        await leases.get_current(
            DURABLE_RUN_ID,
            now=preparation.requested_at,
        )
        is None
    )


@pytest.mark.asyncio
async def test_direct_runtime_factory_composes_only_with_authorizer_and_audit() -> None:
    store = InMemoryDurableRunStore()
    authorizer = _AllowAuthorizer()
    audit = AuditLedger()

    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        reconciliation_authorizer=authorizer,
        reconciliation_audit=audit,
    )

    assert isinstance(
        stack.reconciliation_administration,
        DurableReconciliationAdministration,
    )
    await stack.close()
    assert stack.reconciliation_administration.closed
    assert not audit.closed


@pytest.mark.asyncio
async def test_direct_runtime_factory_defaults_reconciliation_mutation_off() -> None:
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    assert stack.reconciliation_administration is None
    await stack.close()


def test_direct_runtime_factory_requires_authorizer_and_audit_together() -> None:
    store = InMemoryDurableRunStore()
    with pytest.raises(ValueError, match="requires authorizer and audit"):
        create_durable_agent_runtime_stack(
            store=store,
            lease_manager=store.lease_manager,
            compatibility_validator=StaticDurableCompatibilityValidator(()),
            reconciliation_authorizer=_AllowAuthorizer(),
        )


@pytest.mark.asyncio
async def test_prepared_reconciliation_blocks_cleanup_lease_until_discard() -> None:
    store, leases, _authorizer, _audit, administration = await _services()

    preparation = await administration.prepare(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
        DurableRunVersion(1),
        ReconciliationDecision.REMAIN_INDETERMINATE,
        _context(AGENT_RECONCILE_ACTION),
    )

    with pytest.raises(AgentStateConflictError):
        await leases.acquire(
            DURABLE_RUN_ID,
            owner_id="phoenix-retention",
            now=preparation.prepared_at,
        )

    await administration.discard(preparation.id)

    cleanup_lease = await leases.acquire(
        DURABLE_RUN_ID,
        owner_id="phoenix-retention",
        now=preparation.prepared_at,
    )
    assert cleanup_lease.run_id == DURABLE_RUN_ID
    assert cleanup_lease.owner_id == "phoenix-retention"

    await leases.release(cleanup_lease, now=preparation.prepared_at)
    await administration.close()
    await store.close()
