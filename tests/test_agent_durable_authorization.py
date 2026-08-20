from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AGENT_RECONCILE_ACTION,
    AGENT_RESUME_ACTION,
    AgentAuthorizationRejectedError,
    AgentId,
    AgentRunId,
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
    DurableLease,
    DurableLeaseId,
    DurableReconciliationAuthorizer,
    DurableResumeAuthorizer,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    FencingGeneration,
    IndeterminateReason,
    PolicyEngineDurableReconciliationAuthorizer,
    PolicyEngineDurableResumeAuthorizer,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
    ResumeReason,
    ResumeRequest,
    ToolCallId,
    ToolEffect,
    durable_agent_run_resource,
    durable_reconciliation_resource,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.policy import (
    PolicyDecision,
    PolicyEffect,
    PolicyEngine,
    PolicyRequest,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

NOW = datetime(2026, 8, 1, 2, tzinfo=UTC)
REQUEST_TIME = NOW + timedelta(minutes=10)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004"))
OTHER_ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000005"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000005"))
LEASE_ID = DurableLeaseId(UUID("60000000-0000-0000-0000-000000000006"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget(*, deadline: datetime | None = None) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=NOW - timedelta(minutes=1),
        deadline=deadline or NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind,
    status: ExecutionAttemptStatus,
    *,
    attempt_id: ExecutionAttemptId = ATTEMPT_ID,
) -> ExecutionAttempt:
    started_at = (
        NOW + timedelta(minutes=1) if status is not ExecutionAttemptStatus.PREPARED else None
    )
    completed_at = NOW + timedelta(minutes=2) if status.terminal else None
    return ExecutionAttempt(
        attempt_id=attempt_id,
        kind=kind,
        status=status,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW,
        tool_call_id=TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None,
        tool_effect=(
            ToolEffect.IRREVERSIBLE_WRITE if kind is ExecutionAttemptKind.TOOL_INVOCATION else None
        ),
        started_at=started_at,
        completed_at=completed_at,
        external_request_digest=_digest("e"),
        indeterminate_reason=(
            IndeterminateReason.PROCESS_LOSS
            if status is ExecutionAttemptStatus.INDETERMINATE
            else None
        ),
        error_code=(
            "attempt-failed"
            if status
            in {
                ExecutionAttemptStatus.FAILED,
                ExecutionAttemptStatus.TIMED_OUT,
            }
            else None
        ),
    )


def _checkpoint(
    *,
    durable_run_id: DurableAgentRunId = DURABLE_RUN_ID,
    status: DurableRunStatus = DurableRunStatus.PAUSED_SHUTDOWN,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
    version: int = 3,
    created_at: datetime = NOW,
    budget_deadline: datetime | None = None,
    retention_deadline: datetime | None = None,
) -> CheckpointEnvelope:
    if status.terminal:
        next_operation = CheckpointNextOperation.NONE
        active_attempt = None
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=durable_run_id,
            checkpoint_id=CheckpointId(UUID(int=0x70000000000000000000000000000000 + version)),
            sequence=CheckpointSequence(version),
            previous_digest=_digest("f") if version > 1 else None,
            run_version=DurableRunVersion(version),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=next_operation,
                budget=_budget(deadline=budget_deadline),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=retention_deadline or NOW + timedelta(days=7),
                active_attempt=active_attempt,
                metadata={"tenant": "demo"},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _indeterminate_checkpoint(
    kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN,
    *,
    attempt_id: ExecutionAttemptId = ATTEMPT_ID,
) -> CheckpointEnvelope:
    return _checkpoint(
        status=(
            DurableRunStatus.INDETERMINATE_MODEL
            if kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        ),
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            kind,
            ExecutionAttemptStatus.INDETERMINATE,
            attempt_id=attempt_id,
        ),
    )


def _context(
    *,
    actor_id: str = "operator-1",
    authenticated: bool = True,
    principal: str | None = None,
    trusted_actor_id: str | None = None,
) -> SecurityContext:
    attributes = {} if trusted_actor_id is None else {"durable_actor_id": trusted_actor_id}
    return SecurityContext(
        principal=principal or actor_id,
        principal_type=(PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS),
        authenticated=authenticated,
        attributes=attributes,
    )


def _resume_request(
    checkpoint: CheckpointEnvelope,
    *,
    actor_id: str = "operator-1",
    run_id: DurableAgentRunId | None = None,
    version: DurableRunVersion | None = None,
    generation: FencingGeneration | None = None,
    reason: ResumeReason = ResumeReason.OPERATOR_REQUEST,
    requested_at: datetime = REQUEST_TIME,
) -> ResumeRequest:
    return ResumeRequest(
        run_id=checkpoint.durable_run_id if run_id is None else run_id,
        actor_id=actor_id,
        reason=reason,
        expected_version=checkpoint.run_version if version is None else version,
        generation=FencingGeneration(7) if generation is None else generation,
        requested_at=requested_at,
    )


def _lease(
    checkpoint: CheckpointEnvelope,
    *,
    run_id: DurableAgentRunId | None = None,
    generation: int = 7,
    acquired_at: datetime = NOW + timedelta(minutes=1),
    expires_at: datetime = REQUEST_TIME + timedelta(minutes=1),
) -> DurableLease:
    return DurableLease(
        run_id=checkpoint.durable_run_id if run_id is None else run_id,
        lease_id=LEASE_ID,
        owner_id="reconcile-worker",
        generation=FencingGeneration(generation),
        acquired_at=acquired_at,
        expires_at=expires_at,
    )


class _CurrentResumeLeaseManager:
    def __init__(self, current: DurableLease | None) -> None:
        self.current = current
        self.require_current_calls: list[tuple[DurableLease, datetime]] = []

    @property
    def closed(self) -> bool:
        return False

    async def acquire(self, *args: object, **kwargs: object) -> DurableLease:
        raise AssertionError("acquire is outside resume authorization")

    async def get_current(self, *args: object, **kwargs: object) -> DurableLease | None:
        raise AssertionError("get_current is outside resume authorization")

    async def renew(self, *args: object, **kwargs: object) -> DurableLease:
        raise AssertionError("renew is outside resume authorization")

    async def require_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> DurableLease:
        self.require_current_calls.append((lease, now))
        current = self.current
        if (
            current is None
            or current.run_id != lease.run_id
            or current.lease_id != lease.lease_id
            or current.owner_id != lease.owner_id
            or current.generation != lease.generation
            or not current.active_at(now)
        ):
            raise AgentStateConflictError()
        return current

    def guard_current(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> AbstractAsyncContextManager[DurableLease]:
        raise AssertionError("guard_current is outside resume authorization")

    async def release(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("release is outside resume authorization")

    async def close(self) -> None:
        raise AssertionError("close is outside resume authorization")


def _resume_authorizer(
    policy: PolicyEngine,
    *,
    current_lease: DurableLease | None = None,
    clock: Callable[[], datetime] | None = None,
) -> PolicyEngineDurableResumeAuthorizer:
    selected_lease = _lease(_checkpoint()) if current_lease is None else current_lease
    selected_clock = (lambda: REQUEST_TIME) if clock is None else clock
    return PolicyEngineDurableResumeAuthorizer(
        policy,
        _CurrentResumeLeaseManager(selected_lease),
        clock=selected_clock,
    )


def _evidence(
    *,
    observed_at: datetime = REQUEST_TIME - timedelta(seconds=1),
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        evidence_type="provider-receipt",
        evidence_digest=_digest("9"),
        observed_at=observed_at,
        metadata={"source": "reviewed-adapter"},
    )


def _reconciliation_request(
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
    *,
    actor_id: str = "operator-1",
    run_id: DurableAgentRunId | None = None,
    attempt_id: ExecutionAttemptId | None = None,
    version: DurableRunVersion | None = None,
    generation: FencingGeneration | None = None,
    decision: ReconciliationDecision = ReconciliationDecision.REMAIN_INDETERMINATE,
    evidence: ReconciliationEvidence | None = None,
    requested_at: datetime = REQUEST_TIME,
) -> ReconciliationRequest:
    attempt = checkpoint.metadata.active_attempt
    if attempt is None:
        raise AssertionError("reconciliation helper requires an active attempt")
    return ReconciliationRequest(
        run_id=checkpoint.durable_run_id if run_id is None else run_id,
        attempt_id=attempt.attempt_id if attempt_id is None else attempt_id,
        actor_id=actor_id,
        expected_version=checkpoint.run_version if version is None else version,
        generation=lease.generation if generation is None else generation,
        decision=decision,
        evidence=evidence,
        requested_at=requested_at,
    )


def _allow_rule(
    *,
    action: str,
    resource: str,
    attributes: dict[str, str] | None = None,
) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow.{action.replace('.', '-')}",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({"operator-1", "service:recovery"}),
        authenticated=True,
        attribute_equals=attributes or {},
    )


class _RecordingPolicyEngine(PolicyEngine):
    def __init__(self, rules: tuple[PolicyRule, ...]) -> None:
        super().__init__(rules)
        self.requests: list[PolicyRequest] = []

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        self.requests.append(request)
        return await super().enforce(request)


class _ReplacingPolicyEngine(_RecordingPolicyEngine):
    def __init__(
        self,
        rules: tuple[PolicyRule, ...],
        *,
        lease_manager: _CurrentResumeLeaseManager,
        replacement: DurableLease,
    ) -> None:
        super().__init__(rules)
        self._lease_manager = lease_manager
        self._replacement = replacement

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        self._lease_manager.current = self._replacement
        return await super().enforce(request)


def test_actions_and_resources_are_exact() -> None:
    assert AGENT_RESUME_ACTION == "agent.resume"
    assert AGENT_RECONCILE_ACTION == "agent.reconcile"
    assert durable_agent_run_resource(DURABLE_RUN_ID) == (f"durable-agent-run:{DURABLE_RUN_ID}")
    assert durable_reconciliation_resource(DURABLE_RUN_ID, ATTEMPT_ID) == (
        f"durable-agent-run:{DURABLE_RUN_ID}/attempt:{ATTEMPT_ID}"
    )


@pytest.mark.parametrize(
    ("function", "arguments"),
    (
        (durable_agent_run_resource, ("not-a-run",)),
        (durable_reconciliation_resource, ("not-a-run", ATTEMPT_ID)),
        (durable_reconciliation_resource, (DURABLE_RUN_ID, "not-an-attempt")),
    ),
)
def test_resource_helpers_reject_wrong_types(
    function: Callable[..., str],
    arguments: tuple[object, ...],
) -> None:
    with pytest.raises(TypeError):
        function(*arguments)


def test_public_authorizers_implement_protocols() -> None:
    policy = PolicyEngine()
    assert isinstance(
        _resume_authorizer(policy),
        DurableResumeAuthorizer,
    )
    assert isinstance(
        PolicyEngineDurableReconciliationAuthorizer(policy),
        DurableReconciliationAuthorizer,
    )


def test_resume_authorizer_constructor_requires_policy_engine() -> None:
    with pytest.raises(TypeError, match="PolicyEngine"):
        PolicyEngineDurableResumeAuthorizer(
            object(),  # type: ignore[arg-type]
            _CurrentResumeLeaseManager(_lease(_checkpoint())),
        )


def test_resume_authorizer_constructor_requires_lease_manager() -> None:
    with pytest.raises(TypeError, match="DurableLeaseManager"):
        PolicyEngineDurableResumeAuthorizer(
            PolicyEngine(),
            object(),  # type: ignore[arg-type]
        )


def test_reconciliation_authorizer_constructor_requires_policy_engine() -> None:
    with pytest.raises(TypeError, match="PolicyEngine"):
        PolicyEngineDurableReconciliationAuthorizer(object())  # type: ignore[arg-type]


async def test_resume_authorization_allows_one_exact_request() -> None:
    checkpoint = _checkpoint()
    request = _resume_request(checkpoint)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
                attributes={
                    "current_status": DurableRunStatus.PAUSED_SHUTDOWN.value,
                    "expected_version": "3",
                    "fencing_generation": "7",
                    "resume_reason": ResumeReason.OPERATOR_REQUEST.value,
                },
            ),
        )
    )

    await _resume_authorizer(policy).authorize(
        request,
        checkpoint,
        _lease(checkpoint),
        _context(),
    )

    assert (await policy.snapshot()).allowed == 1


async def test_resume_rejects_noncurrent_lease_before_policy() -> None:
    checkpoint = _checkpoint()
    supplied = _lease(checkpoint)
    replacement = _lease(
        checkpoint,
        generation=8,
        acquired_at=REQUEST_TIME,
        expires_at=REQUEST_TIME + timedelta(minutes=5),
    )
    manager = _CurrentResumeLeaseManager(replacement)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableResumeAuthorizer(
            policy,
            manager,
            clock=lambda: REQUEST_TIME,
        ).authorize(
            _resume_request(checkpoint),
            checkpoint,
            supplied,
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0
    assert len(manager.require_current_calls) == 1


async def test_resume_revalidates_current_lease_after_policy() -> None:
    checkpoint = _checkpoint()
    supplied = _lease(checkpoint)
    replacement = _lease(
        checkpoint,
        generation=8,
        acquired_at=REQUEST_TIME,
        expires_at=REQUEST_TIME + timedelta(minutes=5),
    )
    manager = _CurrentResumeLeaseManager(supplied)
    policy = _ReplacingPolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        ),
        lease_manager=manager,
        replacement=replacement,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableResumeAuthorizer(
            policy,
            manager,
            clock=lambda: REQUEST_TIME,
        ).authorize(
            _resume_request(checkpoint),
            checkpoint,
            supplied,
            _context(),
        )

    assert (await policy.snapshot()).allowed == 1
    assert len(manager.require_current_calls) == 2


async def test_resume_accepts_renewed_current_lease_with_same_fenced_identity() -> None:
    checkpoint = _checkpoint()
    supplied = _lease(
        checkpoint,
        expires_at=REQUEST_TIME + timedelta(seconds=1),
    )
    renewed = DurableLease(
        run_id=supplied.run_id,
        lease_id=supplied.lease_id,
        owner_id=supplied.owner_id,
        generation=supplied.generation,
        acquired_at=REQUEST_TIME + timedelta(seconds=1),
        expires_at=REQUEST_TIME + timedelta(minutes=5),
    )
    manager = _CurrentResumeLeaseManager(renewed)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )
    admitted_at = REQUEST_TIME + timedelta(seconds=2)

    await PolicyEngineDurableResumeAuthorizer(
        policy,
        manager,
        clock=lambda: admitted_at,
    ).authorize(
        _resume_request(checkpoint),
        checkpoint,
        supplied,
        _context(),
    )

    assert (await policy.snapshot()).allowed == 1
    assert len(manager.require_current_calls) == 2
    assert all(now == admitted_at for _, now in manager.require_current_calls)


async def test_resume_rejects_lease_expiry_after_policy_before_admission() -> None:
    checkpoint = _checkpoint()
    lease = _lease(
        checkpoint,
        expires_at=REQUEST_TIME + timedelta(seconds=1),
    )
    manager = _CurrentResumeLeaseManager(lease)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )
    times = iter(
        (
            REQUEST_TIME,
            REQUEST_TIME + timedelta(seconds=1),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableResumeAuthorizer(
            policy,
            manager,
            clock=lambda: next(times),
        ).authorize(
            _resume_request(checkpoint),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).allowed == 1
    assert len(manager.require_current_calls) == 2


@pytest.mark.parametrize(
    "checkpoint",
    (
        _checkpoint(budget_deadline=REQUEST_TIME + timedelta(seconds=1)),
        _checkpoint(retention_deadline=REQUEST_TIME + timedelta(seconds=1)),
    ),
)
async def test_resume_rejects_deadline_expiry_after_policy_before_admission(
    checkpoint: CheckpointEnvelope,
) -> None:
    lease = _lease(checkpoint)
    manager = _CurrentResumeLeaseManager(lease)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )
    times = iter(
        (
            REQUEST_TIME,
            REQUEST_TIME + timedelta(seconds=1),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableResumeAuthorizer(
            policy,
            manager,
            clock=lambda: next(times),
        ).authorize(
            _resume_request(checkpoint),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).allowed == 1
    assert len(manager.require_current_calls) == 1


async def test_resume_rejects_clock_regression_after_policy() -> None:
    checkpoint = _checkpoint()
    lease = _lease(checkpoint)
    manager = _CurrentResumeLeaseManager(lease)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )
    times = iter(
        (
            REQUEST_TIME,
            REQUEST_TIME - timedelta(seconds=1),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableResumeAuthorizer(
            policy,
            manager,
            clock=lambda: next(times),
        ).authorize(
            _resume_request(checkpoint),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).allowed == 1
    assert len(manager.require_current_calls) == 1


async def test_resume_authorization_is_default_deny() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )

    assert (await policy.snapshot()).denied == 1


async def test_resume_permission_does_not_grant_reconciliation() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            _reconciliation_request(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )


async def test_reconcile_permission_does_not_grant_resume() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(DURABLE_RUN_ID, ATTEMPT_ID),
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )


async def test_resume_resource_is_bound_to_exact_run() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(OTHER_RUN_ID),
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )


@pytest.mark.parametrize(
    "status",
    (
        DurableRunStatus.CHECKPOINTING,
        DurableRunStatus.RECOVERING,
        DurableRunStatus.RECONCILING,
        DurableRunStatus.COMPLETED,
        DurableRunStatus.FAILED,
        DurableRunStatus.CANCELLED,
        DurableRunStatus.EXPIRED,
    ),
)
async def test_resume_rejects_non_resumable_states_before_policy(
    status: DurableRunStatus,
) -> None:
    checkpoint = _checkpoint(status=status)
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.parametrize(
    "kind",
    (
        ExecutionAttemptKind.MODEL_TURN,
        ExecutionAttemptKind.TOOL_INVOCATION,
    ),
)
async def test_resume_rejects_started_attempt_before_policy(
    kind: ExecutionAttemptKind,
) -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.ACTIVE,
        next_operation=(
            CheckpointNextOperation.MODEL_TURN
            if kind is ExecutionAttemptKind.MODEL_TURN
            else CheckpointNextOperation.TOOL_INVOCATION
        ),
        active_attempt=_attempt(kind, ExecutionAttemptStatus.STARTED),
    )
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_resume_allows_prepared_attempt_after_exact_policy() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.ACTIVE,
        active_attempt=_attempt(
            ExecutionAttemptKind.MODEL_TURN,
            ExecutionAttemptStatus.PREPARED,
        ),
    )
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
                attributes={"attempt_status": "prepared"},
            ),
        )
    )

    await _resume_authorizer(policy).authorize(
        _resume_request(checkpoint),
        checkpoint,
        _lease(checkpoint),
        _context(),
    )


@pytest.mark.parametrize(
    "request_factory",
    (
        lambda checkpoint: _resume_request(checkpoint, run_id=OTHER_RUN_ID),
        lambda checkpoint: _resume_request(
            checkpoint,
            version=checkpoint.run_version.next(),
        ),
        lambda checkpoint: _resume_request(
            checkpoint,
            generation=FencingGeneration(8),
        ),
        lambda checkpoint: _resume_request(
            checkpoint,
            requested_at=checkpoint.created_at - timedelta(seconds=1),
        ),
    ),
)
async def test_resume_rejects_identity_version_generation_or_time_mismatch_before_policy(
    request_factory: Callable[[CheckpointEnvelope], ResumeRequest],
) -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            request_factory(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.parametrize(
    "lease_factory",
    (
        lambda checkpoint: _lease(checkpoint, run_id=OTHER_RUN_ID),
        lambda checkpoint: _lease(
            checkpoint,
            generation=8,
        ),
        lambda checkpoint: _lease(
            checkpoint,
            expires_at=REQUEST_TIME,
        ),
        lambda checkpoint: _lease(
            checkpoint,
            acquired_at=REQUEST_TIME + timedelta(seconds=1),
            expires_at=REQUEST_TIME + timedelta(minutes=5),
        ),
    ),
)
async def test_resume_rejects_foreign_generation_or_inactive_lease_before_policy(
    lease_factory: Callable[[CheckpointEnvelope], DurableLease],
) -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            lease_factory(checkpoint),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.parametrize(
    "checkpoint",
    (
        _checkpoint(budget_deadline=REQUEST_TIME),
        _checkpoint(retention_deadline=REQUEST_TIME),
    ),
)
async def test_resume_rejects_expired_budget_or_retention_before_policy(
    checkpoint: CheckpointEnvelope,
) -> None:
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_resume_requires_authenticated_exact_actor() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(actor_id="other-operator"),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await _resume_authorizer(policy).authorize(
            _resume_request(checkpoint),
            checkpoint,
            _lease(checkpoint),
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_trusted_durable_actor_attribute_binds_namespaced_principal() -> None:
    checkpoint = _checkpoint()
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )

    await _resume_authorizer(policy).authorize(
        _resume_request(checkpoint),
        checkpoint,
        _lease(checkpoint),
        _context(
            principal="service:recovery",
            trusted_actor_id="operator-1",
        ),
    )


async def test_resume_policy_input_is_content_free_and_deterministic() -> None:
    checkpoint = _checkpoint()
    policy = _RecordingPolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )

    await _resume_authorizer(policy).authorize(
        _resume_request(checkpoint),
        checkpoint,
        _lease(checkpoint),
        _context(),
    )

    assert len(policy.requests) == 1
    request = policy.requests[0]
    assert request.created_at == REQUEST_TIME
    assert request.action == AGENT_RESUME_ACTION
    assert request.resource == durable_agent_run_resource(DURABLE_RUN_ID)
    assert set(request.attributes) == {
        "agent_id",
        "agent_run_id",
        "actor_id",
        "attempt_kind",
        "attempt_status",
        "checkpoint_sequence",
        "current_status",
        "effect",
        "expected_version",
        "fencing_generation",
        "next_operation",
        "payload_profile",
        "resume_reason",
        "run_id",
    }
    assert "prompt" not in request.attributes
    assert "result" not in request.attributes


async def test_resume_authorization_does_not_mutate_checkpoint() -> None:
    checkpoint = _checkpoint()
    before = checkpoint
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(DURABLE_RUN_ID),
            ),
        )
    )

    await _resume_authorizer(policy).authorize(
        _resume_request(checkpoint),
        checkpoint,
        _lease(checkpoint),
        _context(),
    )

    assert checkpoint == before


async def test_reconciliation_authorization_allows_one_exact_request() -> None:
    checkpoint = _indeterminate_checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    lease = _lease(checkpoint)
    request = _reconciliation_request(
        checkpoint,
        lease,
        decision=ReconciliationDecision.CONFIRM_SUCCEEDED,
        evidence=_evidence(),
    )
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    DURABLE_RUN_ID,
                    ATTEMPT_ID,
                ),
                attributes={
                    "attempt_kind": "tool_invocation",
                    "decision": "confirm_succeeded",
                    "evidence_type": "provider-receipt",
                    "fencing_generation": "7",
                },
            ),
        )
    )

    await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
        request,
        checkpoint,
        lease,
        _context(),
    )

    assert (await policy.snapshot()).allowed == 1


async def test_reconciliation_authorization_is_default_deny() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            _reconciliation_request(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).denied == 1


async def test_reconciliation_resource_is_bound_to_exact_attempt() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    DURABLE_RUN_ID,
                    OTHER_ATTEMPT_ID,
                ),
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            _reconciliation_request(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )


@pytest.mark.parametrize(
    "decision",
    tuple(ReconciliationDecision),
)
async def test_each_reviewed_reconciliation_decision_requires_exact_policy(
    decision: ReconciliationDecision,
) -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    evidence = (
        _evidence()
        if decision
        in {
            ReconciliationDecision.CONFIRM_SUCCEEDED,
            ReconciliationDecision.CONFIRM_NOT_STARTED,
        }
        else None
    )
    request = _reconciliation_request(
        checkpoint,
        lease,
        decision=decision,
        evidence=evidence,
    )
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    DURABLE_RUN_ID,
                    ATTEMPT_ID,
                ),
                attributes={"decision": decision.value},
            ),
        )
    )

    await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
        request,
        checkpoint,
        lease,
        _context(),
    )


@pytest.mark.parametrize(
    "request_factory",
    (
        lambda checkpoint, lease: _reconciliation_request(
            checkpoint,
            lease,
            run_id=OTHER_RUN_ID,
        ),
        lambda checkpoint, lease: _reconciliation_request(
            checkpoint,
            lease,
            attempt_id=OTHER_ATTEMPT_ID,
        ),
        lambda checkpoint, lease: _reconciliation_request(
            checkpoint,
            lease,
            version=checkpoint.run_version.next(),
        ),
        lambda checkpoint, lease: _reconciliation_request(
            checkpoint,
            lease,
            generation=lease.generation.next(),
        ),
    ),
)
async def test_reconciliation_rejects_exact_identity_mismatches_before_policy(
    request_factory: Callable[[CheckpointEnvelope, DurableLease], ReconciliationRequest],
) -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            request_factory(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.parametrize(
    "lease_factory",
    (
        lambda checkpoint: _lease(checkpoint, run_id=OTHER_RUN_ID),
        lambda checkpoint: _lease(
            checkpoint,
            expires_at=REQUEST_TIME,
        ),
        lambda checkpoint: _lease(
            checkpoint,
            acquired_at=REQUEST_TIME + timedelta(seconds=1),
            expires_at=REQUEST_TIME + timedelta(minutes=5),
        ),
    ),
)
async def test_reconciliation_rejects_foreign_or_inactive_lease_before_policy(
    lease_factory: Callable[[CheckpointEnvelope], DurableLease],
) -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = lease_factory(checkpoint)
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            _reconciliation_request(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.parametrize(
    "checkpoint",
    (
        _checkpoint(status=DurableRunStatus.PAUSED_OPERATOR),
        _checkpoint(
            status=DurableRunStatus.ACTIVE,
            active_attempt=_attempt(
                ExecutionAttemptKind.MODEL_TURN,
                ExecutionAttemptStatus.STARTED,
            ),
        ),
    ),
)
async def test_reconciliation_requires_persisted_indeterminate_state_before_policy(
    checkpoint: CheckpointEnvelope,
) -> None:
    lease = _lease(checkpoint)
    policy = PolicyEngine()
    request = ReconciliationRequest(
        run_id=checkpoint.durable_run_id,
        attempt_id=ATTEMPT_ID,
        actor_id="operator-1",
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        decision=ReconciliationDecision.REMAIN_INDETERMINATE,
        requested_at=REQUEST_TIME,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            request,
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_reconciliation_requires_authenticated_exact_actor() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    policy = PolicyEngine()
    request = _reconciliation_request(checkpoint, lease)

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            request,
            checkpoint,
            lease,
            _context(actor_id="other-operator"),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            request,
            checkpoint,
            lease,
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_reconciliation_rejects_future_evidence_before_policy() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    policy = PolicyEngine()
    request = _reconciliation_request(
        checkpoint,
        lease,
        decision=ReconciliationDecision.CONFIRM_SUCCEEDED,
        evidence=_evidence(observed_at=REQUEST_TIME + timedelta(seconds=1)),
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            request,
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_reconciliation_remains_available_after_execution_budget_expiry() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            ExecutionAttemptKind.MODEL_TURN,
            ExecutionAttemptStatus.INDETERMINATE,
        ),
        budget_deadline=REQUEST_TIME,
    )
    lease = _lease(checkpoint)
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    DURABLE_RUN_ID,
                    ATTEMPT_ID,
                ),
            ),
        )
    )

    await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
        _reconciliation_request(checkpoint, lease),
        checkpoint,
        lease,
        _context(),
    )


async def test_reconciliation_rejects_retention_expiry_before_policy() -> None:
    checkpoint = _checkpoint(
        status=DurableRunStatus.INDETERMINATE_MODEL,
        next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        active_attempt=_attempt(
            ExecutionAttemptKind.MODEL_TURN,
            ExecutionAttemptStatus.INDETERMINATE,
        ),
        retention_deadline=REQUEST_TIME,
    )
    lease = _lease(checkpoint)
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
            _reconciliation_request(checkpoint, lease),
            checkpoint,
            lease,
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


async def test_reconciliation_policy_input_is_content_free_and_exact() -> None:
    checkpoint = _indeterminate_checkpoint(ExecutionAttemptKind.TOOL_INVOCATION)
    lease = _lease(checkpoint)
    policy = _RecordingPolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    DURABLE_RUN_ID,
                    ATTEMPT_ID,
                ),
            ),
        )
    )

    await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
        _reconciliation_request(
            checkpoint,
            lease,
            decision=ReconciliationDecision.CONFIRM_SUCCEEDED,
            evidence=_evidence(),
        ),
        checkpoint,
        lease,
        _context(),
    )

    assert len(policy.requests) == 1
    request = policy.requests[0]
    assert request.created_at == REQUEST_TIME
    assert request.action == AGENT_RECONCILE_ACTION
    assert request.resource == durable_reconciliation_resource(
        DURABLE_RUN_ID,
        ATTEMPT_ID,
    )
    assert set(request.attributes) == {
        "actor_id",
        "attempt_id",
        "attempt_kind",
        "attempt_status",
        "checkpoint_sequence",
        "current_status",
        "decision",
        "effect",
        "evidence_present",
        "evidence_type",
        "expected_version",
        "fencing_generation",
        "run_id",
    }
    assert request.attributes["effect"] == ToolEffect.IRREVERSIBLE_WRITE.value
    assert "evidence_digest" not in request.attributes
    assert "metadata" not in request.attributes
    assert "result" not in request.attributes


async def test_reconciliation_authorization_does_not_mutate_checkpoint_or_lease() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    before_checkpoint = checkpoint
    before_lease = lease
    policy = PolicyEngine(
        (
            _allow_rule(
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    DURABLE_RUN_ID,
                    ATTEMPT_ID,
                ),
            ),
        )
    )

    await PolicyEngineDurableReconciliationAuthorizer(policy).authorize(
        _reconciliation_request(checkpoint, lease),
        checkpoint,
        lease,
        _context(),
    )

    assert checkpoint == before_checkpoint
    assert lease == before_lease


async def test_resume_authorizer_rejects_wrong_request_type() -> None:
    checkpoint = _checkpoint()
    with pytest.raises(TypeError, match="ResumeRequest"):
        await _resume_authorizer(PolicyEngine()).authorize(
            object(),  # type: ignore[arg-type]
            checkpoint,
            _lease(checkpoint),
            _context(),
        )


async def test_resume_authorizer_rejects_wrong_lease_type() -> None:
    checkpoint = _checkpoint()
    with pytest.raises(TypeError, match="DurableLease"):
        await _resume_authorizer(PolicyEngine()).authorize(
            _resume_request(checkpoint),
            checkpoint,
            object(),  # type: ignore[arg-type]
            _context(),
        )


async def test_reconciliation_authorizer_rejects_wrong_request_type() -> None:
    checkpoint = _indeterminate_checkpoint()
    lease = _lease(checkpoint)
    with pytest.raises(TypeError, match="ReconciliationRequest"):
        await PolicyEngineDurableReconciliationAuthorizer(PolicyEngine()).authorize(
            object(),  # type: ignore[arg-type]
            checkpoint,
            lease,
            _context(),
        )
