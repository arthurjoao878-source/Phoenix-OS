from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.approval import (
    InMemoryToolApprovalService,
    ToolApprovalChallenge,
    ToolApprovalRecord,
    ToolApprovalStateService,
    ToolApprovalStatus,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolApprovalId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
)
from phoenix_os.agent.durable_approval import (
    ApprovalWaitReference,
    DurableApprovalRevalidation,
    DurableApprovalRevalidator,
    DurableApprovalState,
    ToolApprovalDurableRevalidator,
    approval_wait_checkpoint_metadata,
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
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 1, 0, tzinfo=UTC)
RECHECK_TIME = NOW + timedelta(seconds=30)
CHECKPOINT_TIME = NOW + timedelta(seconds=1)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000004"))
CHECKPOINT_ID = CheckpointId(UUID("50000000-0000-0000-0000-000000000005"))
SESSION_ID = UUID("60000000-0000-4000-8000-000000000006")
REQUESTER = "worker-1"


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "path": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"path"}),
    )


def _descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId("files.write"),
        name="Write reviewed file",
        description="Write one bounded file in an admitted workspace.",
        input_schema=ToolInputSchema(_schema()),
        output_schema=ToolOutputSchema(
            ToolSchema(
                kind=ToolSchemaType.OBJECT,
                properties={"written": ToolSchema(kind=ToolSchemaType.BOOLEAN)},
                required=frozenset({"written"}),
            )
        ),
        effect=ToolEffect.REVERSIBLE_WRITE,
        approval_may_be_required=True,
        max_input_bytes=4_096,
        max_output_bytes=8_192,
        timeout=timedelta(seconds=10),
        resolver_id="workspace-file",
        adapter_id="deterministic-file-writer",
    )


def _request() -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=AgentId("assistant"),
        run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=ToolId("files.write"),
        arguments={"path": "report.txt"},
        resolved_resource="workspace:docs/report.txt",
        created_at=NOW,
        deadline=NOW + timedelta(minutes=5),
    )


def _requester_context() -> SecurityContext:
    return SecurityContext(
        principal=REQUESTER,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        session_id=SESSION_ID,
    )


def _approver_context() -> SecurityContext:
    return SecurityContext(
        principal="maintainer-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
    )


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


def _checkpoint(
    challenge: ToolApprovalChallenge,
    *,
    approval_metadata: Mapping[str, str] | None = None,
    status: DurableRunStatus = DurableRunStatus.PAUSED_APPROVAL,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.WAIT_APPROVAL,
    actor_id: str = REQUESTER,
    created_at: datetime = CHECKPOINT_TIME,
) -> CheckpointEnvelope:
    values = (
        approval_wait_checkpoint_metadata(challenge, requester=REQUESTER)
        if approval_metadata is None
        else approval_metadata
    )
    metadata_values = {"tenant": "demo", **dict(values)}
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
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id=actor_id,
                next_operation=next_operation,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=NOW,
                    deadline=NOW + timedelta(hours=1),
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=7),
                metadata=metadata_values,
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


async def _challenge(
    service: InMemoryToolApprovalService,
) -> ToolApprovalChallenge:
    return await service.request(
        _request(),
        _descriptor(),
        _requester_context(),
    )


def _legacy_challenge() -> ToolApprovalChallenge:
    return ToolApprovalChallenge(
        approval_id=ToolApprovalId(UUID("80000000-0000-0000-0000-000000000008")),
        run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=ToolId("files.write"),
        effect=ToolEffect.REVERSIBLE_WRITE,
        resolved_resource="workspace:docs/report.txt",
        argument_digest="sha256:" + "b" * 64,
        requested_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
        schema_version=1,
    )


def _mutated_metadata(
    challenge: ToolApprovalChallenge,
    *,
    key: str,
    value: str,
) -> Mapping[str, str]:
    metadata = dict(
        approval_wait_checkpoint_metadata(
            challenge,
            requester=REQUESTER,
        )
    )
    metadata[key] = value
    return metadata


async def test_approval_state_service_protocol_and_pending_record_are_content_free() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)

    assert isinstance(service, ToolApprovalStateService)
    record = await service.lookup(challenge.approval_id)

    assert isinstance(record, ToolApprovalRecord)
    assert record.status is ToolApprovalStatus.PENDING
    assert record.requester == REQUESTER
    assert record.challenge == challenge
    assert record.approved_at is None
    assert record.consumed_at is None
    serialized = repr(record)
    assert "approved_by" not in serialized
    assert "report.txt" not in record.challenge.argument_digest


async def test_lookup_reports_approved_and_consumed_without_mutating_state() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    evidence = await service.approve(challenge.approval_id, _approver_context())

    approved = await service.lookup(challenge.approval_id)
    assert approved is not None
    assert approved.status is ToolApprovalStatus.APPROVED
    assert approved.approved_at == evidence.approved_at
    assert approved.consumed_at is None

    await service.verify_and_consume(
        evidence,
        _request(),
        _descriptor(),
        _requester_context(),
    )
    consumed = await service.lookup(challenge.approval_id)
    assert consumed is not None
    assert consumed.status is ToolApprovalStatus.CONSUMED
    assert consumed.consumed_at is not None


def test_approval_wait_metadata_round_trips_as_immutable_exact_correlation() -> None:
    challenge = ToolApprovalChallenge(
        approval_id=ToolApprovalId(UUID("70000000-0000-0000-0000-000000000007")),
        principal_type=PrincipalType.SERVICE,
        principal=REQUESTER,
        session_id=SESSION_ID,
        agent_id=AgentId("assistant"),
        run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=ToolId("files.write"),
        effect=ToolEffect.REVERSIBLE_WRITE,
        resolver_id="workspace-file",
        adapter_id="deterministic-file-writer",
        resolved_resource="workspace:docs/report.txt",
        argument_digest="sha256:" + "a" * 64,
        requested_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
        schema_version=2,
    )
    metadata = approval_wait_checkpoint_metadata(
        challenge,
        requester=REQUESTER,
    )
    checkpoint = _checkpoint(challenge, approval_metadata=metadata)
    reference = ApprovalWaitReference.from_checkpoint(checkpoint)

    assert reference == ApprovalWaitReference.from_challenge(
        challenge,
        requester=REQUESTER,
    )
    assert reference.to_metadata() == metadata
    with pytest.raises(TypeError):
        metadata["approval.id"] = "other"  # type: ignore[index]
    serialized = repr(metadata)
    assert "approved_by" not in serialized
    assert "approval-token" not in serialized


def test_legacy_approval_wait_reference_default_remains_v1() -> None:
    legacy = _legacy_challenge()
    reference = ApprovalWaitReference(
        legacy.approval_id,
        legacy.run_id,
        legacy.step_id,
        legacy.call_id,
        legacy.tool_id,
        legacy.effect,
        legacy.resolved_resource,
        legacy.argument_digest,
        REQUESTER,
        legacy.requested_at,
        legacy.expires_at,
    )
    assert reference.schema_version == 1
    assert reference.to_metadata()["approval.schema"] == "1"


async def test_legacy_v1_checkpoint_requires_new_approval_without_becoming_authority() -> None:
    legacy = _legacy_challenge()
    metadata = approval_wait_checkpoint_metadata(legacy, requester=REQUESTER)
    assert metadata["approval.schema"] == "1"
    assert "approval.agent" not in metadata
    assert "approval.session-id" not in metadata

    assessment = await ToolApprovalDurableRevalidator(
        InMemoryToolApprovalService(clock=_Clock(NOW))
    ).revalidate(
        _checkpoint(legacy, approval_metadata=metadata),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.REAPPROVAL_REQUIRED
    assert assessment.ready is False
    assert assessment.approval_id == legacy.approval_id


async def test_legacy_v1_recovery_pauses_for_operator_without_authority() -> None:
    legacy = _legacy_challenge()
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(legacy))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        approval_revalidator=ToolApprovalDurableRevalidator(
            InMemoryToolApprovalService(clock=_Clock(NOW))
        ),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECHECK_TIME,
    )

    approval = assessment.approval_revalidation
    assert isinstance(approval, DurableApprovalRevalidation)
    assert approval.state is DurableApprovalState.REAPPROVAL_REQUIRED
    assert approval.ready is False
    assert assessment.point is RecoveryPoint.AWAITING_APPROVAL
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR


@pytest.mark.parametrize(
    "missing_key",
    (
        "approval.schema",
        "approval.id",
        "approval.run",
        "approval.step",
        "approval.call",
        "approval.tool",
        "approval.effect",
        "approval.resource",
        "approval.argument-digest",
        "approval.principal-type",
        "approval.principal",
        "approval.session-id",
        "approval.agent",
        "approval.resolver",
        "approval.adapter",
        "approval.requester",
        "approval.requested-at",
        "approval.expires-at",
    ),
)
async def test_missing_approval_correlation_fails_closed(missing_key: str) -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    metadata = dict(
        approval_wait_checkpoint_metadata(
            challenge,
            requester=REQUESTER,
        )
    )
    del metadata[missing_key]
    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(challenge, approval_metadata=metadata),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.INVALID_CHECKPOINT
    assert assessment.ready is False


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("approval.schema", "3"),
        ("approval.id", "not-a-uuid"),
        ("approval.run", "not-a-uuid"),
        ("approval.step", "not-a-uuid"),
        ("approval.call", "not-a-uuid"),
        ("approval.tool", "Files.Write"),
        ("approval.effect", "unknown"),
        ("approval.principal-type", "unknown"),
        ("approval.session-id", "not-a-uuid"),
        ("approval.agent", "Assistant"),
        ("approval.resolver", "INVALID RESOLVER"),
        ("approval.adapter", "INVALID ADAPTER"),
        ("approval.argument-digest", "sha256:abc"),
        ("approval.requested-at", "2026-08-01T00:00:00"),
        ("approval.expires-at", "not-a-time"),
        ("approval.token", "must-not-persist"),
    ),
)
async def test_malformed_approval_correlation_fails_closed(
    key: str,
    value: str,
) -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(
            challenge,
            approval_metadata=_mutated_metadata(
                challenge,
                key=key,
                value=value,
            ),
        ),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.INVALID_CHECKPOINT


@pytest.mark.parametrize(
    ("checkpoint_change", "expected_state"),
    (
        ("actor", DurableApprovalState.INVALID_CHECKPOINT),
        ("status", DurableApprovalState.INVALID_CHECKPOINT),
        ("future", DurableApprovalState.INVALID_CHECKPOINT),
    ),
)
async def test_checkpoint_identity_or_clock_changes_fail_closed(
    checkpoint_change: str,
    expected_state: DurableApprovalState,
) -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    checkpoint = _checkpoint(challenge)
    now = RECHECK_TIME
    if checkpoint_change == "actor":
        checkpoint = _checkpoint(challenge, actor_id="other-worker")
    elif checkpoint_change == "status":
        checkpoint = _checkpoint(
            challenge,
            status=DurableRunStatus.PAUSED_OPERATOR,
            next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
        )
    else:
        checkpoint = _checkpoint(
            challenge,
            created_at=RECHECK_TIME + timedelta(seconds=1),
        )

    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        checkpoint,
        now=now,
    )

    assert assessment.state is expected_state


async def test_pending_approval_is_revalidated_without_granting_readiness() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    revalidator = ToolApprovalDurableRevalidator(service)

    assessment = await revalidator.revalidate(
        _checkpoint(challenge),
        now=RECHECK_TIME,
    )

    assert isinstance(revalidator, DurableApprovalRevalidator)
    assert assessment.state is DurableApprovalState.PENDING
    assert assessment.ready is False
    assert assessment.approval_id == challenge.approval_id


async def test_approved_revalidation_is_non_consuming_and_grants_no_tool_authority() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    evidence = await service.approve(challenge.approval_id, _approver_context())

    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(challenge),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.APPROVED
    assert assessment.ready is True
    current = await service.lookup(challenge.approval_id)
    assert current is not None
    assert current.status is ToolApprovalStatus.APPROVED

    verification = await service.verify_and_consume(
        evidence,
        _request(),
        _descriptor(),
        _requester_context(),
    )
    assert verification.approval_id == challenge.approval_id


async def test_consumed_approval_never_becomes_ready_again() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    evidence = await service.approve(challenge.approval_id, _approver_context())
    await service.verify_and_consume(
        evidence,
        _request(),
        _descriptor(),
        _requester_context(),
    )

    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(challenge),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.CONSUMED
    assert assessment.ready is False


@pytest.mark.parametrize("approve_first", (False, True))
async def test_expired_pending_or_approved_state_fails_closed(
    approve_first: bool,
) -> None:
    clock = _Clock(NOW)
    service = InMemoryToolApprovalService(
        ttl=timedelta(seconds=20),
        clock=clock,
    )
    challenge = await _challenge(service)
    if approve_first:
        await service.approve(challenge.approval_id, _approver_context())
    clock.advance(timedelta(seconds=30))

    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(challenge),
        now=clock.value,
    )

    assert assessment.state is DurableApprovalState.EXPIRED
    assert assessment.ready is False


async def test_unknown_approval_record_is_missing_not_approved() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    await service.close()
    replacement = InMemoryToolApprovalService(clock=_Clock(NOW))

    assessment = await ToolApprovalDurableRevalidator(replacement).revalidate(
        _checkpoint(challenge),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.MISSING
    assert assessment.ready is False


async def test_closed_approval_service_is_unavailable_not_approved() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    await service.close()

    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(challenge),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.UNAVAILABLE
    assert assessment.ready is False


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("approval.resource", "workspace:docs/other.txt"),
        ("approval.requester", "other-worker"),
        (
            "approval.call",
            "70000000-0000-0000-0000-000000000007",
        ),
    ),
)
async def test_live_record_mismatch_never_reuses_approval(
    key: str,
    value: str,
) -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    metadata = _mutated_metadata(challenge, key=key, value=value)
    actor_id = value if key == "approval.requester" else REQUESTER

    assessment = await ToolApprovalDurableRevalidator(service).revalidate(
        _checkpoint(
            challenge,
            approval_metadata=metadata,
            actor_id=actor_id,
        ),
        now=RECHECK_TIME,
    )

    assert assessment.state is DurableApprovalState.MISMATCHED
    assert assessment.ready is False


@pytest.mark.parametrize("approved", (False, True))
async def test_recovery_attaches_current_approval_state_but_does_not_resume(
    approved: bool,
) -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    if approved:
        await service.approve(challenge.approval_id, _approver_context())
    checkpoint = _checkpoint(challenge)
    store = InMemoryDurableRunStore()
    await store.create(checkpoint)
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        approval_revalidator=ToolApprovalDurableRevalidator(service),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECHECK_TIME,
    )

    approval = assessment.approval_revalidation
    assert isinstance(approval, DurableApprovalRevalidation)
    assert approval.ready is approved
    assert assessment.point is RecoveryPoint.AWAITING_APPROVAL
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert (
        await store.lease_manager.get_current(
            DURABLE_RUN_ID,
            now=RECHECK_TIME,
        )
        is None
    )


async def test_recovery_terminates_substituted_approval_correlation() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    metadata = _mutated_metadata(
        challenge,
        key="approval.resource",
        value="workspace:docs/substituted.txt",
    )
    store = InMemoryDurableRunStore()
    await store.create(
        _checkpoint(
            challenge,
            approval_metadata=metadata,
        )
    )
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
        approval_revalidator=ToolApprovalDurableRevalidator(service),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECHECK_TIME,
    )

    assert assessment.approval_revalidation is not None
    assert assessment.approval_revalidation.state is DurableApprovalState.MISMATCHED
    assert assessment.point is RecoveryPoint.UNSAFE_STATE
    assert assessment.disposition is RecoveryDisposition.TERMINATE_FAILED
    assert (
        await store.lease_manager.get_current(
            DURABLE_RUN_ID,
            now=RECHECK_TIME,
        )
        is None
    )


async def test_recovery_without_revalidator_preserves_safe_operator_pause() -> None:
    service = InMemoryToolApprovalService(clock=_Clock(NOW))
    challenge = await _challenge(service)
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(challenge))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECHECK_TIME,
    )

    assert assessment.approval_revalidation is None
    assert assessment.point is RecoveryPoint.AWAITING_APPROVAL
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR


def test_revalidation_state_values_are_stable() -> None:
    assert tuple(DurableApprovalState) == (
        DurableApprovalState.PENDING,
        DurableApprovalState.APPROVED,
        DurableApprovalState.REAPPROVAL_REQUIRED,
        DurableApprovalState.CONSUMED,
        DurableApprovalState.EXPIRED,
        DurableApprovalState.MISSING,
        DurableApprovalState.MISMATCHED,
        DurableApprovalState.UNAVAILABLE,
        DurableApprovalState.INVALID_CHECKPOINT,
    )
