from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_attempts import StoreBackedDurableExecutionAttemptRecorder
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
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.host_automation import (
    DeterministicHostAutomationAdapter,
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostAutomationApprovalChallenge,
    HostAutomationApprovalEvidence,
    HostAutomationApprovalStatus,
    HostAutomationService,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostId,
    HostProcessListRequest,
    HostWindowFocusRequest,
    HostWindowListRequest,
    InMemoryHostAutomationApprovalGate,
)
from phoenix_os.host_automation.authorization import HOST_APPLICATION_CLOSE_ACTION
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 15, 22, 30, tzinfo=UTC)
_LEASE_TIME = _NOW + timedelta(seconds=1)
_PREPARE_TIME = _NOW + timedelta(seconds=2)
_START_TIME = _NOW + timedelta(seconds=3)
_EFFECT_TIME = _NOW + timedelta(seconds=4)
_RECOVERY_TIME = _NOW + timedelta(minutes=10)

_DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000041"))
_AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000042"))
_STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000043"))
_TOOL_CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000044"))
_HOST = HostId("desktop")
_APP = HostApplicationId("editor")


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


def _checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("50000000-0000-0000-0000-000000000045")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="host-close-worker",
                next_operation=CheckpointNextOperation.TOOL_INVOCATION,
                budget=AgentBudgetSnapshot(
                    steps=1,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=16,
                    output_tokens=0,
                    started_at=_NOW,
                    deadline=_NOW + timedelta(hours=1),
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=7),
                metadata={"tenant": "demo"},
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _approver() -> SecurityContext:
    return SecurityContext(
        principal="user:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
    )


def _close_request_digest(request: HostApplicationCloseRequest) -> CheckpointDigest:
    material = (
        f"phoenix-host-durable-close:v1:{HOST_APPLICATION_CLOSE_ACTION}:"
        f"{request.host_id}:{request.host_epoch}:{request.application_id}:"
        f"{request.process_id}:{request.request_id}"
    ).encode()
    return CheckpointDigest(hashlib.sha256(material).hexdigest())


class _CountingHostAutomationAdapter(DeterministicHostAutomationAdapter):
    def __init__(
        self,
        *,
        host_id: HostId,
        applications: tuple[HostApplicationId, ...],
    ) -> None:
        super().__init__(host_id=host_id, applications=applications)
        self.close_calls = 0

    async def close_application(
        self,
        request: HostApplicationCloseRequest,
    ) -> HostApplicationCloseResult:
        self.close_calls += 1
        return await super().close_application(request)


class _RecordingHostAuthorizer:
    def __init__(self) -> None:
        self.close_authorizations = 0

    async def authorize_process_list(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_window_list(
        self,
        request: HostWindowListRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_application_launch(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_window_focus(
        self,
        request: HostWindowFocusRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_application_close(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.close_authorizations += 1

    async def authorize_clipboard_write(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_clipboard_read(
        self,
        request: HostClipboardReadRequest,
        context: SecurityContext,
    ) -> None:
        del request, context


async def _approved_host_close() -> tuple[
    HostAutomationService,
    _CountingHostAutomationAdapter,
    _RecordingHostAuthorizer,
    InMemoryHostAutomationApprovalGate,
    HostApplicationCloseRequest,
    HostAutomationApprovalChallenge,
    HostAutomationApprovalEvidence,
]:
    adapter = _CountingHostAutomationAdapter(
        host_id=_HOST,
        applications=(_APP,),
    )
    authorizer = _RecordingHostAuthorizer()
    gate = InMemoryHostAutomationApprovalGate(clock=lambda: _EFFECT_TIME)
    service = HostAutomationService(
        adapter=adapter,
        authorizer=authorizer,
        approval_gate=gate,
        require_application_close_approval=True,
    )
    launched = await service.launch_application(
        HostApplicationLaunchRequest(
            host_id=_HOST,
            application_id=_APP,
            created_at=_NOW,
        ),
        _context(),
    )
    request = HostApplicationCloseRequest(
        host_id=_HOST,
        host_epoch=launched.host_epoch,
        application_id=_APP,
        process_id=launched.process_id,
        created_at=_NOW,
    )
    challenge = await service.request_application_close_approval(
        request,
        _context(),
    )
    evidence = await gate.approve(challenge.approval_id, _approver())
    return service, adapter, authorizer, gate, request, challenge, evidence


@pytest.mark.asyncio
@pytest.mark.parametrize("effect_was_admitted", [False, True])
async def test_durable_recovery_never_reissues_started_host_close(
    effect_was_admitted: bool,
) -> None:
    (
        service,
        adapter,
        authorizer,
        gate,
        request,
        challenge,
        evidence,
    ) = await _approved_host_close()

    initial = _checkpoint()
    store = InMemoryDurableRunStore()
    await store.create(initial)
    lease = await store.lease_manager.acquire(
        _DURABLE_RUN_ID,
        owner_id="host-close-worker",
        now=_LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(store=store)
    request_digest = _close_request_digest(request)
    prepared = await recorder.prepare_tool_attempt(
        _DURABLE_RUN_ID,
        expected_version=initial.run_version,
        lease=lease,
        tool_call_id=_TOOL_CALL_ID,
        tool_effect=ToolEffect.IRREVERSIBLE_WRITE,
        external_request_digest=request_digest,
        now=_PREPARE_TIME,
    )
    prepared_attempt = prepared.metadata.active_attempt
    assert prepared_attempt is not None

    started = await recorder.mark_started(
        _DURABLE_RUN_ID,
        prepared_attempt.attempt_id,
        expected_version=prepared.run_version,
        lease=lease,
        now=_START_TIME,
    )
    started_attempt = started.metadata.active_attempt
    assert started_attempt is not None
    assert started_attempt.kind is ExecutionAttemptKind.TOOL_INVOCATION
    assert started_attempt.status is ExecutionAttemptStatus.STARTED
    assert started_attempt.tool_effect is ToolEffect.IRREVERSIBLE_WRITE
    assert started_attempt.external_request_digest == request_digest

    if effect_was_admitted:
        result = await service.close_application(
            request,
            _context(),
            approval=evidence,
        )
        assert result.process_id == request.process_id

    expected_close_calls = 1 if effect_was_admitted else 0
    expected_authorizations = 2 if effect_was_admitted else 1
    assert adapter.close_calls == expected_close_calls
    assert authorizer.close_authorizations == expected_authorizations

    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_compatibility_validator(),
    )
    assessment = await coordinator.persist_indeterminate_candidate(
        _DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=_RECOVERY_TIME,
        reason=IndeterminateReason.PROCESS_LOSS,
    )

    assert adapter.close_calls == expected_close_calls
    assert authorizer.close_authorizations == expected_authorizations
    assert assessment.status is DurableRunStatus.INDETERMINATE_TOOL
    assert assessment.point is RecoveryPoint.ACTIVE_TOOL_ATTEMPT
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert assessment.approval_revalidation is None

    recovered = await store.get_current(_DURABLE_RUN_ID)
    assert recovered is not None
    assert recovered.status is DurableRunStatus.INDETERMINATE_TOOL
    assert recovered.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
    recovered_attempt = recovered.metadata.active_attempt
    assert recovered_attempt is not None
    assert recovered_attempt.status is ExecutionAttemptStatus.INDETERMINATE
    assert recovered_attempt.indeterminate_reason is IndeterminateReason.PROCESS_LOSS
    assert recovered_attempt.tool_effect is ToolEffect.IRREVERSIBLE_WRITE
    assert recovered_attempt.external_request_digest == request_digest
    assert recovered_attempt.started_at == _START_TIME
    assert recovered_attempt.completed_at == _RECOVERY_TIME

    approval = await gate.lookup(challenge.approval_id)
    assert approval is not None
    assert approval.status is (
        HostAutomationApprovalStatus.CONSUMED
        if effect_was_admitted
        else HostAutomationApprovalStatus.APPROVED
    )

    listed = await adapter.list_processes(
        HostProcessListRequest(
            host_id=_HOST,
            created_at=_RECOVERY_TIME,
        )
    )
    if effect_was_admitted:
        assert listed.processes == ()
    else:
        assert [item.process_id for item in listed.processes] == [request.process_id]

    serialized = repr(recovered)
    assert str(challenge.approval_id) not in serialized
    assert evidence.approved_by not in serialized
