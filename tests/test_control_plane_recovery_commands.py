from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.capabilities import (
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    RiskLevel,
)
from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlaneBrowserOrigin,
    ControlPlaneCancelWorkflowCommand,
    ControlPlaneCommandAction,
    ControlPlaneCommandAuthorizer,
    ControlPlaneCommandBindingError,
    ControlPlaneCommandIntent,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneCommandReceipt,
    ControlPlaneCommandStatus,
    ControlPlaneConfirmationProof,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfRejectedError,
    ControlPlaneJobCommandHandler,
    ControlPlanePrincipal,
    ControlPlaneRetryDeadLetterJobCommand,
    ControlPlaneWorkflowCommandHandler,
    ControlPlaneWorkflowCommandResult,
    ControlPlaneWorkflowOrchestrator,
    IdempotencyKey,
    InMemoryControlPlaneConfirmationService,
    InMemoryControlPlaneIdempotencyStore,
)
from phoenix_os.control_plane.protection import ControlPlaneCommandProtector
from phoenix_os.jobs import (
    InMemoryJobRepository,
    JobRecord,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
    RetryPolicy,
)
from phoenix_os.workflows import (
    InMemoryWorkflowRepository,
    WorkflowDefinition,
    WorkflowOrchestrator,
    WorkflowPlanner,
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStep,
)

_NOW = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8765")
_OTHER_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:9999")
_SECRET = b"r" * 32
_RETRY_PERMISSION = ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB.permission
_CANCEL_WORKFLOW_PERMISSION = ControlPlaneCommandAction.CANCEL_WORKFLOW.permission
_RETRY_COMMAND_ID = UUID(int=501)
_WORKFLOW_COMMAND_ID = UUID(int=601)


class _Nonces:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, size: int) -> bytes:
        self.value += 1
        return bytes([self.value]) * size


class _FailingSchedule:
    def __init__(self, scheduler: JobScheduler, *, create_then_raise: bool = False) -> None:
        self._scheduler = scheduler
        self._create_then_raise = create_then_raise

    async def schedule(
        self,
        spec: JobSpec,
        *,
        job_id: UUID | None = None,
        now: datetime | None = None,
    ) -> JobRecord:
        if self._create_then_raise:
            await self._scheduler.schedule(spec, job_id=job_id, now=now)
        raise RuntimeError("internal scheduler detail")

    async def get(self, job_id: UUID) -> JobRecord | None:
        return await self._scheduler.get(job_id)

    async def cancel(self, job_id: UUID, *, now: datetime | None = None) -> bool:
        return await self._scheduler.cancel(job_id, now=now)


class _WorkflowStub:
    def __init__(
        self,
        record: WorkflowRecord | None,
        *,
        returned: WorkflowRecord | None = None,
        raise_after: WorkflowRecord | None = None,
    ) -> None:
        self.record = record
        self.returned = returned
        self.raise_after = raise_after
        self.cancel_calls = 0

    async def get(self, workflow_id: UUID) -> WorkflowRecord | None:
        if self.record is None or self.record.id != workflow_id:
            return None
        return self.record

    async def cancel(
        self,
        workflow_id: UUID,
        *,
        now: datetime | None = None,
    ) -> WorkflowRecord:
        self.cancel_calls += 1
        if self.raise_after is not None:
            self.record = self.raise_after
            raise RuntimeError("internal orchestrator detail")
        if self.returned is None:
            raise RuntimeError("internal orchestrator detail")
        self.record = self.returned
        return self.returned


def _principal(*permissions: str) -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        "operator",
        frozenset({CONTROL_PLANE_READ_PERMISSION, *permissions}),
    )


def _protection() -> tuple[ControlPlaneCsrfProtector, ControlPlaneCommandProtector]:
    csrf = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    confirmations = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    return csrf, ControlPlaneCommandProtector(csrf, confirmations)


async def _registry(
    *,
    descriptor: CapabilityDescriptor | None = None,
    fail: bool = False,
) -> CapabilityRegistry:
    registry = CapabilityRegistry()
    selected = descriptor or CapabilityDescriptor("test.retry")

    def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        if fail:
            raise RuntimeError("provider detail")
        return {"job": str(invocation.id)}

    await registry.register(selected, provider)
    return registry


async def _dead_letter(
    scheduler: JobScheduler,
    *,
    capability: str = "test.retry",
    metadata: dict[str, str] | None = None,
) -> UUID:
    record = await scheduler.schedule(
        JobSpec(
            capability,
            JobSchedule(_NOW),
            arguments={"safe": True},
            retry=RetryPolicy(max_attempts=1),
            metadata={} if metadata is None else metadata,
        ),
        job_id=UUID(int=400),
        now=_NOW,
    )
    runs = await scheduler.run_due(now=_NOW)
    assert len(runs) == 1
    failed = await scheduler.get(record.id)
    assert failed is not None
    assert failed.status is JobStatus.DEAD_LETTER
    return failed.id


async def _retry_stack(
    *,
    descriptor: CapabilityDescriptor | None = None,
    permissions: frozenset[str] | None = None,
    scheduler_wrapper: str | None = None,
) -> tuple[
    CapabilityRegistry,
    JobScheduler,
    ControlPlaneJobCommandHandler,
    ControlPlaneCsrfProtector,
    InMemoryControlPlaneIdempotencyStore,
    ControlPlanePrincipal,
    UUID,
]:
    registry = await _registry(descriptor=descriptor, fail=True)
    repository = InMemoryJobRepository()
    scheduler = JobScheduler(repository, registry)
    original_id = await _dead_letter(scheduler)
    csrf, protector = _protection()
    idempotency = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    principal = ControlPlanePrincipal(
        "operator",
        permissions
        or frozenset(
            {
                CONTROL_PLANE_READ_PERMISSION,
                _RETRY_PERMISSION,
            }
        ),
    )
    selected_scheduler: object = scheduler
    if scheduler_wrapper == "fail":
        selected_scheduler = _FailingSchedule(scheduler)
    elif scheduler_wrapper == "partial":
        selected_scheduler = _FailingSchedule(scheduler, create_then_raise=True)
    handler = ControlPlaneJobCommandHandler(
        selected_scheduler,  # type: ignore[arg-type]
        registry,
        ControlPlaneCommandAuthorizer(),
        protector,
        idempotency,
    )
    return registry, scheduler, handler, csrf, idempotency, principal, original_id


def _retry_context(
    job_id: UUID,
    *,
    key: str = "retry-dead-letter-0001",
    command_id: UUID = _RETRY_COMMAND_ID,
) -> tuple[ControlPlaneRetryDeadLetterJobCommand, ControlPlaneCommandIntent]:
    command = ControlPlaneRetryDeadLetterJobCommand(job_id)
    intent = command.intent(
        IdempotencyKey(key),
        requested_at=_NOW,
        command_id=command_id,
    )
    return command, intent


async def _workflow_records() -> tuple[
    WorkflowOrchestrator,
    WorkflowRecord,
    WorkflowRecord,
    WorkflowRecord,
]:
    registry = await _registry(descriptor=CapabilityDescriptor("workflow.step"))
    jobs = JobScheduler(InMemoryJobRepository(), registry)
    repository = InMemoryWorkflowRepository()
    orchestrator = WorkflowOrchestrator(repository, jobs, planner=WorkflowPlanner())
    definition = WorkflowDefinition("one", (WorkflowStep("step", "workflow.step"),))

    running = await orchestrator.start(definition, workflow_id=UUID(int=700), now=_NOW)

    cancelled_seed = await orchestrator.start(
        definition,
        workflow_id=UUID(int=701),
        now=_NOW,
    )
    cancelled = await orchestrator.cancel(cancelled_seed.id, now=_NOW + timedelta(seconds=1))

    succeeded_seed = await orchestrator.start(
        definition,
        workflow_id=UUID(int=702),
        now=_NOW,
    )
    await jobs.run_due(now=_NOW)
    succeeded = await orchestrator.advance(
        succeeded_seed.id,
        now=_NOW + timedelta(seconds=2),
    )
    assert running.status is WorkflowStatus.RUNNING
    assert cancelled.status is WorkflowStatus.CANCELLED
    assert succeeded.status is WorkflowStatus.SUCCEEDED
    return orchestrator, running, cancelled, succeeded


def _workflow_security(
    orchestrator: ControlPlaneWorkflowOrchestrator,
    *,
    permissions: frozenset[str] | None = None,
) -> tuple[
    ControlPlaneWorkflowCommandHandler,
    ControlPlaneCsrfProtector,
    InMemoryControlPlaneIdempotencyStore,
    ControlPlanePrincipal,
]:
    csrf, protector = _protection()
    idempotency = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=3))
    principal = ControlPlanePrincipal(
        "operator",
        permissions
        or frozenset(
            {
                CONTROL_PLANE_READ_PERMISSION,
                _CANCEL_WORKFLOW_PERMISSION,
            }
        ),
    )
    handler = ControlPlaneWorkflowCommandHandler(
        orchestrator,
        ControlPlaneCommandAuthorizer(),
        protector,
        idempotency,
    )
    return handler, csrf, idempotency, principal


async def _workflow_context(
    handler: ControlPlaneWorkflowCommandHandler,
    csrf: ControlPlaneCsrfProtector,
    principal: ControlPlanePrincipal,
    workflow_id: UUID,
    *,
    key: str = "cancel-workflow-0001",
    command_id: UUID = _WORKFLOW_COMMAND_ID,
) -> tuple[
    ControlPlaneCancelWorkflowCommand,
    ControlPlaneCommandIntent,
    ControlPlaneConfirmationProof,
]:
    command = ControlPlaneCancelWorkflowCommand(workflow_id)
    intent = command.intent(
        IdempotencyKey(key),
        requested_at=_NOW,
        command_id=command_id,
    )
    challenge = await handler.issue_cancel_confirmation(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )
    return command, intent, challenge.proof


def test_retry_dead_letter_command_builds_exact_bound_intent() -> None:
    command, intent = _retry_context(UUID(int=2))

    assert command.target == f"job:{UUID(int=2)}"
    assert intent.action is ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB
    assert intent.target == command.target
    assert intent.payload_digest == command.payload_digest


def test_retry_dead_letter_command_rejects_unknown_schema() -> None:
    with pytest.raises(ValueError, match="schema version"):
        ControlPlaneRetryDeadLetterJobCommand(UUID(int=1), schema_version=2)


@pytest.mark.asyncio
async def test_retry_dead_letter_creates_new_one_time_job_with_trusted_context() -> None:
    _, scheduler, handler, csrf, _, principal, original_id = await _retry_stack()
    command, intent = _retry_context(original_id)

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )
    original = await scheduler.get(original_id)
    retried = await scheduler.get(_RETRY_COMMAND_ID)

    assert result.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert result.receipt.result_code == "job.retried"
    assert result.job_id == _RETRY_COMMAND_ID
    assert original is not None and original.status is JobStatus.DEAD_LETTER
    assert retried is not None and retried.status is JobStatus.SCHEDULED
    assert retried.spec.schedule.interval is None
    assert retried.spec.schedule.run_at == _NOW
    assert retried.spec.arguments == original.spec.arguments
    assert retried.spec.retry == original.spec.retry
    assert retried.spec.context.principal == principal.name
    assert retried.spec.context.permissions == principal.permissions
    assert retried.spec.context.request_id == _RETRY_COMMAND_ID
    assert retried.spec.metadata == {}


@pytest.mark.asyncio
async def test_retry_dead_letter_replay_does_not_create_duplicate_job() -> None:
    _, scheduler, handler, csrf, _, principal, original_id = await _retry_stack()
    command, intent = _retry_context(original_id)
    first = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )
    replay_command, replay_intent = _retry_context(original_id, command_id=UUID(int=999))

    replay = await handler.retry_dead_letter_job(
        principal,
        replay_intent,
        replay_command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert replay == first
    assert (await scheduler.snapshot()).jobs == 2


@pytest.mark.asyncio
async def test_retry_dead_letter_recovers_after_schedule_partial_failure() -> None:
    _, scheduler, handler, csrf, _, principal, original_id = await _retry_stack(
        scheduler_wrapper="partial"
    )
    command, intent = _retry_context(original_id)

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert result.receipt.result_code == "job.retried"
    assert await scheduler.get(_RETRY_COMMAND_ID) is not None


@pytest.mark.asyncio
async def test_retry_dead_letter_returns_safe_failure_on_schedule_error() -> None:
    _, _, handler, csrf, _, principal, original_id = await _retry_stack(scheduler_wrapper="fail")
    command, intent = _retry_context(original_id)

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert result.receipt.status is ControlPlaneCommandStatus.FAILED
    assert result.receipt.result_code == "job.retry-failed"
    assert result.job_id is None


@pytest.mark.asyncio
async def test_retry_dead_letter_requires_exact_permission_before_reservation() -> None:
    _, _, handler, csrf, idempotency, principal, original_id = await _retry_stack(
        permissions=frozenset({CONTROL_PLANE_READ_PERMISSION})
    )
    command, intent = _retry_context(original_id)

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await handler.retry_dead_letter_job(
            principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
        )

    assert (await idempotency.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_retry_dead_letter_rejects_csrf_before_reservation() -> None:
    _, _, handler, csrf, idempotency, principal, original_id = await _retry_stack()
    command, intent = _retry_context(original_id)

    with pytest.raises(ControlPlaneCsrfRejectedError):
        await handler.retry_dead_letter_job(
            principal,
            intent,
            command,
            origin=_OTHER_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
        )

    assert (await idempotency.snapshot()).entries == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["action", "target", "payload_digest"])
async def test_retry_dead_letter_rejects_intent_binding_mismatch(field: str) -> None:
    _, _, handler, csrf, _, principal, original_id = await _retry_stack()
    command, intent = _retry_context(original_id)
    if field == "action":
        intent = replace(intent, action=ControlPlaneCommandAction.CREATE_JOB)
    elif field == "target":
        intent = replace(intent, target="job:other")
    else:
        intent = replace(intent, payload_digest="0" * 64)

    with pytest.raises(ControlPlaneCommandBindingError):
        await handler.retry_dead_letter_job(
            principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
        )


@pytest.mark.asyncio
async def test_retry_dead_letter_rejects_missing_job() -> None:
    _, _, handler, csrf, _, principal, _ = await _retry_stack()
    command, intent = _retry_context(UUID(int=404))

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert result.receipt.result_code == "job.not-found"


@pytest.mark.asyncio
async def test_retry_dead_letter_rejects_non_dead_letter_job() -> None:
    registry, scheduler, handler, csrf, _, principal, _ = await _retry_stack()
    record = await scheduler.schedule(
        JobSpec("test.retry", JobSchedule(_NOW + timedelta(minutes=1))),
        job_id=UUID(int=405),
        now=_NOW,
    )
    assert await registry.describe("test.retry")
    command, intent = _retry_context(record.id)

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert result.receipt.result_code == "job.not-dead-letter"


@pytest.mark.asyncio
async def test_retry_dead_letter_rejects_workflow_owned_job() -> None:
    registry = await _registry(fail=True)
    scheduler = JobScheduler(InMemoryJobRepository(), registry)
    original_id = await _dead_letter(
        scheduler,
        metadata={"phoenix.workflow_id": "opaque", "phoenix.workflow_step": "step"},
    )
    csrf, protector = _protection()
    idempotency = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW)
    principal = _principal(_RETRY_PERMISSION)
    handler = ControlPlaneJobCommandHandler(
        scheduler,
        registry,
        ControlPlaneCommandAuthorizer(),
        protector,
        idempotency,
    )
    command, intent = _retry_context(original_id)

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert result.receipt.result_code == "job.retry-unsupported-owner"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("descriptor", "permissions", "code"),
    [
        (
            CapabilityDescriptor(
                "test.retry",
                required_permissions=frozenset({"mail.send"}),
            ),
            frozenset({CONTROL_PLANE_READ_PERMISSION, _RETRY_PERMISSION}),
            "capability.not-authorized",
        ),
        (
            CapabilityDescriptor("test.retry", risk=RiskLevel.DESTRUCTIVE),
            frozenset({CONTROL_PLANE_READ_PERMISSION, _RETRY_PERMISSION}),
            "capability.unsupported-risk",
        ),
        (
            CapabilityDescriptor("test.retry", confirmation_required=True),
            frozenset({CONTROL_PLANE_READ_PERMISSION, _RETRY_PERMISSION}),
            "capability.unsupported-risk",
        ),
    ],
)
async def test_retry_dead_letter_revalidates_capability_policy(
    descriptor: CapabilityDescriptor,
    permissions: frozenset[str],
    code: str,
) -> None:
    _, _, handler, csrf, _, principal, original_id = await _retry_stack(
        descriptor=descriptor,
        permissions=permissions,
    )
    command, intent = _retry_context(original_id)

    result = await handler.retry_dead_letter_job(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
    )

    assert result.receipt.result_code == code


def test_cancel_workflow_command_builds_exact_bound_intent() -> None:
    command = ControlPlaneCancelWorkflowCommand(UUID(int=7))
    intent = command.intent(
        IdempotencyKey("cancel-workflow-contract-0001"),
        requested_at=_NOW,
        command_id=UUID(int=8),
    )

    assert command.target == f"workflow:{UUID(int=7)}"
    assert intent.action is ControlPlaneCommandAction.CANCEL_WORKFLOW
    assert intent.target == command.target
    assert intent.payload_digest == command.payload_digest


def test_cancel_workflow_command_rejects_unknown_schema() -> None:
    with pytest.raises(ValueError, match="schema version"):
        ControlPlaneCancelWorkflowCommand(UUID(int=1), schema_version=2)


@pytest.mark.asyncio
async def test_cancel_workflow_handler_cancels_running_workflow() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        running.id,
    )

    result = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )
    current = await orchestrator.get(running.id)

    assert result.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert result.receipt.result_code == "workflow.cancelled"
    assert current is not None and current.status is WorkflowStatus.CANCELLED


@pytest.mark.asyncio
async def test_cancel_workflow_replay_returns_original_receipt() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        running.id,
    )
    first = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )
    replay_command, replay_intent, replay_proof = await _workflow_context(
        handler,
        csrf,
        principal,
        running.id,
        command_id=UUID(int=777),
    )

    replay = await handler.cancel_workflow(
        principal,
        replay_intent,
        replay_command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=replay_proof,
    )

    assert replay == first


@pytest.mark.asyncio
async def test_cancel_workflow_treats_already_cancelled_as_success() -> None:
    orchestrator, _, cancelled, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        cancelled.id,
    )

    result = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert result.receipt.result_code == "workflow.cancelled"


@pytest.mark.asyncio
async def test_cancel_workflow_rejects_succeeded_workflow() -> None:
    orchestrator, _, _, succeeded = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        succeeded.id,
    )

    result = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.status is ControlPlaneCommandStatus.FAILED
    assert result.receipt.result_code == "workflow.not-cancellable"


@pytest.mark.asyncio
async def test_cancel_workflow_rejects_missing_workflow() -> None:
    orchestrator, _, _, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        UUID(int=404),
    )

    result = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.result_code == "workflow.not-found"


@pytest.mark.asyncio
async def test_cancel_workflow_requires_exact_permission_before_confirmation() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, idempotency, principal = _workflow_security(
        orchestrator,
        permissions=frozenset({CONTROL_PLANE_READ_PERMISSION}),
    )
    command = ControlPlaneCancelWorkflowCommand(running.id)
    intent = command.intent(
        IdempotencyKey("cancel-workflow-denied-0001"),
        requested_at=_NOW,
    )

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await handler.issue_cancel_confirmation(
            principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
        )

    assert (await idempotency.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_cancel_workflow_rejects_csrf_before_confirmation() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command = ControlPlaneCancelWorkflowCommand(running.id)
    intent = command.intent(
        IdempotencyKey("cancel-workflow-csrf-0001"),
        requested_at=_NOW,
    )

    with pytest.raises(ControlPlaneCsrfRejectedError):
        await handler.issue_cancel_confirmation(
            principal,
            intent,
            command,
            origin=_OTHER_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["action", "target", "payload_digest"])
async def test_cancel_workflow_rejects_intent_binding_mismatch(field: str) -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command = ControlPlaneCancelWorkflowCommand(running.id)
    intent = command.intent(
        IdempotencyKey(f"cancel-workflow-binding-{field}"),
        requested_at=_NOW,
    )
    if field == "action":
        intent = replace(intent, action=ControlPlaneCommandAction.CANCEL_JOB)
    elif field == "target":
        intent = replace(intent, target="workflow:other")
    else:
        intent = replace(intent, payload_digest="0" * 64)

    with pytest.raises(ControlPlaneCommandBindingError):
        await handler.issue_cancel_confirmation(
            principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
        )


@pytest.mark.asyncio
async def test_cancel_workflow_requires_confirmation_proof() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, idempotency, principal = _workflow_security(orchestrator)
    command = ControlPlaneCancelWorkflowCommand(running.id)
    intent = command.intent(
        IdempotencyKey("cancel-workflow-proof-0001"),
        requested_at=_NOW,
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await handler.cancel_workflow(
            principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
            confirmation=ControlPlaneConfirmationProof("v1.1." + "A" * 43 + "." + "B" * 43),
        )

    assert (await idempotency.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_cancel_workflow_rejects_replayed_confirmation() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    handler, csrf, _, principal = _workflow_security(orchestrator)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        running.id,
    )
    await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await handler.cancel_workflow(
            principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=csrf.issue(principal, _ORIGIN),
            confirmation=proof,
        )


@pytest.mark.asyncio
async def test_cancel_workflow_recovers_when_orchestrator_mutates_then_raises() -> None:
    orchestrator, running, _, _ = await _workflow_records()
    cancelled = await orchestrator.cancel(running.id, now=_NOW + timedelta(seconds=4))
    stub = _WorkflowStub(running, raise_after=cancelled)
    handler, csrf, _, principal = _workflow_security(stub)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        running.id,
    )

    result = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.result_code == "workflow.cancelled"


@pytest.mark.asyncio
async def test_cancel_workflow_returns_safe_failure_on_orchestrator_error() -> None:
    _, running, _, _ = await _workflow_records()
    stub = _WorkflowStub(running)
    handler, csrf, _, principal = _workflow_security(stub)
    command, intent, proof = await _workflow_context(
        handler,
        csrf,
        principal,
        running.id,
    )

    result = await handler.cancel_workflow(
        principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=csrf.issue(principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.result_code == "workflow.cancel-failed"


def test_workflow_command_result_rejects_non_workflow_receipt() -> None:
    receipt = ControlPlaneCommandReceipt(
        command_id=UUID(int=1),
        action=ControlPlaneCommandAction.CANCEL_JOB,
        target="job:1",
        status=ControlPlaneCommandStatus.FAILED,
        created_at=_NOW,
        completed_at=_NOW,
        result_code="job.not-found",
    )

    with pytest.raises(ValueError, match=r"workflow\.cancel"):
        ControlPlaneWorkflowCommandResult(receipt)
