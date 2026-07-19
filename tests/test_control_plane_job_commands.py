from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.capabilities import (
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    RiskLevel,
)
from phoenix_os.configuration import SecretValue
from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    MAX_JOB_COMMAND_ARGUMENT_BYTES,
    ControlPlaneBrowserOrigin,
    ControlPlaneCancelJobCommand,
    ControlPlaneCommandAction,
    ControlPlaneCommandAuthorizer,
    ControlPlaneCommandBindingError,
    ControlPlaneCommandIntent,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneCommandStatus,
    ControlPlaneConfirmationProof,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneCreateJobCommand,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfRejectedError,
    ControlPlaneJobCommandHandler,
    ControlPlaneJobCommandResult,
    ControlPlanePrincipal,
    IdempotencyKey,
    InMemoryControlPlaneConfirmationService,
    InMemoryControlPlaneIdempotencyStore,
    command_receipt_to_dict,
)
from phoenix_os.control_plane.protection import ControlPlaneCommandProtector
from phoenix_os.jobs import (
    InMemoryJobRepository,
    JobRepository,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
)

_NOW = datetime(2026, 7, 19, 7, 0, tzinfo=UTC)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8765")
_SECRET = b"j" * 32
_CREATE_PERMISSION = ControlPlaneCommandAction.CREATE_JOB.permission
_CANCEL_PERMISSION = ControlPlaneCommandAction.CANCEL_JOB.permission
_CREATE_COMMAND_ID = UUID(int=1)
_CANCEL_COMMAND_ID = UUID(int=2)


class _Nonces:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, size: int) -> bytes:
        self.value += 1
        return bytes([self.value]) * size


class _Stack:
    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        scheduler: JobScheduler,
        repository: JobRepository,
        handler: ControlPlaneJobCommandHandler,
        csrf: ControlPlaneCsrfProtector,
        idempotency: InMemoryControlPlaneIdempotencyStore,
        principal: ControlPlanePrincipal,
    ) -> None:
        self.registry = registry
        self.scheduler = scheduler
        self.repository = repository
        self.handler = handler
        self.csrf = csrf
        self.idempotency = idempotency
        self.principal = principal


async def _stack(
    *,
    descriptor: CapabilityDescriptor | None = None,
    permissions: frozenset[str] | None = None,
    provider: Callable[[CapabilityInvocation], Mapping[str, object]] | None = None,
    scheduler: JobScheduler | None = None,
) -> _Stack:
    registry = CapabilityRegistry()
    selected = descriptor or CapabilityDescriptor("test.echo")

    def default_provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        return {"arguments": tuple(sorted(invocation.arguments))}

    await registry.register(selected, provider or default_provider)
    repository = InMemoryJobRepository()
    selected_scheduler = scheduler or JobScheduler(repository, registry)
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
    idempotency = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    principal = ControlPlanePrincipal(
        "operator",
        permissions
        or frozenset(
            {
                CONTROL_PLANE_READ_PERMISSION,
                _CREATE_PERMISSION,
                _CANCEL_PERMISSION,
            }
        ),
    )
    handler = ControlPlaneJobCommandHandler(
        selected_scheduler,
        registry,
        ControlPlaneCommandAuthorizer(),
        ControlPlaneCommandProtector(csrf, confirmations),
        idempotency,
    )
    return _Stack(
        registry=registry,
        scheduler=selected_scheduler,
        repository=repository,
        handler=handler,
        csrf=csrf,
        idempotency=idempotency,
        principal=principal,
    )


def _create_command(**overrides: object) -> ControlPlaneCreateJobCommand:
    values: dict[str, Any] = {
        "capability": "test.echo",
        "run_at": _NOW + timedelta(minutes=5),
        "arguments": {"message": "hello", "nested": [1, {"ok": True}]},
        "max_attempts": 3,
        "initial_retry_delay": timedelta(seconds=2),
        "max_retry_delay": timedelta(minutes=1),
        "deadline": 30.0,
    }
    values.update(overrides)
    return ControlPlaneCreateJobCommand(**values)


def _create_intent(
    command: ControlPlaneCreateJobCommand,
    *,
    key: str = "create-job-command-0001",
    command_id: UUID = _CREATE_COMMAND_ID,
) -> ControlPlaneCommandIntent:
    return command.intent(
        IdempotencyKey(key),
        requested_at=_NOW,
        command_id=command_id,
    )


async def _cancel_context(
    stack: _Stack,
    job_id: UUID,
    *,
    key: str = "cancel-job-command-0001",
    command_id: UUID = _CANCEL_COMMAND_ID,
) -> tuple[ControlPlaneCancelJobCommand, ControlPlaneCommandIntent, ControlPlaneConfirmationProof]:
    command = ControlPlaneCancelJobCommand(job_id)
    intent = command.intent(
        IdempotencyKey(key),
        requested_at=_NOW,
        command_id=command_id,
    )
    token = stack.csrf.issue(stack.principal, _ORIGIN)
    challenge = await stack.handler.issue_cancel_confirmation(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=token,
    )
    return command, intent, challenge.proof


def test_create_job_command_builds_canonical_payload_and_intent() -> None:
    command = _create_command(arguments={"b": 2, "a": 1})
    same = _create_command(arguments={"a": 1, "b": 2})
    intent = _create_intent(command)

    assert command.payload_digest == same.payload_digest
    assert command.target == "capability:test.echo"
    assert intent.action is ControlPlaneCommandAction.CREATE_JOB
    assert intent.target == command.target
    assert intent.payload_digest == command.payload_digest
    assert len(command.canonical_payload) < MAX_JOB_COMMAND_ARGUMENT_BYTES


def test_create_job_command_canonicalizes_equivalent_timezones() -> None:
    utc = _create_command(run_at=datetime(2026, 7, 19, 7, tzinfo=UTC))
    offset = _create_command(run_at=datetime(2026, 7, 19, 4, tzinfo=timezone(timedelta(hours=-3))))

    assert utc.payload_digest == offset.payload_digest


def test_create_job_command_deeply_freezes_arguments() -> None:
    command = _create_command(arguments={"nested": [{"value": 1}]})

    with pytest.raises(TypeError):
        command.arguments["other"] = 2  # type: ignore[index]
    nested = command.arguments["nested"]
    assert isinstance(nested, tuple)
    assert isinstance(nested[0], Mapping)
    with pytest.raises(TypeError):
        nested[0]["value"] = 2  # type: ignore[index]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"capability": " "}, "capability"),
        ({"capability": "bad\nname"}, "control characters"),
        ({"run_at": datetime(2026, 7, 19)}, "timezone-aware"),
        ({"interval": timedelta(0)}, "interval"),
        ({"interval": timedelta(days=366)}, "interval"),
        ({"max_attempts": 0}, "max_attempts"),
        ({"max_attempts": 101}, "max_attempts"),
        ({"initial_retry_delay": timedelta(seconds=-1)}, "retry delay"),
        ({"initial_retry_delay": timedelta(days=31)}, "retry delay"),
        ({"retry_multiplier": 0.5}, "multiplier"),
        ({"retry_multiplier": float("nan")}, "multiplier"),
        ({"max_retry_delay": timedelta(seconds=1)}, "cannot precede"),
        ({"deadline": 0}, "deadline"),
        ({"deadline": 3601}, "deadline"),
        ({"schema_version": 2}, "schema version"),
    ],
)
def test_create_job_command_rejects_unsafe_schedule_contracts(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _create_command(**overrides)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({1: "value"}, "keys must be strings"),
        ({"blob": b"secret"}, "unsupported"),
        ({"set": {1, 2}}, "unsupported"),
        ({"number": float("inf")}, "non-finite"),
        ({"value": "bad\x00value"}, "NUL"),
        ({"value": "x" * 4097}, "too long"),
        ({"": 1}, "invalid length"),
        ({"secret": SecretValue("hidden")}, "secret values"),
        ({"items": list(range(257))}, "too many entries"),
        ({f"k{index}": index for index in range(257)}, "too many entries"),
    ],
)
def test_create_job_command_rejects_unsafe_arguments(
    arguments: Mapping[object, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _create_command(arguments=arguments)


def test_create_job_command_rejects_excessive_argument_depth() -> None:
    value: object = "leaf"
    for _ in range(10):
        value = {"nested": value}

    with pytest.raises(ValueError, match="nesting depth"):
        _create_command(arguments={"value": value})


def test_create_job_command_to_spec_uses_trusted_principal_context() -> None:
    command = _create_command(interval=timedelta(hours=1))
    principal = ControlPlanePrincipal(
        "operator",
        frozenset({CONTROL_PLANE_READ_PERMISSION, _CREATE_PERMISSION, "mail.send"}),
    )
    command_id = UUID(int=12)

    spec = command.to_spec(principal, command_id=command_id)

    assert spec.context.principal == "operator"
    assert spec.context.request_id == command_id
    assert spec.context.permissions == principal.permissions
    assert spec.context.confirmed is False
    assert spec.context.metadata == {}
    assert spec.schedule.interval == timedelta(hours=1)
    assert spec.retry.max_attempts == 3


def test_cancel_job_command_builds_exact_target_and_payload() -> None:
    job_id = UUID(int=20)
    command = ControlPlaneCancelJobCommand(job_id)
    intent = command.intent(
        IdempotencyKey("cancel-contract-0001"),
        requested_at=_NOW,
        command_id=UUID(int=21),
    )

    assert command.target == f"job:{job_id}"
    assert intent.action is ControlPlaneCommandAction.CANCEL_JOB
    assert intent.target == command.target
    assert intent.payload_digest == command.payload_digest


def test_job_command_result_requires_job_id_only_for_successful_creation() -> None:
    command = _create_command()
    intent = _create_intent(command)
    pending = InMemoryControlPlaneIdempotencyStore()

    async def build() -> None:
        receipt = (await pending.reserve(intent)).receipt
        ControlPlaneJobCommandResult(receipt)

    asyncio.run(build())


@pytest.mark.asyncio
async def test_create_job_handler_schedules_allowlisted_job_without_running_provider() -> None:
    calls = 0

    def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        nonlocal calls
        calls += 1
        return dict(invocation.arguments)

    stack = await _stack(provider=provider)
    command = _create_command()
    intent = _create_intent(command)

    result = await stack.handler.create_job(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )
    record = await stack.scheduler.get(intent.id)

    assert result.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert result.receipt.result_code == "job.created"
    assert result.job_id == intent.id
    assert record is not None
    assert record.status is JobStatus.SCHEDULED
    assert record.spec.arguments["message"] == "hello"
    assert calls == 0


@pytest.mark.asyncio
async def test_create_job_handler_replays_without_duplicate_job() -> None:
    stack = await _stack()
    command = _create_command()
    first_intent = _create_intent(command)
    first = await stack.handler.create_job(
        stack.principal,
        first_intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )
    replay_intent = _create_intent(command, command_id=UUID(int=99))

    replay = await stack.handler.create_job(
        stack.principal,
        replay_intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )
    snapshot = await stack.scheduler.snapshot()

    assert replay.receipt == first.receipt
    assert replay.job_id == first.job_id
    assert snapshot.jobs == 1


@pytest.mark.asyncio
async def test_create_job_handler_requires_exact_action_permission_before_reservation() -> None:
    stack = await _stack(permissions=frozenset({CONTROL_PLANE_READ_PERMISSION}))
    command = _create_command()

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await stack.handler.create_job(
            stack.principal,
            _create_intent(command),
            command,
            origin=_ORIGIN,
            csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        )

    assert (await stack.idempotency.snapshot()).entries == 0


@pytest.mark.asyncio
async def test_create_job_handler_rejects_csrf_before_reservation() -> None:
    stack = await _stack()
    command = _create_command()
    token = stack.csrf.issue(stack.principal, _ORIGIN)

    with pytest.raises(ControlPlaneCsrfRejectedError):
        await stack.handler.create_job(
            stack.principal,
            _create_intent(command),
            command,
            origin=ControlPlaneBrowserOrigin("http://127.0.0.1:9999"),
            csrf_token=token,
        )

    assert (await stack.idempotency.snapshot()).entries == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["action", "target", "payload_digest"])
async def test_create_job_handler_rejects_intent_body_mismatch(field: str) -> None:
    stack = await _stack()
    command = _create_command()
    intent = _create_intent(command)
    if field == "action":
        intent = replace(intent, action=ControlPlaneCommandAction.CANCEL_JOB)
    elif field == "target":
        intent = replace(intent, target="capability:other")
    else:
        intent = replace(intent, payload_digest="0" * 64)

    with pytest.raises(ControlPlaneCommandBindingError, match="does not match"):
        await stack.handler.create_job(
            stack.principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        )


@pytest.mark.asyncio
async def test_create_job_handler_returns_safe_failure_for_unknown_capability() -> None:
    stack = await _stack()
    command = _create_command(capability="missing.capability")

    result = await stack.handler.create_job(
        stack.principal,
        _create_intent(command),
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )

    assert result.receipt.status is ControlPlaneCommandStatus.FAILED
    assert result.receipt.result_code == "capability.not-found"
    assert result.job_id is None


@pytest.mark.asyncio
async def test_create_job_handler_requires_capability_permissions() -> None:
    descriptor = CapabilityDescriptor(
        "test.echo",
        required_permissions=frozenset({"capability.echo"}),
    )
    stack = await _stack(descriptor=descriptor)
    command = _create_command()

    result = await stack.handler.create_job(
        stack.principal,
        _create_intent(command),
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )

    assert result.receipt.result_code == "capability.not-authorized"
    assert (await stack.scheduler.snapshot()).jobs == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "descriptor",
    [
        CapabilityDescriptor("test.echo", risk=RiskLevel.DESTRUCTIVE),
        CapabilityDescriptor("test.echo", confirmation_required=True),
    ],
)
async def test_create_job_handler_rejects_capabilities_requiring_destructive_confirmation(
    descriptor: CapabilityDescriptor,
) -> None:
    stack = await _stack(descriptor=descriptor)
    command = _create_command()

    result = await stack.handler.create_job(
        stack.principal,
        _create_intent(command),
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )

    assert result.receipt.result_code == "capability.unsupported-risk"
    assert (await stack.scheduler.snapshot()).jobs == 0


@pytest.mark.asyncio
async def test_create_job_handler_accepts_sensitive_capability_with_permission() -> None:
    descriptor = CapabilityDescriptor(
        "test.echo",
        risk=RiskLevel.SENSITIVE,
        required_permissions=frozenset({"capability.echo"}),
    )
    stack = await _stack(
        descriptor=descriptor,
        permissions=frozenset(
            {
                CONTROL_PLANE_READ_PERMISSION,
                _CREATE_PERMISSION,
                _CANCEL_PERMISSION,
                "capability.echo",
            }
        ),
    )
    command = _create_command()

    result = await stack.handler.create_job(
        stack.principal,
        _create_intent(command),
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
    )

    assert result.receipt.result_code == "job.created"


@pytest.mark.asyncio
async def test_create_job_handler_concurrent_replay_creates_one_job() -> None:
    stack = await _stack()
    command = _create_command()
    first = _create_intent(command, command_id=UUID(int=31))
    second = _create_intent(command, command_id=UUID(int=32))

    results = await asyncio.gather(
        stack.handler.create_job(
            stack.principal,
            first,
            command,
            origin=_ORIGIN,
            csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        ),
        stack.handler.create_job(
            stack.principal,
            second,
            command,
            origin=_ORIGIN,
            csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        ),
    )

    assert {result.receipt.result_code for result in results} == {"job.created"}
    assert {result.job_id for result in results} == {UUID(int=31)}
    assert (await stack.scheduler.snapshot()).jobs == 1


@pytest.mark.asyncio
async def test_cancel_job_handler_consumes_confirmation_and_cancels_job() -> None:
    stack = await _stack()
    record = await stack.scheduler.schedule(
        JobSpec("test.echo", JobSchedule(_NOW + timedelta(hours=1))),
        now=_NOW,
    )
    command, intent, proof = await _cancel_context(stack, record.id)

    result = await stack.handler.cancel_job(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        confirmation=proof,
    )
    loaded = await stack.scheduler.get(record.id)

    assert result.receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert result.receipt.result_code == "job.cancelled"
    assert loaded is not None and loaded.status is JobStatus.CANCELLED


@pytest.mark.asyncio
async def test_issue_cancel_confirmation_requires_permission_and_binding() -> None:
    stack = await _stack(permissions=frozenset({CONTROL_PLANE_READ_PERMISSION}))
    command = ControlPlaneCancelJobCommand(UUID(int=40))
    intent = command.intent(
        IdempotencyKey("cancel-permission-0001"),
        requested_at=_NOW,
        command_id=UUID(int=41),
    )

    with pytest.raises(ControlPlaneCommandPermissionDeniedError):
        await stack.handler.issue_cancel_confirmation(
            stack.principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        )

    permitted = await _stack()
    with pytest.raises(ControlPlaneCommandBindingError):
        await permitted.handler.issue_cancel_confirmation(
            permitted.principal,
            replace(intent, target="job:wrong"),
            command,
            origin=_ORIGIN,
            csrf_token=permitted.csrf.issue(permitted.principal, _ORIGIN),
        )


@pytest.mark.asyncio
async def test_cancel_job_handler_rejects_missing_or_replayed_proof() -> None:
    stack = await _stack()
    record = await stack.scheduler.schedule(
        JobSpec("test.echo", JobSchedule(_NOW + timedelta(hours=1))),
        now=_NOW,
    )
    command, intent, proof = await _cancel_context(stack, record.id)

    await stack.handler.cancel_job(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        confirmation=proof,
    )

    with pytest.raises(ControlPlaneConfirmationRejectedError):
        await stack.handler.cancel_job(
            stack.principal,
            intent,
            command,
            origin=_ORIGIN,
            csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
            confirmation=proof,
        )


@pytest.mark.asyncio
async def test_cancel_job_handler_returns_not_found_receipt() -> None:
    stack = await _stack()
    command, intent, proof = await _cancel_context(stack, UUID(int=50))

    result = await stack.handler.cancel_job(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.status is ControlPlaneCommandStatus.FAILED
    assert result.receipt.result_code == "job.not-found"


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", [JobStatus.SUCCEEDED, JobStatus.DEAD_LETTER])
async def test_cancel_job_handler_rejects_terminal_job(terminal: JobStatus) -> None:
    stack = await _stack()
    record = await stack.scheduler.schedule(
        JobSpec("test.echo", JobSchedule(_NOW)),
        now=_NOW,
    )
    repository = stack.repository
    current = await repository.get(record.id)
    assert current is not None
    if terminal is JobStatus.SUCCEEDED:
        lease = await repository.claim(
            record.id,
            owner="test",
            now=_NOW,
            lease_ttl=timedelta(seconds=10),
        )
        assert lease is not None
        await repository.complete(lease, {}, now=_NOW)
    else:
        lease = await repository.claim(
            record.id,
            owner="test",
            now=_NOW,
            lease_ttl=timedelta(seconds=10),
        )
        assert lease is not None
        await repository.fail(lease, "safe", now=_NOW)
    command, intent, proof = await _cancel_context(stack, record.id)

    result = await stack.handler.cancel_job(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.result_code == "job.not-cancellable"


@pytest.mark.asyncio
async def test_cancel_job_handler_reconciles_already_cancelled_job() -> None:
    stack = await _stack()
    record = await stack.scheduler.schedule(
        JobSpec("test.echo", JobSchedule(_NOW + timedelta(hours=1))),
        now=_NOW,
    )
    await stack.scheduler.cancel(record.id, now=_NOW)
    command, intent, proof = await _cancel_context(stack, record.id)

    result = await stack.handler.cancel_job(
        stack.principal,
        intent,
        command,
        origin=_ORIGIN,
        csrf_token=stack.csrf.issue(stack.principal, _ORIGIN),
        confirmation=proof,
    )

    assert result.receipt.result_code == "job.cancelled"


def test_command_receipt_serializer_omits_payloads_and_security_tokens() -> None:
    command = _create_command(arguments={"secret": "not-serialized"})
    intent = _create_intent(command)
    store = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW)

    async def serialize() -> dict[str, object]:
        await store.reserve(intent)
        receipt = await store.complete(intent, result_code="job.created")
        return command_receipt_to_dict(receipt)

    document = asyncio.run(serialize())
    rendered = repr(document)

    assert set(document) == {
        "schema_version",
        "command_id",
        "action",
        "target",
        "status",
        "created_at",
        "completed_at",
        "result_code",
    }
    assert "not-serialized" not in rendered
    assert "create-job-command-0001" not in rendered
