from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent.approval import (
    InMemoryToolApprovalService,
    ToolApprovalEvidence,
    ToolApprovalStatus,
    tool_descriptor_requires_approval,
)
from phoenix_os.agent.contracts import (
    AgentRunId,
    AgentStepId,
    ToolApprovalId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
)
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.policy import PrincipalType, SecurityContext


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


def _object_schema() -> ToolSchema:
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


def _descriptor(**overrides: object) -> ToolDescriptor:
    values: dict[str, object] = {
        "tool_id": ToolId("files.write"),
        "name": "Write reviewed file",
        "description": "Write one bounded file in an admitted workspace.",
        "input_schema": ToolInputSchema(_object_schema()),
        "output_schema": ToolOutputSchema(
            ToolSchema(
                kind=ToolSchemaType.OBJECT,
                properties={"written": ToolSchema(kind=ToolSchemaType.BOOLEAN)},
                required=frozenset({"written"}),
            )
        ),
        "effect": ToolEffect.REVERSIBLE_WRITE,
        "approval_may_be_required": True,
        "max_input_bytes": 4_096,
        "max_output_bytes": 8_192,
        "timeout": timedelta(seconds=10),
        "resolver_id": "workspace-file",
        "adapter_id": "deterministic-file-writer",
    }
    values.update(overrides)
    return ToolDescriptor(**values)  # type: ignore[arg-type]


def _request(**overrides: object) -> ToolInvocationRequest:
    created_at = datetime(2026, 7, 27, 12, tzinfo=UTC)
    values: dict[str, object] = {
        "run_id": AgentRunId(),
        "step_id": AgentStepId(),
        "call_id": ToolCallId(),
        "tool_id": ToolId("files.write"),
        "arguments": {"path": "super-secret.txt"},
        "resolved_resource": "workspace:docs/super-secret.txt",
        "created_at": created_at,
        "deadline": created_at + timedelta(minutes=5),
    }
    values.update(overrides)
    return ToolInvocationRequest(**values)  # type: ignore[arg-type]


def _context(
    *,
    principal: str = "service:assistant",
    authenticated: bool = True,
) -> SecurityContext:
    return SecurityContext(
        principal=principal if authenticated else "anonymous",
        principal_type=PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS,
        authenticated=authenticated,
    )


def _approver() -> SecurityContext:
    return SecurityContext(
        principal="user:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
    )


def test_effect_classification_is_conservative() -> None:
    assert not tool_descriptor_requires_approval(
        _descriptor(
            effect=ToolEffect.READ_ONLY,
            approval_may_be_required=False,
        )
    )
    assert tool_descriptor_requires_approval(
        _descriptor(
            effect=ToolEffect.READ_ONLY,
            approval_may_be_required=True,
        )
    )
    for effect in (
        ToolEffect.REVERSIBLE_WRITE,
        ToolEffect.IRREVERSIBLE_WRITE,
        ToolEffect.EXTERNAL_COMMUNICATION,
    ):
        assert tool_descriptor_requires_approval(
            _descriptor(
                effect=effect,
                approval_may_be_required=False,
            )
        )


@pytest.mark.asyncio
async def test_challenge_is_exact_content_free_and_server_bound() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()

    challenge = await service.request(request, descriptor, _context())

    assert challenge.run_id == request.run_id
    assert challenge.step_id == request.step_id
    assert challenge.call_id == request.call_id
    assert challenge.tool_id == request.tool_id
    assert challenge.effect is ToolEffect.REVERSIBLE_WRITE
    assert challenge.resolved_resource == request.resolved_resource
    assert challenge.argument_digest.startswith("sha256:")
    assert len(challenge.argument_digest) == 71
    assert "super-secret" not in repr(challenge.argument_digest)
    assert "arguments" not in repr(challenge)
    snapshot = await service.snapshot()
    assert snapshot.pending == 1
    assert snapshot.approved == 0
    assert snapshot.consumed == 0


@pytest.mark.asyncio
async def test_approved_evidence_is_consumed_exactly_once() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()
    challenge = await service.request(request, descriptor, _context())
    evidence = await service.approve(challenge.approval_id, _approver())

    verification = await service.verify_and_consume(
        evidence,
        request,
        descriptor,
        _context(),
    )

    assert verification.approval_id == challenge.approval_id
    assert verification.call_id == request.call_id
    with pytest.raises(AgentApprovalRejectedError, match="approval failed"):
        await service.verify_and_consume(
            evidence,
            request,
            descriptor,
            _context(),
        )
    snapshot = await service.snapshot()
    assert snapshot.pending == 0
    assert snapshot.approved == 0
    assert snapshot.consumed == 1


@pytest.mark.asyncio
async def test_unknown_pending_and_fabricated_evidence_fail_closed() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()
    challenge = await service.request(request, descriptor, _context())

    with pytest.raises(AgentApprovalRejectedError):
        await service.approve(ToolApprovalId(), _approver())

    fabricated = ToolApprovalEvidence(
        approval_id=challenge.approval_id,
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        effect=descriptor.effect,
        resolved_resource=request.resolved_resource,
        argument_digest=challenge.argument_digest,
        approved_by="user:maintainer",
        approved_at=clock.value,
        expires_at=challenge.expires_at,
    )
    with pytest.raises(AgentApprovalRejectedError):
        await service.verify_and_consume(
            fabricated,
            request,
            descriptor,
            _context(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "arguments",
        "resource",
        "run",
        "step",
        "call",
        "principal",
        "effect",
        "resolver",
        "adapter",
    ],
)
async def test_mutation_of_any_bound_authority_field_is_rejected(mutation: str) -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()
    context = _context()
    challenge = await service.request(request, descriptor, context)
    evidence = await service.approve(challenge.approval_id, _approver())

    mutated_request = request
    mutated_descriptor = descriptor
    mutated_context = context
    if mutation == "arguments":
        mutated_request = replace(request, arguments={"path": "different.txt"})
    elif mutation == "resource":
        mutated_request = replace(
            request,
            resolved_resource="workspace:docs/different.txt",
        )
    elif mutation == "run":
        mutated_request = replace(request, run_id=AgentRunId())
    elif mutation == "step":
        mutated_request = replace(request, step_id=AgentStepId())
    elif mutation == "call":
        mutated_request = replace(request, call_id=ToolCallId())
    elif mutation == "principal":
        mutated_context = _context(principal="service:other")
    elif mutation == "effect":
        mutated_descriptor = _descriptor(effect=ToolEffect.IRREVERSIBLE_WRITE)
    elif mutation == "resolver":
        mutated_descriptor = _descriptor(resolver_id="other-resolver")
    elif mutation == "adapter":
        mutated_descriptor = _descriptor(adapter_id="other-adapter")

    with pytest.raises(AgentApprovalRejectedError):
        await service.verify_and_consume(
            evidence,
            mutated_request,
            mutated_descriptor,
            mutated_context,
        )


@pytest.mark.asyncio
async def test_confused_deputy_cannot_reuse_approval_for_another_tool() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()
    challenge = await service.request(request, descriptor, _context())
    evidence = await service.approve(challenge.approval_id, _approver())

    other_tool = ToolId("messages.send")
    deputy_request = replace(
        request,
        tool_id=other_tool,
        resolved_resource="channel:security",
    )
    deputy_descriptor = _descriptor(
        tool_id=other_tool,
        name="Send reviewed message",
        effect=ToolEffect.EXTERNAL_COMMUNICATION,
        resolver_id="reviewed-channel",
        adapter_id="deterministic-message-sender",
    )

    with pytest.raises(AgentApprovalRejectedError):
        await service.verify_and_consume(
            evidence,
            deputy_request,
            deputy_descriptor,
            _context(),
        )


@pytest.mark.asyncio
async def test_expired_approval_cannot_be_granted_or_consumed() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(
        ttl=timedelta(seconds=30),
        clock=clock,
    )
    request = _request()
    descriptor = _descriptor()
    challenge = await service.request(request, descriptor, _context())

    clock.advance(timedelta(seconds=30))
    with pytest.raises(AgentApprovalRejectedError):
        await service.approve(challenge.approval_id, _approver())

    second = await service.request(request, descriptor, _context())
    evidence = await service.approve(second.approval_id, _approver())
    clock.advance(timedelta(seconds=30))
    with pytest.raises(AgentApprovalRejectedError):
        await service.verify_and_consume(
            evidence,
            request,
            descriptor,
            _context(),
        )


@pytest.mark.asyncio
async def test_unauthenticated_context_never_creates_or_consumes_authority() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()

    with pytest.raises(AgentApprovalRejectedError):
        await service.request(request, descriptor, _context(authenticated=False))

    challenge = await service.request(request, descriptor, _context())
    with pytest.raises(AgentApprovalRejectedError):
        await service.approve(challenge.approval_id, _context(authenticated=False))

    evidence = await service.approve(challenge.approval_id, _approver())
    with pytest.raises(AgentApprovalRejectedError):
        await service.verify_and_consume(
            evidence,
            request,
            descriptor,
            _context(authenticated=False),
        )


@pytest.mark.asyncio
async def test_read_only_without_requirement_cannot_mint_approval() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor(
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
    )

    with pytest.raises(AgentApprovalRejectedError):
        await service.request(request, descriptor, _context())


@pytest.mark.asyncio
async def test_capacity_reclaims_only_consumed_or_expired_records() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(capacity=1, clock=clock)
    request = _request()
    descriptor = _descriptor()
    challenge = await service.request(request, descriptor, _context())

    with pytest.raises(AgentApprovalRejectedError):
        await service.request(replace(request, call_id=ToolCallId()), descriptor, _context())

    evidence = await service.approve(challenge.approval_id, _approver())
    await service.verify_and_consume(evidence, request, descriptor, _context())
    replacement = await service.request(
        replace(request, call_id=ToolCallId()),
        descriptor,
        _context(),
    )
    assert replacement.approval_id != challenge.approval_id
    assert (await service.snapshot()).entries == 1


@pytest.mark.asyncio
async def test_close_clears_records_and_rejects_future_operations() -> None:
    clock = _Clock(datetime(2026, 7, 27, 12, tzinfo=UTC))
    service = InMemoryToolApprovalService(clock=clock)
    request = _request()
    descriptor = _descriptor()
    await service.request(request, descriptor, _context())

    await service.close()

    snapshot = await service.snapshot()
    assert snapshot.closed
    assert snapshot.entries == 0
    with pytest.raises(AgentServiceUnavailableError):
        await service.request(request, descriptor, _context())


def test_status_values_are_stable() -> None:
    assert tuple(ToolApprovalStatus) == (
        ToolApprovalStatus.PENDING,
        ToolApprovalStatus.APPROVED,
        ToolApprovalStatus.CONSUMED,
    )
