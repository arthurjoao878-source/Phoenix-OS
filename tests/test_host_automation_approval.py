from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.host_automation import (
    HOST_APPLICATION_CLOSE_ACTION,
    HostApplicationCloseRequest,
    HostApplicationId,
    HostAutomationApprovalEvidence,
    HostAutomationApprovalId,
    HostAutomationApprovalRejectedError,
    HostAutomationApprovalStatus,
    HostAutomationServiceUnavailableError,
    HostEpoch,
    HostId,
    HostProcessId,
    InMemoryHostAutomationApprovalGate,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 15, 21, 15, tzinfo=UTC)
_HOST = HostId("desktop")
_APP = HostApplicationId("editor")
_EPOCH = HostEpoch()
_PROCESS = HostProcessId()


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


def _request(**overrides: object) -> HostApplicationCloseRequest:
    values: dict[str, object] = {
        "host_id": _HOST,
        "host_epoch": _EPOCH,
        "application_id": _APP,
        "process_id": _PROCESS,
        "created_at": _NOW,
    }
    values.update(overrides)
    return HostApplicationCloseRequest(**values)  # type: ignore[arg-type]


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


@pytest.mark.asyncio
async def test_host_close_challenge_is_exact_action_bound_and_content_free() -> None:
    clock = _Clock(_NOW)
    gate = InMemoryHostAutomationApprovalGate(clock=clock)
    request = _request()

    challenge = await gate.request_application_close(request, _context())

    assert challenge.action == HOST_APPLICATION_CLOSE_ACTION
    assert challenge.host_id == request.host_id
    assert challenge.host_epoch == request.host_epoch
    assert challenge.application_id == request.application_id
    assert challenge.process_id == request.process_id
    assert challenge.request_id == request.request_id
    assert "pid" not in repr(challenge).lower()
    assert "hwnd" not in repr(challenge).lower()
    snapshot = await gate.snapshot()
    assert snapshot.pending == 1
    assert snapshot.approved == 0
    assert snapshot.consumed == 0


@pytest.mark.asyncio
async def test_host_close_approval_is_single_use() -> None:
    gate = InMemoryHostAutomationApprovalGate(clock=_Clock(_NOW))
    request = _request()
    context = _context()
    challenge = await gate.request_application_close(request, context)
    evidence = await gate.approve(challenge.approval_id, _approver())

    verification = await gate.verify_and_consume_application_close(
        evidence,
        request,
        context,
    )

    assert verification.action == HOST_APPLICATION_CLOSE_ACTION
    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.verify_and_consume_application_close(evidence, request, context)
    snapshot = await gate.snapshot()
    assert snapshot.consumed == 1


@pytest.mark.asyncio
async def test_host_close_approval_rejects_tampered_action_binding() -> None:
    gate = InMemoryHostAutomationApprovalGate(clock=_Clock(_NOW))
    request = _request()
    context = _context()
    challenge = await gate.request_application_close(request, context)
    evidence = await gate.approve(challenge.approval_id, _approver())

    # Simulate tampering after trusted construction/serialization.
    object.__setattr__(evidence, "action", "host.app.launch")

    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.verify_and_consume_application_close(
            evidence,
            request,
            context,
        )

    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_approved_host_close_approval_expires_before_consumption() -> None:
    clock = _Clock(_NOW)
    gate = InMemoryHostAutomationApprovalGate(
        ttl=timedelta(seconds=30),
        clock=clock,
    )
    request = _request()
    context = _context()
    challenge = await gate.request_application_close(request, context)
    evidence = await gate.approve(challenge.approval_id, _approver())

    clock.advance(timedelta(seconds=30))

    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.verify_and_consume_application_close(
            evidence,
            request,
            context,
        )

    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["host", "epoch", "application", "process", "request", "principal"],
)
async def test_changed_host_close_binding_invalidates_approval(mutation: str) -> None:
    gate = InMemoryHostAutomationApprovalGate(clock=_Clock(_NOW))
    request = _request()
    context = _context()
    challenge = await gate.request_application_close(request, context)
    evidence = await gate.approve(challenge.approval_id, _approver())

    mutated_request = request
    mutated_context = context
    if mutation == "host":
        mutated_request = replace(request, host_id=HostId("other"))
    elif mutation == "epoch":
        mutated_request = replace(request, host_epoch=HostEpoch())
    elif mutation == "application":
        mutated_request = replace(request, application_id=HostApplicationId("other"))
    elif mutation == "process":
        mutated_request = replace(request, process_id=HostProcessId())
    elif mutation == "request":
        mutated_request = _request()
    elif mutation == "principal":
        mutated_context = _context(principal="service:other")

    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.verify_and_consume_application_close(
            evidence,
            mutated_request,
            mutated_context,
        )

    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_unknown_fabricated_and_expired_host_approval_fail_closed() -> None:
    clock = _Clock(_NOW)
    gate = InMemoryHostAutomationApprovalGate(
        ttl=timedelta(seconds=30),
        clock=clock,
    )
    request = _request()
    challenge = await gate.request_application_close(request, _context())

    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.approve(HostAutomationApprovalId(), _approver())

    clock.advance(timedelta(seconds=30))
    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.approve(challenge.approval_id, _approver())

    clock.value = _NOW
    second = await gate.request_application_close(request, _context())
    evidence = await gate.approve(second.approval_id, _approver())
    fabricated = HostAutomationApprovalEvidence(
        approval_id=evidence.approval_id,
        action=evidence.action,
        host_id=evidence.host_id,
        host_epoch=evidence.host_epoch,
        application_id=evidence.application_id,
        process_id=evidence.process_id,
        request_id=evidence.request_id,
        approved_by="user:attacker",
        approved_at=evidence.approved_at,
        expires_at=evidence.expires_at,
    )
    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.verify_and_consume_application_close(
            fabricated,
            request,
            _context(),
        )


@pytest.mark.asyncio
async def test_unauthenticated_context_and_closed_gate_never_create_authority() -> None:
    gate = InMemoryHostAutomationApprovalGate(clock=_Clock(_NOW))
    request = _request()

    with pytest.raises(HostAutomationApprovalRejectedError):
        await gate.request_application_close(
            request,
            _context(authenticated=False),
        )

    await gate.close()
    with pytest.raises(HostAutomationServiceUnavailableError):
        await gate.request_application_close(request, _context())
