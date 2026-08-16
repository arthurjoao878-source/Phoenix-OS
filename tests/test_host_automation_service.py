from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from phoenix_os.host_automation import (
    DeterministicHostAutomationAdapter,
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostAutomationApprovalRejectedError,
    HostAutomationApprovalStatus,
    HostAutomationAuthorizationRejectedError,
    HostAutomationService,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostEpoch,
    HostId,
    HostProcessId,
    HostProcessListRequest,
    HostWindowFocusRequest,
    HostWindowListRequest,
    InMemoryHostAutomationApprovalGate,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 15, 21, 20, tzinfo=UTC)
_HOST = HostId("desktop")
_APP = HostApplicationId("editor")


def _context(principal: str = "service:assistant") -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _approver() -> SecurityContext:
    return SecurityContext(
        principal="user:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
    )


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


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


class _RecordingAuthorizer:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.reject_close = False

    async def authorize_process_list(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("process.list")

    async def authorize_window_list(
        self,
        request: HostWindowListRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("window.list")

    async def authorize_application_launch(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("app.launch")

    async def authorize_window_focus(
        self,
        request: HostWindowFocusRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("window.focus")

    async def authorize_application_close(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("app.close")
        if self.reject_close:
            raise HostAutomationAuthorizationRejectedError()

    async def authorize_clipboard_write(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("clipboard.write")

    async def authorize_clipboard_read(
        self,
        request: HostClipboardReadRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        self.calls.append("clipboard.read")


async def _service_with_launched_process(
    *,
    require_approval: bool = True,
    approval_gate: InMemoryHostAutomationApprovalGate | None = None,
) -> tuple[
    HostAutomationService,
    _CountingHostAutomationAdapter,
    _RecordingAuthorizer,
    InMemoryHostAutomationApprovalGate,
    HostApplicationCloseRequest,
]:
    adapter = _CountingHostAutomationAdapter(
        host_id=_HOST,
        applications=(_APP,),
    )
    authorizer = _RecordingAuthorizer()
    gate = approval_gate if approval_gate is not None else InMemoryHostAutomationApprovalGate()
    service = HostAutomationService(
        adapter=adapter,
        authorizer=authorizer,
        approval_gate=gate,
        require_application_close_approval=require_approval,
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
    return service, adapter, authorizer, gate, request


def test_service_does_not_expose_approval_grant_authority() -> None:
    adapter = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        applications=(_APP,),
    )
    service = HostAutomationService(
        adapter=adapter,
        authorizer=_RecordingAuthorizer(),
        approval_gate=InMemoryHostAutomationApprovalGate(),
        require_application_close_approval=True,
    )

    assert not hasattr(service, "approve_application_close")
    assert not hasattr(service, "adapter")


def test_close_approval_configuration_is_explicit() -> None:
    adapter = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        applications=(_APP,),
    )
    authorizer = _RecordingAuthorizer()

    with pytest.raises(ValueError, match="requires an approval gate"):
        HostAutomationService(
            adapter=adapter,
            authorizer=authorizer,
            require_application_close_approval=True,
        )


@pytest.mark.asyncio
async def test_host_service_requires_fresh_authorization_before_close_approval() -> None:
    service, _, authorizer, gate, request = await _service_with_launched_process()
    authorizer.reject_close = True

    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await service.request_application_close_approval(request, _context())

    snapshot = await gate.snapshot()
    assert snapshot.entries == 0


@pytest.mark.asyncio
async def test_host_service_requires_approval_for_destructive_close() -> None:
    service, adapter, _, _, request = await _service_with_launched_process()

    with pytest.raises(HostAutomationApprovalRejectedError):
        await service.close_application(request, _context())

    assert adapter.close_calls == 0
    listed = await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))
    assert [item.process_id for item in listed.processes] == [request.process_id]


@pytest.mark.asyncio
async def test_host_service_exact_approved_close_consumes_once_and_executes_once() -> None:
    service, adapter, authorizer, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())

    result = await service.close_application(
        request,
        _context(),
        approval=evidence,
    )

    assert result.process_id == request.process_id
    assert adapter.close_calls == 1
    assert authorizer.calls.count("app.close") == 2
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.CONSUMED
    listed = await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))
    assert listed.processes == ()


@pytest.mark.asyncio
async def test_host_service_replayed_approval_never_reaches_adapter_again() -> None:
    service, adapter, _, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())

    await service.close_application(
        request,
        _context(),
        approval=evidence,
    )
    assert adapter.close_calls == 1

    with pytest.raises(HostAutomationApprovalRejectedError):
        await service.close_application(
            request,
            _context(),
            approval=evidence,
        )

    assert adapter.close_calls == 1


@pytest.mark.asyncio
async def test_tampered_action_approval_never_reaches_adapter() -> None:
    service, adapter, _, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())

    # Simulate tampering after trusted construction/serialization.
    object.__setattr__(evidence, "action", "host.app.launch")

    with pytest.raises(HostAutomationApprovalRejectedError):
        await service.close_application(
            request,
            _context(),
            approval=evidence,
        )

    assert adapter.close_calls == 0
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_expired_approved_close_never_reaches_adapter() -> None:
    clock = _Clock(_NOW)
    gate = InMemoryHostAutomationApprovalGate(
        ttl=timedelta(seconds=30),
        clock=clock,
    )
    service, adapter, _, returned_gate, request = await _service_with_launched_process(
        approval_gate=gate,
    )
    assert returned_gate is gate

    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())
    clock.advance(timedelta(seconds=30))

    with pytest.raises(HostAutomationApprovalRejectedError):
        await service.close_application(
            request,
            _context(),
            approval=evidence,
        )

    assert adapter.close_calls == 0
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_changed_target_or_requester_does_not_consume_close_approval() -> None:
    service, adapter, _, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())

    changed = replace(request, application_id=HostApplicationId("other"))
    with pytest.raises(HostAutomationApprovalRejectedError):
        await service.close_application(
            changed,
            _context(),
            approval=evidence,
        )
    with pytest.raises(HostAutomationApprovalRejectedError):
        await service.close_application(
            request,
            _context("service:other"),
            approval=evidence,
        )

    assert adapter.close_calls == 0
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["host", "epoch", "process", "request"])
async def test_changed_close_binding_never_reaches_adapter(mutation: str) -> None:
    service, adapter, _, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())

    expected_error: type[Exception]
    if mutation == "host":
        changed = replace(request, host_id=HostId("other"))
        expected_error = HostAutomationServiceUnavailableError
    elif mutation == "epoch":
        changed = replace(request, host_epoch=HostEpoch())
        expected_error = HostAutomationStaleIdentityError
    elif mutation == "process":
        changed = replace(request, process_id=HostProcessId())
        expected_error = HostAutomationApprovalRejectedError
    else:
        changed = replace(request, request_id=uuid4())
        expected_error = HostAutomationApprovalRejectedError

    with pytest.raises(expected_error):
        await service.close_application(
            changed,
            _context(),
            approval=evidence,
        )

    assert adapter.close_calls == 0
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_stale_host_epoch_rejects_before_approval_consumption() -> None:
    service, adapter, _, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())
    adapter.invalidate_identities()

    with pytest.raises(HostAutomationStaleIdentityError):
        await service.close_application(
            request,
            _context(),
            approval=evidence,
        )

    assert adapter.close_calls == 0
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_current_policy_denial_wins_without_consuming_prior_approval() -> None:
    service, adapter, authorizer, gate, request = await _service_with_launched_process()
    challenge = await service.request_application_close_approval(request, _context())
    evidence = await gate.approve(challenge.approval_id, _approver())
    authorizer.reject_close = True

    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await service.close_application(
            request,
            _context(),
            approval=evidence,
        )

    assert adapter.close_calls == 0
    record = await gate.lookup(challenge.approval_id)
    assert record is not None
    assert record.status is HostAutomationApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_close_can_be_configured_without_host_specific_approval() -> None:
    service, adapter, authorizer, _, request = await _service_with_launched_process(
        require_approval=False
    )

    result = await service.close_application(request, _context())

    assert result.process_id == request.process_id
    assert adapter.close_calls == 1
    assert authorizer.calls.count("app.close") == 1


@pytest.mark.asyncio
async def test_service_close_owns_gate_and_adapter_lifecycle() -> None:
    service, adapter, _, gate, _ = await _service_with_launched_process()

    await service.close()

    assert service.closed is True
    assert adapter.closed is True
    assert gate.closed is True
    with pytest.raises(HostAutomationServiceUnavailableError):
        await service.list_processes(
            HostProcessListRequest(host_id=_HOST, created_at=_NOW),
            _context(),
        )
