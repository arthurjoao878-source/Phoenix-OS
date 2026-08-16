"""Policy-controlled host service with explicit destructive approval."""

from __future__ import annotations

from phoenix_os.host_automation.approval import (
    HostAutomationApprovalChallenge,
    HostAutomationApprovalEvidence,
    HostAutomationApprovalGate,
)
from phoenix_os.host_automation.authorization import HostAutomationAuthorizer
from phoenix_os.host_automation.contracts import (
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
    HostApplicationLaunchRequest,
    HostApplicationLaunchResult,
    HostAutomationAdapter,
    HostClipboardReadRequest,
    HostClipboardReadResult,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostProcessListRequest,
    HostProcessListResult,
    HostWindowFocusRequest,
    HostWindowFocusResult,
    HostWindowListRequest,
    HostWindowListResult,
)
from phoenix_os.host_automation.errors import (
    HostAutomationApprovalRejectedError,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
)
from phoenix_os.policy import SecurityContext


class HostAutomationService:
    """Apply fresh host authorization and configured approval before adapter effects."""

    def __init__(
        self,
        *,
        adapter: HostAutomationAdapter,
        authorizer: HostAutomationAuthorizer,
        approval_gate: HostAutomationApprovalGate | None = None,
        require_application_close_approval: bool = False,
    ) -> None:
        if not isinstance(adapter, HostAutomationAdapter):
            raise TypeError("adapter must implement HostAutomationAdapter")
        if not isinstance(authorizer, HostAutomationAuthorizer):
            raise TypeError("authorizer must implement HostAutomationAuthorizer")
        if approval_gate is not None and not isinstance(
            approval_gate,
            HostAutomationApprovalGate,
        ):
            raise TypeError("approval_gate must implement HostAutomationApprovalGate")
        if not isinstance(require_application_close_approval, bool):
            raise TypeError("require_application_close_approval must be a boolean")
        if require_application_close_approval and approval_gate is None:
            raise ValueError("application close approval requires an approval gate")

        self._adapter = adapter
        self._authorizer = authorizer
        self._approval_gate = approval_gate
        self._require_application_close_approval = require_application_close_approval
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def list_processes(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> HostProcessListResult:
        self._ensure_open()
        await self._authorizer.authorize_process_list(request, context)
        return await self._adapter.list_processes(request)

    async def list_windows(
        self,
        request: HostWindowListRequest,
        context: SecurityContext,
    ) -> HostWindowListResult:
        self._ensure_open()
        await self._authorizer.authorize_window_list(request, context)
        return await self._adapter.list_windows(request)

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> HostApplicationLaunchResult:
        self._ensure_open()
        await self._authorizer.authorize_application_launch(request, context)
        return await self._adapter.launch_application(request)

    async def focus_window(
        self,
        request: HostWindowFocusRequest,
        context: SecurityContext,
    ) -> HostWindowFocusResult:
        self._ensure_open()
        await self._authorizer.authorize_window_focus(request, context)
        return await self._adapter.focus_window(request)

    async def request_application_close_approval(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> HostAutomationApprovalChallenge:
        self._ensure_open()
        gate = self._required_close_approval_gate()
        await self._authorizer.authorize_application_close(request, context)
        self._validate_adapter_close_identity(request)
        return await gate.request_application_close(request, context)

    async def close_application(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
        *,
        approval: HostAutomationApprovalEvidence | None = None,
    ) -> HostApplicationCloseResult:
        self._ensure_open()
        await self._authorizer.authorize_application_close(request, context)
        self._validate_adapter_close_identity(request)

        if self._require_application_close_approval:
            if approval is None:
                raise HostAutomationApprovalRejectedError()
            gate = self._required_close_approval_gate()
            await gate.verify_and_consume_application_close(
                approval,
                request,
                context,
            )

        return await self._adapter.close_application(request)

    async def read_clipboard(
        self,
        request: HostClipboardReadRequest,
        context: SecurityContext,
    ) -> HostClipboardReadResult:
        self._ensure_open()
        await self._authorizer.authorize_clipboard_read(request, context)
        return await self._adapter.read_clipboard(request)

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> HostClipboardWriteResult:
        self._ensure_open()
        await self._authorizer.authorize_clipboard_write(request, context)
        return await self._adapter.write_clipboard(request)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        gate = self._approval_gate
        if gate is not None:
            await gate.close()
        await self._adapter.close()

    def _required_close_approval_gate(self) -> HostAutomationApprovalGate:
        gate = self._approval_gate
        if gate is None or not self._require_application_close_approval:
            raise HostAutomationApprovalRejectedError()
        return gate

    def _validate_adapter_close_identity(self, request: HostApplicationCloseRequest) -> None:
        if request.host_id != self._adapter.host_id:
            raise HostAutomationServiceUnavailableError()
        if request.host_epoch != self._adapter.host_epoch:
            raise HostAutomationStaleIdentityError()

    def _ensure_open(self) -> None:
        if self._closed:
            raise HostAutomationServiceUnavailableError()
