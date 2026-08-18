"""Policy-controlled host service with explicit destructive approval."""

from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import replace
from time import monotonic_ns
from typing import TypeVar
from uuid import UUID

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
    HostAutomationAdapterError,
    HostAutomationApprovalRejectedError,
    HostAutomationError,
    HostAutomationErrorCode,
    HostAutomationIndeterminateEffectError,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
)
from phoenix_os.host_automation.observer import (
    HostAutomationObserver,
    HostAutomationOperation,
    HostAutomationOperationObservation,
    HostAutomationOperationOutcome,
    NullHostAutomationObserver,
)
from phoenix_os.policy import SecurityContext

_T = TypeVar("_T")


class HostAutomationService:
    """Apply fresh host authorization and configured approval before adapter effects."""

    def __init__(
        self,
        *,
        adapter: HostAutomationAdapter,
        authorizer: HostAutomationAuthorizer,
        approval_gate: HostAutomationApprovalGate | None = None,
        require_application_close_approval: bool = False,
        observer: HostAutomationObserver | None = None,
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
        if observer is not None and not isinstance(observer, HostAutomationObserver):
            raise TypeError("observer must implement HostAutomationObserver")

        self._adapter = adapter
        self._authorizer = authorizer
        self._approval_gate = approval_gate
        self._require_application_close_approval = require_application_close_approval
        self._observer = observer if observer is not None else NullHostAutomationObserver()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def list_processes(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> HostProcessListResult:
        started = self._started_observation(
            HostAutomationOperation.PROCESS_LIST,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
            self._ensure_open()
            await self._authorizer.authorize_process_list(request, context)
            result = await self._call_readonly_adapter(self._adapter.list_processes(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
                result_count=len(result.processes),
                truncated=result.truncated,
            ),
            context,
        )
        return result

    async def list_windows(
        self,
        request: HostWindowListRequest,
        context: SecurityContext,
    ) -> HostWindowListResult:
        started = self._started_observation(
            HostAutomationOperation.WINDOW_LIST,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
            self._ensure_open()
            await self._authorizer.authorize_window_list(request, context)
            result = await self._call_readonly_adapter(self._adapter.list_windows(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
                result_count=len(result.windows),
                truncated=result.truncated,
            ),
            context,
        )
        return result

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> HostApplicationLaunchResult:
        started = self._started_observation(
            HostAutomationOperation.APPLICATION_LAUNCH,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
            self._ensure_open()
            await self._authorizer.authorize_application_launch(request, context)
            result = await self._call_effectful_adapter(self._adapter.launch_application(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
            ),
            context,
        )
        return result

    async def focus_window(
        self,
        request: HostWindowFocusRequest,
        context: SecurityContext,
    ) -> HostWindowFocusResult:
        started = self._started_observation(
            HostAutomationOperation.WINDOW_FOCUS,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
            self._ensure_open()
            await self._authorizer.authorize_window_focus(request, context)
            result = await self._call_effectful_adapter(self._adapter.focus_window(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
            ),
            context,
        )
        return result

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
        started = self._started_observation(
            HostAutomationOperation.APPLICATION_CLOSE,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
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

            result = await self._call_effectful_adapter(self._adapter.close_application(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
            ),
            context,
        )
        return result

    async def read_clipboard(
        self,
        request: HostClipboardReadRequest,
        context: SecurityContext,
    ) -> HostClipboardReadResult:
        started = self._started_observation(
            HostAutomationOperation.CLIPBOARD_READ,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
            self._ensure_open()
            await self._authorizer.authorize_clipboard_read(request, context)
            result = await self._call_readonly_adapter(self._adapter.read_clipboard(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
            ),
            context,
        )
        return result

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> HostClipboardWriteResult:
        started = self._started_observation(
            HostAutomationOperation.CLIPBOARD_WRITE,
            request.request_id,
        )
        await self._record(started, context)
        started_ns = monotonic_ns()
        try:
            self._ensure_open()
            await self._authorizer.authorize_clipboard_write(request, context)
            result = await self._call_effectful_adapter(self._adapter.write_clipboard(request))
        except Exception as exception:
            await self._record(
                self._failed_observation(started, exception, started_ns),
                context,
            )
            raise
        await self._record(
            replace(
                started,
                outcome=HostAutomationOperationOutcome.SUCCEEDED,
                duration_ms=_duration_ms(started_ns),
            ),
            context,
        )
        return result

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

    def _started_observation(
        self,
        operation: HostAutomationOperation,
        request_id: object,
    ) -> HostAutomationOperationObservation:
        if not isinstance(request_id, UUID):
            raise TypeError("request_id must be UUID")
        return HostAutomationOperationObservation(
            operation=operation,
            outcome=HostAutomationOperationOutcome.STARTED,
            host_id=self._adapter.host_id,
            request_id=request_id,
        )

    async def _record(
        self,
        observation: HostAutomationOperationObservation,
        context: SecurityContext,
    ) -> None:
        try:
            await self._observer.record(observation, context)
        except Exception:
            pass

    def _failed_observation(
        self,
        started: HostAutomationOperationObservation,
        exception: Exception,
        started_ns: int,
    ) -> HostAutomationOperationObservation:
        outcome, error_code = _failure_metadata(exception)
        return replace(
            started,
            outcome=outcome,
            duration_ms=_duration_ms(started_ns),
            error_code=error_code,
        )

    async def _call_readonly_adapter(self, operation: Awaitable[_T]) -> _T:
        try:
            return await operation
        except HostAutomationError:
            raise
        except Exception:
            raise HostAutomationAdapterError() from None

    async def _call_effectful_adapter(self, operation: Awaitable[_T]) -> _T:
        try:
            return await operation
        except HostAutomationError:
            raise
        except Exception:
            raise HostAutomationIndeterminateEffectError() from None


def _duration_ms(started_ns: int) -> int:
    return max(0, (monotonic_ns() - started_ns) // 1_000_000)


def _failure_metadata(
    exception: Exception,
) -> tuple[HostAutomationOperationOutcome, HostAutomationErrorCode | None]:
    if not isinstance(exception, HostAutomationError):
        return HostAutomationOperationOutcome.FAILED, None
    code = exception.code
    if code in {
        HostAutomationErrorCode.AUTHORIZATION_REJECTED,
        HostAutomationErrorCode.APPROVAL_REJECTED,
    }:
        return HostAutomationOperationOutcome.REJECTED, code
    if code is HostAutomationErrorCode.CANCELLED:
        return HostAutomationOperationOutcome.CANCELLED, code
    if code is HostAutomationErrorCode.TIMEOUT:
        return HostAutomationOperationOutcome.TIMED_OUT, code
    if code is HostAutomationErrorCode.INDETERMINATE_EFFECT:
        return HostAutomationOperationOutcome.INDETERMINATE, code
    return HostAutomationOperationOutcome.FAILED, code
