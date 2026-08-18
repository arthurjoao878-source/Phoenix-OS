"""Policy-controlled host service with explicit destructive approval."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import InitVar, dataclass, field, replace
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
    HostAutomationLimits,
    HostClipboardReadRequest,
    HostClipboardReadResult,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostEpoch,
    HostId,
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


@dataclass(frozen=True, slots=True)
class HostAutomationServiceSnapshot:
    """Content-free bounded runtime health for one configured host service."""

    host_id: HostId
    host_epoch: HostEpoch
    limits: HostAutomationLimits
    closed: bool
    close_approval_required: bool
    schema_version: int = 1
    available: bool = field(init=False)
    _available: InitVar[bool | None] = None

    def __post_init__(self, _available: bool | None) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.limits, HostAutomationLimits):
            raise TypeError("limits must be HostAutomationLimits")
        if type(self.closed) is not bool:
            raise TypeError("closed must be a boolean")
        if type(self.close_approval_required) is not bool:
            raise TypeError("close_approval_required must be a boolean")
        if _available is not None and type(_available) is not bool:
            raise TypeError("available must be a boolean")
        available = not self.closed if _available is None else _available
        if self.closed and available:
            raise ValueError("closed host service snapshot cannot be available")
        object.__setattr__(self, "available", available)
        if self.schema_version != 1:
            raise ValueError("unsupported host service snapshot version")


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
        self._runtime_managed = False
        self._runtime_availability: Callable[[], bool] | None = None
        self._operation_condition = asyncio.Condition()
        self._in_flight_operations = 0
        self._close_lock = asyncio.Lock()
        self._closing = False

    def _bind_runtime_lifecycle(self) -> None:
        if self._closed:
            raise RuntimeError("closed host automation service cannot be Runtime-owned")
        if self._runtime_managed:
            raise RuntimeError("host automation service is already Runtime-owned")
        self._runtime_managed = True
        self._runtime_availability = None

    def _activate_runtime_lifecycle(self, availability: Callable[[], bool]) -> None:
        if not callable(availability):
            raise TypeError("availability must be callable")
        if not self._runtime_managed:
            raise RuntimeError("host automation service is not Runtime-owned")
        if self._closed:
            raise RuntimeError("host automation service is already closed")
        self._runtime_availability = availability

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def host_id(self) -> HostId:
        return self._adapter.host_id

    async def snapshot(self) -> HostAutomationServiceSnapshot:
        """Return content-free health without probing desktop state."""

        return HostAutomationServiceSnapshot(
            host_id=self._adapter.host_id,
            host_epoch=self._adapter.host_epoch,
            limits=self._adapter.limits,
            closed=self._closed,
            close_approval_required=self._require_application_close_approval,
            _available=self._is_available(),
        )

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
            async with self._operation_scope():
                await self._authorizer.authorize_process_list(request, context)
                self._ensure_open()
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
            async with self._operation_scope():
                await self._authorizer.authorize_window_list(request, context)
                self._ensure_open()
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
            async with self._operation_scope():
                await self._authorizer.authorize_application_launch(request, context)
                self._ensure_open()
                result = await self._call_effectful_adapter(
                    self._adapter.launch_application(request)
                )
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
            async with self._operation_scope():
                await self._authorizer.authorize_window_focus(request, context)
                self._ensure_open()
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
        async with self._operation_scope():
            gate = self._required_close_approval_gate()
            await self._authorizer.authorize_application_close(request, context)
            self._validate_adapter_close_identity(request)
            self._ensure_open()
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
            async with self._operation_scope():
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

                self._ensure_open()
                result = await self._call_effectful_adapter(
                    self._adapter.close_application(request)
                )
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
            async with self._operation_scope():
                await self._authorizer.authorize_clipboard_read(request, context)
                self._ensure_open()
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
            async with self._operation_scope():
                await self._authorizer.authorize_clipboard_write(request, context)
                self._ensure_open()
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
        async with self._close_lock:
            if self._closed:
                return

            async with self._operation_condition:
                self._runtime_availability = None
                self._closing = True
                while self._in_flight_operations:
                    await self._operation_condition.wait()

            gate = self._approval_gate
            if gate is not None:
                await gate.close()
            await self._adapter.close()

            async with self._operation_condition:
                self._closed = True
                self._closing = False
                self._operation_condition.notify_all()

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
        if not self._is_available():
            raise HostAutomationServiceUnavailableError()

    def _is_available(self) -> bool:
        if self._closed or self._closing:
            return False
        if not self._runtime_managed:
            return True
        availability = self._runtime_availability
        if availability is None:
            return False
        try:
            return availability() is True
        except Exception:
            return False

    @asynccontextmanager
    async def _operation_scope(self) -> AsyncIterator[None]:
        async with self._operation_condition:
            self._ensure_open()
            self._in_flight_operations += 1
        try:
            yield
        finally:
            async with self._operation_condition:
                self._in_flight_operations -= 1
                self._operation_condition.notify_all()

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
