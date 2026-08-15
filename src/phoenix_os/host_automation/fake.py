"""Deterministic in-memory host adapter for tests and architecture validation."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import NAMESPACE_URL, uuid5

from phoenix_os.host_automation.contracts import (
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationLaunchResult,
    HostAutomationLimits,
    HostClipboardReadRequest,
    HostClipboardReadResult,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostEpoch,
    HostId,
    HostProcessDescriptor,
    HostProcessId,
    HostProcessListRequest,
    HostProcessListResult,
    HostWindowDescriptor,
    HostWindowFocusRequest,
    HostWindowFocusResult,
    HostWindowId,
    HostWindowListRequest,
    HostWindowListResult,
)
from phoenix_os.host_automation.errors import (
    HostApplicationNotConfiguredError,
    HostAutomationLimitExceededError,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
    HostAutomationTargetNotFoundError,
)

_DEFAULT_HOST_AUTOMATION_LIMITS = HostAutomationLimits()


class DeterministicHostAutomationAdapter:
    """Exercise host contracts without network, native APIs, or external side effects."""

    def __init__(
        self,
        *,
        host_id: HostId | str = "deterministic-host",
        host_epoch: HostEpoch | None = None,
        limits: HostAutomationLimits = _DEFAULT_HOST_AUTOMATION_LIMITS,
        applications: Sequence[HostApplicationId | str] = (),
        processes: Sequence[HostProcessDescriptor] = (),
        windows: Sequence[HostWindowDescriptor] = (),
        clipboard_text: str = "",
        clipboard_read_enabled: bool = True,
        clipboard_write_enabled: bool = True,
    ) -> None:
        self._host_id = host_id if isinstance(host_id, HostId) else HostId(host_id)
        if host_epoch is not None and not isinstance(host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(limits, HostAutomationLimits):
            raise TypeError("limits must be HostAutomationLimits")
        if not isinstance(clipboard_read_enabled, bool):
            raise TypeError("clipboard_read_enabled must be a boolean")
        if not isinstance(clipboard_write_enabled, bool):
            raise TypeError("clipboard_write_enabled must be a boolean")

        self._limits = limits
        self._epoch_sequence = 0
        self._host_epoch = host_epoch or self._derived_epoch(self._epoch_sequence)
        self._applications = self._normalize_applications(applications)
        self._processes = self._normalize_processes(processes)
        self._windows = self._normalize_windows(windows)
        self._clipboard_text = self._validate_clipboard_text(clipboard_text)
        self._clipboard_read_enabled = clipboard_read_enabled
        self._clipboard_write_enabled = clipboard_write_enabled
        self._launch_sequence = 0
        self._closed = False

    @property
    def host_id(self) -> HostId:
        return self._host_id

    @property
    def host_epoch(self) -> HostEpoch:
        return self._host_epoch

    @property
    def limits(self) -> HostAutomationLimits:
        return self._limits

    @property
    def closed(self) -> bool:
        return self._closed

    def invalidate_identities(self, host_epoch: HostEpoch | None = None) -> HostEpoch:
        """Rotate the fake host epoch and discard all previously exposed opaque identities."""

        self._ensure_open()
        if host_epoch is not None and not isinstance(host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        self._epoch_sequence += 1
        next_epoch = host_epoch or self._derived_epoch(self._epoch_sequence)
        if next_epoch == self._host_epoch:
            raise ValueError("host_epoch must change when identities are invalidated")
        self._host_epoch = next_epoch
        self._processes.clear()
        self._windows.clear()
        self._launch_sequence = 0
        return self._host_epoch

    async def list_processes(self, request: HostProcessListRequest) -> HostProcessListResult:
        self._ensure_open()
        if not isinstance(request, HostProcessListRequest):
            raise TypeError("request must be HostProcessListRequest")
        self._require_host(request.host_id)
        if request.limit > self._limits.max_process_results:
            raise HostAutomationLimitExceededError()

        ordered = tuple(
            sorted(
                self._processes.values(),
                key=lambda descriptor: str(descriptor.process_id),
            )
        )
        selected = ordered[: request.limit]
        return HostProcessListResult(
            request_id=request.request_id,
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            processes=selected,
            truncated=len(ordered) > len(selected),
            created_at=request.created_at,
        )

    async def list_windows(self, request: HostWindowListRequest) -> HostWindowListResult:
        self._ensure_open()
        if not isinstance(request, HostWindowListRequest):
            raise TypeError("request must be HostWindowListRequest")
        self._require_host(request.host_id)
        if request.limit > self._limits.max_window_results:
            raise HostAutomationLimitExceededError()

        ordered = tuple(
            sorted(
                self._windows.values(),
                key=lambda descriptor: str(descriptor.window_id),
            )
        )
        selected = ordered[: request.limit]
        return HostWindowListResult(
            request_id=request.request_id,
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            windows=selected,
            truncated=len(ordered) > len(selected),
            created_at=request.created_at,
        )

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult:
        self._ensure_open()
        if not isinstance(request, HostApplicationLaunchRequest):
            raise TypeError("request must be HostApplicationLaunchRequest")
        self._require_host(request.host_id)
        if request.application_id not in self._applications:
            raise HostApplicationNotConfiguredError()

        process_id = self._derived_process_id(request.application_id, self._launch_sequence)
        self._launch_sequence += 1
        descriptor = HostProcessDescriptor(
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            process_id=process_id,
            application_id=request.application_id,
        )
        self._processes[process_id] = descriptor
        return HostApplicationLaunchResult(
            request_id=request.request_id,
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            application_id=request.application_id,
            process_id=process_id,
            created_at=request.created_at,
        )

    async def focus_window(self, request: HostWindowFocusRequest) -> HostWindowFocusResult:
        self._ensure_open()
        if not isinstance(request, HostWindowFocusRequest):
            raise TypeError("request must be HostWindowFocusRequest")
        self._require_host(request.host_id)
        self._require_epoch(request.host_epoch)

        window = self._windows.get(request.window_id)
        if window is None:
            raise HostAutomationTargetNotFoundError()
        process = self._processes.get(request.process_id)
        if process is None:
            raise HostAutomationStaleIdentityError()
        if (
            window.host_epoch != self._host_epoch
            or window.process_id != request.process_id
            or process.host_epoch != self._host_epoch
            or (
                request.application_id is not None
                and (
                    window.application_id != request.application_id
                    or process.application_id != request.application_id
                )
            )
        ):
            raise HostAutomationStaleIdentityError()

        return HostWindowFocusResult(
            request_id=request.request_id,
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            window_id=request.window_id,
            process_id=request.process_id,
            created_at=request.created_at,
        )

    async def close_application(
        self,
        request: HostApplicationCloseRequest,
    ) -> HostApplicationCloseResult:
        self._ensure_open()
        if not isinstance(request, HostApplicationCloseRequest):
            raise TypeError("request must be HostApplicationCloseRequest")
        self._require_host(request.host_id)
        self._require_epoch(request.host_epoch)

        process = self._processes.get(request.process_id)
        if process is None:
            raise HostAutomationTargetNotFoundError()
        if (
            process.host_epoch != self._host_epoch
            or process.application_id != request.application_id
        ):
            raise HostAutomationStaleIdentityError()

        del self._processes[request.process_id]
        stale_windows = tuple(
            window_id
            for window_id, window in self._windows.items()
            if window.process_id == request.process_id
        )
        for window_id in stale_windows:
            del self._windows[window_id]

        return HostApplicationCloseResult(
            request_id=request.request_id,
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            application_id=request.application_id,
            process_id=request.process_id,
            created_at=request.created_at,
        )

    async def read_clipboard(self, request: HostClipboardReadRequest) -> HostClipboardReadResult:
        self._ensure_open()
        if not isinstance(request, HostClipboardReadRequest):
            raise TypeError("request must be HostClipboardReadRequest")
        self._require_host(request.host_id)
        if not self._clipboard_read_enabled:
            raise HostAutomationOperationDisabledError()
        text = self._validate_clipboard_text(self._clipboard_text)
        return HostClipboardReadResult(
            request_id=request.request_id,
            host_id=self._host_id,
            text=text,
            created_at=request.created_at,
        )

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
    ) -> HostClipboardWriteResult:
        self._ensure_open()
        if not isinstance(request, HostClipboardWriteRequest):
            raise TypeError("request must be HostClipboardWriteRequest")
        self._require_host(request.host_id)
        if not self._clipboard_write_enabled:
            raise HostAutomationOperationDisabledError()

        text = self._validate_clipboard_text(request.text)
        encoded = text.encode("utf-8")
        self._clipboard_text = text
        return HostClipboardWriteResult(
            request_id=request.request_id,
            host_id=self._host_id,
            written_characters=len(text),
            written_bytes=len(encoded),
            created_at=request.created_at,
        )

    async def close(self) -> None:
        if self._closed:
            return
        self._processes.clear()
        self._windows.clear()
        self._clipboard_text = ""
        self._closed = True

    def _normalize_applications(
        self,
        applications: Sequence[HostApplicationId | str],
    ) -> frozenset[HostApplicationId]:
        if isinstance(applications, (str, bytes)) or not isinstance(applications, Sequence):
            raise TypeError("applications must be a sequence")
        normalized: set[HostApplicationId] = set()
        for item in applications:
            application_id = (
                item if isinstance(item, HostApplicationId) else HostApplicationId(item)
            )
            if application_id in normalized:
                raise ValueError("applications contain a duplicate normalized application id")
            normalized.add(application_id)
        return frozenset(normalized)

    def _normalize_processes(
        self,
        processes: Sequence[HostProcessDescriptor],
    ) -> dict[HostProcessId, HostProcessDescriptor]:
        if isinstance(processes, (str, bytes)) or not isinstance(processes, Sequence):
            raise TypeError("processes must be a sequence")
        if len(processes) > self._limits.max_process_results:
            raise HostAutomationLimitExceededError()

        normalized: dict[HostProcessId, HostProcessDescriptor] = {}
        for process in processes:
            if not isinstance(process, HostProcessDescriptor):
                raise TypeError("processes must contain HostProcessDescriptor values")
            if process.host_id != self._host_id or process.host_epoch != self._host_epoch:
                raise ValueError("process descriptor belongs to a different host or epoch")
            if (
                process.application_id is not None
                and process.application_id not in self._applications
            ):
                raise ValueError("process descriptor references an unconfigured application")
            if len(process.label) > self._limits.max_process_label_chars:
                raise HostAutomationLimitExceededError()
            if process.process_id in normalized:
                raise ValueError("processes contain a duplicate process identity")
            normalized[process.process_id] = process
        return normalized

    def _normalize_windows(
        self,
        windows: Sequence[HostWindowDescriptor],
    ) -> dict[HostWindowId, HostWindowDescriptor]:
        if isinstance(windows, (str, bytes)) or not isinstance(windows, Sequence):
            raise TypeError("windows must be a sequence")
        if len(windows) > self._limits.max_window_results:
            raise HostAutomationLimitExceededError()

        normalized: dict[HostWindowId, HostWindowDescriptor] = {}
        for window in windows:
            if not isinstance(window, HostWindowDescriptor):
                raise TypeError("windows must contain HostWindowDescriptor values")
            if window.host_id != self._host_id or window.host_epoch != self._host_epoch:
                raise ValueError("window descriptor belongs to a different host or epoch")
            process = self._processes.get(window.process_id)
            if process is None:
                raise ValueError("window descriptor references an unknown process identity")
            if window.application_id != process.application_id:
                raise ValueError("window descriptor application does not match its process")
            if len(window.title) > self._limits.max_window_title_chars:
                raise HostAutomationLimitExceededError()
            if window.window_id in normalized:
                raise ValueError("windows contain a duplicate window identity")
            normalized[window.window_id] = window
        return normalized

    def _validate_clipboard_text(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError("clipboard text must be a string")
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError as exception:
            raise ValueError("clipboard text is not valid Unicode") from exception
        if (
            len(text) > self._limits.max_clipboard_text_chars
            or len(encoded) > self._limits.max_clipboard_text_bytes
        ):
            raise HostAutomationLimitExceededError()
        return text

    def _require_host(self, host_id: HostId) -> None:
        if host_id != self._host_id:
            raise HostAutomationTargetNotFoundError()

    def _require_epoch(self, host_epoch: HostEpoch) -> None:
        if host_epoch != self._host_epoch:
            raise HostAutomationStaleIdentityError()

    def _ensure_open(self) -> None:
        if self._closed:
            raise HostAutomationServiceUnavailableError()

    def _derived_epoch(self, sequence: int) -> HostEpoch:
        return HostEpoch(
            uuid5(
                NAMESPACE_URL,
                f"phoenix://host-automation/{self._host_id}/epoch/{sequence}",
            )
        )

    def _derived_process_id(
        self,
        application_id: HostApplicationId,
        sequence: int,
    ) -> HostProcessId:
        return HostProcessId(
            uuid5(
                NAMESPACE_URL,
                (
                    f"phoenix://host-automation/{self._host_id}/epoch/"
                    f"{self._host_epoch}/application/{application_id}/process/{sequence}"
                ),
            )
        )
