"""Windows host-automation adapter with bounded read-only discovery."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from phoenix_os.host_automation.contracts import (
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
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
    HostWindowFocusRequest,
    HostWindowFocusResult,
    HostWindowListRequest,
    HostWindowListResult,
)
from phoenix_os.host_automation.errors import (
    HostAutomationAdapterError,
    HostAutomationLimitExceededError,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationTimeoutError,
    HostAutomationUnsupportedPlatformError,
)

_DEFAULT_WINDOWS_HOST_AUTOMATION_LIMITS = HostAutomationLimits()
_WINDOWS_PROCESS_SCAN_MULTIPLIER = 8
_WINDOWS_MIN_PROCESS_SCAN_COUNT = 64
_WINDOWS_MAX_PROCESS_SCAN_COUNT = 32_768


@dataclass(frozen=True, slots=True)
class _NativeProcessRecord:
    pid: int
    creation_time: int
    label: str

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("native process pid must be a positive integer")
        if (
            isinstance(self.creation_time, bool)
            or not isinstance(self.creation_time, int)
            or self.creation_time < 0
        ):
            raise ValueError("native process creation_time must be a non-negative integer")
        if not isinstance(self.label, str):
            raise TypeError("native process label must be a string")


@dataclass(frozen=True, slots=True)
class _NativeProcessSnapshot:
    records: tuple[_NativeProcessRecord, ...]
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.records, tuple):
            raise TypeError("native process records must be a tuple")
        if not isinstance(self.truncated, bool):
            raise TypeError("native process truncated must be a boolean")
        for record in self.records:
            if not isinstance(record, _NativeProcessRecord):
                raise TypeError("native process snapshot contains an invalid record")


class _WindowsDiscoveryBackend(Protocol):
    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> _NativeProcessSnapshot: ...


class _CtypesWindowsDiscoveryBackend:
    """Use reviewed Toolhelp/process APIs without leaking native identities."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise HostAutomationUnsupportedPlatformError()

        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        get_last_error = getattr(ctypes, "get_last_error", None)
        if win_dll is None or get_last_error is None:
            raise HostAutomationUnsupportedPlatformError()

        self._ctypes = ctypes
        self._wintypes = wintypes
        self._get_last_error: Callable[[], int] = get_last_error
        self._kernel32: Any = win_dll("kernel32", use_last_error=True)

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        self._process_entry_type: type[Any] = PROCESSENTRY32W
        self._configure_signatures()

    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> _NativeProcessSnapshot:
        if isinstance(maximum_records, bool) or not isinstance(maximum_records, int):
            raise TypeError("maximum_records must be an integer")
        if maximum_records <= 0:
            raise ValueError("maximum_records must be greater than zero")
        if isinstance(maximum_label_characters, bool) or not isinstance(
            maximum_label_characters, int
        ):
            raise TypeError("maximum_label_characters must be an integer")
        if maximum_label_characters <= 0:
            raise ValueError("maximum_label_characters must be greater than zero")

        ctypes = self._ctypes
        snapshot = self._kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if snapshot == invalid_handle:
            raise RuntimeError("windows process snapshot creation failed")

        records: list[_NativeProcessRecord] = []
        truncated = False
        examined = 0
        maximum_examined = min(
            _WINDOWS_MAX_PROCESS_SCAN_COUNT,
            max(
                _WINDOWS_MIN_PROCESS_SCAN_COUNT,
                maximum_records * _WINDOWS_PROCESS_SCAN_MULTIPLIER,
            ),
        )
        entry = self._process_entry_type()
        entry.dwSize = ctypes.sizeof(self._process_entry_type)

        try:
            success = bool(self._kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
            if not success:
                if self._get_last_error() == 18:
                    return _NativeProcessSnapshot(())
                raise RuntimeError("windows process enumeration failed")

            while success:
                examined += 1
                pid = int(entry.th32ProcessID)
                if pid > 0:
                    creation_time = self._read_process_creation_time(pid)
                    if creation_time is not None:
                        label = _content_minimized_process_label(
                            str(entry.szExeFile),
                            maximum_characters=maximum_label_characters,
                        )
                        records.append(
                            _NativeProcessRecord(
                                pid=pid,
                                creation_time=creation_time,
                                label=label,
                            )
                        )
                        if len(records) >= maximum_records:
                            truncated = True
                            break

                if examined >= maximum_examined:
                    truncated = True
                    break

                success = bool(self._kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
                if not success and self._get_last_error() not in (0, 18):
                    raise RuntimeError("windows process enumeration failed")
        finally:
            self._kernel32.CloseHandle(snapshot)

        records.sort(key=lambda item: (item.label.casefold(), item.pid, item.creation_time))
        return _NativeProcessSnapshot(tuple(records), truncated=truncated)

    def _read_process_creation_time(self, pid: int) -> int | None:
        ctypes = self._ctypes
        wintypes = self._wintypes
        process = self._kernel32.OpenProcess(0x1000, False, pid)
        if not process:
            return None

        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        try:
            success = bool(
                self._kernel32.GetProcessTimes(
                    process,
                    ctypes.byref(creation),
                    ctypes.byref(exit_time),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                )
            )
            if not success:
                return None
            return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
        finally:
            self._kernel32.CloseHandle(process)

    def _configure_signatures(self) -> None:
        ctypes = self._ctypes
        wintypes = self._wintypes
        entry_pointer = ctypes.POINTER(self._process_entry_type)

        self._kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self._kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, entry_pointer]
        self._kernel32.Process32FirstW.restype = wintypes.BOOL
        self._kernel32.Process32NextW.argtypes = [wintypes.HANDLE, entry_pointer]
        self._kernel32.Process32NextW.restype = wintypes.BOOL
        self._kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._kernel32.OpenProcess.restype = wintypes.HANDLE
        filetime_pointer = ctypes.POINTER(wintypes.FILETIME)
        self._kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            filetime_pointer,
            filetime_pointer,
            filetime_pointer,
            filetime_pointer,
        ]
        self._kernel32.GetProcessTimes.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL


class WindowsHostAutomationAdapter:
    """Windows implementation boundary; only read-only process discovery is enabled here."""

    def __init__(
        self,
        *,
        host_id: HostId | str = "local-windows",
        limits: HostAutomationLimits = _DEFAULT_WINDOWS_HOST_AUTOMATION_LIMITS,
    ) -> None:
        if sys.platform != "win32":
            raise HostAutomationUnsupportedPlatformError()
        self._host_id: HostId = host_id if isinstance(host_id, HostId) else HostId(host_id)
        if not isinstance(limits, HostAutomationLimits):
            raise TypeError("limits must be HostAutomationLimits")

        self._limits: HostAutomationLimits = limits
        self._host_epoch: HostEpoch = HostEpoch()
        self._backend: _WindowsDiscoveryBackend = _CtypesWindowsDiscoveryBackend()
        self._process_ids: dict[tuple[int, int], HostProcessId] = {}
        self._native_processes: dict[HostProcessId, _NativeProcessRecord] = {}
        self._closed: bool = False
        self._lock: asyncio.Lock = asyncio.Lock()

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

    async def list_processes(self, request: HostProcessListRequest) -> HostProcessListResult:
        if not isinstance(request, HostProcessListRequest):
            raise TypeError("request must be HostProcessListRequest")
        self._require_host(request.host_id)
        if request.limit > self._limits.max_process_results:
            raise HostAutomationLimitExceededError()

        async with self._lock:
            self._ensure_open()
            scan_limit = self._limits.max_process_results + 1
            try:
                snapshot = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._backend.enumerate_processes,
                        maximum_records=scan_limit,
                        maximum_label_characters=self._limits.max_process_label_chars,
                    ),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
            except TimeoutError as exception:
                raise HostAutomationTimeoutError() from exception
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

            ordered_records = tuple(
                sorted(
                    snapshot.records,
                    key=lambda record: (
                        _content_minimized_process_label(
                            record.label,
                            maximum_characters=self._limits.max_process_label_chars,
                        ).casefold(),
                        record.pid,
                        record.creation_time,
                    ),
                )
            )
            visible_records = ordered_records[: self._limits.max_process_results]
            self._refresh_process_identities(visible_records)
            selected = visible_records[: request.limit]
            descriptors = tuple(self._descriptor_for(record) for record in selected)
            truncated = (
                snapshot.truncated
                or len(snapshot.records) > self._limits.max_process_results
                or len(visible_records) > request.limit
            )
            return HostProcessListResult(
                request_id=request.request_id,
                host_id=self._host_id,
                host_epoch=self._host_epoch,
                processes=descriptors,
                truncated=truncated,
                created_at=request.created_at,
            )

    async def list_windows(self, request: HostWindowListRequest) -> HostWindowListResult:
        if not isinstance(request, HostWindowListRequest):
            raise TypeError("request must be HostWindowListRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        raise HostAutomationOperationDisabledError()

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult:
        if not isinstance(request, HostApplicationLaunchRequest):
            raise TypeError("request must be HostApplicationLaunchRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        raise HostAutomationOperationDisabledError()

    async def focus_window(self, request: HostWindowFocusRequest) -> HostWindowFocusResult:
        if not isinstance(request, HostWindowFocusRequest):
            raise TypeError("request must be HostWindowFocusRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        raise HostAutomationOperationDisabledError()

    async def close_application(
        self,
        request: HostApplicationCloseRequest,
    ) -> HostApplicationCloseResult:
        if not isinstance(request, HostApplicationCloseRequest):
            raise TypeError("request must be HostApplicationCloseRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        raise HostAutomationOperationDisabledError()

    async def read_clipboard(self, request: HostClipboardReadRequest) -> HostClipboardReadResult:
        if not isinstance(request, HostClipboardReadRequest):
            raise TypeError("request must be HostClipboardReadRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        raise HostAutomationOperationDisabledError()

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
    ) -> HostClipboardWriteResult:
        if not isinstance(request, HostClipboardWriteRequest):
            raise TypeError("request must be HostClipboardWriteRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        raise HostAutomationOperationDisabledError()

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._process_ids.clear()
            self._native_processes.clear()
            self._closed = True

    def _refresh_process_identities(
        self,
        records: tuple[_NativeProcessRecord, ...],
    ) -> None:
        active_keys = {(record.pid, record.creation_time) for record in records}
        self._process_ids = {
            key: process_id for key, process_id in self._process_ids.items() if key in active_keys
        }

        native_processes: dict[HostProcessId, _NativeProcessRecord] = {}
        for record in records:
            key = (record.pid, record.creation_time)
            process_id = self._process_ids.get(key)
            if process_id is None:
                process_id = HostProcessId()
                self._process_ids[key] = process_id
            native_processes[process_id] = record
        self._native_processes = native_processes

    def _descriptor_for(self, record: _NativeProcessRecord) -> HostProcessDescriptor:
        process_id = self._process_ids[(record.pid, record.creation_time)]
        return HostProcessDescriptor(
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            process_id=process_id,
            label=_content_minimized_process_label(
                record.label,
                maximum_characters=self._limits.max_process_label_chars,
            ),
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise HostAutomationServiceUnavailableError()

    def _require_host(self, host_id: HostId) -> None:
        if host_id != self._host_id:
            raise HostAutomationServiceUnavailableError()


def _content_minimized_process_label(value: str, *, maximum_characters: int) -> str:
    if not isinstance(value, str):
        raise TypeError("process label must be a string")
    if (
        isinstance(maximum_characters, bool)
        or not isinstance(maximum_characters, int)
        or maximum_characters <= 0
    ):
        raise ValueError("maximum_characters must be a positive integer")

    normalized = value.replace("/", "\\").rsplit("\\", 1)[-1].replace("\x00", "").strip()
    return normalized[:maximum_characters]
