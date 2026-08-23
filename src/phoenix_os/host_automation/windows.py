"""Windows host-automation adapter with bounded discovery and configured effects."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

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
    HostAutomationAdapterError,
    HostAutomationIndeterminateEffectError,
    HostAutomationLimitExceededError,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
    HostAutomationTargetNotFoundError,
    HostAutomationTimeoutError,
    HostAutomationUnsafeDesktopError,
    HostAutomationUnsupportedPlatformError,
)
from phoenix_os.host_automation.windows_clipboard import (
    _CtypesWindowsClipboardBackend,
    _WindowsClipboardBackend,
    _WindowsClipboardLimitExceededError,
)
from phoenix_os.host_automation.windows_effects import (
    WindowsApplicationProfile,
    _CtypesWindowsEffectsBackend,
    _normalize_windows_application_profiles,
    _run_windows_effect,
    _WindowsCloseTarget,
    _WindowsEffectIndeterminateError,
    _WindowsEffectsBackend,
    _WindowsEffectStaleIdentityError,
    _WindowsEffectTimedOutError,
    _WindowsEffectUnsafeDesktopError,
    _WindowsFocusTarget,
)
from phoenix_os.host_automation.windows_window_lifetime import (
    _CtypesWindowsWindowLifetimeGuard,
    _WindowsWindowLifetimeGuard,
)


class _WindowsLifetimeAwareEffectsBackend(Protocol):
    _window_lifetime_guard: _WindowsWindowLifetimeGuard | None


_DEFAULT_WINDOWS_HOST_AUTOMATION_LIMITS = HostAutomationLimits()
_WINDOWS_PROCESS_SCAN_MULTIPLIER = 8
_WINDOWS_MIN_PROCESS_SCAN_COUNT = 64
_WINDOWS_MAX_PROCESS_SCAN_COUNT = 32_768
_WINDOWS_WINDOW_SCAN_MULTIPLIER = 8
_WINDOWS_MIN_WINDOW_SCAN_COUNT = 64
_WINDOWS_MAX_WINDOW_SCAN_COUNT = 16_384
_WINDOWS_MAX_DESKTOP_NAME_CHARS = 256


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


@dataclass(frozen=True, slots=True)
class _NativeWindowRecord:
    hwnd: int
    pid: int
    creation_time: int
    title: str

    def __post_init__(self) -> None:
        if isinstance(self.hwnd, bool) or not isinstance(self.hwnd, int) or self.hwnd <= 0:
            raise ValueError("native window handle must be a positive integer")
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("native window pid must be a positive integer")
        if (
            isinstance(self.creation_time, bool)
            or not isinstance(self.creation_time, int)
            or self.creation_time < 0
        ):
            raise ValueError("native window creation_time must be a non-negative integer")
        if not isinstance(self.title, str):
            raise TypeError("native window title must be a string")


@dataclass(frozen=True, slots=True)
class _NativeWindowSnapshot:
    records: tuple[_NativeWindowRecord, ...]
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.records, tuple):
            raise TypeError("native window records must be a tuple")
        if not isinstance(self.truncated, bool):
            raise TypeError("native window truncated must be a boolean")
        for record in self.records:
            if not isinstance(record, _NativeWindowRecord):
                raise TypeError("native window snapshot contains an invalid record")


@dataclass(frozen=True, slots=True)
class _DesktopContext:
    session_id: int
    desktop_name: str

    def __post_init__(self) -> None:
        if isinstance(self.session_id, bool) or not isinstance(self.session_id, int):
            raise TypeError("session_id must be an integer")
        if self.session_id < 0:
            raise ValueError("session_id must be non-negative")
        if not isinstance(self.desktop_name, str) or not self.desktop_name:
            raise ValueError("desktop_name must be a non-empty string")


class _UnsafeDesktopBoundaryError(RuntimeError):
    pass


class _WindowsDiscoveryBackend(Protocol):
    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> _NativeProcessSnapshot: ...

    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> _NativeWindowSnapshot: ...


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

        self._ctypes: Any = ctypes
        self._wintypes: Any = wintypes
        self._get_last_error: Callable[[], int] = get_last_error
        self._kernel32: Any = win_dll("kernel32", use_last_error=True)
        self._user32: Any = win_dll("user32", use_last_error=True)
        self._enum_windows_proc_type: Any = ctypes.WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HWND,
            wintypes.LPARAM,
        )

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

    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> _NativeWindowSnapshot:
        if isinstance(maximum_records, bool) or not isinstance(maximum_records, int):
            raise TypeError("maximum_records must be an integer")
        if maximum_records <= 0:
            raise ValueError("maximum_records must be greater than zero")
        if isinstance(maximum_title_characters, bool) or not isinstance(
            maximum_title_characters, int
        ):
            raise TypeError("maximum_title_characters must be an integer")
        if maximum_title_characters <= 0:
            raise ValueError("maximum_title_characters must be greater than zero")

        before = self._current_desktop_context()
        records: list[_NativeWindowRecord] = []
        truncated = False
        stopped_intentionally = False
        examined = 0
        maximum_examined = min(
            _WINDOWS_MAX_WINDOW_SCAN_COUNT,
            max(
                _WINDOWS_MIN_WINDOW_SCAN_COUNT,
                maximum_records * _WINDOWS_WINDOW_SCAN_MULTIPLIER,
            ),
        )

        def visit(hwnd: int, lparam: int) -> bool:
            nonlocal examined, stopped_intentionally, truncated
            del lparam
            examined += 1
            if examined > maximum_examined:
                truncated = True
                stopped_intentionally = True
                return False

            native_hwnd = int(hwnd) if hwnd else 0
            if native_hwnd > 0 and bool(self._user32.IsWindowVisible(hwnd)):
                record = self._capture_window_record(
                    native_hwnd,
                    expected_session_id=before.session_id,
                    maximum_title_characters=maximum_title_characters,
                )
                if record is not None:
                    records.append(record)
                    if len(records) >= maximum_records:
                        truncated = True
                        stopped_intentionally = True
                        return False

            if examined >= maximum_examined:
                truncated = True
                stopped_intentionally = True
                return False
            return True

        callback = self._enum_windows_proc_type(visit)
        set_last_error = getattr(self._ctypes, "set_last_error", None)
        if callable(set_last_error):
            set_last_error(0)
        success = bool(self._user32.EnumWindows(callback, 0))
        if not success and not stopped_intentionally:
            raise RuntimeError("windows window enumeration failed")

        after = self._current_desktop_context()
        if after != before:
            raise _UnsafeDesktopBoundaryError("desktop changed during window enumeration")

        records.sort(
            key=lambda item: (
                item.title.casefold(),
                item.pid,
                item.creation_time,
                item.hwnd,
            )
        )
        return _NativeWindowSnapshot(tuple(records), truncated=truncated)

    def _capture_window_record(
        self,
        hwnd: int,
        *,
        expected_session_id: int,
        maximum_title_characters: int,
    ) -> _NativeWindowRecord | None:
        if not bool(self._user32.IsWindow(hwnd)):
            return None

        pid_before = self._window_process_id(hwnd)
        if pid_before is None:
            return None
        if self._process_session_id(pid_before) != expected_session_id:
            return None
        creation_before = self._read_process_creation_time(pid_before)
        if creation_before is None:
            return None

        title = self._read_window_title(
            hwnd,
            maximum_characters=maximum_title_characters,
        )

        if not bool(self._user32.IsWindow(hwnd)):
            return None
        pid_after = self._window_process_id(hwnd)
        if pid_after is None or pid_after != pid_before:
            return None
        creation_after = self._read_process_creation_time(pid_after)
        if creation_after != creation_before:
            return None
        if self._process_session_id(pid_after) != expected_session_id:
            return None

        return _NativeWindowRecord(
            hwnd=hwnd,
            pid=pid_before,
            creation_time=creation_before,
            title=title,
        )

    def _window_process_id(self, hwnd: int) -> int | None:
        pid = self._wintypes.DWORD()
        thread_id = self._user32.GetWindowThreadProcessId(hwnd, self._ctypes.byref(pid))
        if not thread_id or not pid.value:
            return None
        return int(pid.value)

    def _process_session_id(self, pid: int) -> int | None:
        session_id = self._wintypes.DWORD()
        success = bool(self._kernel32.ProcessIdToSessionId(pid, self._ctypes.byref(session_id)))
        if not success:
            return None
        return int(session_id.value)

    def _read_window_title(self, hwnd: int, *, maximum_characters: int) -> str:
        length = max(0, int(self._user32.GetWindowTextLengthW(hwnd)))
        capacity = min(length, maximum_characters) + 1
        buffer = self._ctypes.create_unicode_buffer(max(1, capacity))
        copied = int(self._user32.GetWindowTextW(hwnd, buffer, len(buffer)))
        if copied <= 0:
            return ""
        return _content_minimized_window_title(
            str(buffer.value),
            maximum_characters=maximum_characters,
        )

    def _current_desktop_context(self) -> _DesktopContext:
        current_pid = int(self._kernel32.GetCurrentProcessId())
        session_id = self._process_session_id(current_pid)
        if session_id is None:
            raise _UnsafeDesktopBoundaryError("current Windows session is unavailable")

        input_desktop = self._user32.OpenInputDesktop(0, False, 0x0001)
        if not input_desktop:
            raise _UnsafeDesktopBoundaryError("input desktop is unavailable")
        try:
            input_name = self._desktop_name(input_desktop)
        finally:
            self._user32.CloseDesktop(input_desktop)

        thread_desktop = self._user32.GetThreadDesktop(self._kernel32.GetCurrentThreadId())
        if not thread_desktop:
            raise _UnsafeDesktopBoundaryError("thread desktop is unavailable")
        thread_name = self._desktop_name(thread_desktop)
        if input_name.casefold() != thread_name.casefold():
            raise _UnsafeDesktopBoundaryError("thread desktop is not the input desktop")

        return _DesktopContext(session_id=session_id, desktop_name=input_name)

    def _desktop_name(self, desktop: object) -> str:
        buffer = self._ctypes.create_unicode_buffer(_WINDOWS_MAX_DESKTOP_NAME_CHARS + 1)
        needed = self._wintypes.DWORD()
        success = bool(
            self._user32.GetUserObjectInformationW(
                desktop,
                2,
                buffer,
                self._ctypes.sizeof(buffer),
                self._ctypes.byref(needed),
            )
        )
        if not success:
            raise _UnsafeDesktopBoundaryError("Windows desktop identity is unavailable")
        name = str(buffer.value).strip()
        if not name:
            raise _UnsafeDesktopBoundaryError("Windows desktop identity is empty")
        return name

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
        self._kernel32.GetCurrentProcessId.argtypes = []
        self._kernel32.GetCurrentProcessId.restype = wintypes.DWORD
        self._kernel32.GetCurrentThreadId.argtypes = []
        self._kernel32.GetCurrentThreadId.restype = wintypes.DWORD
        self._kernel32.ProcessIdToSessionId.argtypes = [
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL

        self._user32.EnumWindows.argtypes = [self._enum_windows_proc_type, wintypes.LPARAM]
        self._user32.EnumWindows.restype = wintypes.BOOL
        self._user32.IsWindow.argtypes = [wintypes.HWND]
        self._user32.IsWindow.restype = wintypes.BOOL
        self._user32.IsWindowVisible.argtypes = [wintypes.HWND]
        self._user32.IsWindowVisible.restype = wintypes.BOOL
        self._user32.GetWindowThreadProcessId.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        self._user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        self._user32.GetWindowTextLengthW.restype = ctypes.c_int
        self._user32.GetWindowTextW.argtypes = [
            wintypes.HWND,
            wintypes.LPWSTR,
            ctypes.c_int,
        ]
        self._user32.GetWindowTextW.restype = ctypes.c_int
        self._user32.OpenInputDesktop.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        self._user32.OpenInputDesktop.restype = wintypes.HANDLE
        self._user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
        self._user32.GetThreadDesktop.restype = wintypes.HANDLE
        self._user32.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._user32.GetUserObjectInformationW.restype = wintypes.BOOL
        self._user32.CloseDesktop.argtypes = [wintypes.HANDLE]
        self._user32.CloseDesktop.restype = wintypes.BOOL


class WindowsHostAutomationAdapter:
    """Windows implementation boundary for bounded discovery and configured effects."""

    def __init__(
        self,
        *,
        host_id: HostId | str = "local-windows",
        limits: HostAutomationLimits = _DEFAULT_WINDOWS_HOST_AUTOMATION_LIMITS,
        application_profiles: Sequence[WindowsApplicationProfile] = (),
        clipboard_read_enabled: bool = False,
    ) -> None:
        if sys.platform != "win32":
            raise HostAutomationUnsupportedPlatformError()
        self._host_id: HostId = host_id if isinstance(host_id, HostId) else HostId(host_id)
        if not isinstance(limits, HostAutomationLimits):
            raise TypeError("limits must be HostAutomationLimits")
        if not isinstance(clipboard_read_enabled, bool):
            raise TypeError("clipboard_read_enabled must be a boolean")

        self._limits: HostAutomationLimits = limits
        self._clipboard_read_enabled: bool = clipboard_read_enabled
        self._application_profiles: dict[HostApplicationId, WindowsApplicationProfile] = (
            _normalize_windows_application_profiles(application_profiles)
        )
        self._effects_backend: _WindowsEffectsBackend | None = None
        self._clipboard_backend: _WindowsClipboardBackend | None = None
        self._window_lifetime_guard: _WindowsWindowLifetimeGuard | None = None
        self._host_epoch: HostEpoch = HostEpoch()
        self._backend: _WindowsDiscoveryBackend = _CtypesWindowsDiscoveryBackend()
        self._process_ids: dict[tuple[int, int], HostProcessId] = {}
        self._native_processes: dict[HostProcessId, _NativeProcessRecord] = {}
        self._application_ids_by_native_process: dict[tuple[int, int], HostApplicationId] = {}
        self._last_process_records: dict[tuple[int, int], _NativeProcessRecord] = {}
        self._last_window_process_records: dict[tuple[int, int], _NativeProcessRecord] = {}
        self._window_ids: dict[tuple[int, int, int, int], HostWindowId] = {}
        self._native_windows: dict[HostWindowId, _NativeWindowRecord] = {}
        self._window_lifetime_revisions: dict[HostWindowId, int] = {}
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
        if request.limit > self._limits.max_window_results:
            raise HostAutomationLimitExceededError()

        async with self._lock:
            self._ensure_open()
            scan_limit = self._limits.max_window_results + 1
            try:
                guard = self._window_lifetime_guard_for_operation()
                await asyncio.wait_for(
                    asyncio.to_thread(guard.start),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
                before_lifetime = await asyncio.wait_for(
                    asyncio.to_thread(guard.barrier),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
                snapshot = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._backend.enumerate_windows,
                        maximum_records=scan_limit,
                        maximum_title_characters=self._limits.max_window_title_chars,
                    ),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
                await asyncio.wait_for(
                    asyncio.to_thread(guard.barrier),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
            except TimeoutError as exception:
                raise HostAutomationTimeoutError() from exception
            except asyncio.CancelledError:
                raise
            except _UnsafeDesktopBoundaryError as exception:
                raise HostAutomationUnsafeDesktopError() from exception
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

            stable_records: list[_NativeWindowRecord] = []
            lifetime_revisions: dict[int, int] = {}
            try:
                for record in snapshot.records:
                    revision = guard.revision_for(record.hwnd)
                    if revision > before_lifetime:
                        continue
                    stable_records.append(record)
                    lifetime_revisions[record.hwnd] = revision
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

            ordered_records = tuple(
                sorted(
                    stable_records,
                    key=lambda record: (
                        _content_minimized_window_title(
                            record.title,
                            maximum_characters=self._limits.max_window_title_chars,
                        ).casefold(),
                        record.pid,
                        record.creation_time,
                        record.hwnd,
                    ),
                )
            )
            visible_records = ordered_records[: self._limits.max_window_results]
            self._refresh_window_identities(visible_records, lifetime_revisions)
            selected = visible_records[: request.limit]
            descriptors = tuple(self._window_descriptor_for(record) for record in selected)
            truncated = (
                snapshot.truncated
                or len(snapshot.records) > self._limits.max_window_results
                or len(visible_records) > request.limit
            )
            return HostWindowListResult(
                request_id=request.request_id,
                host_id=self._host_id,
                host_epoch=self._host_epoch,
                windows=descriptors,
                truncated=truncated,
                created_at=request.created_at,
            )

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult:
        if not isinstance(request, HostApplicationLaunchRequest):
            raise TypeError("request must be HostApplicationLaunchRequest")
        self._require_host(request.host_id)

        async with self._lock:
            self._ensure_open()
            profile = self._application_profiles.get(request.application_id)
            if profile is None:
                raise HostApplicationNotConfiguredError()

            backend = self._effects_backend_for_operation()
            try:
                launched = await _run_windows_effect(
                    lambda attempt: backend.launch_application(
                        profile,
                        attempt=attempt,
                    ),
                    timeout_seconds=self._limits.operation_timeout.total_seconds(),
                )
            except asyncio.CancelledError:
                raise
            except _WindowsEffectTimedOutError as exception:
                raise HostAutomationTimeoutError() from exception
            except _WindowsEffectIndeterminateError as exception:
                raise HostAutomationIndeterminateEffectError() from exception
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

            record = _NativeProcessRecord(
                pid=launched.pid,
                creation_time=launched.creation_time,
                label=launched.label,
            )
            key = (record.pid, record.creation_time)
            self._last_process_records[key] = record
            self._application_ids_by_native_process[key] = request.application_id
            self._rebuild_process_identity_state()
            process_id = self._process_ids[key]
            return HostApplicationLaunchResult(
                request_id=request.request_id,
                host_id=self._host_id,
                host_epoch=self._host_epoch,
                application_id=request.application_id,
                process_id=process_id,
                created_at=request.created_at,
            )

    async def focus_window(self, request: HostWindowFocusRequest) -> HostWindowFocusResult:
        if not isinstance(request, HostWindowFocusRequest):
            raise TypeError("request must be HostWindowFocusRequest")
        self._require_host(request.host_id)

        async with self._lock:
            self._ensure_open()
            if request.host_epoch != self._host_epoch:
                raise HostAutomationStaleIdentityError()

            native_window = self._native_windows.get(request.window_id)
            if native_window is None:
                raise HostAutomationTargetNotFoundError()

            native_key = (native_window.pid, native_window.creation_time)
            process_id = self._process_ids.get(native_key)
            if process_id != request.process_id:
                raise HostAutomationStaleIdentityError()

            application_id = self._application_ids_by_native_process.get(native_key)
            if request.application_id is not None and application_id != request.application_id:
                raise HostAutomationStaleIdentityError()

            lifetime_revision = self._window_lifetime_revisions.get(request.window_id)
            if lifetime_revision is None:
                raise HostAutomationStaleIdentityError()

            guard = self._window_lifetime_guard_for_operation()
            backend = self._effects_backend_for_operation()
            # The concrete backend requires the private lifetime guard. The cast
            # describes this private binding without relying on the monkeypatchable
            # concrete constructor symbol as an isinstance() operand.
            cast(
                _WindowsLifetimeAwareEffectsBackend,
                backend,
            )._window_lifetime_guard = guard
            target = _WindowsFocusTarget(
                hwnd=native_window.hwnd,
                pid=native_window.pid,
                creation_time=native_window.creation_time,
                lifetime_revision=lifetime_revision,
            )
            try:
                await _run_windows_effect(
                    lambda attempt: backend.focus_window(
                        target,
                        attempt=attempt,
                    ),
                    timeout_seconds=self._limits.operation_timeout.total_seconds(),
                )
            except asyncio.CancelledError:
                raise
            except _WindowsEffectTimedOutError as exception:
                raise HostAutomationTimeoutError() from exception
            except _WindowsEffectIndeterminateError as exception:
                raise HostAutomationIndeterminateEffectError() from exception
            except _WindowsEffectStaleIdentityError as exception:
                raise HostAutomationStaleIdentityError() from exception
            except _WindowsEffectUnsafeDesktopError as exception:
                raise HostAutomationUnsafeDesktopError() from exception
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

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
        if not isinstance(request, HostApplicationCloseRequest):
            raise TypeError("request must be HostApplicationCloseRequest")
        self._require_host(request.host_id)

        async with self._lock:
            self._ensure_open()
            if request.host_epoch != self._host_epoch:
                raise HostAutomationStaleIdentityError()

            native_process = self._native_processes.get(request.process_id)
            if native_process is None:
                raise HostAutomationTargetNotFoundError()

            native_key = (native_process.pid, native_process.creation_time)
            if self._process_ids.get(native_key) != request.process_id:
                raise HostAutomationStaleIdentityError()
            if self._application_ids_by_native_process.get(native_key) != request.application_id:
                raise HostAutomationStaleIdentityError()

            backend = self._effects_backend_for_operation()
            target = _WindowsCloseTarget(
                pid=native_process.pid,
                creation_time=native_process.creation_time,
            )
            try:
                await _run_windows_effect(
                    lambda attempt: backend.close_application(
                        target,
                        attempt=attempt,
                    ),
                    timeout_seconds=self._limits.operation_timeout.total_seconds(),
                )
            except asyncio.CancelledError:
                raise
            except _WindowsEffectTimedOutError as exception:
                raise HostAutomationTimeoutError() from exception
            except _WindowsEffectIndeterminateError as exception:
                raise HostAutomationIndeterminateEffectError() from exception
            except _WindowsEffectStaleIdentityError as exception:
                raise HostAutomationStaleIdentityError() from exception
            except _WindowsEffectUnsafeDesktopError as exception:
                raise HostAutomationUnsafeDesktopError() from exception
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

            return HostApplicationCloseResult(
                request_id=request.request_id,
                host_id=self._host_id,
                host_epoch=self._host_epoch,
                application_id=request.application_id,
                process_id=request.process_id,
                created_at=request.created_at,
            )

    async def read_clipboard(self, request: HostClipboardReadRequest) -> HostClipboardReadResult:
        if not isinstance(request, HostClipboardReadRequest):
            raise TypeError("request must be HostClipboardReadRequest")
        self._require_host(request.host_id)
        self._ensure_open()
        if not self._clipboard_read_enabled:
            raise HostAutomationOperationDisabledError()

        async with self._lock:
            self._ensure_open()
            backend = self._clipboard_backend_for_operation()
            text: object = ""
            failure: Exception | None = None
            try:
                text = await asyncio.wait_for(
                    asyncio.to_thread(
                        backend.read_text,
                        maximum_chars=self._limits.max_clipboard_text_chars,
                        maximum_utf8_bytes=self._limits.max_clipboard_text_bytes,
                    ),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
            except TimeoutError:
                failure = HostAutomationTimeoutError()
            except asyncio.CancelledError:
                raise
            except _WindowsClipboardLimitExceededError:
                failure = HostAutomationLimitExceededError()
            except _WindowsEffectUnsafeDesktopError:
                failure = HostAutomationUnsafeDesktopError()
            except Exception:
                failure = HostAutomationAdapterError()

            if failure is not None:
                raise failure
            if not isinstance(text, str):
                raise HostAutomationAdapterError()

            encoded: bytes | None
            try:
                encoded = text.encode("utf-8")
            except UnicodeEncodeError:
                encoded = None
            if encoded is None:
                raise HostAutomationAdapterError()
            if (
                len(text) > self._limits.max_clipboard_text_chars
                or len(encoded) > self._limits.max_clipboard_text_bytes
            ):
                raise HostAutomationLimitExceededError()

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
        if not isinstance(request, HostClipboardWriteRequest):
            raise TypeError("request must be HostClipboardWriteRequest")
        self._require_host(request.host_id)

        encoded = request.text.encode("utf-8")
        if (
            len(request.text) > self._limits.max_clipboard_text_chars
            or len(encoded) > self._limits.max_clipboard_text_bytes
        ):
            raise HostAutomationLimitExceededError()

        async with self._lock:
            self._ensure_open()
            backend = self._clipboard_backend_for_operation()
            failure: Exception | None = None
            try:
                await _run_windows_effect(
                    lambda attempt: backend.write_text(
                        request.text,
                        attempt=attempt,
                    ),
                    timeout_seconds=self._limits.operation_timeout.total_seconds(),
                )
            except asyncio.CancelledError:
                raise
            except _WindowsEffectTimedOutError:
                failure = HostAutomationTimeoutError()
            except _WindowsEffectIndeterminateError:
                failure = HostAutomationIndeterminateEffectError()
            except _WindowsEffectUnsafeDesktopError:
                failure = HostAutomationUnsafeDesktopError()
            except Exception:
                failure = HostAutomationAdapterError()

            if failure is not None:
                raise failure

            return HostClipboardWriteResult(
                request_id=request.request_id,
                host_id=self._host_id,
                written_characters=len(request.text),
                written_bytes=len(encoded),
                created_at=request.created_at,
            )

    async def close(self) -> None:
        async with self._lock:
            if not self._closed:
                self._process_ids.clear()
                self._native_processes.clear()
                self._application_ids_by_native_process.clear()
                self._last_process_records.clear()
                self._last_window_process_records.clear()
                self._window_ids.clear()
                self._native_windows.clear()
                self._window_lifetime_revisions.clear()
                self._closed = True

            guard = self._window_lifetime_guard
            if guard is None:
                return

            try:
                await asyncio.wait_for(
                    asyncio.to_thread(guard.close),
                    timeout=self._limits.operation_timeout.total_seconds(),
                )
            except TimeoutError as exception:
                raise HostAutomationTimeoutError() from exception
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                raise HostAutomationAdapterError() from exception

            # Release the guard only after native hook/thread cleanup succeeds.
            # If cleanup fails or times out, the adapter stays closed but retains
            # the guard so a later close() can retry cleanup without reopening ops.
            self._window_lifetime_guard = None

    def _refresh_process_identities(
        self,
        records: tuple[_NativeProcessRecord, ...],
    ) -> None:
        self._last_process_records = {
            (record.pid, record.creation_time): record for record in records
        }
        self._rebuild_process_identity_state()

    def _refresh_window_identities(
        self,
        records: tuple[_NativeWindowRecord, ...],
        lifetime_revisions: dict[int, int],
    ) -> None:
        self._last_window_process_records = {
            (record.pid, record.creation_time): _NativeProcessRecord(
                pid=record.pid,
                creation_time=record.creation_time,
                label="",
            )
            for record in records
        }
        self._rebuild_process_identity_state()

        active_keys = {
            (record.hwnd, record.pid, record.creation_time, lifetime_revisions[record.hwnd])
            for record in records
        }
        self._window_ids = {
            key: window_id for key, window_id in self._window_ids.items() if key in active_keys
        }

        native_windows: dict[HostWindowId, _NativeWindowRecord] = {}
        window_lifetime_revisions: dict[HostWindowId, int] = {}
        for record in records:
            revision = lifetime_revisions[record.hwnd]
            key = (record.hwnd, record.pid, record.creation_time, revision)
            window_id = self._window_ids.get(key)
            if window_id is None:
                window_id = HostWindowId()
                self._window_ids[key] = window_id
            native_windows[window_id] = record
            window_lifetime_revisions[window_id] = revision
        self._native_windows = native_windows
        self._window_lifetime_revisions = window_lifetime_revisions

    def _rebuild_process_identity_state(self) -> None:
        active_records = dict(self._last_window_process_records)
        active_records.update(self._last_process_records)
        active_keys = set(active_records)
        self._application_ids_by_native_process = {
            key: application_id
            for key, application_id in self._application_ids_by_native_process.items()
            if key in active_keys
        }
        self._process_ids = {
            key: process_id for key, process_id in self._process_ids.items() if key in active_keys
        }

        native_processes: dict[HostProcessId, _NativeProcessRecord] = {}
        for key, record in active_records.items():
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
            application_id=self._application_ids_by_native_process.get(
                (record.pid, record.creation_time)
            ),
            label=_content_minimized_process_label(
                record.label,
                maximum_characters=self._limits.max_process_label_chars,
            ),
        )

    def _window_descriptor_for(self, record: _NativeWindowRecord) -> HostWindowDescriptor:
        process_id = self._process_ids[(record.pid, record.creation_time)]
        matching_window_ids = [
            window_id
            for (hwnd, pid, creation_time, _revision), window_id in self._window_ids.items()
            if (hwnd == record.hwnd and pid == record.pid and creation_time == record.creation_time)
        ]
        if len(matching_window_ids) != 1:
            raise RuntimeError("window lifetime identity binding is inconsistent")
        window_id = matching_window_ids[0]
        return HostWindowDescriptor(
            host_id=self._host_id,
            host_epoch=self._host_epoch,
            window_id=window_id,
            process_id=process_id,
            application_id=self._application_ids_by_native_process.get(
                (record.pid, record.creation_time)
            ),
            title=_content_minimized_window_title(
                record.title,
                maximum_characters=self._limits.max_window_title_chars,
            ),
        )

    def _window_lifetime_guard_for_operation(self) -> _WindowsWindowLifetimeGuard:
        guard = self._window_lifetime_guard
        if guard is None:
            guard = _CtypesWindowsWindowLifetimeGuard()
            self._window_lifetime_guard = guard
        return guard

    def _effects_backend_for_operation(self) -> _WindowsEffectsBackend:
        backend = self._effects_backend
        if backend is None:
            backend = _CtypesWindowsEffectsBackend()
            self._effects_backend = backend
        return backend

    def _clipboard_backend_for_operation(self) -> _WindowsClipboardBackend:
        backend = self._clipboard_backend
        if backend is None:
            backend = _CtypesWindowsClipboardBackend()
            self._clipboard_backend = backend
        return backend

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


def _content_minimized_window_title(value: str, *, maximum_characters: int) -> str:
    if not isinstance(value, str):
        raise TypeError("window title must be a string")
    if (
        isinstance(maximum_characters, bool)
        or not isinstance(maximum_characters, int)
        or maximum_characters <= 0
    ):
        raise ValueError("maximum_characters must be a positive integer")

    normalized = value.replace("\x00", "").strip()
    return normalized[:maximum_characters]
