"""Windows-specific configured application launch and side-effect admission helpers."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PureWindowsPath
from threading import Lock
from typing import Any, Protocol

from phoenix_os.host_automation.contracts import HostApplicationId


@dataclass(frozen=True, slots=True)
class WindowsApplicationProfile:
    """Trusted adapter configuration for one launchable Windows application."""

    application_id: HostApplicationId
    executable: str
    working_directory: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.application_id, HostApplicationId):
            raise TypeError("application_id must be HostApplicationId")
        object.__setattr__(
            self,
            "executable",
            _validated_local_windows_path(
                self.executable,
                label="application executable",
                executable=True,
            ),
        )
        if self.working_directory is not None:
            object.__setattr__(
                self,
                "working_directory",
                _validated_local_windows_path(
                    self.working_directory,
                    label="application working directory",
                    executable=False,
                ),
            )


@dataclass(frozen=True, slots=True)
class _WindowsLaunchedProcess:
    pid: int
    creation_time: int
    label: str

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("launched process pid must be a positive integer")
        if (
            isinstance(self.creation_time, bool)
            or not isinstance(self.creation_time, int)
            or self.creation_time < 0
        ):
            raise ValueError("launched process creation_time must be non-negative")
        if not isinstance(self.label, str):
            raise TypeError("launched process label must be a string")


class _WindowsEffectPreventedError(RuntimeError):
    pass


class _WindowsEffectTimedOutError(RuntimeError):
    pass


class _WindowsEffectIndeterminateError(RuntimeError):
    pass


class _WindowsEffectAttempt:
    """Coordinate cancellation with the exact native-effect admission boundary."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._cancel_requested: bool = False
        self._started: bool = False

    def begin_effect(self) -> bool:
        with self._lock:
            if self._cancel_requested:
                return False
            self._started = True
            return True

    def cancel_before_start(self) -> bool:
        with self._lock:
            if self._started:
                return False
            self._cancel_requested = True
            return True


class _WindowsEffectsBackend(Protocol):
    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: _WindowsEffectAttempt,
    ) -> _WindowsLaunchedProcess: ...


class _CtypesWindowsEffectsBackend:
    """Launch configured executables with CreateProcessW and no model command line."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows effects backend requires win32")

        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise RuntimeError("Windows native APIs are unavailable")

        self._ctypes: Any = ctypes
        self._wintypes: Any = wintypes
        self._kernel32: Any = win_dll("kernel32", use_last_error=True)

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]

        self._startup_info_type: type[Any] = STARTUPINFOW
        self._process_information_type: type[Any] = PROCESS_INFORMATION
        self._configure_signatures()

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: _WindowsEffectAttempt,
    ) -> _WindowsLaunchedProcess:
        if not isinstance(profile, WindowsApplicationProfile):
            raise TypeError("profile must be WindowsApplicationProfile")
        if not isinstance(attempt, _WindowsEffectAttempt):
            raise TypeError("attempt must be _WindowsEffectAttempt")

        if not attempt.begin_effect():
            raise _WindowsEffectPreventedError()

        startup = self._startup_info_type()
        startup.cb = self._ctypes.sizeof(self._startup_info_type)
        process_info = self._process_information_type()

        success = bool(
            self._kernel32.CreateProcessW(
                profile.executable,
                None,
                None,
                None,
                False,
                0,
                None,
                profile.working_directory,
                self._ctypes.byref(startup),
                self._ctypes.byref(process_info),
            )
        )
        if not success:
            raise RuntimeError("configured Windows application launch failed")

        try:
            pid = int(process_info.dwProcessId)
            creation_time = self._read_creation_time(process_info.hProcess)
            if pid <= 0 or creation_time is None:
                raise _WindowsEffectIndeterminateError()
            return _WindowsLaunchedProcess(
                pid=pid,
                creation_time=creation_time,
                label=PureWindowsPath(profile.executable).name,
            )
        finally:
            if process_info.hThread:
                self._kernel32.CloseHandle(process_info.hThread)
            if process_info.hProcess:
                self._kernel32.CloseHandle(process_info.hProcess)

    def _read_creation_time(self, process: object) -> int | None:
        creation = self._wintypes.FILETIME()
        exit_time = self._wintypes.FILETIME()
        kernel = self._wintypes.FILETIME()
        user = self._wintypes.FILETIME()
        success = bool(
            self._kernel32.GetProcessTimes(
                process,
                self._ctypes.byref(creation),
                self._ctypes.byref(exit_time),
                self._ctypes.byref(kernel),
                self._ctypes.byref(user),
            )
        )
        if not success:
            return None
        return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)

    def _configure_signatures(self) -> None:
        ctypes = self._ctypes
        wintypes = self._wintypes
        self._kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(self._startup_info_type),
            ctypes.POINTER(self._process_information_type),
        ]
        self._kernel32.CreateProcessW.restype = wintypes.BOOL
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


def _normalize_windows_application_profiles(
    profiles: Sequence[WindowsApplicationProfile],
) -> dict[HostApplicationId, WindowsApplicationProfile]:
    if isinstance(profiles, (str, bytes)) or not isinstance(profiles, Sequence):
        raise TypeError("application_profiles must be a sequence")
    normalized: dict[HostApplicationId, WindowsApplicationProfile] = {}
    for profile in profiles:
        if not isinstance(profile, WindowsApplicationProfile):
            raise TypeError("application_profiles must contain WindowsApplicationProfile values")
        if profile.application_id in normalized:
            raise ValueError("application_profiles contain a duplicate application id")
        normalized[profile.application_id] = profile
    return normalized


async def _run_windows_effect[T](
    operation: Callable[[_WindowsEffectAttempt], T],
    *,
    timeout_seconds: float,
) -> T:
    if not callable(operation):
        raise TypeError("operation must be callable")
    if not isinstance(timeout_seconds, float | int) or isinstance(timeout_seconds, bool):
        raise TypeError("timeout_seconds must be numeric")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    attempt = _WindowsEffectAttempt()
    task = asyncio.create_task(asyncio.to_thread(operation, attempt))
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=float(timeout_seconds))
    except TimeoutError as exception:
        if task.done():
            return task.result()
        prevented = attempt.cancel_before_start()
        task.add_done_callback(_consume_background_effect_task)
        if prevented:
            raise _WindowsEffectTimedOutError() from exception
        raise _WindowsEffectIndeterminateError() from exception
    except asyncio.CancelledError as exception:
        prevented = attempt.cancel_before_start()
        task.add_done_callback(_consume_background_effect_task)
        if prevented:
            raise
        raise _WindowsEffectIndeterminateError() from exception


def _consume_background_effect_task(task: asyncio.Future[Any]) -> None:
    if task.cancelled():
        return
    task.exception()


def _validated_local_windows_path(value: str, *, label: str, executable: bool) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty exact path")
    if any(character in value for character in ("\x00", "\r", "\n", '"', "<", ">", "|", "?", "*")):
        raise ValueError(f"{label} contains an unsupported character")

    path = PureWindowsPath(value)
    if not path.is_absolute() or not path.drive.endswith(":"):
        raise ValueError(f"{label} must be an absolute local drive path")
    normalized = str(path)
    if normalized.startswith("\\\\"):
        raise ValueError(f"{label} must not be a UNC or device path")
    if executable and path.suffix.casefold() != ".exe":
        raise ValueError("application executable must name an .exe file")
    return normalized
