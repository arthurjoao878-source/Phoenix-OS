"""Windows-only bounded plain-text clipboard write backend."""

from __future__ import annotations

import sys
from typing import Any, Protocol

from phoenix_os.host_automation.windows_effects import (
    _WindowsEffectAttempt,
    _WindowsEffectIndeterminateError,
    _WindowsEffectPreventedError,
    _WindowsEffectUnsafeDesktopError,
)

_WINDOWS_CF_UNICODETEXT = 13
_WINDOWS_GMEM_MOVEABLE = 0x0002
_WINDOWS_WS_POPUP = 0x80000000
_WINDOWS_MAX_DESKTOP_NAME_CHARS = 256


class _WindowsClipboardBackend(Protocol):
    def write_text(
        self,
        text: str,
        *,
        attempt: _WindowsEffectAttempt,
    ) -> None: ...


class _CtypesWindowsClipboardBackend:
    """Write one immediate-rendered CF_UNICODETEXT payload without format expansion."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows clipboard backend requires win32")

        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise RuntimeError("Windows clipboard APIs are unavailable")

        self._ctypes: Any = ctypes
        self._wintypes: Any = wintypes
        self._kernel32: Any = win_dll("kernel32", use_last_error=True)
        self._user32: Any = win_dll("user32", use_last_error=True)
        self._configure_signatures()

    def write_text(
        self,
        text: str,
        *,
        attempt: _WindowsEffectAttempt,
    ) -> None:
        if not isinstance(text, str):
            raise TypeError("clipboard text must be a string")
        if "\x00" in text:
            raise ValueError("clipboard text must not contain NUL")
        if not isinstance(attempt, _WindowsEffectAttempt):
            raise TypeError("attempt must be _WindowsEffectAttempt")

        try:
            payload = text.encode("utf-16-le") + b"\x00\x00"
        except UnicodeEncodeError as exception:
            raise ValueError("clipboard text is not valid Unicode") from exception

        before = self._current_desktop_context()
        memory = self._kernel32.GlobalAlloc(_WINDOWS_GMEM_MOVEABLE, len(payload))
        if not memory:
            raise RuntimeError("Windows clipboard allocation failed")

        transferred = False
        opened = False
        owner = None
        try:
            pointer = self._kernel32.GlobalLock(memory)
            if not pointer:
                raise RuntimeError("Windows clipboard memory lock failed")
            try:
                self._ctypes.memmove(pointer, payload, len(payload))
            finally:
                self._kernel32.GlobalUnlock(memory)

            owner = self._create_hidden_owner_window()
            if not self._user32.OpenClipboard(owner):
                raise RuntimeError("Windows clipboard is unavailable")
            opened = True

            after = self._current_desktop_context()
            if after != before:
                raise _WindowsEffectUnsafeDesktopError()

            if not attempt.begin_effect():
                raise _WindowsEffectPreventedError()

            if not self._user32.EmptyClipboard():
                raise _WindowsEffectIndeterminateError()
            if not self._user32.SetClipboardData(_WINDOWS_CF_UNICODETEXT, memory):
                raise _WindowsEffectIndeterminateError()
            transferred = True
        finally:
            active_exception = sys.exc_info()[0] is not None
            cleanup_failed = False
            if opened and not self._user32.CloseClipboard():
                cleanup_failed = True
            if owner and not self._user32.DestroyWindow(owner):
                cleanup_failed = True
            if not transferred and memory and self._kernel32.GlobalFree(memory):
                cleanup_failed = True
            if cleanup_failed and not active_exception:
                if transferred:
                    raise _WindowsEffectIndeterminateError()
                raise RuntimeError("Windows clipboard cleanup failed")

    def _create_hidden_owner_window(self) -> object:
        instance = self._kernel32.GetModuleHandleW(None)
        if not instance:
            raise RuntimeError("Windows module handle is unavailable")
        owner = self._user32.CreateWindowExW(
            0,
            "STATIC",
            "",
            _WINDOWS_WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            instance,
            None,
        )
        if not owner:
            raise RuntimeError("Windows clipboard owner window creation failed")
        return owner

    def _current_desktop_context(self) -> tuple[int, str]:
        current_pid = int(self._kernel32.GetCurrentProcessId())
        session_id = self._wintypes.DWORD()
        if not self._kernel32.ProcessIdToSessionId(
            current_pid,
            self._ctypes.byref(session_id),
        ):
            raise _WindowsEffectUnsafeDesktopError()

        input_desktop = self._user32.OpenInputDesktop(0, False, 0x0001)
        if not input_desktop:
            raise _WindowsEffectUnsafeDesktopError()
        try:
            input_name = self._desktop_name(input_desktop)
        finally:
            self._user32.CloseDesktop(input_desktop)

        thread_desktop = self._user32.GetThreadDesktop(self._kernel32.GetCurrentThreadId())
        if not thread_desktop:
            raise _WindowsEffectUnsafeDesktopError()
        thread_name = self._desktop_name(thread_desktop)
        if input_name.casefold() != thread_name.casefold():
            raise _WindowsEffectUnsafeDesktopError()
        return int(session_id.value), input_name

    def _desktop_name(self, desktop: object) -> str:
        buffer = self._ctypes.create_unicode_buffer(_WINDOWS_MAX_DESKTOP_NAME_CHARS + 1)
        needed = self._wintypes.DWORD()
        if not self._user32.GetUserObjectInformationW(
            desktop,
            2,
            buffer,
            self._ctypes.sizeof(buffer),
            self._ctypes.byref(needed),
        ):
            raise _WindowsEffectUnsafeDesktopError()
        name = str(buffer.value).strip()
        if not name:
            raise _WindowsEffectUnsafeDesktopError()
        return name

    def _configure_signatures(self) -> None:
        ctypes = self._ctypes
        wintypes = self._wintypes

        self._kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        self._kernel32.GlobalAlloc.restype = wintypes.HANDLE
        self._kernel32.GlobalLock.argtypes = [wintypes.HANDLE]
        self._kernel32.GlobalLock.restype = ctypes.c_void_p
        self._kernel32.GlobalUnlock.argtypes = [wintypes.HANDLE]
        self._kernel32.GlobalUnlock.restype = wintypes.BOOL
        self._kernel32.GlobalFree.argtypes = [wintypes.HANDLE]
        self._kernel32.GlobalFree.restype = wintypes.HANDLE
        self._kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self._kernel32.GetModuleHandleW.restype = wintypes.HANDLE
        self._kernel32.GetCurrentProcessId.argtypes = []
        self._kernel32.GetCurrentProcessId.restype = wintypes.DWORD
        self._kernel32.GetCurrentThreadId.argtypes = []
        self._kernel32.GetCurrentThreadId.restype = wintypes.DWORD
        self._kernel32.ProcessIdToSessionId.argtypes = [
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._kernel32.ProcessIdToSessionId.restype = wintypes.BOOL

        self._user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.c_void_p,
        ]
        self._user32.CreateWindowExW.restype = wintypes.HWND
        self._user32.DestroyWindow.argtypes = [wintypes.HWND]
        self._user32.DestroyWindow.restype = wintypes.BOOL
        self._user32.OpenClipboard.argtypes = [wintypes.HWND]
        self._user32.OpenClipboard.restype = wintypes.BOOL
        self._user32.CloseClipboard.argtypes = []
        self._user32.CloseClipboard.restype = wintypes.BOOL
        self._user32.EmptyClipboard.argtypes = []
        self._user32.EmptyClipboard.restype = wintypes.BOOL
        self._user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        self._user32.SetClipboardData.restype = wintypes.HANDLE
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
