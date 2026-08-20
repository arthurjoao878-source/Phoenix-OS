"""Private Windows window-lifetime observation and fencing for RFC-0033 EA-12."""

from __future__ import annotations

import secrets
import sys
import threading
from typing import Any, Protocol

EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
OBJID_WINDOW = 0
CHILDID_SELF = 0
WINEVENT_OUTOFCONTEXT = 0
WM_USER = 0x0400
WM_BARRIER = WM_USER + 0x45
WM_STOP = WM_USER + 0x46
PM_NOREMOVE = 0
MAX_SENTINEL_VALUE = 0x7FFFFFFF
WAIT_SECONDS = 5.0


class _WindowsWindowLifetimeGuard(Protocol):
    def start(self) -> None: ...
    def barrier(self) -> int: ...
    def revision_for(self, hwnd: int) -> int: ...
    def close(self) -> None: ...


class _CtypesWindowsWindowLifetimeGuard:
    # Keep these declarations outside the sys.platform-gated constructor so
    # strict mypy can type-check this Windows-only implementation on Linux CI.
    _user32: Any
    _kernel32: Any
    _msg_type: type[Any]
    _callback_type: Any
    _lock: Any
    _ready: threading.Event
    _stopped: threading.Event
    _thread: threading.Thread
    _thread_id: int
    _sentinel_hwnd: int
    _sentinel_object_id: int
    _event_index: int
    _started: bool
    _closing: bool
    _closed: bool

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows window lifetime guard requires win32")
        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise RuntimeError("Windows native APIs are unavailable")

        self._ctypes: Any = ctypes
        self._wintypes: Any = wintypes
        self._user32 = win_dll("user32", use_last_error=True)
        self._kernel32 = win_dll("kernel32", use_last_error=True)

        class POINT(ctypes.Structure):
            _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]

        class MSG(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("message", wintypes.UINT),
                ("wParam", wintypes.WPARAM),
                ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD),
                ("pt", POINT),
            ]

        self._msg_type = MSG
        self._callback_type = ctypes.WINFUNCTYPE(
            None,
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.HWND,
            wintypes.LONG,
            wintypes.LONG,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self._configure_signatures()

        self._lock = threading.RLock()
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._thread = threading.Thread(
            target=self._thread_main,
            name="phoenix-window-lifetime-guard",
            daemon=True,
        )
        self._thread_id = 0
        self._sentinel_hwnd = 0
        # A per-guard CSPRNG object id plus a per-barrier CSPRNG child id prevents
        # another process from predicting a synthetic fence event.
        self._sentinel_object_id = secrets.randbelow(MAX_SENTINEL_VALUE) + 1
        self._callback: object | None = None
        self._event_index = 0
        self._revisions: dict[int, int] = {}
        self._pending: dict[int, threading.Event] = {}
        self._barriers: dict[int, int] = {}
        self._failure: BaseException | None = None
        self._started = False
        self._closing = False
        self._closed = False

    def _configure_signatures(self) -> None:
        c, w = self._ctypes, self._wintypes
        self._user32.PeekMessageW.argtypes = [
            c.POINTER(self._msg_type),
            w.HWND,
            w.UINT,
            w.UINT,
            w.UINT,
        ]
        self._user32.PeekMessageW.restype = w.BOOL
        self._user32.GetMessageW.argtypes = [
            c.POINTER(self._msg_type),
            w.HWND,
            w.UINT,
            w.UINT,
        ]
        self._user32.GetMessageW.restype = w.BOOL
        self._user32.TranslateMessage.argtypes = [c.POINTER(self._msg_type)]
        self._user32.TranslateMessage.restype = w.BOOL
        self._user32.DispatchMessageW.argtypes = [c.POINTER(self._msg_type)]
        self._user32.DispatchMessageW.restype = w.LPARAM
        self._user32.PostThreadMessageW.argtypes = [
            w.DWORD,
            w.UINT,
            w.WPARAM,
            w.LPARAM,
        ]
        self._user32.PostThreadMessageW.restype = w.BOOL
        self._user32.SetWinEventHook.argtypes = [
            w.DWORD,
            w.DWORD,
            w.HMODULE,
            self._callback_type,
            w.DWORD,
            w.DWORD,
            w.DWORD,
        ]
        self._user32.SetWinEventHook.restype = w.HANDLE
        self._user32.UnhookWinEvent.argtypes = [w.HANDLE]
        self._user32.UnhookWinEvent.restype = w.BOOL
        self._user32.NotifyWinEvent.argtypes = [
            w.DWORD,
            w.HWND,
            w.LONG,
            w.LONG,
        ]
        self._user32.NotifyWinEvent.restype = None
        self._user32.CreateWindowExW.argtypes = [
            w.DWORD,
            w.LPCWSTR,
            w.LPCWSTR,
            w.DWORD,
            c.c_int,
            c.c_int,
            c.c_int,
            c.c_int,
            w.HWND,
            w.HMENU,
            w.HINSTANCE,
            w.LPVOID,
        ]
        self._user32.CreateWindowExW.restype = w.HWND
        self._user32.DestroyWindow.argtypes = [w.HWND]
        self._user32.DestroyWindow.restype = w.BOOL
        self._kernel32.GetCurrentThreadId.argtypes = []
        self._kernel32.GetCurrentThreadId.restype = w.DWORD
        self._kernel32.GetModuleHandleW.argtypes = [w.LPCWSTR]
        self._kernel32.GetModuleHandleW.restype = w.HMODULE

    def _ptr(self, value: object) -> int:
        raw = self._ctypes.cast(value, self._ctypes.c_void_p).value
        return 0 if raw is None else int(raw)

    def _message_parent(self) -> object:
        bits = self._ctypes.sizeof(self._ctypes.c_void_p) * 8
        return self._wintypes.HWND((1 << bits) - 3)

    def _record_failure(self, failure: BaseException) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = failure
            waiters = tuple(self._pending.values())
        for waiter in waiters:
            waiter.set()

    def _raise_failure(self) -> None:
        with self._lock:
            failure = self._failure
        if failure is not None:
            raise RuntimeError("window lifetime guard thread failed") from failure

    def _new_barrier_token_locked(self) -> int:
        for _ in range(128):
            token = secrets.randbelow(MAX_SENTINEL_VALUE) + 1
            if token not in self._pending and token not in self._barriers:
                return token
        raise RuntimeError("window lifetime guard could not allocate a barrier token")

    def start(self) -> None:
        with self._lock:
            if self._closing or self._closed:
                raise RuntimeError("window lifetime guard is closed")
            if self._started:
                self._raise_failure()
                if not self._thread.is_alive():
                    raise RuntimeError("window lifetime guard thread is unavailable")
                return
            self._started = True
            self._thread.start()

        if not self._ready.wait(WAIT_SECONDS):
            failure = RuntimeError("window lifetime guard did not become ready")
            self._record_failure(failure)
            raise failure
        self._raise_failure()
        if not self._thread.is_alive():
            failure = RuntimeError("window lifetime guard thread stopped during startup")
            self._record_failure(failure)
            raise failure

        # Startup is complete only after the installed hook's own callback stream
        # has crossed a same-stream fence.
        self.barrier()

    def _event_callback(
        self,
        _hook: object,
        event: int,
        hwnd: object,
        id_object: int,
        id_child: int,
        _event_thread: int,
        _event_time: int,
    ) -> None:
        try:
            hwnd_value = self._ptr(hwnd)
            waiter: threading.Event | None = None
            with self._lock:
                self._event_index += 1
                index = self._event_index
                barrier_token = int(id_child)
                if (
                    int(event) == EVENT_OBJECT_CREATE
                    and hwnd_value == self._sentinel_hwnd
                    and int(id_object) == self._sentinel_object_id
                    and barrier_token in self._pending
                    and barrier_token not in self._barriers
                ):
                    self._barriers[barrier_token] = index
                    waiter = self._pending[barrier_token]
                elif (
                    int(event) in (EVENT_OBJECT_CREATE, EVENT_OBJECT_DESTROY)
                    and int(id_object) == OBJID_WINDOW
                    and int(id_child) == CHILDID_SELF
                    and hwnd_value != 0
                    and hwnd_value != self._sentinel_hwnd
                ):
                    self._revisions[hwnd_value] = index
            if waiter is not None:
                waiter.set()
        except BaseException as exc:
            # ctypes callbacks do not propagate Python exceptions back to the
            # installing thread. Capture them explicitly so all protected paths
            # fail closed and pending fences wake promptly.
            self._record_failure(exc)

    def _cleanup_native(self, hook: object, sentinel: object) -> None:
        if hook:
            try:
                if not bool(self._user32.UnhookWinEvent(hook)):
                    self._record_failure(self._ctypes.WinError(self._ctypes.get_last_error()))
            except BaseException as exc:
                self._record_failure(exc)
        if sentinel:
            try:
                if not bool(self._user32.DestroyWindow(sentinel)):
                    self._record_failure(self._ctypes.WinError(self._ctypes.get_last_error()))
            except BaseException as exc:
                self._record_failure(exc)

    def _thread_main(self) -> None:
        hook = self._wintypes.HANDLE()
        sentinel = self._wintypes.HWND()
        try:
            self._thread_id = int(self._kernel32.GetCurrentThreadId())
            msg = self._msg_type()
            self._user32.PeekMessageW(
                self._ctypes.byref(msg),
                self._wintypes.HWND(),
                WM_USER,
                WM_USER,
                PM_NOREMOVE,
            )
            module = self._kernel32.GetModuleHandleW(None)
            sentinel = self._user32.CreateWindowExW(
                0,
                "STATIC",
                "",
                0,
                0,
                0,
                0,
                0,
                self._message_parent(),
                self._wintypes.HMENU(),
                module,
                None,
            )
            if not sentinel:
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            self._sentinel_hwnd = self._ptr(sentinel)

            self._callback = self._callback_type(self._event_callback)
            hook = self._user32.SetWinEventHook(
                EVENT_OBJECT_CREATE,
                EVENT_OBJECT_DESTROY,
                self._wintypes.HMODULE(),
                self._callback,
                0,
                0,
                WINEVENT_OUTOFCONTEXT,
            )
            if not hook:
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            self._ready.set()

            while True:
                result = int(
                    self._user32.GetMessageW(
                        self._ctypes.byref(msg),
                        self._wintypes.HWND(),
                        0,
                        0,
                    )
                )
                if result == -1:
                    raise self._ctypes.WinError(self._ctypes.get_last_error())
                if result == 0 or int(msg.message) == WM_STOP:
                    break
                if int(msg.message) == WM_BARRIER:
                    self._user32.NotifyWinEvent(
                        EVENT_OBJECT_CREATE,
                        self._wintypes.HWND(self._sentinel_hwnd),
                        self._sentinel_object_id,
                        int(msg.wParam),
                    )
                    continue
                self._user32.TranslateMessage(self._ctypes.byref(msg))
                self._user32.DispatchMessageW(self._ctypes.byref(msg))
        except BaseException as exc:
            self._record_failure(exc)
            self._ready.set()
        finally:
            self._cleanup_native(hook, sentinel)
            self._stopped.set()

    def barrier(self) -> int:
        self._raise_failure()
        with self._lock:
            if self._closing or self._closed or not self._started or not self._thread.is_alive():
                raise RuntimeError("window lifetime guard is unavailable")
            barrier_token = self._new_barrier_token_locked()
            waiter = threading.Event()
            self._pending[barrier_token] = waiter
            thread_id = self._thread_id

        if not self._user32.PostThreadMessageW(
            thread_id,
            WM_BARRIER,
            barrier_token,
            0,
        ):
            with self._lock:
                self._pending.pop(barrier_token, None)
            failure = self._ctypes.WinError(self._ctypes.get_last_error())
            self._record_failure(failure)
            raise failure

        if not waiter.wait(WAIT_SECONDS):
            with self._lock:
                self._pending.pop(barrier_token, None)
                self._barriers.pop(barrier_token, None)
            failure = RuntimeError("window lifetime barrier timed out")
            self._record_failure(failure)
            raise failure

        with self._lock:
            self._pending.pop(barrier_token, None)
            index = self._barriers.pop(barrier_token, None)
        self._raise_failure()
        if index is None:
            failure = RuntimeError("window lifetime barrier completed without index")
            self._record_failure(failure)
            raise failure
        return index

    def revision_for(self, hwnd: int) -> int:
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise ValueError("hwnd must be a positive integer")
        self._raise_failure()
        with self._lock:
            if self._closing or self._closed or not self._started or not self._thread.is_alive():
                raise RuntimeError("window lifetime guard is unavailable")
            return self._revisions.get(hwnd, 0)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                already_closed = True
                started = self._started
                thread_id = self._thread_id
            else:
                already_closed = False
                if self._closing:
                    raise RuntimeError("window lifetime guard close is already in progress")
                self._closing = True
                started = self._started
                thread_id = self._thread_id

        if already_closed:
            self._raise_failure()
            return

        try:
            if started and self._thread.is_alive():
                if not self._user32.PostThreadMessageW(
                    thread_id,
                    WM_STOP,
                    0,
                    0,
                ):
                    raise self._ctypes.WinError(self._ctypes.get_last_error())
                if not self._stopped.wait(WAIT_SECONDS):
                    raise RuntimeError("window lifetime guard thread did not stop")
                self._thread.join(timeout=0.1)
                if self._thread.is_alive():
                    raise RuntimeError("window lifetime guard thread did not join")
            self._raise_failure()
        except BaseException:
            with self._lock:
                self._closing = False
                if not self._thread.is_alive():
                    self._closed = True
            raise
        else:
            with self._lock:
                self._closing = False
                self._closed = True
