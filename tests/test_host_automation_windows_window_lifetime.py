from __future__ import annotations

import secrets
import threading
from types import SimpleNamespace

import pytest

import phoenix_os.host_automation.windows_window_lifetime as lifetime_module


def _bare_guard() -> lifetime_module._CtypesWindowsWindowLifetimeGuard:
    guard = object.__new__(lifetime_module._CtypesWindowsWindowLifetimeGuard)
    guard._lock = threading.RLock()
    guard._ready = threading.Event()
    guard._stopped = threading.Event()
    guard._thread = threading.Thread(target=lambda: None)
    guard._thread_id = 17
    guard._sentinel_hwnd = 900
    guard._sentinel_object_id = 123_456_789
    guard._callback = None
    guard._event_index = 0
    guard._revisions = {}
    guard._pending = {}
    guard._barriers = {}
    guard._failure = None
    guard._started = True
    guard._closing = False
    guard._closed = False
    return guard


def test_window_lifetime_callback_filters_sentinel_and_non_window_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _bare_guard()
    monkeypatch.setattr(guard, "_ptr", lambda value: int(value))

    barrier_waiter = threading.Event()
    guard._pending[77] = barrier_waiter
    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_CREATE,
        900,
        guard._sentinel_object_id,
        77,
        17,
        0,
    )

    assert barrier_waiter.is_set()
    assert guard._barriers[77] == 1
    assert guard._revisions == {}

    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_CREATE,
        900,
        lifetime_module.OBJID_WINDOW,
        lifetime_module.CHILDID_SELF,
        17,
        0,
    )
    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_CREATE,
        100,
        1,
        lifetime_module.CHILDID_SELF,
        17,
        0,
    )
    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_CREATE,
        100,
        lifetime_module.OBJID_WINDOW,
        4,
        17,
        0,
    )
    assert guard._revisions == {}

    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_CREATE,
        100,
        lifetime_module.OBJID_WINDOW,
        lifetime_module.CHILDID_SELF,
        17,
        0,
    )
    first_revision = guard._revisions[100]
    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_DESTROY,
        100,
        lifetime_module.OBJID_WINDOW,
        lifetime_module.CHILDID_SELF,
        17,
        0,
    )
    assert guard._revisions[100] > first_revision


def test_window_lifetime_callback_failure_is_captured_and_wakes_barriers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _bare_guard()
    waiter = threading.Event()
    guard._pending[88] = waiter

    def fail_ptr(_value: object) -> int:
        raise ValueError("callback failure")

    monkeypatch.setattr(guard, "_ptr", fail_ptr)
    guard._event_callback(
        None,
        lifetime_module.EVENT_OBJECT_CREATE,
        100,
        lifetime_module.OBJID_WINDOW,
        lifetime_module.CHILDID_SELF,
        17,
        0,
    )

    assert waiter.is_set()
    assert isinstance(guard._failure, ValueError)
    with pytest.raises(RuntimeError, match="thread failed"):
        guard._raise_failure()


def test_window_lifetime_cleanup_treats_false_unhook_as_failure() -> None:
    guard = _bare_guard()
    calls: list[tuple[str, object]] = []

    def unhook_win_event(hook: object) -> bool:
        calls.append(("unhook", hook))
        return False

    def destroy_window(hwnd: object) -> bool:
        calls.append(("destroy", hwnd))
        return True

    guard._user32 = SimpleNamespace(
        UnhookWinEvent=unhook_win_event,
        DestroyWindow=destroy_window,
    )
    guard._ctypes = SimpleNamespace(
        get_last_error=lambda: 5,
        WinError=lambda code: OSError(code, "native cleanup failure"),
    )

    guard._cleanup_native(111, 222)

    assert calls == [("unhook", 111), ("destroy", 222)]
    with pytest.raises(RuntimeError, match="thread failed"):
        guard._raise_failure()


def test_window_lifetime_barrier_fails_closed_when_worker_is_dead() -> None:
    guard = _bare_guard()

    with pytest.raises(RuntimeError, match="unavailable"):
        guard.barrier()


def test_window_lifetime_barrier_tokens_are_positive_and_collision_avoiding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _bare_guard()
    guard._pending[10] = threading.Event()
    values = iter((9, 9, 14))
    monkeypatch.setattr(
        secrets,
        "randbelow",
        lambda _maximum: next(values),
    )

    with guard._lock:
        token = guard._new_barrier_token_locked()

    assert token == 15
    assert 0 < token <= lifetime_module.MAX_SENTINEL_VALUE
