import asyncio
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

import phoenix_os.host_automation.windows as windows_module
import phoenix_os.host_automation.windows_effects as effects_module
from phoenix_os.host_automation import (
    HostApplicationId,
    HostAutomationAdapterError,
    HostAutomationIndeterminateEffectError,
    HostAutomationLimits,
    HostAutomationStaleIdentityError,
    HostAutomationTargetNotFoundError,
    HostAutomationTimeoutError,
    HostAutomationUnsafeDesktopError,
    HostEpoch,
    HostId,
    HostProcessId,
    HostWindowFocusRequest,
    HostWindowId,
    HostWindowListRequest,
    WindowsHostAutomationAdapter,
)

_NOW = datetime(2026, 8, 15, 19, 30, tzinfo=UTC)
_HOST = HostId("desktop")
_APP = HostApplicationId("editor")


def _window(
    hwnd: int = 100,
    pid: int = 42,
    creation_time: int = 1000,
    title: str = "Editor",
) -> windows_module._NativeWindowRecord:
    return windows_module._NativeWindowRecord(
        hwnd=hwnd,
        pid=pid,
        creation_time=creation_time,
        title=title,
    )


class _FocusDiscoveryBackend:
    def __init__(self, record: windows_module._NativeWindowRecord | None = None) -> None:
        self._record = record or _window()

    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> windows_module._NativeProcessSnapshot:
        del maximum_records, maximum_label_characters
        return windows_module._NativeProcessSnapshot(())

    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> windows_module._NativeWindowSnapshot:
        del maximum_title_characters
        return windows_module._NativeWindowSnapshot((self._record,)[:maximum_records])


class _SuccessfulFocusBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.targets: list[effects_module._WindowsFocusTarget] = []

    def focus_window(
        self,
        target: effects_module._WindowsFocusTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        self.calls += 1
        self.targets.append(target)
        assert attempt.begin_effect() is True


class _StaleFocusBackend:
    def __init__(self) -> None:
        self.calls = 0

    def focus_window(
        self,
        target: effects_module._WindowsFocusTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target, attempt
        self.calls += 1
        raise effects_module._WindowsEffectStaleIdentityError()


class _UnsafeDesktopFocusBackend:
    def __init__(self) -> None:
        self.calls = 0

    def focus_window(
        self,
        target: effects_module._WindowsFocusTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target, attempt
        self.calls += 1
        raise effects_module._WindowsEffectUnsafeDesktopError()


class _FailingFocusBackend:
    def __init__(self) -> None:
        self.calls = 0

    def focus_window(
        self,
        target: effects_module._WindowsFocusTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target, attempt
        self.calls += 1
        raise OSError("HWND=0xdead pid=4242 title=secret")


class _SlowBeforeAdmissionFocusBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.started = False
        self.prevented = False

    def focus_window(
        self,
        target: effects_module._WindowsFocusTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target
        self.calls += 1
        time.sleep(0.03)
        if not attempt.begin_effect():
            self.prevented = True
            raise effects_module._WindowsEffectPreventedError()
        self.started = True


class _SlowAfterAdmissionFocusBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.started = False
        self.admitted = Event()
        self.release = Event()

    def focus_window(
        self,
        target: effects_module._WindowsFocusTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target
        self.calls += 1
        assert attempt.begin_effect() is True
        self.started = True
        self.admitted.set()
        if not self.release.wait(timeout=3.0):
            raise RuntimeError("focus test backend release timed out")


class _FakeWindowLifetimeGuard:
    def __init__(self) -> None:
        self.index = 0
        self.revisions: dict[int, int] = {}
        self.started = False
        self.closed = False
        self.on_barrier: Callable[[], None] | None = None

    def start(self) -> None:
        self.started = True

    def barrier(self) -> int:
        if not self.started or self.closed:
            raise RuntimeError("fake window lifetime guard unavailable")
        self.index += 1
        callback = self.on_barrier
        if callback is not None:
            self.on_barrier = None
            callback()
        return self.index

    def revision_for(self, hwnd: int) -> int:
        if not self.started or self.closed:
            raise RuntimeError("fake window lifetime guard unavailable")
        return self.revisions.get(hwnd, 0)

    def rebirth(self, hwnd: int) -> None:
        self.index += 1
        self.revisions[hwnd] = self.index

    def close(self) -> None:
        self.closed = True


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    effects_backend: object,
    *,
    record: windows_module._NativeWindowRecord | None = None,
    limits: HostAutomationLimits | None = None,
) -> WindowsHostAutomationAdapter:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsDiscoveryBackend",
        lambda: _FocusDiscoveryBackend(record),
    )
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsEffectsBackend",
        lambda: effects_backend,
    )
    guard = _FakeWindowLifetimeGuard()
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsWindowLifetimeGuard",
        lambda: guard,
    )
    return WindowsHostAutomationAdapter(
        host_id=_HOST,
        limits=limits or HostAutomationLimits(),
    )


async def _listed_focus_request(
    adapter: WindowsHostAutomationAdapter,
    *,
    application_id: HostApplicationId | None = None,
) -> HostWindowFocusRequest:
    listed = await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))
    window = listed.windows[0]
    return HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=listed.host_epoch,
        window_id=window.window_id,
        process_id=window.process_id,
        application_id=application_id,
        created_at=_NOW,
    )


@pytest.mark.asyncio
async def test_windows_focus_uses_exact_opaque_window_process_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)

    result = await adapter.focus_window(request)

    assert effects.calls == 1
    assert effects.targets == [
        effects_module._WindowsFocusTarget(
            hwnd=100,
            pid=42,
            creation_time=1000,
            lifetime_revision=0,
        )
    ]
    assert result.host_id == _HOST
    assert result.host_epoch == adapter.host_epoch
    assert result.window_id == request.window_id
    assert result.process_id == request.process_id
    assert str(result.window_id) != "100"
    assert str(result.process_id) != "42"


@pytest.mark.asyncio
async def test_windows_focus_rejects_stale_epoch_process_and_application_before_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)

    stale_epoch = HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=HostEpoch(),
        window_id=request.window_id,
        process_id=request.process_id,
        created_at=_NOW,
    )
    wrong_process = HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=request.host_epoch,
        window_id=request.window_id,
        process_id=HostProcessId(),
        created_at=_NOW,
    )
    wrong_application = HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=request.host_epoch,
        window_id=request.window_id,
        process_id=request.process_id,
        application_id=_APP,
        created_at=_NOW,
    )

    for invalid in (stale_epoch, wrong_process, wrong_application):
        with pytest.raises(HostAutomationStaleIdentityError):
            await adapter.focus_window(invalid)

    assert effects.calls == 0


@pytest.mark.asyncio
async def test_windows_focus_unknown_window_fails_without_native_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)

    with pytest.raises(HostAutomationTargetNotFoundError):
        await adapter.focus_window(
            HostWindowFocusRequest(
                host_id=_HOST,
                host_epoch=request.host_epoch,
                window_id=HostWindowId(),
                process_id=request.process_id,
                created_at=_NOW,
            )
        )

    assert effects.calls == 0


@pytest.mark.asyncio
async def test_windows_focus_toctou_stale_native_identity_is_safe_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _StaleFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)

    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.focus_window(request)

    assert effects.calls == 1


@pytest.mark.asyncio
async def test_windows_focus_unsafe_desktop_is_safe_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _UnsafeDesktopFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)

    with pytest.raises(HostAutomationUnsafeDesktopError) as captured:
        await adapter.focus_window(request)

    assert effects.calls == 1
    assert str(captured.value) == "host desktop state is not safe for this operation"


@pytest.mark.asyncio
async def test_windows_focus_native_failure_redacts_details_and_is_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _FailingFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.focus_window(request)

    assert effects.calls == 1
    assert str(captured.value) == "host automation adapter failed"
    for forbidden in ("0xdead", "4242", "secret"):
        assert forbidden not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_focus_timeout_before_effect_admission_prevents_late_focus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SlowBeforeAdmissionFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)
    adapter._limits = HostAutomationLimits(operation_timeout=timedelta(milliseconds=1))

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.focus_window(request)

    await asyncio.sleep(0.04)
    assert effects.calls == 1
    assert effects.prevented is True
    assert effects.started is False


@pytest.mark.asyncio
async def test_windows_focus_timeout_after_effect_admission_is_indeterminate_and_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SlowAfterAdmissionFocusBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _listed_focus_request(adapter)
    adapter._limits = HostAutomationLimits(operation_timeout=timedelta(seconds=1))

    focus_task = asyncio.create_task(adapter.focus_window(request))
    admitted = await asyncio.to_thread(effects.admitted.wait, 2.0)
    assert admitted is True

    try:
        with pytest.raises(HostAutomationIndeterminateEffectError):
            await focus_task
    finally:
        effects.release.set()

    await asyncio.sleep(0.05)
    assert effects.calls == 1
    assert effects.started is True


def test_native_focus_revalidation_rejects_owner_and_creation_time_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(
        IsWindow=lambda hwnd: bool(hwnd),
        IsWindowVisible=lambda hwnd: bool(hwnd),
    )
    target = effects_module._WindowsFocusTarget(hwnd=100, pid=42, creation_time=1000)

    owners = iter((42, 43))
    monkeypatch.setattr(backend, "_window_process_id", lambda hwnd: next(owners))
    monkeypatch.setattr(backend, "_process_session_id", lambda pid: 7)
    monkeypatch.setattr(backend, "_read_process_creation_time", lambda pid: 1000)

    with pytest.raises(effects_module._WindowsEffectStaleIdentityError):
        backend._revalidate_focus_target(target, expected_session_id=7)

    owners = iter((42, 42))
    creation_times = iter((1000, 2000))
    monkeypatch.setattr(backend, "_window_process_id", lambda hwnd: next(owners))
    monkeypatch.setattr(
        backend,
        "_read_process_creation_time",
        lambda pid: next(creation_times),
    )

    with pytest.raises(effects_module._WindowsEffectStaleIdentityError):
        backend._revalidate_focus_target(target, expected_session_id=7)


def test_native_focus_revalidation_rejects_session_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(
        IsWindow=lambda hwnd: bool(hwnd),
        IsWindowVisible=lambda hwnd: bool(hwnd),
    )
    target = effects_module._WindowsFocusTarget(hwnd=100, pid=42, creation_time=1000)

    monkeypatch.setattr(backend, "_window_process_id", lambda hwnd: 42)
    session_ids = iter((7, 8))
    monkeypatch.setattr(backend, "_process_session_id", lambda pid: next(session_ids))
    monkeypatch.setattr(backend, "_read_process_creation_time", lambda pid: 1000)

    with pytest.raises(effects_module._WindowsEffectUnsafeDesktopError):
        backend._revalidate_focus_target(target, expected_session_id=7)


def test_native_focus_rechecks_desktop_and_target_before_single_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    guard = _FakeWindowLifetimeGuard()
    guard.start()
    backend._window_lifetime_guard = guard

    def set_foreground_window(hwnd: int) -> bool:
        events.append(("set", hwnd))
        return True

    backend._user32 = SimpleNamespace(SetForegroundWindow=set_foreground_window)
    target = effects_module._WindowsFocusTarget(
        hwnd=100,
        pid=42,
        creation_time=1000,
        lifetime_revision=0,
    )
    contexts = iter(((7, "Default"), (7, "Default")))

    def current_desktop_context() -> tuple[int, str]:
        events.append("desktop")
        return next(contexts)

    def revalidate_focus_target(
        checked: effects_module._WindowsFocusTarget,
        *,
        expected_session_id: int,
    ) -> None:
        events.append(("revalidate", expected_session_id, checked.hwnd))

    class _RecordingAttempt(effects_module._WindowsEffectAttempt):
        def begin_effect(self) -> bool:
            events.append("admit")
            return super().begin_effect()

    monkeypatch.setattr(backend, "_current_desktop_context", current_desktop_context)
    monkeypatch.setattr(backend, "_revalidate_focus_target", revalidate_focus_target)

    backend.focus_window(target, attempt=_RecordingAttempt())

    assert events == [
        "desktop",
        ("revalidate", 7, 100),
        "desktop",
        ("revalidate", 7, 100),
        "admit",
        ("set", 100),
    ]


def test_native_focus_rejects_window_rebirth_before_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_calls: list[int] = []
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    guard = _FakeWindowLifetimeGuard()
    guard.start()
    backend._window_lifetime_guard = guard

    def set_foreground_window(hwnd: int) -> bool:
        set_calls.append(hwnd)
        return True

    backend._user32 = SimpleNamespace(SetForegroundWindow=set_foreground_window)
    target = effects_module._WindowsFocusTarget(
        hwnd=100,
        pid=42,
        creation_time=1000,
        lifetime_revision=0,
    )
    monkeypatch.setattr(backend, "_current_desktop_context", lambda: (7, "Default"))
    monkeypatch.setattr(
        backend,
        "_revalidate_focus_target",
        lambda target, expected_session_id: None,
    )
    guard.on_barrier = lambda: guard.rebirth(100)
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectStaleIdentityError):
        backend.focus_window(target, attempt=attempt)

    assert set_calls == []
    assert attempt.cancel_before_start() is True


def test_native_focus_rejects_desktop_change_before_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_calls: list[int] = []
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    guard = _FakeWindowLifetimeGuard()
    guard.start()
    backend._window_lifetime_guard = guard

    def set_foreground_window(hwnd: int) -> bool:
        set_calls.append(hwnd)
        return True

    backend._user32 = SimpleNamespace(SetForegroundWindow=set_foreground_window)
    target = effects_module._WindowsFocusTarget(
        hwnd=100,
        pid=42,
        creation_time=1000,
        lifetime_revision=0,
    )
    contexts = iter(((7, "Default"), (7, "Winlogon")))

    monkeypatch.setattr(backend, "_current_desktop_context", lambda: next(contexts))
    monkeypatch.setattr(
        backend,
        "_revalidate_focus_target",
        lambda target, expected_session_id: None,
    )
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectUnsafeDesktopError):
        backend.focus_window(target, attempt=attempt)

    assert set_calls == []
    assert attempt.cancel_before_start() is True


def test_windows_focus_surface_contains_no_keyboard_or_mouse_injection() -> None:
    source_path = effects_module.__file__
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")
    for forbidden in (
        "SendInput",
        "keybd_event",
        "mouse_event",
        "AttachThreadInput",
    ):
        assert forbidden not in source


@pytest.mark.asyncio
async def test_windows_focus_old_reborn_id_is_rejected_and_new_id_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulFocusBackend()
    adapter = _adapter(monkeypatch, effects)

    old_request = await _listed_focus_request(adapter)
    guard = adapter._window_lifetime_guard
    assert isinstance(guard, _FakeWindowLifetimeGuard)
    guard.rebirth(100)

    new_request = await _listed_focus_request(adapter)
    assert new_request.window_id != old_request.window_id
    assert new_request.process_id == old_request.process_id

    with pytest.raises(HostAutomationTargetNotFoundError):
        await adapter.focus_window(old_request)
    assert effects.calls == 0

    await adapter.focus_window(new_request)
    assert effects.calls == 1


def test_native_focus_guard_failure_prevents_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingBarrierGuard(_FakeWindowLifetimeGuard):
        def barrier(self) -> int:
            raise RuntimeError("lifetime barrier failed")

    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    guard = _FailingBarrierGuard()
    guard.start()
    backend._window_lifetime_guard = guard
    set_calls: list[int] = []

    def set_foreground_window(hwnd: int) -> bool:
        set_calls.append(hwnd)
        return True

    backend._user32 = SimpleNamespace(SetForegroundWindow=set_foreground_window)
    target = effects_module._WindowsFocusTarget(
        hwnd=100,
        pid=42,
        creation_time=1000,
        lifetime_revision=0,
    )
    monkeypatch.setattr(backend, "_current_desktop_context", lambda: (7, "Default"))
    monkeypatch.setattr(
        backend,
        "_revalidate_focus_target",
        lambda target, expected_session_id: None,
    )
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(RuntimeError, match="lifetime barrier failed"):
        backend.focus_window(target, attempt=attempt)

    assert set_calls == []
    assert attempt.cancel_before_start() is True


def test_native_focus_lifetime_change_after_admission_has_no_fictitious_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    guard = _FakeWindowLifetimeGuard()
    guard.start()
    backend._window_lifetime_guard = guard
    target = effects_module._WindowsFocusTarget(
        hwnd=100,
        pid=42,
        creation_time=1000,
        lifetime_revision=0,
    )
    monkeypatch.setattr(backend, "_current_desktop_context", lambda: (7, "Default"))
    monkeypatch.setattr(
        backend,
        "_revalidate_focus_target",
        lambda target, expected_session_id: None,
    )

    set_calls: list[int] = []

    def set_foreground_window(hwnd: int) -> bool:
        set_calls.append(hwnd)
        guard.rebirth(hwnd)
        return True

    backend._user32 = SimpleNamespace(SetForegroundWindow=set_foreground_window)
    attempt = effects_module._WindowsEffectAttempt()

    backend.focus_window(target, attempt=attempt)

    assert set_calls == [100]
    assert attempt.cancel_before_start() is False
    assert guard.revision_for(100) != target.lifetime_revision
