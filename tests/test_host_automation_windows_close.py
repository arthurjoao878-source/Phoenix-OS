import asyncio
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

import phoenix_os.host_automation.windows as windows_module
import phoenix_os.host_automation.windows_effects as effects_module
from phoenix_os.host_automation import (
    HostApplicationCloseRequest,
    HostApplicationId,
    HostApplicationLaunchRequest,
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
    WindowsHostAutomationAdapter,
)
from phoenix_os.host_automation.windows_effects import WindowsApplicationProfile

_NOW = datetime(2026, 8, 15, 20, 40, tzinfo=UTC)
_HOST = HostId("desktop")
_APP = HostApplicationId("editor")


class _DiscoveryBackend:
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
        del maximum_records, maximum_title_characters
        return windows_module._NativeWindowSnapshot(())


class _SuccessfulCloseBackend:
    def __init__(self) -> None:
        self.launch_calls = 0
        self.close_calls = 0
        self.close_targets: list[effects_module._WindowsCloseTarget] = []

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> effects_module._WindowsLaunchedProcess:
        del profile
        self.launch_calls += 1
        assert attempt.begin_effect() is True
        return effects_module._WindowsLaunchedProcess(
            pid=4242,
            creation_time=9001,
            label="editor.exe",
        )

    def close_application(
        self,
        target: effects_module._WindowsCloseTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        self.close_calls += 1
        self.close_targets.append(target)
        assert attempt.begin_effect() is True


class _StaleCloseBackend(_SuccessfulCloseBackend):
    def close_application(
        self,
        target: effects_module._WindowsCloseTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target, attempt
        self.close_calls += 1
        raise effects_module._WindowsEffectStaleIdentityError()


class _UnsafeCloseBackend(_SuccessfulCloseBackend):
    def close_application(
        self,
        target: effects_module._WindowsCloseTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target, attempt
        self.close_calls += 1
        raise effects_module._WindowsEffectUnsafeDesktopError()


class _FailingCloseBackend(_SuccessfulCloseBackend):
    def close_application(
        self,
        target: effects_module._WindowsCloseTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target, attempt
        self.close_calls += 1
        raise OSError("pid=4242 hwnd=0xdead title=secret")


class _SlowBeforeAdmissionCloseBackend(_SuccessfulCloseBackend):
    def __init__(self) -> None:
        super().__init__()
        self.prevented = False
        self.started = False

    def close_application(
        self,
        target: effects_module._WindowsCloseTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target
        self.close_calls += 1
        time.sleep(0.03)
        if not attempt.begin_effect():
            self.prevented = True
            raise effects_module._WindowsEffectPreventedError()
        self.started = True


class _SlowAfterAdmissionCloseBackend(_SuccessfulCloseBackend):
    def __init__(self) -> None:
        super().__init__()
        self.started = False
        self.admitted = Event()
        self.release = Event()

    def close_application(
        self,
        target: effects_module._WindowsCloseTarget,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del target
        self.close_calls += 1
        assert attempt.begin_effect() is True
        self.started = True
        self.admitted.set()
        if not self.release.wait(timeout=3.0):
            raise RuntimeError("close test backend release timed out")


def _profile() -> WindowsApplicationProfile:
    return WindowsApplicationProfile(
        application_id=_APP,
        executable=r"C:\Program Files\Phoenix\editor.exe",
        working_directory=r"C:\Program Files\Phoenix",
    )


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    effects_backend: object,
) -> WindowsHostAutomationAdapter:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_module, "_CtypesWindowsDiscoveryBackend", _DiscoveryBackend)
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsEffectsBackend",
        lambda: effects_backend,
    )
    return WindowsHostAutomationAdapter(
        host_id=_HOST,
        application_profiles=(_profile(),),
    )


async def _launched_close_request(
    adapter: WindowsHostAutomationAdapter,
) -> HostApplicationCloseRequest:
    launched = await adapter.launch_application(
        HostApplicationLaunchRequest(
            host_id=_HOST,
            application_id=_APP,
            created_at=_NOW,
        )
    )
    return HostApplicationCloseRequest(
        host_id=_HOST,
        host_epoch=launched.host_epoch,
        application_id=launched.application_id,
        process_id=launched.process_id,
        created_at=_NOW,
    )


@pytest.mark.asyncio
async def test_windows_close_targets_exact_configured_process_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)

    result = await adapter.close_application(request)

    assert effects.launch_calls == 1
    assert effects.close_calls == 1
    assert effects.close_targets == [
        effects_module._WindowsCloseTarget(pid=4242, creation_time=9001)
    ]
    assert result.host_id == _HOST
    assert result.host_epoch == request.host_epoch
    assert result.application_id == _APP
    assert result.process_id == request.process_id
    assert str(result.process_id) != "4242"


@pytest.mark.asyncio
async def test_windows_close_rejects_stale_epoch_process_and_application_before_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)

    invalid_requests = (
        HostApplicationCloseRequest(
            host_id=_HOST,
            host_epoch=HostEpoch(),
            application_id=_APP,
            process_id=request.process_id,
            created_at=_NOW,
        ),
        HostApplicationCloseRequest(
            host_id=_HOST,
            host_epoch=request.host_epoch,
            application_id=_APP,
            process_id=HostProcessId(),
            created_at=_NOW,
        ),
        HostApplicationCloseRequest(
            host_id=_HOST,
            host_epoch=request.host_epoch,
            application_id=HostApplicationId("other"),
            process_id=request.process_id,
            created_at=_NOW,
        ),
    )

    expected = (
        HostAutomationStaleIdentityError,
        HostAutomationTargetNotFoundError,
        HostAutomationStaleIdentityError,
    )
    for invalid, error_type in zip(invalid_requests, expected, strict=True):
        with pytest.raises(error_type):
            await adapter.close_application(invalid)

    assert effects.close_calls == 0


@pytest.mark.asyncio
async def test_windows_close_native_stale_identity_is_safe_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _StaleCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)

    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.close_application(request)

    assert effects.close_calls == 1


@pytest.mark.asyncio
async def test_windows_close_unsafe_desktop_is_safe_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _UnsafeCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)

    with pytest.raises(HostAutomationUnsafeDesktopError):
        await adapter.close_application(request)

    assert effects.close_calls == 1


@pytest.mark.asyncio
async def test_windows_close_native_failure_redacts_details_and_is_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _FailingCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.close_application(request)

    assert effects.close_calls == 1
    assert str(captured.value) == "host automation adapter failed"
    for forbidden in ("4242", "0xdead", "secret"):
        assert forbidden not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_close_timeout_before_effect_admission_prevents_late_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SlowBeforeAdmissionCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)
    adapter._limits = HostAutomationLimits(operation_timeout=timedelta(milliseconds=1))

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.close_application(request)

    await asyncio.sleep(0.04)
    assert effects.close_calls == 1
    assert effects.prevented is True
    assert effects.started is False


@pytest.mark.asyncio
async def test_windows_close_timeout_after_effect_admission_is_indeterminate_and_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SlowAfterAdmissionCloseBackend()
    adapter = _adapter(monkeypatch, effects)
    request = await _launched_close_request(adapter)
    adapter._limits = HostAutomationLimits(operation_timeout=timedelta(seconds=1))

    close_task = asyncio.create_task(adapter.close_application(request))
    admitted = await asyncio.to_thread(effects.admitted.wait, 2.0)
    assert admitted is True

    try:
        with pytest.raises(HostAutomationIndeterminateEffectError):
            await close_task
    finally:
        effects.release.set()

    await asyncio.sleep(0.05)
    assert effects.close_calls == 1
    assert effects.started is True


def test_native_close_revalidates_and_posts_only_graceful_wm_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    def post_message(hwnd: int, message: int, wparam: int, lparam: int) -> bool:
        events.append(("post", hwnd, message, wparam, lparam))
        return True

    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(PostMessageW=post_message)
    target = effects_module._WindowsCloseTarget(pid=42, creation_time=1000)
    contexts = iter(((7, "Default"), (7, "Default")))

    def current_desktop_context() -> tuple[int, str]:
        events.append("desktop")
        return next(contexts)

    def revalidate_close_target(
        checked: effects_module._WindowsCloseTarget,
        *,
        expected_session_id: int,
    ) -> None:
        events.append(("target", checked.pid, checked.creation_time, expected_session_id))

    def enumerate_close_windows(pid: int) -> tuple[int, ...]:
        events.append(("enumerate", pid))
        return (100, 101)

    def revalidate_close_window(
        hwnd: int,
        checked: effects_module._WindowsCloseTarget,
    ) -> None:
        events.append(("window", hwnd, checked.pid, checked.creation_time))

    class _RecordingAttempt(effects_module._WindowsEffectAttempt):
        def begin_effect(self) -> bool:
            events.append("admit")
            return super().begin_effect()

    monkeypatch.setattr(backend, "_current_desktop_context", current_desktop_context)
    monkeypatch.setattr(backend, "_revalidate_close_target", revalidate_close_target)
    monkeypatch.setattr(backend, "_enumerate_close_windows", enumerate_close_windows)
    monkeypatch.setattr(backend, "_revalidate_close_window", revalidate_close_window)

    backend.close_application(target, attempt=_RecordingAttempt())

    assert events == [
        "desktop",
        ("target", 42, 1000, 7),
        ("enumerate", 42),
        "desktop",
        ("target", 42, 1000, 7),
        ("window", 100, 42, 1000),
        ("window", 101, 42, 1000),
        "admit",
        ("window", 100, 42, 1000),
        ("post", 100, 0x0010, 0, 0),
        ("window", 101, 42, 1000),
        ("post", 101, 0x0010, 0, 0),
    ]


def test_native_close_rejects_process_reuse_and_session_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    target = effects_module._WindowsCloseTarget(pid=42, creation_time=1000)

    creation_times = iter((1000, 2000))
    monkeypatch.setattr(
        backend,
        "_read_process_creation_time",
        lambda pid: next(creation_times),
    )
    monkeypatch.setattr(backend, "_process_session_id", lambda pid: 7)

    with pytest.raises(effects_module._WindowsEffectStaleIdentityError):
        backend._revalidate_close_target(target, expected_session_id=7)

    monkeypatch.setattr(backend, "_read_process_creation_time", lambda pid: 1000)
    session_ids = iter((7, 8))
    monkeypatch.setattr(backend, "_process_session_id", lambda pid: next(session_ids))

    with pytest.raises(effects_module._WindowsEffectUnsafeDesktopError):
        backend._revalidate_close_target(target, expected_session_id=7)


def test_native_close_rejects_desktop_change_before_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    post_calls: list[int] = []

    def post_message(hwnd: int, message: int, wparam: int, lparam: int) -> bool:
        del message, wparam, lparam
        post_calls.append(hwnd)
        return True

    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(PostMessageW=post_message)
    target = effects_module._WindowsCloseTarget(pid=42, creation_time=1000)
    contexts = iter(((7, "Default"), (7, "Winlogon")))

    monkeypatch.setattr(backend, "_current_desktop_context", lambda: next(contexts))
    monkeypatch.setattr(
        backend,
        "_revalidate_close_target",
        lambda target, expected_session_id: None,
    )
    monkeypatch.setattr(backend, "_enumerate_close_windows", lambda pid: (100,))
    monkeypatch.setattr(
        backend,
        "_revalidate_close_window",
        lambda hwnd, target: None,
    )
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectUnsafeDesktopError):
        backend.close_application(target, attempt=attempt)

    assert post_calls == []
    assert attempt.cancel_before_start() is True


def test_native_close_rejects_target_change_before_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    post_calls: list[int] = []

    def post_message(hwnd: int, message: int, wparam: int, lparam: int) -> bool:
        del message, wparam, lparam
        post_calls.append(hwnd)
        return True

    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(PostMessageW=post_message)
    target = effects_module._WindowsCloseTarget(pid=42, creation_time=1000)
    contexts = iter(((7, "Default"), (7, "Default")))
    target_checks = 0

    def revalidate_close_target(
        checked: effects_module._WindowsCloseTarget,
        *,
        expected_session_id: int,
    ) -> None:
        nonlocal target_checks
        assert checked == target
        assert expected_session_id == 7
        target_checks += 1
        if target_checks == 2:
            raise effects_module._WindowsEffectStaleIdentityError()

    monkeypatch.setattr(backend, "_current_desktop_context", lambda: next(contexts))
    monkeypatch.setattr(backend, "_revalidate_close_target", revalidate_close_target)
    monkeypatch.setattr(backend, "_enumerate_close_windows", lambda pid: (100,))
    monkeypatch.setattr(
        backend,
        "_revalidate_close_window",
        lambda hwnd, checked: None,
    )
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectStaleIdentityError):
        backend.close_application(target, attempt=attempt)

    assert target_checks == 2
    assert post_calls == []
    assert attempt.cancel_before_start() is True


def test_native_close_partial_effect_becomes_indeterminate_without_retarget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    post_calls: list[int] = []

    def post_message(hwnd: int, message: int, wparam: int, lparam: int) -> bool:
        assert message == 0x0010
        assert wparam == 0
        assert lparam == 0
        post_calls.append(hwnd)
        return True

    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(PostMessageW=post_message)
    target = effects_module._WindowsCloseTarget(pid=42, creation_time=1000)
    contexts = iter(((7, "Default"), (7, "Default")))
    checks: dict[int, int] = {}

    def revalidate_close_window(
        hwnd: int,
        checked: effects_module._WindowsCloseTarget,
    ) -> None:
        assert checked == target
        checks[hwnd] = checks.get(hwnd, 0) + 1
        if hwnd == 101 and checks[hwnd] == 2:
            raise effects_module._WindowsEffectStaleIdentityError()

    monkeypatch.setattr(backend, "_current_desktop_context", lambda: next(contexts))
    monkeypatch.setattr(
        backend,
        "_revalidate_close_target",
        lambda checked, expected_session_id: None,
    )
    monkeypatch.setattr(backend, "_enumerate_close_windows", lambda pid: (100, 101))
    monkeypatch.setattr(backend, "_revalidate_close_window", revalidate_close_window)
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectIndeterminateError):
        backend.close_application(target, attempt=attempt)

    assert post_calls == [100]
    assert checks == {100: 2, 101: 2}
    assert attempt.cancel_before_start() is False


def test_native_close_post_failure_after_admission_is_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    post_calls: list[int] = []

    def post_message(hwnd: int, message: int, wparam: int, lparam: int) -> bool:
        assert message == 0x0010
        assert wparam == 0
        assert lparam == 0
        post_calls.append(hwnd)
        return False

    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._user32 = SimpleNamespace(PostMessageW=post_message)
    target = effects_module._WindowsCloseTarget(pid=42, creation_time=1000)
    contexts = iter(((7, "Default"), (7, "Default")))

    monkeypatch.setattr(backend, "_current_desktop_context", lambda: next(contexts))
    monkeypatch.setattr(
        backend,
        "_revalidate_close_target",
        lambda checked, expected_session_id: None,
    )
    monkeypatch.setattr(backend, "_enumerate_close_windows", lambda pid: (100,))
    monkeypatch.setattr(
        backend,
        "_revalidate_close_window",
        lambda hwnd, checked: None,
    )
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectIndeterminateError):
        backend.close_application(target, attempt=attempt)

    assert post_calls == [100]
    assert attempt.cancel_before_start() is False


def test_native_close_window_enumeration_is_strictly_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(effects_module._CtypesWindowsEffectsBackend)
    backend._enum_windows_proc_type = lambda callback: callback

    def enum_windows(callback: object, lparam: int) -> bool:
        assert callable(callback)
        for hwnd in range(1, effects_module._WINDOWS_MAX_CLOSE_WINDOWS + 2):
            if not callback(hwnd, lparam):
                return False
        return True

    backend._user32 = SimpleNamespace(EnumWindows=enum_windows)
    monkeypatch.setattr(backend, "_window_process_id", lambda hwnd: 42)

    with pytest.raises(RuntimeError, match="window limit exceeded"):
        backend._enumerate_close_windows(42)


def test_windows_close_surface_has_no_force_kill_fallback() -> None:
    source_path = effects_module.__file__
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")
    for forbidden in (
        "TerminateProcess",
        "taskkill",
        "EndTask",
        "WM_QUIT",
    ):
        assert forbidden not in source
