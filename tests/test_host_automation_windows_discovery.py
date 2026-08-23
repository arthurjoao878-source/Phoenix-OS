import asyncio
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

import phoenix_os.host_automation.windows as windows_module
from phoenix_os.host_automation import (
    HostAutomationAdapterError,
    HostAutomationLimitExceededError,
    HostAutomationLimits,
    HostAutomationServiceUnavailableError,
    HostAutomationTimeoutError,
    HostAutomationUnsafeDesktopError,
    HostId,
    HostProcessListRequest,
    HostWindowListRequest,
    WindowsHostAutomationAdapter,
)

_NOW = datetime(2026, 8, 15, 3, tzinfo=UTC)
_HOST = HostId("desktop")


def _window(
    hwnd: int,
    pid: int,
    creation_time: int,
    title: str,
) -> windows_module._NativeWindowRecord:
    return windows_module._NativeWindowRecord(
        hwnd=hwnd,
        pid=pid,
        creation_time=creation_time,
        title=title,
    )


def _process(
    pid: int,
    creation_time: int,
    label: str,
) -> windows_module._NativeProcessRecord:
    return windows_module._NativeProcessRecord(
        pid=pid,
        creation_time=creation_time,
        label=label,
    )


class _WindowDiscoveryBackend:
    def __init__(
        self,
        window_snapshots: tuple[windows_module._NativeWindowSnapshot, ...],
        *,
        process_snapshots: tuple[windows_module._NativeProcessSnapshot, ...] = (
            windows_module._NativeProcessSnapshot(()),
        ),
    ) -> None:
        self._window_snapshots = window_snapshots
        self._process_snapshots = process_snapshots
        self.window_calls = 0
        self.process_calls = 0
        self.maximum_records: list[int] = []
        self.maximum_title_characters: list[int] = []

    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> windows_module._NativeProcessSnapshot:
        del maximum_label_characters
        index = min(self.process_calls, len(self._process_snapshots) - 1)
        self.process_calls += 1
        snapshot = self._process_snapshots[index]
        records = snapshot.records[:maximum_records]
        return windows_module._NativeProcessSnapshot(
            records,
            truncated=snapshot.truncated or len(snapshot.records) > maximum_records,
        )

    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> windows_module._NativeWindowSnapshot:
        self.maximum_records.append(maximum_records)
        self.maximum_title_characters.append(maximum_title_characters)
        index = min(self.window_calls, len(self._window_snapshots) - 1)
        self.window_calls += 1
        snapshot = self._window_snapshots[index]
        records = snapshot.records[:maximum_records]
        return windows_module._NativeWindowSnapshot(
            records,
            truncated=snapshot.truncated or len(snapshot.records) > maximum_records,
        )


class _UnsafeWindowDiscoveryBackend(_WindowDiscoveryBackend):
    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> windows_module._NativeWindowSnapshot:
        del maximum_records, maximum_title_characters
        raise windows_module._UnsafeDesktopBoundaryError("Winlogon desktop handle=0xfeed pid=4242")


class _FailingWindowDiscoveryBackend(_WindowDiscoveryBackend):
    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> windows_module._NativeWindowSnapshot:
        del maximum_records, maximum_title_characters
        raise OSError("HWND=0xdead pid=4242 title=secret")


class _SlowWindowDiscoveryBackend(_WindowDiscoveryBackend):
    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> windows_module._NativeWindowSnapshot:
        del maximum_records, maximum_title_characters
        time.sleep(0.03)
        return windows_module._NativeWindowSnapshot(())


class _FakeWindowLifetimeGuard:
    def __init__(self) -> None:
        self.index = 0
        self.revisions: dict[int, int] = {}
        self.started = False
        self.closed = False

    def start(self) -> None:
        self.started = True

    def barrier(self) -> int:
        if not self.started or self.closed:
            raise RuntimeError("fake window lifetime guard unavailable")
        self.index += 1
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
    backend: object,
    *,
    limits: HostAutomationLimits | None = None,
) -> WindowsHostAutomationAdapter:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsDiscoveryBackend",
        lambda: backend,
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


@pytest.mark.asyncio
async def test_window_enumeration_is_bounded_sorted_and_content_minimized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _WindowDiscoveryBackend(
        (
            windows_module._NativeWindowSnapshot(
                (
                    _window(300, 30, 3000, " Zulu \x00"),
                    _window(100, 10, 1000, "Alpha"),
                    _window(200, 20, 2000, "beta"),
                )
            ),
        )
    )
    limits = HostAutomationLimits(
        max_window_results=2,
        max_window_title_chars=32,
    )
    adapter = _adapter(monkeypatch, backend, limits=limits)

    result = await adapter.list_windows(
        HostWindowListRequest(host_id=_HOST, limit=2, created_at=_NOW)
    )

    assert [item.title for item in result.windows] == ["Alpha", "beta"]
    assert len(result.windows) == 2
    assert result.truncated is True
    assert all(item.host_id == _HOST for item in result.windows)
    assert all(item.host_epoch == adapter.host_epoch for item in result.windows)
    assert backend.maximum_records == [3]
    assert backend.maximum_title_characters == [32]
    for item in result.windows:
        UUID(str(item.window_id))
        UUID(str(item.process_id))
        assert str(item.window_id) not in {"100", "200", "300"}


@pytest.mark.asyncio
async def test_same_window_keeps_opaque_id_but_native_handle_reuse_gets_new_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _WindowDiscoveryBackend(
        (
            windows_module._NativeWindowSnapshot((_window(100, 10, 1000, "Editor"),)),
            windows_module._NativeWindowSnapshot((_window(100, 10, 1000, "Renamed"),)),
            windows_module._NativeWindowSnapshot((_window(100, 11, 2000, "Other"),)),
        )
    )
    adapter = _adapter(monkeypatch, backend)
    request = HostWindowListRequest(host_id=_HOST, created_at=_NOW)

    first = await adapter.list_windows(request)
    second = await adapter.list_windows(request)
    reused = await adapter.list_windows(request)

    assert first.windows[0].window_id == second.windows[0].window_id
    assert first.windows[0].process_id == second.windows[0].process_id
    assert second.windows[0].title == "Renamed"
    assert reused.windows[0].window_id != first.windows[0].window_id
    assert reused.windows[0].process_id != first.windows[0].process_id


@pytest.mark.asyncio
async def test_same_hwnd_same_process_rebirth_gets_new_window_identity_without_empty_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _WindowDiscoveryBackend(
        (
            windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "First"),)),
            windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Second"),)),
        )
    )
    adapter = _adapter(monkeypatch, backend)
    request = HostWindowListRequest(host_id=_HOST, created_at=_NOW)

    first = await adapter.list_windows(request)
    first_id = first.windows[0].window_id

    guard = adapter._window_lifetime_guard
    assert isinstance(guard, _FakeWindowLifetimeGuard)
    guard.rebirth(100)

    second = await adapter.list_windows(request)

    assert second.windows[0].window_id != first_id
    assert second.windows[0].process_id == first.windows[0].process_id


@pytest.mark.asyncio
async def test_process_and_window_discovery_share_one_opaque_process_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _WindowDiscoveryBackend(
        (windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),),
        process_snapshots=(
            windows_module._NativeProcessSnapshot((_process(42, 1000, "editor.exe"),)),
        ),
    )
    adapter = _adapter(monkeypatch, backend)

    processes = await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))
    windows = await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    assert processes.processes[0].process_id == windows.windows[0].process_id
    assert windows.windows[0].application_id is None


@pytest.mark.asyncio
async def test_window_identity_disappears_when_not_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _WindowDiscoveryBackend(
        (
            windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),
            windows_module._NativeWindowSnapshot(()),
        )
    )
    adapter = _adapter(monkeypatch, backend)
    request = HostWindowListRequest(host_id=_HOST, created_at=_NOW)

    first = await adapter.list_windows(request)
    window_id = first.windows[0].window_id
    await adapter.list_windows(request)

    assert window_id not in adapter._native_windows


@pytest.mark.asyncio
async def test_window_request_limit_must_fit_configured_windows_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(
        monkeypatch,
        _WindowDiscoveryBackend((windows_module._NativeWindowSnapshot(()),)),
        limits=HostAutomationLimits(max_window_results=1),
    )

    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, limit=2, created_at=_NOW))


@pytest.mark.asyncio
async def test_unsafe_desktop_is_translated_to_safe_public_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _UnsafeWindowDiscoveryBackend((windows_module._NativeWindowSnapshot(()),))
    adapter = _adapter(monkeypatch, backend)

    with pytest.raises(HostAutomationUnsafeDesktopError) as captured:
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    assert str(captured.value) == "host desktop state is not safe for this operation"
    assert "Winlogon" not in str(captured.value)
    assert "4242" not in str(captured.value)


@pytest.mark.asyncio
async def test_window_native_failure_is_translated_without_native_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FailingWindowDiscoveryBackend((windows_module._NativeWindowSnapshot(()),))
    adapter = _adapter(monkeypatch, backend)

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    assert str(captured.value) == "host automation adapter failed"
    for forbidden in ("0xdead", "4242", "secret"):
        assert forbidden not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_window_discovery_has_a_finite_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(
        monkeypatch,
        _SlowWindowDiscoveryBackend((windows_module._NativeWindowSnapshot(()),)),
        limits=HostAutomationLimits(operation_timeout=timedelta(milliseconds=1)),
    )

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    await asyncio.sleep(0.04)


def test_native_window_capture_drops_changed_owner_or_creation_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(windows_module._CtypesWindowsDiscoveryBackend)
    backend._user32 = SimpleNamespace(IsWindow=lambda hwnd: bool(hwnd))

    owners = iter((42, 43))
    monkeypatch.setattr(backend, "_window_process_id", lambda hwnd: next(owners))
    monkeypatch.setattr(backend, "_process_session_id", lambda pid: 7)
    monkeypatch.setattr(backend, "_read_process_creation_time", lambda pid: 1000)
    monkeypatch.setattr(backend, "_read_window_title", lambda hwnd, maximum_characters: "Editor")

    assert (
        backend._capture_window_record(
            100,
            expected_session_id=7,
            maximum_title_characters=64,
        )
        is None
    )

    owners = iter((42, 42))
    creation_times = iter((1000, 2000))
    monkeypatch.setattr(backend, "_window_process_id", lambda hwnd: next(owners))
    monkeypatch.setattr(backend, "_read_process_creation_time", lambda pid: next(creation_times))

    assert (
        backend._capture_window_record(
            100,
            expected_session_id=7,
            maximum_title_characters=64,
        )
        is None
    )


def test_windows_window_title_removes_nul_trims_and_applies_limit() -> None:
    assert (
        windows_module._content_minimized_window_title(
            "  Secret \x00 Window  ",
            maximum_characters=8,
        )
        == "Secret  "
    )


@pytest.mark.asyncio
async def test_windows_adapter_close_clears_window_identity_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(
        monkeypatch,
        _WindowDiscoveryBackend(
            (windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),)
        ),
    )

    await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))
    assert adapter._native_windows

    await adapter.close()

    assert adapter._native_windows == {}
    with pytest.raises(HostAutomationServiceUnavailableError):
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))


@pytest.mark.skipif(
    sys.platform != "win32", reason="Windows native window discovery requires Windows"
)
@pytest.mark.asyncio
async def test_real_windows_window_discovery_is_bounded_and_exposes_no_native_handle() -> None:
    adapter = WindowsHostAutomationAdapter(
        host_id=HostId("integration-windows"),
        limits=HostAutomationLimits(
            max_window_results=128,
            max_window_title_chars=512,
        ),
    )
    try:
        result = await adapter.list_windows(
            HostWindowListRequest(
                host_id=adapter.host_id,
                limit=128,
                created_at=datetime.now(UTC),
            )
        )
    finally:
        await adapter.close()

    assert len(result.windows) <= 128
    assert result.host_id == HostId("integration-windows")
    assert result.host_epoch == adapter.host_epoch
    assert all(item.host_id == result.host_id for item in result.windows)
    assert all(item.host_epoch == result.host_epoch for item in result.windows)
    assert all(len(item.title) <= 512 for item in result.windows)
    assert all(item.application_id is None for item in result.windows)
    for item in result.windows:
        UUID(str(item.window_id))
        UUID(str(item.process_id))


@pytest.mark.asyncio
async def test_window_discovery_omits_record_changed_during_lifetime_bracket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _FakeWindowLifetimeGuard()

    class _ChangingBackend(_WindowDiscoveryBackend):
        def enumerate_windows(
            self,
            *,
            maximum_records: int,
            maximum_title_characters: int,
        ) -> windows_module._NativeWindowSnapshot:
            snapshot = super().enumerate_windows(
                maximum_records=maximum_records,
                maximum_title_characters=maximum_title_characters,
            )
            guard.rebirth(100)
            return snapshot

    backend = _ChangingBackend(
        (windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),)
    )
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_module, "_CtypesWindowsDiscoveryBackend", lambda: backend)
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsWindowLifetimeGuard",
        lambda: guard,
    )
    adapter = WindowsHostAutomationAdapter(host_id=_HOST)

    result = await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    assert result.windows == ()
    assert adapter._window_ids == {}
    assert adapter._native_windows == {}


@pytest.mark.asyncio
async def test_window_discovery_startup_guard_failure_mints_no_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingStartGuard(_FakeWindowLifetimeGuard):
        def start(self) -> None:
            raise RuntimeError("guard startup failed")

    backend = _WindowDiscoveryBackend(
        (windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),)
    )
    guard = _FailingStartGuard()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_module, "_CtypesWindowsDiscoveryBackend", lambda: backend)
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsWindowLifetimeGuard",
        lambda: guard,
    )
    adapter = WindowsHostAutomationAdapter(host_id=_HOST)

    with pytest.raises(HostAutomationAdapterError):
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    assert adapter._window_ids == {}
    assert adapter._native_windows == {}


@pytest.mark.asyncio
async def test_window_lifetime_guard_is_closed_with_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _WindowDiscoveryBackend(
        (windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),)
    )
    adapter = _adapter(monkeypatch, backend)
    await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))
    guard = adapter._window_lifetime_guard
    assert isinstance(guard, _FakeWindowLifetimeGuard)

    await adapter.close()

    assert guard.closed is True
    assert adapter.closed is True


@pytest.mark.asyncio
async def test_window_lifetime_guard_close_failure_is_retryable_after_adapter_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingCloseOnceGuard(_FakeWindowLifetimeGuard):
        def __init__(self) -> None:
            super().__init__()
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise RuntimeError("guard close failed")
            super().close()

    backend = _WindowDiscoveryBackend(
        (windows_module._NativeWindowSnapshot((_window(100, 42, 1000, "Editor"),)),)
    )
    guard = _FailingCloseOnceGuard()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_module, "_CtypesWindowsDiscoveryBackend", lambda: backend)
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsWindowLifetimeGuard",
        lambda: guard,
    )
    adapter = WindowsHostAutomationAdapter(host_id=_HOST)
    await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))

    with pytest.raises(HostAutomationAdapterError):
        await adapter.close()

    assert adapter.closed is True
    assert adapter._window_lifetime_guard is guard
    assert guard.closed is False
    assert guard.close_calls == 1

    await adapter.close()

    assert adapter.closed is True
    assert guard.closed is True
    assert guard.close_calls == 2
    assert adapter._window_lifetime_guard is None
