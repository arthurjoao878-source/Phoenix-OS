import asyncio
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import PureWindowsPath

import pytest

import phoenix_os.host_automation.windows as windows_module
from phoenix_os.host_automation import (
    HostAutomationAdapter,
    HostAutomationAdapterError,
    HostAutomationLimitExceededError,
    HostAutomationLimits,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationTimeoutError,
    HostAutomationUnsupportedPlatformError,
    HostId,
    HostProcessListRequest,
    HostWindowListRequest,
    WindowsHostAutomationAdapter,
)

_NOW = datetime(2026, 8, 15, 2, tzinfo=UTC)
_HOST = HostId("desktop")


class _FakeWindowsDiscoveryBackend:
    def __init__(
        self,
        snapshots: tuple[windows_module._NativeProcessSnapshot, ...],
    ) -> None:
        self._snapshots = snapshots
        self.calls = 0
        self.maximum_records: list[int] = []
        self.maximum_label_characters: list[int] = []

    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> windows_module._NativeProcessSnapshot:
        self.maximum_records.append(maximum_records)
        self.maximum_label_characters.append(maximum_label_characters)
        index = min(self.calls, len(self._snapshots) - 1)
        self.calls += 1
        snapshot = self._snapshots[index]
        records = snapshot.records[:maximum_records]
        return windows_module._NativeProcessSnapshot(
            records=records,
            truncated=snapshot.truncated or len(snapshot.records) > maximum_records,
        )


class _FailingWindowsDiscoveryBackend:
    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> windows_module._NativeProcessSnapshot:
        del maximum_records, maximum_label_characters
        raise OSError("native pid=4242 path=C:\\secret\\app.exe")


class _SlowWindowsDiscoveryBackend:
    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> windows_module._NativeProcessSnapshot:
        del maximum_records, maximum_label_characters
        time.sleep(0.03)
        return windows_module._NativeProcessSnapshot(())


def _record(pid: int, creation_time: int, label: str) -> windows_module._NativeProcessRecord:
    return windows_module._NativeProcessRecord(
        pid=pid,
        creation_time=creation_time,
        label=label,
    )


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
    return WindowsHostAutomationAdapter(
        host_id=_HOST,
        limits=limits or HostAutomationLimits(),
    )


def test_windows_adapter_rejects_unsupported_platform_before_native_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")

    with pytest.raises(HostAutomationUnsupportedPlatformError):
        WindowsHostAutomationAdapter(host_id=_HOST)


@pytest.mark.asyncio
async def test_process_enumeration_is_bounded_sorted_and_content_minimized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeWindowsDiscoveryBackend(
        (
            windows_module._NativeProcessSnapshot(
                (
                    _record(30, 300, "Zulu.exe"),
                    _record(10, 100, "C:\\Apps\\Alpha.exe"),
                    _record(20, 200, "beta.exe"),
                )
            ),
        )
    )
    limits = HostAutomationLimits(
        max_process_results=2,
        max_process_label_chars=32,
    )
    adapter = _adapter(monkeypatch, backend, limits=limits)

    result = await adapter.list_processes(
        HostProcessListRequest(host_id=_HOST, limit=2, created_at=_NOW)
    )

    assert [item.label for item in result.processes] == ["Alpha.exe", "beta.exe"]
    assert len(result.processes) == 2
    assert result.truncated is True
    assert all(item.host_id == _HOST for item in result.processes)
    assert all(item.host_epoch == adapter.host_epoch for item in result.processes)
    assert all("\\" not in item.label and "/" not in item.label for item in result.processes)
    assert backend.maximum_records == [3]
    assert backend.maximum_label_characters == [32]


@pytest.mark.asyncio
async def test_same_native_process_keeps_opaque_id_but_pid_reuse_gets_new_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeWindowsDiscoveryBackend(
        (
            windows_module._NativeProcessSnapshot((_record(42, 1000, "app.exe"),)),
            windows_module._NativeProcessSnapshot((_record(42, 1000, "app.exe"),)),
            windows_module._NativeProcessSnapshot((_record(42, 2000, "app.exe"),)),
        )
    )
    adapter = _adapter(monkeypatch, backend)
    request = HostProcessListRequest(host_id=_HOST, limit=10, created_at=_NOW)

    first = await adapter.list_processes(request)
    second = await adapter.list_processes(request)
    reused = await adapter.list_processes(request)

    assert first.host_epoch == second.host_epoch == reused.host_epoch
    assert first.processes[0].process_id == second.processes[0].process_id
    assert reused.processes[0].process_id != first.processes[0].process_id
    assert str(first.processes[0].process_id) != "42"
    assert str(reused.processes[0].process_id) != "42"


@pytest.mark.asyncio
async def test_process_identity_disappears_from_native_map_when_not_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeWindowsDiscoveryBackend(
        (
            windows_module._NativeProcessSnapshot((_record(42, 1000, "app.exe"),)),
            windows_module._NativeProcessSnapshot(()),
        )
    )
    adapter = _adapter(monkeypatch, backend)
    request = HostProcessListRequest(host_id=_HOST, created_at=_NOW)

    first = await adapter.list_processes(request)
    process_id = first.processes[0].process_id
    await adapter.list_processes(request)

    assert process_id not in adapter._native_processes


@pytest.mark.asyncio
async def test_process_request_limit_must_fit_configured_windows_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = HostAutomationLimits(max_process_results=1)
    adapter = _adapter(
        monkeypatch,
        _FakeWindowsDiscoveryBackend((windows_module._NativeProcessSnapshot(()),)),
        limits=limits,
    )

    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.list_processes(
            HostProcessListRequest(host_id=_HOST, limit=2, created_at=_NOW)
        )


@pytest.mark.asyncio
async def test_native_failures_are_translated_without_native_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(monkeypatch, _FailingWindowsDiscoveryBackend())

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))

    assert str(captured.value) == "host automation adapter failed"
    assert "4242" not in str(captured.value)
    assert "secret" not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_process_discovery_has_a_finite_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = HostAutomationLimits(operation_timeout=timedelta(milliseconds=1))
    adapter = _adapter(monkeypatch, _SlowWindowsDiscoveryBackend(), limits=limits)

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))

    await asyncio.sleep(0.04)


@pytest.mark.asyncio
async def test_unimplemented_windows_effects_remain_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(
        monkeypatch,
        _FakeWindowsDiscoveryBackend((windows_module._NativeProcessSnapshot(()),)),
    )

    with pytest.raises(HostAutomationOperationDisabledError):
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, created_at=_NOW))


@pytest.mark.asyncio
async def test_windows_adapter_close_clears_identity_state_and_rejects_new_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeWindowsDiscoveryBackend(
        (windows_module._NativeProcessSnapshot((_record(42, 1000, "app.exe"),)),)
    )
    adapter = _adapter(monkeypatch, backend)

    await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))
    assert adapter._native_processes

    await adapter.close()

    assert adapter.closed is True
    assert adapter._native_processes == {}
    with pytest.raises(HostAutomationServiceUnavailableError):
        await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))


def test_windows_process_label_strips_paths_nul_and_applies_limit() -> None:
    assert (
        windows_module._content_minimized_process_label(
            " C:\\secret\\Phoenix.exe\x00junk ",
            maximum_characters=7,
        )
        == "Phoenix"
    )


def test_windows_adapter_satisfies_os_neutral_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(
        monkeypatch,
        _FakeWindowsDiscoveryBackend((windows_module._NativeProcessSnapshot(()),)),
    )

    assert isinstance(adapter, HostAutomationAdapter)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native discovery requires Windows")
@pytest.mark.asyncio
async def test_real_windows_process_discovery_is_bounded_and_exposes_no_native_path() -> None:
    adapter = WindowsHostAutomationAdapter(
        host_id=HostId("integration-windows"),
        limits=HostAutomationLimits(max_process_results=128, max_process_label_chars=260),
    )
    try:
        result = await adapter.list_processes(
            HostProcessListRequest(
                host_id=adapter.host_id,
                limit=128,
                created_at=datetime.now(UTC),
            )
        )
    finally:
        await adapter.close()

    assert len(result.processes) <= 128
    assert result.host_id == HostId("integration-windows")
    assert result.host_epoch == adapter.host_epoch
    assert all(item.host_id == result.host_id for item in result.processes)
    assert all(item.host_epoch == result.host_epoch for item in result.processes)
    assert all(len(item.label) <= 260 for item in result.processes)
    assert all(
        item.label == PureWindowsPath(item.label).name for item in result.processes if item.label
    )
