import asyncio
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest

import phoenix_os.host_automation.windows as windows_module
import phoenix_os.host_automation.windows_clipboard as clipboard_module
import phoenix_os.host_automation.windows_effects as effects_module
from phoenix_os.host_automation import (
    HostAutomationAdapterError,
    HostAutomationIndeterminateEffectError,
    HostAutomationLimitExceededError,
    HostAutomationLimits,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationTimeoutError,
    HostAutomationUnsafeDesktopError,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostId,
    WindowsHostAutomationAdapter,
)

_NOW = datetime(2026, 8, 16, 3, 10, tzinfo=UTC)
_HOST = HostId("desktop")


class _NoopDiscoveryBackend:
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


class _SuccessfulClipboardBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.texts: list[str] = []

    def write_text(
        self,
        text: str,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        self.calls += 1
        assert attempt.begin_effect() is True
        self.texts.append(text)


class _FailBeforeAdmissionClipboardBackend:
    def __init__(self) -> None:
        self.calls = 0

    def write_text(
        self,
        text: str,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del attempt
        self.calls += 1
        raise OSError(f"native clipboard failure containing sensitive text: {text}")


class _UnsafeClipboardBackend:
    def __init__(self) -> None:
        self.calls = 0

    def write_text(
        self,
        text: str,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del text, attempt
        self.calls += 1
        raise effects_module._WindowsEffectUnsafeDesktopError()


class _SlowBeforeAdmissionClipboardBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.started = False
        self.prevented = False

    def write_text(
        self,
        text: str,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        del text
        self.calls += 1
        time.sleep(0.03)
        if not attempt.begin_effect():
            self.prevented = True
            raise effects_module._WindowsEffectPreventedError()
        self.started = True


class _SlowAfterAdmissionClipboardBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.started = False
        self.started_event = Event()
        self.texts: list[str] = []

    def write_text(
        self,
        text: str,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        self.calls += 1
        assert attempt.begin_effect() is True
        self.started = True
        self.started_event.set()
        self.texts.append(text)
        time.sleep(0.03)


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    clipboard_backend: object,
    *,
    limits: HostAutomationLimits | None = None,
) -> WindowsHostAutomationAdapter:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsDiscoveryBackend",
        _NoopDiscoveryBackend,
    )
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsClipboardBackend",
        lambda: clipboard_backend,
    )
    return WindowsHostAutomationAdapter(
        host_id=_HOST,
        limits=limits or HostAutomationLimits(),
    )


@pytest.mark.asyncio
async def test_windows_clipboard_write_is_bounded_plain_text_effect_and_read_stays_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _SuccessfulClipboardBackend()
    adapter = _adapter(monkeypatch, backend)
    text = "Phoenix 🔥"

    result = await adapter.write_clipboard(
        HostClipboardWriteRequest(host_id=_HOST, text=text, created_at=_NOW)
    )

    assert backend.calls == 1
    assert backend.texts == [text]
    assert result.host_id == _HOST
    assert result.written_characters == len(text)
    assert result.written_bytes == len(text.encode("utf-8"))

    with pytest.raises(HostAutomationOperationDisabledError):
        await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["12345", "🔥🔥🔥"])
async def test_windows_clipboard_write_rejects_deployment_limits_before_native_effect(
    monkeypatch: pytest.MonkeyPatch,
    text: str,
) -> None:
    backend = _SuccessfulClipboardBackend()
    adapter = _adapter(
        monkeypatch,
        backend,
        limits=HostAutomationLimits(
            max_clipboard_text_chars=4,
            max_clipboard_text_bytes=8,
        ),
    )

    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(host_id=_HOST, text=text, created_at=_NOW)
        )

    assert backend.calls == 0
    assert backend.texts == []


@pytest.mark.asyncio
async def test_windows_clipboard_write_wrong_host_never_reaches_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _SuccessfulClipboardBackend()
    adapter = _adapter(monkeypatch, backend)

    with pytest.raises(HostAutomationServiceUnavailableError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(
                host_id=HostId("other"),
                text="blocked",
                created_at=_NOW,
            )
        )

    assert backend.calls == 0


@pytest.mark.asyncio
async def test_windows_clipboard_write_native_failure_is_safe_and_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FailBeforeAdmissionClipboardBackend()
    adapter = _adapter(monkeypatch, backend)
    secret = "super-secret-clipboard-value"

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.write_clipboard(
            HostClipboardWriteRequest(
                host_id=_HOST,
                text=secret,
                created_at=_NOW,
            )
        )

    assert backend.calls == 1
    assert str(captured.value) == "host automation adapter failed"
    assert secret not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_clipboard_write_unsafe_desktop_maps_to_safe_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _UnsafeClipboardBackend()
    adapter = _adapter(monkeypatch, backend)

    with pytest.raises(HostAutomationUnsafeDesktopError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(
                host_id=_HOST,
                text="safe",
                created_at=_NOW,
            )
        )

    assert backend.calls == 1


@pytest.mark.asyncio
async def test_windows_clipboard_write_timeout_before_admission_prevents_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _SlowBeforeAdmissionClipboardBackend()
    adapter = _adapter(
        monkeypatch,
        backend,
        limits=HostAutomationLimits(operation_timeout=timedelta(milliseconds=1)),
    )

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(
                host_id=_HOST,
                text="prevented",
                created_at=_NOW,
            )
        )

    await asyncio.sleep(0.04)
    assert backend.calls == 1
    assert backend.started is False
    assert backend.prevented is True


@pytest.mark.asyncio
async def test_windows_clipboard_write_timeout_after_admission_is_indeterminate_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _SlowAfterAdmissionClipboardBackend()
    adapter = _adapter(
        monkeypatch,
        backend,
        limits=HostAutomationLimits(operation_timeout=timedelta(milliseconds=1)),
    )
    text = "admitted-once"

    with pytest.raises(HostAutomationIndeterminateEffectError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(
                host_id=_HOST,
                text=text,
                created_at=_NOW,
            )
        )

    await asyncio.sleep(0.04)
    assert backend.calls == 1
    assert backend.started is True
    assert backend.texts == [text]


@pytest.mark.asyncio
async def test_windows_clipboard_write_cancellation_after_admission_is_indeterminate_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _SlowAfterAdmissionClipboardBackend()
    adapter = _adapter(monkeypatch, backend)
    text = "cancelled-after-admission"

    task = asyncio.create_task(
        adapter.write_clipboard(
            HostClipboardWriteRequest(
                host_id=_HOST,
                text=text,
                created_at=_NOW,
            )
        )
    )
    assert await asyncio.wait_for(
        asyncio.to_thread(backend.started_event.wait),
        timeout=1.0,
    )
    task.cancel()

    with pytest.raises(HostAutomationIndeterminateEffectError):
        await task

    await asyncio.sleep(0.04)
    assert backend.calls == 1
    assert backend.texts == [text]


class _NativeClipboardKernel32:
    def __init__(self) -> None:
        self.free_calls = 0

    def GlobalAlloc(self, flags: int, size: int) -> int:
        assert flags == clipboard_module._WINDOWS_GMEM_MOVEABLE
        assert size > 0
        return 101

    def GlobalLock(self, memory: int) -> int:
        assert memory == 101
        return 202

    def GlobalUnlock(self, memory: int) -> bool:
        assert memory == 101
        return True

    def GlobalFree(self, memory: int) -> None:
        assert memory == 101
        self.free_calls += 1
        return None


class _NativeClipboardUser32:
    def __init__(self, *, close_succeeds: bool) -> None:
        self.close_succeeds = close_succeeds
        self.set_calls = 0
        self.close_calls = 0
        self.destroy_calls = 0

    def OpenClipboard(self, owner: int) -> bool:
        assert owner == 303
        return True

    def EmptyClipboard(self) -> bool:
        return True

    def SetClipboardData(self, format_id: int, memory: int) -> int:
        assert format_id == clipboard_module._WINDOWS_CF_UNICODETEXT
        assert memory == 101
        self.set_calls += 1
        return memory

    def CloseClipboard(self) -> bool:
        self.close_calls += 1
        return self.close_succeeds

    def DestroyWindow(self, owner: int) -> bool:
        assert owner == 303
        self.destroy_calls += 1
        return True


class _NativeClipboardCtypes:
    @staticmethod
    def memmove(destination: int, payload: bytes, size: int) -> int:
        assert destination == 202
        assert size == len(payload)
        return destination


def _native_clipboard_backend(
    *, close_succeeds: bool
) -> tuple[
    clipboard_module._CtypesWindowsClipboardBackend,
    _NativeClipboardKernel32,
    _NativeClipboardUser32,
]:
    backend = object.__new__(clipboard_module._CtypesWindowsClipboardBackend)
    kernel32 = _NativeClipboardKernel32()
    user32 = _NativeClipboardUser32(close_succeeds=close_succeeds)
    backend._ctypes = _NativeClipboardCtypes()
    backend._kernel32 = kernel32
    backend._user32 = user32
    backend._current_desktop_context = lambda: (1, "Default")  # type: ignore[method-assign]
    backend._create_hidden_owner_window = lambda: 303  # type: ignore[method-assign]
    return backend, kernel32, user32


def test_windows_clipboard_native_writer_marks_cleanup_failure_indeterminate_after_transfer() -> (
    None
):
    backend, kernel32, user32 = _native_clipboard_backend(close_succeeds=False)
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(effects_module._WindowsEffectIndeterminateError):
        backend.write_text("copied-once", attempt=attempt)

    assert user32.set_calls == 1
    assert user32.close_calls == 1
    assert user32.destroy_calls == 1
    assert kernel32.free_calls == 0


def test_windows_clipboard_native_writer_rejects_embedded_nul_before_native_state() -> None:
    backend = object.__new__(clipboard_module._CtypesWindowsClipboardBackend)
    attempt = effects_module._WindowsEffectAttempt()

    with pytest.raises(ValueError, match="must not contain NUL"):
        backend.write_text("before\x00after", attempt=attempt)


def test_windows_clipboard_native_writer_names_only_unicode_text_format() -> None:
    source_path = clipboard_module.__file__
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")

    assert clipboard_module._WINDOWS_CF_UNICODETEXT == 13
    assert "SetClipboardData(_WINDOWS_CF_UNICODETEXT, memory)" in source
    for forbidden in (
        "CF_HDROP",
        "CF_BITMAP",
        "CF_DIB",
        "CF_DIBV5",
        "CF_ENHMETAFILE",
        "HTML Format",
    ):
        assert forbidden not in source
