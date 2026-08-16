import asyncio
import ctypes
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import phoenix_os.host_automation.windows as windows_module
import phoenix_os.host_automation.windows_clipboard as clipboard_module
import phoenix_os.host_automation.windows_effects as effects_module
from phoenix_os.host_automation import (
    HostAutomationAdapterError,
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

_NOW = datetime(2026, 8, 16, 3, 50, tzinfo=UTC)
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


class _ReadWriteClipboardBackend:
    def __init__(self, text: str = "") -> None:
        self.text = text
        self.read_calls = 0
        self.write_calls = 0
        self.read_limits: list[tuple[int, int]] = []
        self.writes: list[str] = []

    def read_text(
        self,
        *,
        maximum_chars: int,
        maximum_utf8_bytes: int,
    ) -> str:
        self.read_calls += 1
        self.read_limits.append((maximum_chars, maximum_utf8_bytes))
        return self.text

    def write_text(
        self,
        text: str,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> None:
        self.write_calls += 1
        assert attempt.begin_effect() is True
        self.writes.append(text)


class _FailingReadClipboardBackend(_ReadWriteClipboardBackend):
    def read_text(
        self,
        *,
        maximum_chars: int,
        maximum_utf8_bytes: int,
    ) -> str:
        del maximum_chars, maximum_utf8_bytes
        self.read_calls += 1
        raise OSError("native read leaked secret=clipboard-password")


class _UnsafeReadClipboardBackend(_ReadWriteClipboardBackend):
    def read_text(
        self,
        *,
        maximum_chars: int,
        maximum_utf8_bytes: int,
    ) -> str:
        del maximum_chars, maximum_utf8_bytes
        self.read_calls += 1
        raise effects_module._WindowsEffectUnsafeDesktopError()


class _SlowReadClipboardBackend(_ReadWriteClipboardBackend):
    def read_text(
        self,
        *,
        maximum_chars: int,
        maximum_utf8_bytes: int,
    ) -> str:
        del maximum_chars, maximum_utf8_bytes
        self.read_calls += 1
        time.sleep(0.03)
        return "late-read"


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    backend: object,
    *,
    read_enabled: bool = False,
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
        lambda: backend,
    )
    return WindowsHostAutomationAdapter(
        host_id=_HOST,
        limits=limits or HostAutomationLimits(),
        clipboard_read_enabled=read_enabled,
    )


@pytest.mark.asyncio
async def test_windows_clipboard_read_is_disabled_by_default_without_disabling_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _ReadWriteClipboardBackend("secret")
    adapter = _adapter(monkeypatch, backend)

    with pytest.raises(HostAutomationOperationDisabledError):
        await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    write = await adapter.write_clipboard(
        HostClipboardWriteRequest(
            host_id=_HOST,
            text="write-still-enabled",
            created_at=_NOW,
        )
    )

    assert backend.read_calls == 0
    assert backend.write_calls == 1
    assert backend.writes == ["write-still-enabled"]
    assert write.written_characters == len("write-still-enabled")


@pytest.mark.asyncio
async def test_windows_clipboard_read_explicit_enable_returns_bounded_unicode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "Phoenix 🔥"
    backend = _ReadWriteClipboardBackend(text)
    limits = HostAutomationLimits(
        max_clipboard_text_chars=123,
        max_clipboard_text_bytes=456,
    )
    adapter = _adapter(
        monkeypatch,
        backend,
        read_enabled=True,
        limits=limits,
    )

    result = await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    assert result.host_id == _HOST
    assert result.text == text
    assert backend.read_calls == 1
    assert backend.read_limits == [(123, 456)]


def test_windows_clipboard_read_enable_flag_requires_boolean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsDiscoveryBackend",
        _NoopDiscoveryBackend,
    )

    with pytest.raises(TypeError, match="clipboard_read_enabled must be a boolean"):
        WindowsHostAutomationAdapter(
            host_id=_HOST,
            clipboard_read_enabled=1,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_windows_clipboard_read_wrong_host_never_reaches_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _ReadWriteClipboardBackend("secret")
    adapter = _adapter(monkeypatch, backend, read_enabled=True)

    with pytest.raises(HostAutomationServiceUnavailableError):
        await adapter.read_clipboard(
            HostClipboardReadRequest(
                host_id=HostId("other"),
                created_at=_NOW,
            )
        )

    assert backend.read_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["12345", "🔥🔥🔥"])
async def test_windows_clipboard_read_defensively_rejects_backend_limit_overflow(
    monkeypatch: pytest.MonkeyPatch,
    text: str,
) -> None:
    backend = _ReadWriteClipboardBackend(text)
    adapter = _adapter(
        monkeypatch,
        backend,
        read_enabled=True,
        limits=HostAutomationLimits(
            max_clipboard_text_chars=4,
            max_clipboard_text_bytes=8,
        ),
    )

    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    assert backend.read_calls == 1


@pytest.mark.asyncio
async def test_windows_clipboard_read_native_failure_is_safe_and_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FailingReadClipboardBackend()
    adapter = _adapter(monkeypatch, backend, read_enabled=True)

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    assert backend.read_calls == 1
    assert str(captured.value) == "host automation adapter failed"
    assert "clipboard-password" not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_clipboard_read_unsafe_desktop_maps_to_safe_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _UnsafeReadClipboardBackend()
    adapter = _adapter(monkeypatch, backend, read_enabled=True)

    with pytest.raises(HostAutomationUnsafeDesktopError):
        await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    assert backend.read_calls == 1


@pytest.mark.asyncio
async def test_windows_clipboard_read_timeout_is_bounded_read_only_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _SlowReadClipboardBackend()
    adapter = _adapter(
        monkeypatch,
        backend,
        read_enabled=True,
        limits=HostAutomationLimits(operation_timeout=timedelta(milliseconds=1)),
    )

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    await asyncio.sleep(0.04)
    assert backend.read_calls == 1


class _NativeReadKernel32:
    def __init__(self, payload: bytes) -> None:
        self.buffer = ctypes.create_string_buffer(payload)
        self.unlock_calls = 0

    def GlobalSize(self, memory: int) -> int:
        assert memory == 101
        return len(self.buffer)

    def GlobalLock(self, memory: int) -> int:
        assert memory == 101
        return ctypes.addressof(self.buffer)

    def GlobalUnlock(self, memory: int) -> bool:
        assert memory == 101
        self.unlock_calls += 1
        return True


class _NativeReadUser32:
    def __init__(
        self,
        *,
        format_available: bool = True,
        close_succeeds: bool = True,
    ) -> None:
        self.format_available = format_available
        self.close_succeeds = close_succeeds
        self.format_calls: list[int] = []
        self.get_calls: list[int] = []
        self.close_calls = 0

    def OpenClipboard(self, owner: object) -> bool:
        assert owner is None
        return True

    def IsClipboardFormatAvailable(self, format_id: int) -> bool:
        self.format_calls.append(format_id)
        return self.format_available

    def GetClipboardData(self, format_id: int) -> int:
        self.get_calls.append(format_id)
        return 101

    def CloseClipboard(self) -> bool:
        self.close_calls += 1
        return self.close_succeeds


def _native_read_backend(
    text: str,
    *,
    format_available: bool = True,
    close_succeeds: bool = True,
    terminate: bool = True,
) -> tuple[
    clipboard_module._CtypesWindowsClipboardBackend,
    _NativeReadKernel32,
    _NativeReadUser32,
]:
    payload = text.encode("utf-16-le")
    if terminate:
        payload += b"\x00\x00"
    backend = object.__new__(clipboard_module._CtypesWindowsClipboardBackend)
    kernel32 = _NativeReadKernel32(payload)
    user32 = _NativeReadUser32(
        format_available=format_available,
        close_succeeds=close_succeeds,
    )
    backend._ctypes = ctypes
    backend._kernel32 = kernel32
    backend._user32 = user32
    backend._current_desktop_context = lambda: (1, "Default")  # type: ignore[method-assign]
    return backend, kernel32, user32


def test_windows_clipboard_native_reader_uses_only_unicode_text_and_never_frees_handle() -> None:
    backend, kernel32, user32 = _native_read_backend("Phoenix 🔥")

    text = backend.read_text(
        maximum_chars=64,
        maximum_utf8_bytes=128,
    )

    assert text == "Phoenix 🔥"
    assert user32.format_calls == [clipboard_module._WINDOWS_CF_UNICODETEXT]
    assert user32.get_calls == [clipboard_module._WINDOWS_CF_UNICODETEXT]
    assert user32.close_calls == 1
    assert kernel32.unlock_calls == 1


def test_windows_clipboard_native_reader_returns_empty_when_unicode_text_is_unavailable() -> None:
    backend, kernel32, user32 = _native_read_backend(
        "ignored",
        format_available=False,
    )

    text = backend.read_text(
        maximum_chars=64,
        maximum_utf8_bytes=128,
    )

    assert text == ""
    assert user32.format_calls == [clipboard_module._WINDOWS_CF_UNICODETEXT]
    assert user32.get_calls == []
    assert user32.close_calls == 1
    assert kernel32.unlock_calls == 0


@pytest.mark.parametrize(
    ("text", "maximum_chars", "maximum_bytes"),
    [
        ("12345", 4, 32),
        ("🔥🔥🔥", 16, 8),
    ],
)
def test_windows_clipboard_native_reader_enforces_char_and_utf8_byte_limits(
    text: str,
    maximum_chars: int,
    maximum_bytes: int,
) -> None:
    backend, kernel32, user32 = _native_read_backend(text)

    with pytest.raises(clipboard_module._WindowsClipboardLimitExceededError):
        backend.read_text(
            maximum_chars=maximum_chars,
            maximum_utf8_bytes=maximum_bytes,
        )

    assert user32.get_calls == [clipboard_module._WINDOWS_CF_UNICODETEXT]
    assert user32.close_calls == 1
    assert kernel32.unlock_calls == 1


def test_windows_clipboard_native_reader_stops_at_bound_without_unbounded_materialization() -> None:
    backend, kernel32, user32 = _native_read_backend("x" * 100)

    with pytest.raises(clipboard_module._WindowsClipboardLimitExceededError):
        backend.read_text(
            maximum_chars=4,
            maximum_utf8_bytes=8,
        )

    assert user32.get_calls == [clipboard_module._WINDOWS_CF_UNICODETEXT]
    assert user32.close_calls == 1
    assert kernel32.unlock_calls == 1


def test_windows_clipboard_native_reader_requires_nul_termination_within_allocation() -> None:
    backend, kernel32, user32 = _native_read_backend(
        "abc",
        terminate=False,
    )

    with pytest.raises(RuntimeError, match="not NUL-terminated"):
        backend.read_text(
            maximum_chars=64,
            maximum_utf8_bytes=128,
        )

    assert user32.close_calls == 1
    assert kernel32.unlock_calls == 1


def test_windows_clipboard_native_reader_cleanup_failure_does_not_return_sensitive_text() -> None:
    backend, kernel32, user32 = _native_read_backend(
        "sensitive",
        close_succeeds=False,
    )

    with pytest.raises(RuntimeError, match="clipboard cleanup failed"):
        backend.read_text(
            maximum_chars=64,
            maximum_utf8_bytes=128,
        )

    assert user32.get_calls == [clipboard_module._WINDOWS_CF_UNICODETEXT]
    assert kernel32.unlock_calls == 1


def test_windows_clipboard_native_reader_names_only_unicode_text_format() -> None:
    source_path = clipboard_module.__file__
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")

    assert "IsClipboardFormatAvailable(_WINDOWS_CF_UNICODETEXT)" in source
    assert "GetClipboardData(_WINDOWS_CF_UNICODETEXT)" in source
    for forbidden in (
        "GetClipboardData(CF_HDROP",
        "GetClipboardData(CF_BITMAP",
        "GetClipboardData(CF_DIB",
        "GetClipboardData(CF_DIBV5",
        "GetClipboardData(CF_ENHMETAFILE",
        "HTML Format",
    ):
        assert forbidden not in source
