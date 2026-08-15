from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

import phoenix_os.host_automation.fake as fake_module
from phoenix_os.host_automation import (
    DeterministicHostAutomationAdapter,
    HostApplicationCloseRequest,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationNotConfiguredError,
    HostAutomationAdapter,
    HostAutomationLimitExceededError,
    HostAutomationLimits,
    HostAutomationOperationDisabledError,
    HostAutomationServiceUnavailableError,
    HostAutomationStaleIdentityError,
    HostAutomationTargetNotFoundError,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostEpoch,
    HostId,
    HostProcessDescriptor,
    HostProcessId,
    HostProcessListRequest,
    HostWindowDescriptor,
    HostWindowFocusRequest,
    HostWindowId,
    HostWindowListRequest,
)

_NOW = datetime(2026, 8, 15, 1, 30, tzinfo=UTC)
_HOST = HostId("local")
_APP = HostApplicationId("editor")
_OTHER_APP = HostApplicationId("viewer")
_EPOCH = HostEpoch(UUID("32000000-0000-4000-8000-000000000040"))
_PROCESS_ONE = HostProcessId(UUID("32000000-0000-4000-8000-000000000041"))
_PROCESS_TWO = HostProcessId(UUID("32000000-0000-4000-8000-000000000042"))
_WINDOW = HostWindowId(UUID("32000000-0000-4000-8000-000000000043"))


def _seeded_adapter(
    *,
    limits: HostAutomationLimits | None = None,
) -> DeterministicHostAutomationAdapter:
    resolved_limits = limits or HostAutomationLimits(
        max_process_results=4,
        max_window_results=4,
        max_process_label_chars=64,
        max_window_title_chars=128,
        max_clipboard_text_chars=32,
        max_clipboard_text_bytes=64,
        operation_timeout=timedelta(seconds=5),
    )
    process_one = HostProcessDescriptor(
        host_id=_HOST,
        host_epoch=_EPOCH,
        process_id=_PROCESS_ONE,
        application_id=_APP,
        label="Editor",
    )
    process_two = HostProcessDescriptor(
        host_id=_HOST,
        host_epoch=_EPOCH,
        process_id=_PROCESS_TWO,
        application_id=_OTHER_APP,
        label="Viewer",
    )
    window = HostWindowDescriptor(
        host_id=_HOST,
        host_epoch=_EPOCH,
        window_id=_WINDOW,
        process_id=_PROCESS_ONE,
        application_id=_APP,
        title="draft.txt — Editor",
    )
    return DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        limits=resolved_limits,
        applications=(_APP, _OTHER_APP),
        processes=(process_two, process_one),
        windows=(window,),
        clipboard_text="seed",
    )


def test_fake_adapter_is_os_neutral_runtime_protocol_implementation() -> None:
    adapter = _seeded_adapter()

    assert isinstance(adapter, HostAutomationAdapter)
    assert adapter.host_id == _HOST
    assert adapter.host_epoch == _EPOCH
    assert adapter.closed is False

    source_path = fake_module.__file__
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")
    for forbidden in (
        "import ctypes",
        "from ctypes",
        "import os",
        "from os",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
    ):
        assert forbidden not in source


@pytest.mark.asyncio
async def test_fake_process_and_window_listing_is_deterministic_and_bounded() -> None:
    adapter = _seeded_adapter()

    process_result = await adapter.list_processes(
        HostProcessListRequest(
            host_id=_HOST,
            limit=1,
            created_at=_NOW,
        )
    )
    window_result = await adapter.list_windows(
        HostWindowListRequest(
            host_id=_HOST,
            limit=4,
            created_at=_NOW,
        )
    )

    assert [item.process_id for item in process_result.processes] == [_PROCESS_ONE]
    assert process_result.truncated is True
    assert [item.window_id for item in window_result.windows] == [_WINDOW]
    assert window_result.truncated is False
    assert process_result.host_epoch == _EPOCH
    assert window_result.host_epoch == _EPOCH


@pytest.mark.asyncio
async def test_fake_listing_rejects_requests_above_deployment_limits() -> None:
    limits = HostAutomationLimits(
        max_process_results=1,
        max_window_results=1,
        max_process_label_chars=64,
        max_window_title_chars=128,
        max_clipboard_text_chars=32,
        max_clipboard_text_bytes=64,
        operation_timeout=timedelta(seconds=5),
    )
    process = HostProcessDescriptor(
        host_id=_HOST,
        host_epoch=_EPOCH,
        process_id=_PROCESS_ONE,
        application_id=_APP,
    )
    adapter = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        limits=limits,
        applications=(_APP,),
        processes=(process,),
    )

    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.list_processes(
            HostProcessListRequest(host_id=_HOST, limit=2, created_at=_NOW)
        )
    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.list_windows(HostWindowListRequest(host_id=_HOST, limit=2, created_at=_NOW))


@pytest.mark.asyncio
async def test_fake_launch_uses_only_configured_application_identity() -> None:
    first = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        applications=(_APP,),
    )
    second = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        applications=(_APP,),
    )
    request = HostApplicationLaunchRequest(
        host_id=_HOST,
        application_id=_APP,
        created_at=_NOW,
    )

    first_result = await first.launch_application(request)
    second_result = await second.launch_application(request)

    assert first_result.process_id == second_result.process_id
    assert first_result.application_id == _APP

    with pytest.raises(HostApplicationNotConfiguredError):
        await first.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=HostApplicationId("not-configured"),
                created_at=_NOW,
            )
        )


@pytest.mark.asyncio
async def test_fake_focus_requires_exact_epoch_window_process_and_application_relation() -> None:
    adapter = _seeded_adapter()
    request = HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=_EPOCH,
        window_id=_WINDOW,
        process_id=_PROCESS_ONE,
        application_id=_APP,
        created_at=_NOW,
    )

    result = await adapter.focus_window(request)

    assert result.window_id == _WINDOW
    assert result.process_id == _PROCESS_ONE

    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.focus_window(
            HostWindowFocusRequest(
                host_id=_HOST,
                host_epoch=_EPOCH,
                window_id=_WINDOW,
                process_id=_PROCESS_TWO,
                application_id=_APP,
                created_at=_NOW,
            )
        )
    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.focus_window(
            HostWindowFocusRequest(
                host_id=_HOST,
                host_epoch=_EPOCH,
                window_id=_WINDOW,
                process_id=_PROCESS_ONE,
                application_id=_OTHER_APP,
                created_at=_NOW,
            )
        )


@pytest.mark.asyncio
async def test_fake_epoch_rotation_makes_old_process_and_window_identities_stale() -> None:
    adapter = _seeded_adapter()
    old_focus = HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=_EPOCH,
        window_id=_WINDOW,
        process_id=_PROCESS_ONE,
        application_id=_APP,
        created_at=_NOW,
    )
    old_close = HostApplicationCloseRequest(
        host_id=_HOST,
        host_epoch=_EPOCH,
        application_id=_APP,
        process_id=_PROCESS_ONE,
        created_at=_NOW,
    )

    next_epoch = adapter.invalidate_identities()

    assert next_epoch != _EPOCH
    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.focus_window(old_focus)
    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.close_application(old_close)

    current = await adapter.list_processes(
        HostProcessListRequest(host_id=_HOST, limit=4, created_at=_NOW)
    )
    assert current.host_epoch == next_epoch
    assert current.processes == ()


@pytest.mark.asyncio
async def test_fake_close_requires_exact_application_process_binding_and_removes_windows() -> None:
    adapter = _seeded_adapter()

    with pytest.raises(HostAutomationStaleIdentityError):
        await adapter.close_application(
            HostApplicationCloseRequest(
                host_id=_HOST,
                host_epoch=_EPOCH,
                application_id=_OTHER_APP,
                process_id=_PROCESS_ONE,
                created_at=_NOW,
            )
        )

    result = await adapter.close_application(
        HostApplicationCloseRequest(
            host_id=_HOST,
            host_epoch=_EPOCH,
            application_id=_APP,
            process_id=_PROCESS_ONE,
            created_at=_NOW,
        )
    )

    assert result.process_id == _PROCESS_ONE
    processes = await adapter.list_processes(
        HostProcessListRequest(host_id=_HOST, limit=4, created_at=_NOW)
    )
    windows = await adapter.list_windows(
        HostWindowListRequest(host_id=_HOST, limit=4, created_at=_NOW)
    )
    assert [item.process_id for item in processes.processes] == [_PROCESS_TWO]
    assert windows.windows == ()


@pytest.mark.asyncio
async def test_fake_clipboard_read_and_write_can_be_configured_independently() -> None:
    write_only = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        clipboard_read_enabled=False,
        clipboard_write_enabled=True,
    )
    read_only = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        clipboard_text="existing",
        clipboard_read_enabled=True,
        clipboard_write_enabled=False,
    )

    write_result = await write_only.write_clipboard(
        HostClipboardWriteRequest(host_id=_HOST, text="Phoenix 🔥", created_at=_NOW)
    )
    assert write_result.written_characters == len("Phoenix 🔥")
    assert write_result.written_bytes == len("Phoenix 🔥".encode())
    with pytest.raises(HostAutomationOperationDisabledError):
        await write_only.read_clipboard(HostClipboardReadRequest(host_id=_HOST, created_at=_NOW))

    read_result = await read_only.read_clipboard(
        HostClipboardReadRequest(host_id=_HOST, created_at=_NOW)
    )
    assert read_result.text == "existing"
    with pytest.raises(HostAutomationOperationDisabledError):
        await read_only.write_clipboard(
            HostClipboardWriteRequest(host_id=_HOST, text="blocked", created_at=_NOW)
        )


@pytest.mark.asyncio
async def test_fake_clipboard_enforces_deployment_byte_and_character_limits() -> None:
    limits = HostAutomationLimits(
        max_process_results=4,
        max_window_results=4,
        max_process_label_chars=64,
        max_window_title_chars=128,
        max_clipboard_text_chars=4,
        max_clipboard_text_bytes=8,
        operation_timeout=timedelta(seconds=5),
    )
    adapter = DeterministicHostAutomationAdapter(
        host_id=_HOST,
        host_epoch=_EPOCH,
        limits=limits,
    )

    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(host_id=_HOST, text="12345", created_at=_NOW)
        )
    with pytest.raises(HostAutomationLimitExceededError):
        await adapter.write_clipboard(
            HostClipboardWriteRequest(host_id=_HOST, text="🔥🔥🔥", created_at=_NOW)
        )


@pytest.mark.asyncio
async def test_fake_wrong_host_fails_closed_without_retargeting() -> None:
    adapter = _seeded_adapter()

    with pytest.raises(HostAutomationTargetNotFoundError):
        await adapter.list_processes(
            HostProcessListRequest(
                host_id=HostId("other"),
                limit=1,
                created_at=_NOW,
            )
        )
    with pytest.raises(HostAutomationTargetNotFoundError):
        await adapter.focus_window(
            HostWindowFocusRequest(
                host_id=HostId("other"),
                host_epoch=_EPOCH,
                window_id=_WINDOW,
                process_id=_PROCESS_ONE,
                application_id=_APP,
                created_at=_NOW,
            )
        )


@pytest.mark.asyncio
async def test_fake_close_is_idempotent_and_rejects_future_operations() -> None:
    adapter = _seeded_adapter()

    await adapter.close()
    await adapter.close()

    assert adapter.closed is True
    with pytest.raises(HostAutomationServiceUnavailableError):
        await adapter.list_processes(
            HostProcessListRequest(host_id=_HOST, limit=1, created_at=_NOW)
        )
    with pytest.raises(HostAutomationServiceUnavailableError):
        adapter.invalidate_identities()


def test_fake_seed_data_must_match_current_host_epoch_and_application_relation() -> None:
    other_epoch = HostEpoch(UUID("32000000-0000-4000-8000-000000000044"))
    stale_process = HostProcessDescriptor(
        host_id=_HOST,
        host_epoch=other_epoch,
        process_id=_PROCESS_ONE,
        application_id=_APP,
    )
    with pytest.raises(ValueError, match="different host or epoch"):
        DeterministicHostAutomationAdapter(
            host_id=_HOST,
            host_epoch=_EPOCH,
            applications=(_APP,),
            processes=(stale_process,),
        )

    process = HostProcessDescriptor(
        host_id=_HOST,
        host_epoch=_EPOCH,
        process_id=_PROCESS_ONE,
        application_id=_APP,
    )
    mismatched_window = HostWindowDescriptor(
        host_id=_HOST,
        host_epoch=_EPOCH,
        window_id=_WINDOW,
        process_id=_PROCESS_ONE,
        application_id=_OTHER_APP,
    )
    with pytest.raises(ValueError, match="application does not match"):
        DeterministicHostAutomationAdapter(
            host_id=_HOST,
            host_epoch=_EPOCH,
            applications=(_APP, _OTHER_APP),
            processes=(process,),
            windows=(mismatched_window,),
        )
