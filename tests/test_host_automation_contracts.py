from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.host_automation import (
    MAX_HOST_CLIPBOARD_TEXT_BYTES,
    MAX_HOST_CLIPBOARD_TEXT_CHARS,
    MAX_HOST_LIST_RESULTS,
    MAX_HOST_WINDOW_TITLE_CHARS,
    HostApplicationCloseRequest,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostAutomationAdapter,
    HostAutomationLimits,
    HostClipboardReadRequest,
    HostClipboardReadResult,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostEpoch,
    HostId,
    HostProcessDescriptor,
    HostProcessId,
    HostProcessListRequest,
    HostProcessListResult,
    HostWindowDescriptor,
    HostWindowFocusRequest,
    HostWindowId,
    HostWindowListRequest,
    HostWindowListResult,
)

_NOW = datetime(2026, 8, 15, 1, tzinfo=UTC)


def test_server_owned_identifiers_normalize_and_reject_unsafe_values() -> None:
    assert str(HostId(" LOCAL.DESKTOP ")) == "local.desktop"
    assert str(HostApplicationId(" Browser_1 ")) == "browser_1"

    for value in ("", "has space", "/native", "shell&escape"):
        with pytest.raises(ValueError):
            HostId(value)


def test_epoch_process_and_window_identities_are_opaque_immutable_uuids() -> None:
    epoch = HostEpoch()
    process_id = HostProcessId()
    window_id = HostWindowId()

    assert isinstance(epoch.value, UUID)
    assert isinstance(process_id.value, UUID)
    assert isinstance(window_id.value, UUID)
    with pytest.raises(FrozenInstanceError):
        process_id.value = UUID(int=1)  # type: ignore[misc]


def test_process_and_window_descriptors_bind_identity_to_host_epoch() -> None:
    host_id = HostId("local")
    epoch = HostEpoch()
    application_id = HostApplicationId("editor")
    process_id = HostProcessId()
    process = HostProcessDescriptor(
        host_id=host_id,
        host_epoch=epoch,
        process_id=process_id,
        application_id=application_id,
        label="Editor",
    )
    window = HostWindowDescriptor(
        host_id=host_id,
        host_epoch=epoch,
        window_id=HostWindowId(),
        process_id=process_id,
        application_id=application_id,
        title="draft.txt — Editor",
    )

    assert process.host_id == host_id
    assert process.host_epoch == epoch
    assert window.process_id == process_id
    assert window.title == "draft.txt — Editor"


def test_public_descriptors_expose_no_native_pid_hwnd_path_or_handle_authority() -> None:
    names = {
        field.name
        for contract in (HostProcessDescriptor, HostWindowDescriptor)
        for field in fields(contract)
    }

    for forbidden in (
        "pid",
        "hwnd",
        "handle",
        "path",
        "executable",
        "command_line",
        "environment",
        "process_handle",
        "window_handle",
    ):
        assert forbidden not in names


def test_window_title_is_bounded_sensitive_untrusted_text() -> None:
    host_id = HostId("local")
    epoch = HostEpoch()
    process_id = HostProcessId()

    descriptor = HostWindowDescriptor(
        host_id=host_id,
        host_epoch=epoch,
        window_id=HostWindowId(),
        process_id=process_id,
        title="  user visible title  ",
    )
    assert descriptor.title == "  user visible title  "

    with pytest.raises(ValueError, match="character count"):
        HostWindowDescriptor(
            host_id=host_id,
            host_epoch=epoch,
            window_id=HostWindowId(),
            process_id=process_id,
            title="x" * (MAX_HOST_WINDOW_TITLE_CHARS + 1),
        )


def test_list_requests_have_finite_bounds_and_aware_timestamps() -> None:
    request = HostProcessListRequest(host_id=HostId("local"), limit=10, created_at=_NOW)
    assert request.limit == 10
    assert request.created_at.utcoffset() == timedelta(0)

    with pytest.raises(ValueError, match="greater than zero"):
        HostProcessListRequest(host_id=HostId("local"), limit=0)
    with pytest.raises(ValueError, match="global maximum"):
        HostWindowListRequest(host_id=HostId("local"), limit=MAX_HOST_LIST_RESULTS + 1)
    with pytest.raises(ValueError, match="timezone-aware"):
        HostProcessListRequest(
            host_id=HostId("local"),
            created_at=datetime(2026, 8, 15, 1),
        )


def test_list_results_freeze_caller_sequences_and_reject_cross_epoch_items() -> None:
    host_id = HostId("local")
    epoch = HostEpoch()
    process = HostProcessDescriptor(
        host_id=host_id,
        host_epoch=epoch,
        process_id=HostProcessId(),
    )
    source = [process]
    result = HostProcessListResult(
        request_id=UUID(int=1),
        host_id=host_id,
        host_epoch=epoch,
        processes=source,
        created_at=_NOW,
    )
    source.clear()

    assert tuple(result.processes) == (process,)

    with pytest.raises(ValueError, match="different host or epoch"):
        HostProcessListResult(
            request_id=UUID(int=2),
            host_id=host_id,
            host_epoch=epoch,
            processes=(
                HostProcessDescriptor(
                    host_id=host_id,
                    host_epoch=HostEpoch(),
                    process_id=HostProcessId(),
                ),
            ),
            created_at=_NOW,
        )


def test_list_results_reject_duplicate_opaque_identities() -> None:
    host_id = HostId("local")
    epoch = HostEpoch()
    process_id = HostProcessId()
    process = HostProcessDescriptor(
        host_id=host_id,
        host_epoch=epoch,
        process_id=process_id,
    )

    with pytest.raises(ValueError, match="duplicate process"):
        HostProcessListResult(
            request_id=UUID(int=1),
            host_id=host_id,
            host_epoch=epoch,
            processes=(process, process),
            created_at=_NOW,
        )


def test_focus_and_close_requests_require_explicit_epoch_bound_target_identity() -> None:
    host_id = HostId("local")
    epoch = HostEpoch()
    application_id = HostApplicationId("editor")
    process_id = HostProcessId()
    window_id = HostWindowId()

    focus = HostWindowFocusRequest(
        host_id=host_id,
        host_epoch=epoch,
        window_id=window_id,
        process_id=process_id,
        application_id=application_id,
        created_at=_NOW,
    )
    close = HostApplicationCloseRequest(
        host_id=host_id,
        host_epoch=epoch,
        application_id=application_id,
        process_id=process_id,
        created_at=_NOW,
    )

    assert focus.host_epoch == epoch
    assert focus.process_id == close.process_id
    assert close.application_id == application_id


def test_launch_contract_accepts_only_configured_application_identity() -> None:
    request = HostApplicationLaunchRequest(
        host_id=HostId("local"),
        application_id=HostApplicationId("editor"),
        created_at=_NOW,
    )

    assert {field.name for field in fields(request)} == {
        "host_id",
        "application_id",
        "request_id",
        "created_at",
    }


def test_clipboard_contracts_are_text_only_and_bounded_by_chars_and_utf8_bytes() -> None:
    host_id = HostId("local")
    read = HostClipboardReadRequest(host_id=host_id, created_at=_NOW)
    write = HostClipboardWriteRequest(host_id=host_id, text="Phoenix 🔥", created_at=_NOW)

    assert read.host_id == host_id
    assert write.text == "Phoenix 🔥"

    with pytest.raises(ValueError, match="must not contain NUL"):
        HostClipboardWriteRequest(
            host_id=host_id,
            text="before\x00after",
        )

    with pytest.raises(ValueError, match="character count"):
        HostClipboardWriteRequest(
            host_id=host_id,
            text="x" * (MAX_HOST_CLIPBOARD_TEXT_CHARS + 1),
        )

    oversized_by_bytes = "🔥" * ((MAX_HOST_CLIPBOARD_TEXT_BYTES // 4) + 1)
    assert len(oversized_by_bytes) <= MAX_HOST_CLIPBOARD_TEXT_CHARS
    with pytest.raises(ValueError, match="byte count"):
        HostClipboardWriteRequest(host_id=host_id, text=oversized_by_bytes)


def test_clipboard_results_do_not_echo_written_content() -> None:
    host_id = HostId("local")
    write = HostClipboardWriteResult(
        request_id=UUID(int=1),
        host_id=host_id,
        written_characters=3,
        written_bytes=5,
        created_at=_NOW,
    )
    read = HostClipboardReadResult(
        request_id=UUID(int=2),
        host_id=host_id,
        text="abc",
        created_at=_NOW,
    )

    assert "text" not in {field.name for field in fields(write)}
    assert read.text == "abc"
    with pytest.raises(ValueError, match="less than"):
        HostClipboardWriteResult(
            request_id=UUID(int=3),
            host_id=host_id,
            written_characters=3,
            written_bytes=2,
            created_at=_NOW,
        )


def test_host_automation_limits_are_finite_and_composable() -> None:
    deployment = HostAutomationLimits(
        max_process_results=100,
        max_window_results=100,
        max_process_label_chars=256,
        max_window_title_chars=512,
        max_clipboard_text_chars=10_000,
        max_clipboard_text_bytes=30_000,
        operation_timeout=timedelta(seconds=30),
    )
    restricted = HostAutomationLimits(
        max_process_results=10,
        max_window_results=10,
        max_process_label_chars=128,
        max_window_title_chars=256,
        max_clipboard_text_chars=1_000,
        max_clipboard_text_bytes=3_000,
        operation_timeout=timedelta(seconds=5),
    )

    assert deployment.contains(restricted)
    assert not restricted.contains(deployment)
    with pytest.raises(ValueError, match="greater than zero"):
        HostAutomationLimits(max_process_results=0)
    with pytest.raises(ValueError, match="cannot be less"):
        HostAutomationLimits(
            max_clipboard_text_chars=100,
            max_clipboard_text_bytes=99,
        )


def test_process_and_window_list_result_types_are_distinct() -> None:
    host_id = HostId("local")
    epoch = HostEpoch()
    process_id = HostProcessId()
    process_result = HostProcessListResult(
        request_id=UUID(int=1),
        host_id=host_id,
        host_epoch=epoch,
        processes=(
            HostProcessDescriptor(
                host_id=host_id,
                host_epoch=epoch,
                process_id=process_id,
            ),
        ),
        created_at=_NOW,
    )
    window_result = HostWindowListResult(
        request_id=UUID(int=2),
        host_id=host_id,
        host_epoch=epoch,
        windows=(
            HostWindowDescriptor(
                host_id=host_id,
                host_epoch=epoch,
                window_id=HostWindowId(),
                process_id=process_id,
            ),
        ),
        created_at=_NOW,
    )

    assert len(process_result.processes) == 1
    assert len(window_result.windows) == 1


def test_host_automation_adapter_is_runtime_checkable_protocol() -> None:
    assert getattr(HostAutomationAdapter, "_is_runtime_protocol", False) is True
