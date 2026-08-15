"""Immutable OS-neutral contracts for secure host automation."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

MAX_HOST_IDENTIFIER_LENGTH = 128
MAX_HOST_PROCESS_LABEL_CHARS = 1_024
MAX_HOST_WINDOW_TITLE_CHARS = 4_096
MAX_HOST_LIST_RESULTS = 4_096
MAX_HOST_CLIPBOARD_TEXT_CHARS = 1_048_576
MAX_HOST_CLIPBOARD_TEXT_BYTES = 2_097_152
MAX_HOST_OPERATION_TIMEOUT = timedelta(minutes=5)

_HOST_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if len(normalized) > MAX_HOST_IDENTIFIER_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    if _HOST_IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _require_uuid(value: UUID, *, label: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{label} must be UUID")


def _require_bool(value: bool, *, label: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a boolean")


def _positive_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _non_negative_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} cannot be negative")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _bounded_unicode(
    value: str,
    *,
    label: str,
    maximum_chars: int,
    maximum_bytes: int | None = None,
    allow_blank: bool = True,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not allow_blank and not value:
        raise ValueError(f"{label} must not be blank")
    if len(value) > maximum_chars:
        raise ValueError(f"{label} exceeds the maximum character count")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ValueError(f"{label} is not valid Unicode") from exception
    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds the maximum byte count")
    return value


@dataclass(frozen=True, slots=True, order=True)
class HostId:
    """Stable server-owned identity for one configured host target."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _normalize_identifier(self.value, label="host id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class HostEpoch:
    """Opaque finite adapter-session identity used to reject stale native references."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _require_uuid(self.value, label="host epoch")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class HostApplicationId:
    """Stable server-owned identity for one configured application profile."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="host application id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class HostProcessId:
    """Opaque Phoenix process identity; never a native PID contract."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _require_uuid(self.value, label="host process id")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class HostWindowId:
    """Opaque Phoenix window identity; never a native HWND contract."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _require_uuid(self.value, label="host window id")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class HostProcessDescriptor:
    """Content-minimized untrusted process data bound to one host epoch."""

    host_id: HostId
    host_epoch: HostEpoch
    process_id: HostProcessId
    application_id: HostApplicationId | None = None
    label: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        if self.application_id is not None and not isinstance(
            self.application_id, HostApplicationId
        ):
            raise TypeError("application_id must be HostApplicationId")
        object.__setattr__(
            self,
            "label",
            _bounded_unicode(
                self.label,
                label="process label",
                maximum_chars=MAX_HOST_PROCESS_LABEL_CHARS,
            ),
        )


@dataclass(frozen=True, slots=True)
class HostWindowDescriptor:
    """Reviewed untrusted window data bound to one process and host epoch."""

    host_id: HostId
    host_epoch: HostEpoch
    window_id: HostWindowId
    process_id: HostProcessId
    application_id: HostApplicationId | None = None
    title: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.window_id, HostWindowId):
            raise TypeError("window_id must be HostWindowId")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        if self.application_id is not None and not isinstance(
            self.application_id, HostApplicationId
        ):
            raise TypeError("application_id must be HostApplicationId")
        object.__setattr__(
            self,
            "title",
            _bounded_unicode(
                self.title,
                label="window title",
                maximum_chars=MAX_HOST_WINDOW_TITLE_CHARS,
            ),
        )


@dataclass(frozen=True, slots=True)
class HostAutomationLimits:
    """Finite deployment limits for one host-automation adapter."""

    max_process_results: int = 128
    max_window_results: int = 128
    max_process_label_chars: int = 256
    max_window_title_chars: int = 512
    max_clipboard_text_chars: int = 65_536
    max_clipboard_text_bytes: int = 131_072
    operation_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        _positive_int(
            self.max_process_results,
            label="max_process_results",
            maximum=MAX_HOST_LIST_RESULTS,
        )
        _positive_int(
            self.max_window_results,
            label="max_window_results",
            maximum=MAX_HOST_LIST_RESULTS,
        )
        _positive_int(
            self.max_process_label_chars,
            label="max_process_label_chars",
            maximum=MAX_HOST_PROCESS_LABEL_CHARS,
        )
        _positive_int(
            self.max_window_title_chars,
            label="max_window_title_chars",
            maximum=MAX_HOST_WINDOW_TITLE_CHARS,
        )
        _positive_int(
            self.max_clipboard_text_chars,
            label="max_clipboard_text_chars",
            maximum=MAX_HOST_CLIPBOARD_TEXT_CHARS,
        )
        _positive_int(
            self.max_clipboard_text_bytes,
            label="max_clipboard_text_bytes",
            maximum=MAX_HOST_CLIPBOARD_TEXT_BYTES,
        )
        if not isinstance(self.operation_timeout, timedelta):
            raise TypeError("operation_timeout must be a timedelta")
        if self.operation_timeout <= timedelta(0):
            raise ValueError("operation_timeout must be greater than zero")
        if self.operation_timeout > MAX_HOST_OPERATION_TIMEOUT:
            raise ValueError("operation_timeout exceeds the global maximum")
        if self.max_clipboard_text_bytes < self.max_clipboard_text_chars:
            raise ValueError(
                "max_clipboard_text_bytes cannot be less than max_clipboard_text_chars"
            )

    def contains(self, other: HostAutomationLimits) -> bool:
        if not isinstance(other, HostAutomationLimits):
            raise TypeError("other must be HostAutomationLimits")
        return (
            other.max_process_results <= self.max_process_results
            and other.max_window_results <= self.max_window_results
            and other.max_process_label_chars <= self.max_process_label_chars
            and other.max_window_title_chars <= self.max_window_title_chars
            and other.max_clipboard_text_chars <= self.max_clipboard_text_chars
            and other.max_clipboard_text_bytes <= self.max_clipboard_text_bytes
            and other.operation_timeout <= self.operation_timeout
        )


@dataclass(frozen=True, slots=True)
class HostProcessListRequest:
    host_id: HostId
    limit: int = 128
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        _positive_int(self.limit, label="process list limit", maximum=MAX_HOST_LIST_RESULTS)
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostWindowListRequest:
    host_id: HostId
    limit: int = 128
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        _positive_int(self.limit, label="window list limit", maximum=MAX_HOST_LIST_RESULTS)
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostApplicationLaunchRequest:
    host_id: HostId
    application_id: HostApplicationId
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.application_id, HostApplicationId):
            raise TypeError("application_id must be HostApplicationId")
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostWindowFocusRequest:
    host_id: HostId
    host_epoch: HostEpoch
    window_id: HostWindowId
    process_id: HostProcessId
    application_id: HostApplicationId | None = None
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.window_id, HostWindowId):
            raise TypeError("window_id must be HostWindowId")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        if self.application_id is not None and not isinstance(
            self.application_id, HostApplicationId
        ):
            raise TypeError("application_id must be HostApplicationId")
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostApplicationCloseRequest:
    host_id: HostId
    host_epoch: HostEpoch
    application_id: HostApplicationId
    process_id: HostProcessId
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.application_id, HostApplicationId):
            raise TypeError("application_id must be HostApplicationId")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostClipboardReadRequest:
    host_id: HostId
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostClipboardWriteRequest:
    host_id: HostId
    text: str
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        object.__setattr__(
            self,
            "text",
            _bounded_unicode(
                self.text,
                label="clipboard text",
                maximum_chars=MAX_HOST_CLIPBOARD_TEXT_CHARS,
                maximum_bytes=MAX_HOST_CLIPBOARD_TEXT_BYTES,
            ),
        )
        _require_uuid(self.request_id, label="request_id")
        _aware(self.created_at, label="created_at")


def _freeze_processes(
    value: Sequence[HostProcessDescriptor],
    *,
    host_id: HostId,
    host_epoch: HostEpoch,
) -> tuple[HostProcessDescriptor, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError("processes must be a sequence")
    frozen = tuple(value)
    if len(frozen) > MAX_HOST_LIST_RESULTS:
        raise ValueError("process result exceeds the global maximum")
    seen: set[HostProcessId] = set()
    for descriptor in frozen:
        if not isinstance(descriptor, HostProcessDescriptor):
            raise TypeError("process result items must be HostProcessDescriptor")
        if descriptor.host_id != host_id or descriptor.host_epoch != host_epoch:
            raise ValueError("process descriptor belongs to a different host or epoch")
        if descriptor.process_id in seen:
            raise ValueError("process result contains a duplicate process identity")
        seen.add(descriptor.process_id)
    return frozen


def _freeze_windows(
    value: Sequence[HostWindowDescriptor],
    *,
    host_id: HostId,
    host_epoch: HostEpoch,
) -> tuple[HostWindowDescriptor, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError("windows must be a sequence")
    frozen = tuple(value)
    if len(frozen) > MAX_HOST_LIST_RESULTS:
        raise ValueError("window result exceeds the global maximum")
    seen: set[HostWindowId] = set()
    for descriptor in frozen:
        if not isinstance(descriptor, HostWindowDescriptor):
            raise TypeError("window result items must be HostWindowDescriptor")
        if descriptor.host_id != host_id or descriptor.host_epoch != host_epoch:
            raise ValueError("window descriptor belongs to a different host or epoch")
        if descriptor.window_id in seen:
            raise ValueError("window result contains a duplicate window identity")
        seen.add(descriptor.window_id)
    return frozen


@dataclass(frozen=True, slots=True)
class HostProcessListResult:
    request_id: UUID
    host_id: HostId
    host_epoch: HostEpoch
    processes: Sequence[HostProcessDescriptor]
    truncated: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        object.__setattr__(
            self,
            "processes",
            _freeze_processes(
                self.processes,
                host_id=self.host_id,
                host_epoch=self.host_epoch,
            ),
        )
        _require_bool(self.truncated, label="truncated")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostWindowListResult:
    request_id: UUID
    host_id: HostId
    host_epoch: HostEpoch
    windows: Sequence[HostWindowDescriptor]
    truncated: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        object.__setattr__(
            self,
            "windows",
            _freeze_windows(
                self.windows,
                host_id=self.host_id,
                host_epoch=self.host_epoch,
            ),
        )
        _require_bool(self.truncated, label="truncated")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostApplicationLaunchResult:
    request_id: UUID
    host_id: HostId
    host_epoch: HostEpoch
    application_id: HostApplicationId
    process_id: HostProcessId
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.application_id, HostApplicationId):
            raise TypeError("application_id must be HostApplicationId")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostWindowFocusResult:
    request_id: UUID
    host_id: HostId
    host_epoch: HostEpoch
    window_id: HostWindowId
    process_id: HostProcessId
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.window_id, HostWindowId):
            raise TypeError("window_id must be HostWindowId")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostApplicationCloseResult:
    request_id: UUID
    host_id: HostId
    host_epoch: HostEpoch
    application_id: HostApplicationId
    process_id: HostProcessId
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        if not isinstance(self.host_epoch, HostEpoch):
            raise TypeError("host_epoch must be HostEpoch")
        if not isinstance(self.application_id, HostApplicationId):
            raise TypeError("application_id must be HostApplicationId")
        if not isinstance(self.process_id, HostProcessId):
            raise TypeError("process_id must be HostProcessId")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostClipboardReadResult:
    request_id: UUID
    host_id: HostId
    text: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        object.__setattr__(
            self,
            "text",
            _bounded_unicode(
                self.text,
                label="clipboard text",
                maximum_chars=MAX_HOST_CLIPBOARD_TEXT_CHARS,
                maximum_bytes=MAX_HOST_CLIPBOARD_TEXT_BYTES,
            ),
        )
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class HostClipboardWriteResult:
    request_id: UUID
    host_id: HostId
    written_characters: int
    written_bytes: int
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, label="request_id")
        if not isinstance(self.host_id, HostId):
            raise TypeError("host_id must be HostId")
        _non_negative_int(
            self.written_characters,
            label="written_characters",
            maximum=MAX_HOST_CLIPBOARD_TEXT_CHARS,
        )
        _non_negative_int(
            self.written_bytes,
            label="written_bytes",
            maximum=MAX_HOST_CLIPBOARD_TEXT_BYTES,
        )
        if self.written_bytes < self.written_characters:
            raise ValueError("written_bytes cannot be less than written_characters")
        _aware(self.created_at, label="created_at")


@runtime_checkable
class HostAutomationAdapter(Protocol):
    """OS-specific implementation boundary; public signatures remain OS-neutral."""

    @property
    def host_id(self) -> HostId: ...

    @property
    def host_epoch(self) -> HostEpoch: ...

    @property
    def limits(self) -> HostAutomationLimits: ...

    async def list_processes(self, request: HostProcessListRequest) -> HostProcessListResult: ...

    async def list_windows(self, request: HostWindowListRequest) -> HostWindowListResult: ...

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult: ...

    async def focus_window(self, request: HostWindowFocusRequest) -> HostWindowFocusResult: ...

    async def close_application(
        self,
        request: HostApplicationCloseRequest,
    ) -> HostApplicationCloseResult: ...

    async def read_clipboard(
        self, request: HostClipboardReadRequest
    ) -> HostClipboardReadResult: ...

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
    ) -> HostClipboardWriteResult: ...

    async def close(self) -> None: ...
