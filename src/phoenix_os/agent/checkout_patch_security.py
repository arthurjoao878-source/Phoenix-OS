"""Content-free RFC-0039 workspace patch security-metadata bindings."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Protocol, cast

_WINDOWS_CTYPES = cast(Any, ctypes)

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_WINDOWS_FILE_ATTRIBUTES = 0xFFFFFFFF
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_HANDLE_EOF = 38
_OWNER_SECURITY_INFORMATION = 0x00000001
_GROUP_SECURITY_INFORMATION = 0x00000002
_DACL_SECURITY_INFORMATION = 0x00000004
_SECURITY_INFORMATION_MASK = (
    _OWNER_SECURITY_INFORMATION | _GROUP_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
)
_FIND_STREAM_INFO_STANDARD = 0
_MAX_STREAM_NAME = 296


class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", wintypes.WCHAR * _MAX_STREAM_NAME),
    ]


class _SecurityMetadataBackend(Protocol):
    def file_attributes(self, path: str) -> int: ...

    def security_descriptor(self, path: str) -> bytes: ...

    def named_stream_count(self, path: str) -> int: ...


@dataclass(frozen=True, slots=True)
class CheckoutPatchSecurityMetadata:
    """Canonical content-free security metadata for one observed checkout file."""

    platform: str
    file_attributes: int
    security_descriptor_digest: str
    named_stream_count: int
    link_count: int
    fingerprint: str

    def __post_init__(self) -> None:
        if self.platform != "windows":
            raise ValueError("workspace patch security metadata platform is unsupported")
        if (
            isinstance(self.file_attributes, bool)
            or not isinstance(self.file_attributes, int)
            or not 0 <= self.file_attributes <= _MAX_WINDOWS_FILE_ATTRIBUTES
        ):
            raise ValueError("file_attributes is out of bounds")
        _require_digest(self.security_descriptor_digest, label="security_descriptor_digest")
        if (
            isinstance(self.named_stream_count, bool)
            or not isinstance(self.named_stream_count, int)
            or self.named_stream_count < 0
        ):
            raise ValueError("named_stream_count must be non-negative")
        if self.named_stream_count != 0:
            raise ValueError("alternate data streams are unsupported")
        if isinstance(self.link_count, bool) or not isinstance(self.link_count, int):
            raise TypeError("link_count must be an int")
        if self.link_count != 1:
            raise ValueError("workspace patch requires a unique-link target")
        _require_digest(self.fingerprint, label="fingerprint")
        expected = _metadata_fingerprint(
            platform=self.platform,
            file_attributes=self.file_attributes,
            security_descriptor_digest=self.security_descriptor_digest,
            named_stream_count=self.named_stream_count,
            link_count=self.link_count,
        )
        if self.fingerprint != expected:
            raise ValueError("security metadata fingerprint is inconsistent")


def bind_checkout_patch_security_metadata(
    *,
    file_attributes: int,
    security_descriptor_digest: str,
    named_stream_count: int,
    link_count: int,
) -> CheckoutPatchSecurityMetadata:
    """Bind observed Windows metadata without retaining raw security-descriptor bytes."""

    fingerprint = _metadata_fingerprint(
        platform="windows",
        file_attributes=file_attributes,
        security_descriptor_digest=security_descriptor_digest,
        named_stream_count=named_stream_count,
        link_count=link_count,
    )
    return CheckoutPatchSecurityMetadata(
        platform="windows",
        file_attributes=file_attributes,
        security_descriptor_digest=security_descriptor_digest,
        named_stream_count=named_stream_count,
        link_count=link_count,
        fingerprint=fingerprint,
    )


def observe_checkout_patch_security_metadata(
    path: str | os.PathLike[str],
    *,
    _backend: _SecurityMetadataBackend | None = None,
) -> CheckoutPatchSecurityMetadata:
    """Observe fail-closed Windows metadata for an already-resolved checkout target."""

    path_text = os.fspath(path)
    if not isinstance(path_text, str):
        raise TypeError("workspace patch security metadata path must resolve to str")
    if not path_text or "\x00" in path_text:
        raise ValueError("workspace patch security metadata path is invalid")

    info = os.lstat(path_text)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("workspace patch target must be a regular file")
    if info.st_nlink != 1:
        raise ValueError("workspace patch requires a unique-link target")

    backend = _backend if _backend is not None else _WindowsSecurityMetadataBackend()
    file_attributes = backend.file_attributes(path_text)
    if file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("workspace patch target cannot be a reparse point")

    descriptor = backend.security_descriptor(path_text)
    if not isinstance(descriptor, bytes) or not descriptor:
        raise ValueError("workspace patch security descriptor is unavailable")

    named_stream_count = backend.named_stream_count(path_text)

    return bind_checkout_patch_security_metadata(
        file_attributes=file_attributes,
        security_descriptor_digest=_digest(descriptor),
        named_stream_count=named_stream_count,
        link_count=info.st_nlink,
    )


class _WindowsSecurityMetadataBackend:
    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("workspace patch security metadata observation requires Windows")

        win_dll = _WINDOWS_CTYPES.WinDLL
        self._kernel32 = win_dll("kernel32", use_last_error=True)
        self._advapi32 = win_dll("advapi32", use_last_error=True)

        self._get_file_attributes = self._kernel32.GetFileAttributesW
        self._get_file_attributes.argtypes = [wintypes.LPCWSTR]
        self._get_file_attributes.restype = wintypes.DWORD

        self._get_file_security = self._advapi32.GetFileSecurityW
        self._get_file_security.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._get_file_security.restype = wintypes.BOOL

        self._find_first_stream = self._kernel32.FindFirstStreamW
        self._find_first_stream.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(_WIN32_FIND_STREAM_DATA),
            wintypes.DWORD,
        ]
        self._find_first_stream.restype = ctypes.c_void_p

        self._find_next_stream = self._kernel32.FindNextStreamW
        self._find_next_stream.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WIN32_FIND_STREAM_DATA),
        ]
        self._find_next_stream.restype = wintypes.BOOL

        self._find_close = self._kernel32.FindClose
        self._find_close.argtypes = [ctypes.c_void_p]
        self._find_close.restype = wintypes.BOOL

    def file_attributes(self, path: str) -> int:
        value = int(self._get_file_attributes(path))
        if value == _INVALID_FILE_ATTRIBUTES:
            error = _last_error()
            raise OSError(error, "GetFileAttributesW failed", path)
        return value

    def security_descriptor(self, path: str) -> bytes:
        needed = wintypes.DWORD(0)
        _clear_last_error()
        first_ok = bool(
            self._get_file_security(
                path,
                _SECURITY_INFORMATION_MASK,
                None,
                0,
                ctypes.byref(needed),
            )
        )
        first_error = _last_error()
        if first_ok or first_error != _ERROR_INSUFFICIENT_BUFFER or needed.value <= 0:
            raise OSError(first_error, "GetFileSecurityW size query failed", path)

        buffer = (ctypes.c_ubyte * needed.value)()
        returned = wintypes.DWORD(0)
        _clear_last_error()
        second_ok = bool(
            self._get_file_security(
                path,
                _SECURITY_INFORMATION_MASK,
                ctypes.cast(buffer, wintypes.LPVOID),
                needed.value,
                ctypes.byref(returned),
            )
        )
        if not second_ok:
            error = _last_error()
            raise OSError(error, "GetFileSecurityW read failed", path)
        if returned.value <= 0 or returned.value > needed.value:
            raise OSError("GetFileSecurityW returned an invalid descriptor length")
        return bytes(buffer[: returned.value])

    def named_stream_count(self, path: str) -> int:
        data = _WIN32_FIND_STREAM_DATA()
        _clear_last_error()
        handle = self._find_first_stream(
            path,
            _FIND_STREAM_INFO_STANDARD,
            ctypes.byref(data),
            0,
        )

        invalid_handle = ctypes.c_void_p(-1).value
        handle_value = None if handle is None else int(handle)
        if handle_value == invalid_handle:
            error = _last_error()
            if error == _ERROR_HANDLE_EOF:
                return 0
            raise OSError(error, "FindFirstStreamW failed", path)

        named_streams = 0
        try:
            if data.cStreamName != "::$DATA":
                named_streams += 1

            while True:
                next_data = _WIN32_FIND_STREAM_DATA()
                _clear_last_error()
                if bool(self._find_next_stream(handle, ctypes.byref(next_data))):
                    if next_data.cStreamName != "::$DATA":
                        named_streams += 1
                    continue

                error = _last_error()
                if error == _ERROR_HANDLE_EOF:
                    break
                raise OSError(error, "FindNextStreamW failed", path)
        finally:
            self._find_close(handle)

        return named_streams


def _clear_last_error() -> None:
    _WINDOWS_CTYPES.set_last_error(0)


def _last_error() -> int:
    return int(_WINDOWS_CTYPES.get_last_error())


def _metadata_fingerprint(
    *,
    platform: str,
    file_attributes: int,
    security_descriptor_digest: str,
    named_stream_count: int,
    link_count: int,
) -> str:
    _require_digest(security_descriptor_digest, label="security_descriptor_digest")
    record = {
        "schema": "rfc0039.workspace.patch.security-metadata.v1",
        "platform": platform,
        "file_attributes": file_attributes,
        "security_descriptor_digest": security_descriptor_digest,
        "named_stream_count": named_stream_count,
        "link_count": link_count,
    }
    return _digest(_canonical_json_bytes(record))


def _require_digest(value: str, *, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical sha256 digest")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
