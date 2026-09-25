"""Confined RFC-0039 physical workspace patch commit primitive."""

from __future__ import annotations

import ctypes
import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from phoenix_os.agent.checkout_patch_commit import (
    CheckoutPatchCommitTicket,
    revalidate_checkout_patch_commit,
)
from phoenix_os.agent.checkout_patch_preparation import CheckoutPatchPreparation
from phoenix_os.agent.checkout_patch_security import (
    observe_checkout_patch_security_metadata,
)
from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_TEXT_READ_BYTES,
    CheckoutReadResult,
    RegisteredDevelopmentCheckoutAdapter,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError

_DIGEST_PREFIX = "sha256:"


class _SecurityObserverBackend(Protocol):
    def file_attributes(self, path: str) -> int: ...

    def security_descriptor(self, path: str) -> bytes: ...

    def named_stream_count(self, path: str) -> int: ...


class _PhysicalCommitBackend(Protocol):
    def replace_file(self, target: Path, replacement: Path) -> None: ...

    def flush_file(self, path: Path) -> None: ...


@dataclass(frozen=True, slots=True)
class CheckoutPatchPhysicalCommitResult:
    """Content-free result for one proven physical patch application."""

    workspace_id: UUID
    logical_path: str
    before_content_digest: str
    after_content_digest: str
    preparation_digest: str
    security_metadata_fingerprint: str
    changed_line_count: int
    status: str

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_id, UUID):
            raise TypeError("workspace_id must be UUID")
        if not isinstance(self.logical_path, str) or not self.logical_path:
            raise ValueError("logical_path must be non-empty")
        for label, value in (
            ("before_content_digest", self.before_content_digest),
            ("after_content_digest", self.after_content_digest),
            ("preparation_digest", self.preparation_digest),
            ("security_metadata_fingerprint", self.security_metadata_fingerprint),
        ):
            _require_digest(value, label=label)
        if (
            isinstance(self.changed_line_count, bool)
            or not isinstance(self.changed_line_count, int)
            or self.changed_line_count < 1
        ):
            raise ValueError("changed_line_count must be positive")
        if self.status != "applied":
            raise ValueError("physical commit result status must be applied")


class CheckoutPatchCommitIndeterminateError(RuntimeError):
    """Raised only after physical replacement may already have occurred."""

    def __init__(
        self,
        *,
        logical_path: str,
        before_content_digest: str,
        after_content_digest: str,
        preparation_digest: str,
    ) -> None:
        super().__init__("workspace patch physical commit is indeterminate")
        self.logical_path = logical_path
        self.before_content_digest = before_content_digest
        self.after_content_digest = after_content_digest
        self.preparation_digest = preparation_digest


def commit_checkout_patch_physical(
    adapter: RegisteredDevelopmentCheckoutAdapter,
    current_read_result: CheckoutReadResult,
    preparation: CheckoutPatchPreparation,
    ticket: CheckoutPatchCommitTicket,
    *,
    run_id: AgentRunId,
    step_id: AgentStepId,
    call_id: ToolCallId,
    pre_effect_validator: Callable[[], None],
    _physical_backend: _PhysicalCommitBackend | None = None,
    _security_backend: _SecurityObserverBackend | None = None,
) -> CheckoutPatchPhysicalCommitResult:
    """Apply one exact prepared candidate through same-directory atomic replacement."""

    if not isinstance(adapter, RegisteredDevelopmentCheckoutAdapter):
        raise TypeError("adapter must be RegisteredDevelopmentCheckoutAdapter")
    if not isinstance(current_read_result, CheckoutReadResult):
        raise TypeError("current_read_result must be CheckoutReadResult")
    if not isinstance(preparation, CheckoutPatchPreparation):
        raise TypeError("preparation must be CheckoutPatchPreparation")
    if not isinstance(ticket, CheckoutPatchCommitTicket):
        raise TypeError("ticket must be CheckoutPatchCommitTicket")
    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    if not isinstance(step_id, AgentStepId):
        raise TypeError("step_id must be AgentStepId")
    if not isinstance(call_id, ToolCallId):
        raise TypeError("call_id must be ToolCallId")
    if not callable(pre_effect_validator):
        raise TypeError("pre_effect_validator must be callable")

    physical_backend = (
        _physical_backend if _physical_backend is not None else _WindowsPhysicalCommitBackend()
    )

    target = adapter._patch_target_for_commit(preparation.logical_path)
    security_metadata = observe_checkout_patch_security_metadata(
        target,
        _backend=_security_backend,
    )
    fresh_ticket = revalidate_checkout_patch_commit(
        adapter.registration,
        current_read_result,
        preparation,
        security_metadata=security_metadata,
        run_id=run_id,
        step_id=step_id,
        call_id=call_id,
    )
    if fresh_ticket != ticket:
        raise AgentStateConflictError()

    _validate_live_target(
        adapter,
        preparation,
        ticket,
        security_backend=_security_backend,
    )

    candidate = preparation.candidate_bytes
    if _digest(candidate) != ticket.after_content_digest:
        raise AgentStateConflictError()

    temp_path = _write_same_directory_temp(target, candidate)
    effect_started = False

    try:
        _validate_live_target(
            adapter,
            preparation,
            ticket,
            security_backend=_security_backend,
        )
        pre_effect_validator()
        _validate_live_target(
            adapter,
            preparation,
            ticket,
            security_backend=_security_backend,
        )

        effect_started = True
        physical_backend.replace_file(target, temp_path)
        physical_backend.flush_file(target)

        if temp_path.exists():
            raise OSError("workspace patch replacement temp still exists after replace")

        post_target = adapter._patch_target_for_commit(preparation.logical_path)
        post_payload = _read_stable_file(post_target, expected_file_identity=None)
        if _digest(post_payload) != ticket.after_content_digest:
            raise AgentStateConflictError()

        post_security = observe_checkout_patch_security_metadata(
            post_target,
            _backend=_security_backend,
        )
        if post_security.fingerprint != ticket.security_metadata_fingerprint:
            raise AgentStateConflictError()

        return CheckoutPatchPhysicalCommitResult(
            workspace_id=ticket.workspace_id,
            logical_path=ticket.logical_path,
            before_content_digest=ticket.before_content_digest,
            after_content_digest=ticket.after_content_digest,
            preparation_digest=ticket.preparation_digest,
            security_metadata_fingerprint=ticket.security_metadata_fingerprint,
            changed_line_count=ticket.changed_line_count,
            status="applied",
        )
    except Exception as exception:
        if effect_started:
            _best_effort_unlink(temp_path)
            raise CheckoutPatchCommitIndeterminateError(
                logical_path=ticket.logical_path,
                before_content_digest=ticket.before_content_digest,
                after_content_digest=ticket.after_content_digest,
                preparation_digest=ticket.preparation_digest,
            ) from exception
        _strict_unlink(temp_path)
        raise


def _validate_live_target(
    adapter: RegisteredDevelopmentCheckoutAdapter,
    preparation: CheckoutPatchPreparation,
    ticket: CheckoutPatchCommitTicket,
    *,
    security_backend: _SecurityObserverBackend | None,
) -> None:
    target = adapter._patch_target_for_commit(preparation.logical_path)
    payload = _read_stable_file(
        target,
        expected_file_identity=ticket.file_identity,
    )
    if _digest(payload) != ticket.before_content_digest:
        raise AgentStateConflictError()

    security = observe_checkout_patch_security_metadata(
        target,
        _backend=security_backend,
    )
    if security.fingerprint != ticket.security_metadata_fingerprint:
        raise AgentStateConflictError()


def _read_stable_file(
    path: Path,
    *,
    expected_file_identity: str | None,
) -> bytes:
    before = _require_safe_regular_file(path)
    if expected_file_identity is not None:
        if _file_identity_digest(before) != expected_file_identity:
            raise AgentStateConflictError()

    if before.st_size > MAX_CHECKOUT_TEXT_READ_BYTES:
        raise AgentCodecError("workspace patch target exceeds supported bounds")

    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            _require_same_open_identity(before, opened_before)
            payload = handle.read(MAX_CHECKOUT_TEXT_READ_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
            _require_same_open_identity(opened_before, opened_after)
    except AgentStateConflictError:
        raise
    except OSError as exception:
        raise AgentCodecError("workspace patch target cannot be read") from exception

    if len(payload) > MAX_CHECKOUT_TEXT_READ_BYTES:
        raise AgentCodecError("workspace patch target exceeds supported bounds")

    after = _require_safe_regular_file(path)
    _require_same_open_identity(before, after)
    if expected_file_identity is not None:
        if _file_identity_digest(after) != expected_file_identity:
            raise AgentStateConflictError()
    return payload


def _write_same_directory_temp(target: Path, candidate: bytes) -> Path:
    if not isinstance(candidate, bytes):
        raise TypeError("candidate must be bytes")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _ in range(8):
        name = f".phoenix-patch-{secrets.token_hex(16)}.tmp"
        temp_path = target.parent / name
        try:
            descriptor = os.open(temp_path, flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exception:
            raise AgentCodecError("workspace patch temp file cannot be created") from exception

        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(candidate)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            _strict_unlink(temp_path)
            raise

        if temp_path.parent != target.parent:
            _strict_unlink(temp_path)
            raise AgentCodecError("workspace patch temp file escaped target directory")
        return temp_path

    raise AgentCodecError("workspace patch temp file name allocation failed")


class _WindowsPhysicalCommitBackend:
    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("workspace patch physical commit requires Windows")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._replace_file = kernel32.ReplaceFileW
        self._replace_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._replace_file.restype = ctypes.c_int

    def replace_file(self, target: Path, replacement: Path) -> None:
        ctypes.set_last_error(0)
        succeeded = bool(
            self._replace_file(
                str(target),
                str(replacement),
                None,
                0,
                None,
                None,
            )
        )
        if not succeeded:
            error = int(ctypes.get_last_error())
            raise OSError(error, "ReplaceFileW failed", str(target))

    def flush_file(self, path: Path) -> None:
        try:
            with path.open("r+b") as handle:
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exception:
            raise OSError("workspace patch replaced file cannot be flushed") from exception


def _require_safe_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exception:
        raise AgentCodecError("workspace patch target is unavailable") from exception

    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or bool(reparse_flag and attributes & reparse_flag)
        or info.st_nlink != 1
    ):
        raise AgentCodecError("workspace patch target is unsafe")
    return info


def _require_same_open_identity(
    before: os.stat_result,
    after: os.stat_result,
) -> None:
    if _open_identity(before) != _open_identity(after):
        raise AgentStateConflictError()


def _open_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(stat.S_IFMT(info.st_mode)),
        int(info.st_nlink),
        int(info.st_size),
    )


def _file_identity_digest(info: os.stat_result) -> str:
    payload = (f"file\0{int(info.st_dev)}\0{int(info.st_ino)}\0{stat.S_IFMT(info.st_mode)}").encode(
        "ascii"
    )
    return _digest(payload)


def _digest(payload: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(payload).hexdigest()


def _require_digest(value: str, *, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith(_DIGEST_PREFIX)
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} must be a canonical SHA-256 digest")


def _strict_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exception:
        raise AgentCodecError("workspace patch temp file cleanup failed") from exception


def _best_effort_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return
