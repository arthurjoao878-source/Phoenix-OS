"""Confined read-only registered development checkout core for RFC-0039 P0."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from uuid import UUID

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)

MAX_CHECKOUT_LIST_ENTRIES: Final = 256
MAX_CHECKOUT_LIST_RESULT_BYTES: Final = 65_536
MAX_CHECKOUT_TEXT_READ_BYTES: Final = 1_048_576
MAX_CHECKOUT_LOGICAL_PATH_BYTES: Final = 4_096
MAX_CHECKOUT_LOGICAL_SEGMENT_BYTES: Final = 255

_WORKSPACE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PORTABLE_LOGICAL_SEGMENT = re.compile(r"^[a-z0-9._-]+$")
_RESERVED_COMPONENTS = frozenset({".git", ".hg", ".svn"})
_WINDOWS_RESERVED_STEMS = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class CheckoutEntryCategory(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"


@dataclass(frozen=True, slots=True)
class RegisteredDevelopmentCheckout:
    """Content-free admitted checkout registration; native root remains adapter-private."""

    workspace_id: UUID
    workspace_name: str
    generation: int
    root_identity: str
    read_prefixes: tuple[str, ...]
    patch_prefixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_id, UUID):
            raise TypeError("workspace_id must be UUID")
        if not isinstance(self.workspace_name, str):
            raise TypeError("workspace_name must be a string")
        if _WORKSPACE_NAME.fullmatch(self.workspace_name) is None:
            raise ValueError("workspace_name is invalid")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= 2**63 - 1
        ):
            raise ValueError("generation must be a positive bounded integer")
        _require_digest(self.root_identity, label="root_identity")
        prefixes = tuple(
            _canonical_logical_path(value, label="read prefix") for value in self.read_prefixes
        )
        if not prefixes:
            raise ValueError("read_prefixes must not be empty")
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("read_prefixes contain duplicates")
        canonical_read_prefixes = tuple(sorted(prefixes))
        object.__setattr__(self, "read_prefixes", canonical_read_prefixes)

        patch_prefixes = tuple(
            _canonical_logical_path(value, label="patch prefix") for value in self.patch_prefixes
        )
        if len(set(patch_prefixes)) != len(patch_prefixes):
            raise ValueError("patch_prefixes contain duplicates")
        if any(
            not any(
                _within_prefix(patch_prefix, read_prefix) for read_prefix in canonical_read_prefixes
            )
            for patch_prefix in patch_prefixes
        ):
            raise ValueError("patch_prefixes must be within read_prefixes")
        object.__setattr__(self, "patch_prefixes", tuple(sorted(patch_prefixes)))


@dataclass(frozen=True, slots=True, order=True)
class CheckoutListEntry:
    logical_path: str
    category: CheckoutEntryCategory

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "logical_path",
            _canonical_logical_path(self.logical_path, label="list entry logical path"),
        )
        if not isinstance(self.category, CheckoutEntryCategory):
            raise TypeError("category must be CheckoutEntryCategory")


@dataclass(frozen=True, slots=True)
class CheckoutListResult:
    workspace_id: UUID
    registration_generation: int
    prefix: str
    entries: tuple[CheckoutListEntry, ...]
    excluded_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_id, UUID):
            raise TypeError("workspace_id must be UUID")
        if (
            isinstance(self.registration_generation, bool)
            or not isinstance(self.registration_generation, int)
            or self.registration_generation < 1
        ):
            raise ValueError("registration_generation must be positive")
        object.__setattr__(
            self,
            "prefix",
            _canonical_logical_path(self.prefix, label="list prefix"),
        )
        entries = tuple(self.entries)
        if any(not isinstance(entry, CheckoutListEntry) for entry in entries):
            raise TypeError("entries must contain CheckoutListEntry values")
        if len(entries) > MAX_CHECKOUT_LIST_ENTRIES:
            raise ValueError("entries exceed checkout list bound")
        if tuple(sorted(entries)) != entries:
            raise ValueError("entries must be deterministically sorted")
        if (
            isinstance(self.excluded_count, bool)
            or not isinstance(self.excluded_count, int)
            or self.excluded_count < 0
        ):
            raise ValueError("excluded_count must be a non-negative integer")
        if (
            _serialized_list_result_size(entries, self.excluded_count)
            > MAX_CHECKOUT_LIST_RESULT_BYTES
        ):
            raise ValueError("serialized checkout list result exceeds bound")
        object.__setattr__(self, "entries", entries)


@dataclass(frozen=True, slots=True)
class CheckoutFileSnapshot:
    """Server-owned current-run freshness evidence; never a source of authority."""

    run_id: AgentRunId
    workspace_id: UUID
    registration_generation: int
    logical_path: str
    root_identity: str
    file_identity: str
    content_digest: str
    byte_length: int

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.workspace_id, UUID):
            raise TypeError("workspace_id must be UUID")
        if (
            isinstance(self.registration_generation, bool)
            or not isinstance(self.registration_generation, int)
            or self.registration_generation < 1
        ):
            raise ValueError("registration_generation must be positive")
        object.__setattr__(
            self,
            "logical_path",
            _canonical_logical_path(self.logical_path, label="snapshot logical path"),
        )
        _require_digest(self.root_identity, label="root_identity")
        _require_digest(self.file_identity, label="file_identity")
        _require_digest(self.content_digest, label="content_digest")
        if (
            isinstance(self.byte_length, bool)
            or not isinstance(self.byte_length, int)
            or not 0 <= self.byte_length <= MAX_CHECKOUT_TEXT_READ_BYTES
        ):
            raise ValueError("byte_length is out of bounds")


@dataclass(frozen=True, slots=True)
class CheckoutReadResult:
    snapshot: CheckoutFileSnapshot
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, CheckoutFileSnapshot):
            raise TypeError("snapshot must be CheckoutFileSnapshot")
        if not isinstance(self.text, str):
            raise TypeError("text must be a string")
        encoded = self.text.encode("utf-8")
        if len(encoded) != self.snapshot.byte_length or len(encoded) > MAX_CHECKOUT_TEXT_READ_BYTES:
            raise ValueError("text does not match snapshot byte length")
        if "\x00" in self.text:
            raise ValueError("text contains NUL")


def checkout_prefix_resource(
    registration: RegisteredDevelopmentCheckout,
    prefix: str,
) -> str:
    """Return the exact RFC-0039 protected resource for one checkout list."""

    _require_registration(registration)
    canonical = _canonical_logical_path(prefix, label="checkout list prefix")
    return f"development-checkout:{registration.workspace_id}/prefix:{canonical}"


def checkout_path_resource(
    registration: RegisteredDevelopmentCheckout,
    logical_path: str,
) -> str:
    """Return the exact RFC-0039 protected resource for one checkout file read."""

    _require_registration(registration)
    canonical = _canonical_logical_path(logical_path, label="checkout file path")
    return f"development-checkout:{registration.workspace_id}/path:{canonical}"


class RegisteredDevelopmentCheckoutAdapter:
    """Confined filesystem adapter; it performs no policy grant or tool admission."""

    def __init__(
        self,
        *,
        workspace_id: UUID,
        workspace_name: str,
        generation: int,
        root: Path | str,
        read_prefixes: tuple[str, ...],
        patch_prefixes: tuple[str, ...] = (),
        protected_paths: tuple[Path | str, ...] = (),
        protected_roots: tuple[Path | str, ...] = (),
    ) -> None:
        configured = _admit_root(root)
        root_info = _require_safe_directory(configured)
        root_identity = _identity_digest("root", root_info)

        registration = RegisteredDevelopmentCheckout(
            workspace_id=workspace_id,
            workspace_name=workspace_name,
            generation=generation,
            root_identity=root_identity,
            read_prefixes=read_prefixes,
            patch_prefixes=patch_prefixes,
        )

        self._root = configured
        self._registration = registration
        self._protected_paths = tuple(
            _canonical_native_protection(value, label="protected path") for value in protected_paths
        )
        self._protected_roots = tuple(
            _canonical_native_protection(value, label="protected root") for value in protected_roots
        )
        self._closed = False

    @property
    def registration(self) -> RegisteredDevelopmentCheckout:
        return self._registration

    @property
    def closed(self) -> bool:
        return self._closed

    async def list(
        self,
        prefix: str,
        *,
        max_entries: int = MAX_CHECKOUT_LIST_ENTRIES,
    ) -> CheckoutListResult:
        self._ensure_open()
        canonical = _canonical_logical_path(prefix, label="checkout list prefix")
        self._require_read_eligible(canonical)
        if _is_reserved_logical_path(canonical):
            raise AgentCodecError("checkout list target is protected")
        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or not 1 <= max_entries <= MAX_CHECKOUT_LIST_ENTRIES
        ):
            raise ValueError("max_entries is out of bounds")

        self._require_current_root()
        target = self._confined_target(canonical)
        self._require_not_native_protected(target)
        self._require_safe_parent_chain(target.parent)
        before = _require_safe_directory(target)

        candidates: list[CheckoutListEntry] = []
        excluded = 0
        try:
            with os.scandir(target) as scan:
                for entry in scan:
                    try:
                        segment = _canonical_segment(entry.name)
                        child_logical = f"{canonical}/{segment}"
                        if _is_reserved_logical_path(child_logical):
                            excluded += 1
                            continue
                        child_path = target / entry.name
                        self._require_not_native_protected(child_path)
                        info = child_path.lstat()
                        if stat.S_ISREG(info.st_mode):
                            if (
                                stat.S_ISLNK(info.st_mode)
                                or _is_reparse(info)
                                or info.st_nlink != 1
                            ):
                                excluded += 1
                                continue
                            category = CheckoutEntryCategory.FILE
                        elif stat.S_ISDIR(info.st_mode):
                            if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
                                excluded += 1
                                continue
                            category = CheckoutEntryCategory.DIRECTORY
                        else:
                            excluded += 1
                            continue
                        candidates.append(
                            CheckoutListEntry(
                                logical_path=child_logical,
                                category=category,
                            )
                        )
                    except (OSError, ValueError, AgentCodecError):
                        excluded += 1
        except OSError as exception:
            raise AgentCodecError("checkout directory cannot be listed") from exception

        after = _require_safe_directory(target)
        if _stat_snapshot(before) != _stat_snapshot(after):
            raise AgentStateConflictError()
        self._require_current_root()

        ordered = sorted(candidates)
        if len(ordered) > max_entries:
            excluded += len(ordered) - max_entries
            ordered = ordered[:max_entries]

        while ordered and _serialized_list_result_size(tuple(ordered), excluded) > (
            MAX_CHECKOUT_LIST_RESULT_BYTES
        ):
            ordered.pop()
            excluded += 1

        result = CheckoutListResult(
            workspace_id=self._registration.workspace_id,
            registration_generation=self._registration.generation,
            prefix=canonical,
            entries=tuple(ordered),
            excluded_count=excluded,
        )
        if _serialized_list_result_size(result.entries, result.excluded_count) > (
            MAX_CHECKOUT_LIST_RESULT_BYTES
        ):
            raise AgentCodecError("checkout list result exceeds supported bounds")
        return result

    async def read(
        self,
        logical_path: str,
        *,
        run_id: AgentRunId,
        max_content_bytes: int | None = None,
    ) -> CheckoutReadResult:
        self._ensure_open()
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if max_content_bytes is None:
            effective_content_limit = MAX_CHECKOUT_TEXT_READ_BYTES
        elif isinstance(max_content_bytes, bool) or not isinstance(max_content_bytes, int):
            raise TypeError("max_content_bytes must be an int or None")
        elif not 1 <= max_content_bytes <= MAX_CHECKOUT_TEXT_READ_BYTES:
            raise ValueError("max_content_bytes is out of bounds")
        else:
            effective_content_limit = max_content_bytes

        canonical = _canonical_logical_path(logical_path, label="checkout read path")
        self._require_read_eligible(canonical)
        if _is_reserved_logical_path(canonical):
            raise AgentCodecError("checkout read target is protected")

        self._require_current_root()
        target = self._confined_target(canonical)
        self._require_not_native_protected(target)
        self._require_safe_parent_chain(target.parent)

        before = _require_safe_regular_file(target)
        if before.st_size > MAX_CHECKOUT_TEXT_READ_BYTES:
            raise AgentCodecError("checkout read exceeds supported bounds")
        if before.st_size > effective_content_limit:
            raise AgentLimitExceededError()

        try:
            with target.open("rb") as handle:
                opened = os.fstat(handle.fileno())
                _require_same_open_file_identity(before, opened)
                payload = handle.read(effective_content_limit + 1)
                opened_after = os.fstat(handle.fileno())
                _require_same_open_file_identity(opened, opened_after)
        except AgentStateConflictError:
            raise
        except OSError as exception:
            raise AgentCodecError("checkout file cannot be read") from exception

        if len(payload) > effective_content_limit:
            if effective_content_limit < MAX_CHECKOUT_TEXT_READ_BYTES:
                raise AgentLimitExceededError()
            raise AgentCodecError("checkout read exceeds supported bounds")

        after = _require_safe_regular_file(target)
        _require_same_file_snapshot(before, after)
        self._require_current_root()

        if b"\x00" in payload:
            raise AgentCodecError("checkout text contains NUL")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exception:
            raise AgentCodecError("checkout text is not valid UTF-8") from exception

        snapshot = CheckoutFileSnapshot(
            run_id=run_id,
            workspace_id=self._registration.workspace_id,
            registration_generation=self._registration.generation,
            logical_path=canonical,
            root_identity=self._registration.root_identity,
            file_identity=_identity_digest("file", before),
            content_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
            byte_length=len(payload),
        )
        return CheckoutReadResult(snapshot=snapshot, text=text)

    async def close(self) -> None:
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()

    def _require_current_root(self) -> None:
        info = _require_safe_directory(self._root)
        if _identity_digest("root", info) != self._registration.root_identity:
            raise AgentStateConflictError()

    def _require_read_eligible(self, logical_path: str) -> None:
        if not any(
            _within_prefix(logical_path, prefix) for prefix in self._registration.read_prefixes
        ):
            raise AgentCodecError("checkout target is outside admitted read prefixes")

    def _require_patch_eligible(self, logical_path: str) -> None:
        if not any(
            _within_prefix(logical_path, prefix) for prefix in self._registration.patch_prefixes
        ):
            raise AgentCodecError("checkout target is outside admitted patch prefixes")

    def _patch_target_for_commit(self, logical_path: str) -> Path:
        self._ensure_open()
        canonical = _canonical_logical_path(logical_path, label="checkout patch path")
        self._require_patch_eligible(canonical)
        if _is_reserved_logical_path(canonical):
            raise AgentCodecError("checkout patch target is protected")

        self._require_current_root()
        target = self._confined_target(canonical)
        self._require_not_native_protected(target)
        self._require_safe_parent_chain(target.parent)
        _require_safe_regular_file(target)
        self._require_current_root()
        return target

    def _confined_target(self, logical_path: str) -> Path:
        candidate = self._root.joinpath(*logical_path.split("/"))
        try:
            common = os.path.commonpath((str(self._root), str(candidate)))
        except ValueError as exception:
            raise AgentCodecError("checkout logical path is invalid") from exception
        if _norm_native(common) != _norm_native(str(self._root)):
            raise AgentCodecError("checkout logical path escapes admitted root")
        return candidate

    def _require_safe_parent_chain(self, parent: Path) -> None:
        self._require_current_root()
        try:
            relative = parent.relative_to(self._root)
        except ValueError as exception:
            raise AgentCodecError("checkout path escapes admitted root") from exception

        current = self._root
        for segment in relative.parts:
            current = current / segment
            _require_safe_directory(current)

    def _require_not_native_protected(self, target: Path) -> None:
        normalized = _norm_native(str(target))
        if any(normalized == protected for protected in self._protected_paths):
            raise AgentCodecError("checkout target is protected")
        for protected_root in self._protected_roots:
            try:
                common = os.path.commonpath((normalized, protected_root))
            except ValueError:
                continue
            if _norm_native(common) == protected_root:
                raise AgentCodecError("checkout target is protected")


def _admit_root(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)):
        raise TypeError("root must be Path or str")
    configured = Path(value)
    if not configured.is_absolute():
        raise ValueError("checkout root must be absolute")

    try:
        original_info = configured.lstat()
        resolved = configured.resolve(strict=True)
    except OSError as exception:
        raise AgentCodecError("checkout root is unavailable") from exception

    if not stat.S_ISDIR(original_info.st_mode) or stat.S_ISLNK(original_info.st_mode):
        raise AgentCodecError("checkout root is unsafe")
    if _is_reparse(original_info):
        raise AgentCodecError("checkout root is unsafe")
    if _norm_native(str(configured)) != _norm_native(str(resolved)):
        raise AgentCodecError("checkout root must be canonical")
    if resolved.parent == resolved or _norm_native(str(resolved)) == _norm_native(resolved.anchor):
        raise AgentCodecError("filesystem root cannot be a checkout")

    _require_safe_directory(resolved)
    return resolved


def _canonical_native_protection(value: Path | str, *, label: str) -> str:
    if not isinstance(value, (Path, str)):
        raise TypeError(f"{label} must be Path or str")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exception:
        raise AgentCodecError(f"{label} is unavailable") from exception
    return _norm_native(str(resolved))


def _require_safe_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exception:
        raise AgentCodecError("checkout directory is unavailable") from exception
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise AgentCodecError("checkout directory is unsafe")
    return info


def _require_safe_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exception:
        raise AgentCodecError("checkout file is unavailable") from exception
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
    ):
        raise AgentCodecError("checkout file is unsafe")
    return info


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def _stat_snapshot(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _open_file_identity_snapshot(
    info: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(stat.S_IFMT(info.st_mode)),
        int(info.st_nlink),
        int(info.st_size),
    )


def _require_same_open_file_identity(
    before: os.stat_result,
    after: os.stat_result,
) -> None:
    if _open_file_identity_snapshot(before) != _open_file_identity_snapshot(after):
        raise AgentStateConflictError()


def _require_same_file_snapshot(before: os.stat_result, after: os.stat_result) -> None:
    if _stat_snapshot(before) != _stat_snapshot(after):
        raise AgentStateConflictError()


def _identity_digest(kind: str, info: os.stat_result) -> str:
    if kind not in {"root", "file"}:
        raise ValueError("unsupported checkout identity kind")
    payload = (
        f"{kind}\0{int(info.st_dev)}\0{int(info.st_ino)}\0{stat.S_IFMT(info.st_mode)}"
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _require_digest(value: str, *, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} must be a canonical SHA-256 digest")


def _canonical_segment(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("logical path segment must be a string")
    if (
        not value
        or value in {".", ".."}
        or _PORTABLE_LOGICAL_SEGMENT.fullmatch(value) is None
        or value.endswith(".")
        or value in _RESERVED_COMPONENTS
    ):
        raise ValueError("logical path segment is not portable and policy-safe")
    stem = value.split(".", 1)[0]
    if stem in _WINDOWS_RESERVED_STEMS:
        raise ValueError("logical path segment uses a reserved device name")
    if len(value.encode("ascii")) > MAX_CHECKOUT_LOGICAL_SEGMENT_BYTES:
        raise ValueError("logical path segment exceeds bound")
    return value


def _canonical_logical_path(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value or value.startswith("/") or value.endswith("/") or "//" in value:
        raise ValueError(f"{label} is invalid")
    if "\\" in value or ":" in value or "\x00" in value:
        raise ValueError(f"{label} is invalid")
    if len(value.encode("utf-8")) > MAX_CHECKOUT_LOGICAL_PATH_BYTES:
        raise ValueError(f"{label} exceeds bound")
    segments = value.split("/")
    canonical = "/".join(_canonical_segment(segment) for segment in segments)
    if canonical != value:
        raise ValueError(f"{label} is not canonical")
    return canonical


def canonical_checkout_logical_path(value: str) -> str:
    """Return one portable policy-safe RFC-0039 logical path or fail closed."""

    return _canonical_logical_path(value, label="checkout logical path")


def _within_prefix(logical_path: str, prefix: str) -> bool:
    return logical_path == prefix or logical_path.startswith(prefix + "/")


def _is_reserved_logical_path(logical_path: str) -> bool:
    return any(segment.lower() in _RESERVED_COMPONENTS for segment in logical_path.split("/"))


def _norm_native(value: str) -> str:
    return os.path.normcase(os.path.normpath(value))


def _serialized_list_result_size(
    entries: tuple[CheckoutListEntry, ...],
    excluded_count: int,
) -> int:
    payload = {
        "entries": [
            {"logical_path": entry.logical_path, "category": entry.category.value}
            for entry in entries
        ],
        "excluded_count": excluded_count,
    }
    return len(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _require_registration(value: RegisteredDevelopmentCheckout) -> None:
    if not isinstance(value, RegisteredDevelopmentCheckout):
        raise TypeError("registration must be RegisteredDevelopmentCheckout")
