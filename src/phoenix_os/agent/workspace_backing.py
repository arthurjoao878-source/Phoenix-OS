"""Provider-neutral confined backing adapters for Phoenix workspace artifact bytes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.agent.workspace_contracts import (
    MAX_WORKSPACE_ARTIFACT_BYTES,
    ArtifactDigest,
    ArtifactId,
    ArtifactVersion,
    WorkspaceScope,
)

_BACKING_KEY_PATTERN = re.compile(
    r"^[0-9a-f]{64}/[0-9a-f]{32}/v[1-9][0-9]{0,18}/[0-9a-f]{32}\.blob$"
)


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceBackingKey:
    """Opaque Phoenix-owned backing identity; never a user or model path."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("workspace backing key must be a string")
        if _BACKING_KEY_PATTERN.fullmatch(self.value) is None:
            raise ValueError("workspace backing key is invalid")

    def __str__(self) -> str:
        return self.value

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.value.split("/"))


def workspace_backing_key(
    scope: WorkspaceScope,
    artifact_id: ArtifactId,
    version: ArtifactVersion,
    *,
    token: UUID | None = None,
) -> WorkspaceBackingKey:
    """Create one opaque unique backing key from trusted Phoenix identities."""

    if not isinstance(scope, WorkspaceScope):
        raise TypeError("scope must be WorkspaceScope")
    if not isinstance(artifact_id, ArtifactId):
        raise TypeError("artifact_id must be ArtifactId")
    if not isinstance(version, ArtifactVersion):
        raise TypeError("version must be ArtifactVersion")
    if token is not None and not isinstance(token, UUID):
        raise TypeError("token must be UUID or None")

    identity = f"{scope.namespace.value}\0{scope.kind.value}\0{scope.scope_id.value}".encode()
    scope_digest = hashlib.sha256(identity).hexdigest()
    write_token = uuid4() if token is None else token
    return WorkspaceBackingKey(
        f"{scope_digest}/{artifact_id.value.hex}/v{version.value}/{write_token.hex}.blob"
    )


@runtime_checkable
class WorkspaceBackingAdapter(Protocol):
    """Provider-neutral immutable byte-object boundary below workspace metadata."""

    @property
    def closed(self) -> bool: ...

    async def write(
        self,
        key: WorkspaceBackingKey,
        content: bytes,
        *,
        expected_digest: ArtifactDigest,
    ) -> None: ...

    async def read(
        self,
        key: WorkspaceBackingKey,
        *,
        expected_digest: ArtifactDigest,
    ) -> bytes: ...

    async def delete(self, key: WorkspaceBackingKey) -> None: ...

    async def exists(self, key: WorkspaceBackingKey) -> bool: ...

    async def close(self) -> None: ...


def _validated_content(content: bytes, digest: ArtifactDigest) -> bytes:
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if len(content) > MAX_WORKSPACE_ARTIFACT_BYTES:
        raise AgentCodecError("workspace backing content exceeds supported bounds")
    if not isinstance(digest, ArtifactDigest):
        raise TypeError("expected_digest must be ArtifactDigest")
    actual = "sha256:" + hashlib.sha256(content).hexdigest()
    if actual != digest.value:
        raise AgentCodecError("workspace backing digest mismatch")
    return content


class InMemoryWorkspaceBackingAdapter:
    """Deterministic immutable backing adapter for tests and reference composition."""

    def __init__(self) -> None:
        self._objects: dict[WorkspaceBackingKey, bytes] = {}
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def write(
        self,
        key: WorkspaceBackingKey,
        content: bytes,
        *,
        expected_digest: ArtifactDigest,
    ) -> None:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        normalized = _validated_content(content, expected_digest)
        current = self._objects.get(key)
        if current is not None:
            if current != normalized:
                raise AgentStateConflictError()
            return
        self._objects[key] = normalized

    async def read(
        self,
        key: WorkspaceBackingKey,
        *,
        expected_digest: ArtifactDigest,
    ) -> bytes:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        if not isinstance(expected_digest, ArtifactDigest):
            raise TypeError("expected_digest must be ArtifactDigest")
        content = self._objects.get(key)
        if content is None:
            raise AgentCodecError("workspace backing object is missing")
        return _validated_content(content, expected_digest)

    async def delete(self, key: WorkspaceBackingKey) -> None:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        self._objects.pop(key, None)

    async def exists(self, key: WorkspaceBackingKey) -> bool:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        return key in self._objects

    async def close(self) -> None:
        self._closed = True
        self._objects.clear()

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def _require_safe_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exception:
        raise AgentCodecError("workspace backing directory is unavailable") from exception
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise AgentCodecError("workspace backing directory is unsafe")


def _require_safe_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exception:
        raise AgentCodecError("workspace backing object is unavailable") from exception
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
    ):
        raise AgentCodecError("workspace backing object is unsafe")
    return info


class LocalFilesystemWorkspaceBackingAdapter:
    """Confined local reference adapter using only opaque Phoenix backing keys."""

    def __init__(self, root: Path | str, *, create: bool = False) -> None:
        if not isinstance(root, (Path, str)):
            raise TypeError("root must be Path or str")
        if not isinstance(create, bool):
            raise TypeError("create must be bool")

        configured = Path(root)
        if not configured.is_absolute():
            raise ValueError("workspace backing root must be absolute")

        if create:
            try:
                configured.mkdir(parents=True, exist_ok=True)
            except OSError as exception:
                raise AgentCodecError("workspace backing root cannot be created") from exception

        _require_safe_directory(configured)
        self._root = configured.resolve(strict=True)
        _require_safe_directory(self._root)
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def root(self) -> Path:
        return self._root

    async def write(
        self,
        key: WorkspaceBackingKey,
        content: bytes,
        *,
        expected_digest: ArtifactDigest,
    ) -> None:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        normalized = _validated_content(content, expected_digest)
        target = self._target(key)
        self._ensure_parent_chain(target.parent)

        temp = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
        try:
            with temp.open("xb") as handle:
                handle.write(normalized)
                handle.flush()
                os.fsync(handle.fileno())
            _require_safe_regular_file(temp)

            # Publish without replacement. Linking a fully fsynced temporary regular
            # file makes the final name visible atomically while O_EXCL-like target
            # creation semantics prevent a concurrent writer from being clobbered.
            # The temporary link is removed immediately after publication, leaving
            # the authoritative backing object with exactly one link.
            self._ensure_parent_chain(target.parent)
            try:
                os.link(temp, target)
            except FileExistsError:
                existing = self._read_target_bytes(target)
                if existing != normalized:
                    raise AgentStateConflictError() from None
                return

            try:
                temp.unlink()
            except OSError as exception:
                raise AgentCodecError("workspace backing publish cleanup failed") from exception

            self._ensure_parent_chain(target.parent)
            persisted = self._read_target_bytes(target)
            _validated_content(persisted, expected_digest)
        except FileExistsError as exception:
            raise AgentStateConflictError() from exception
        except AgentStateConflictError:
            raise
        except AgentCodecError:
            raise
        except OSError as exception:
            raise AgentCodecError("workspace backing write failed") from exception
        finally:
            try:
                if temp.exists():
                    temp.unlink()
            except OSError:
                pass

    async def read(
        self,
        key: WorkspaceBackingKey,
        *,
        expected_digest: ArtifactDigest,
    ) -> bytes:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        if not isinstance(expected_digest, ArtifactDigest):
            raise TypeError("expected_digest must be ArtifactDigest")
        target = self._target(key)
        content = self._read_target_bytes(target)
        return _validated_content(content, expected_digest)

    async def delete(self, key: WorkspaceBackingKey) -> None:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        target = self._target(key)
        self._ensure_parent_chain(target.parent)
        try:
            _require_safe_regular_file(target)
        except FileNotFoundError:
            return
        try:
            target.unlink()
        except OSError as exception:
            raise AgentCodecError("workspace backing delete failed") from exception

    async def exists(self, key: WorkspaceBackingKey) -> bool:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")
        target = self._target(key)
        self._ensure_parent_chain(target.parent)
        try:
            _require_safe_regular_file(target)
        except FileNotFoundError:
            return False
        return True

    async def close(self) -> None:
        self._closed = True

    def _target(self, key: WorkspaceBackingKey) -> Path:
        candidate = self._root.joinpath(*key.segments)
        try:
            common = os.path.commonpath((str(self._root), str(candidate)))
        except ValueError as exception:
            raise AgentCodecError("workspace backing path is invalid") from exception
        if Path(common) != self._root:
            raise AgentCodecError("workspace backing path escapes configured root")
        return candidate

    def _ensure_parent_chain(self, parent: Path) -> None:
        _require_safe_directory(self._root)
        try:
            relative = parent.relative_to(self._root)
        except ValueError as exception:
            raise AgentCodecError("workspace backing path escapes configured root") from exception

        current = self._root
        for segment in relative.parts:
            current = current / segment
            if current.exists():
                _require_safe_directory(current)
                continue
            try:
                current.mkdir()
            except FileExistsError:
                pass
            except OSError as exception:
                raise AgentCodecError("workspace backing directory creation failed") from exception
            _require_safe_directory(current)

    def _read_target_bytes(self, target: Path) -> bytes:
        """Read one confined regular object without assigning trust to its bytes."""

        self._ensure_parent_chain(target.parent)
        try:
            info = _require_safe_regular_file(target)
        except FileNotFoundError as exception:
            raise AgentCodecError("workspace backing object is missing") from exception
        if info.st_size > MAX_WORKSPACE_ARTIFACT_BYTES:
            raise AgentCodecError("workspace backing object exceeds supported bounds")
        try:
            content = target.read_bytes()
        except OSError as exception:
            raise AgentCodecError("workspace backing read failed") from exception

        self._ensure_parent_chain(target.parent)
        try:
            after = _require_safe_regular_file(target)
        except FileNotFoundError as exception:
            raise AgentCodecError("workspace backing object changed during read") from exception
        before_snapshot = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        after_snapshot = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_snapshot != after_snapshot or len(content) != info.st_size:
            raise AgentCodecError("workspace backing object changed during read")
        return content

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()
