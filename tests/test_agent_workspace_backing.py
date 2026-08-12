from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCodecError,
    AgentId,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    ArtifactId,
    ArtifactVersion,
    InMemoryWorkspaceBackingAdapter,
    LocalFilesystemWorkspaceBackingAdapter,
    WorkspaceBackingKey,
    WorkspaceNamespace,
    WorkspaceScope,
    agent_workspace_scope,
    artifact_content_digest,
    workspace_backing_key,
)

_ARTIFACT_ID = ArtifactId(UUID("70000000-0000-0000-0000-000000000031"))
_TOKEN = UUID("80000000-0000-0000-0000-000000000031")


def _scope() -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=WorkspaceNamespace("default"),
        agent_id=AgentId("researcher"),
    )


def _key() -> WorkspaceBackingKey:
    return workspace_backing_key(
        _scope(),
        _ARTIFACT_ID,
        ArtifactVersion(1),
        token=_TOKEN,
    )


def test_backing_key_is_opaque_deterministic_and_bounded() -> None:
    first = _key()
    second = _key()

    assert first == second
    assert len(first.segments) == 4
    assert first.segments[1] == _ARTIFACT_ID.value.hex
    assert first.segments[2] == "v1"
    assert first.segments[3] == f"{_TOKEN.hex}.blob"
    assert "researcher" not in str(first)
    assert "default" not in str(first)

    with pytest.raises(ValueError):
        WorkspaceBackingKey("../escape")
    with pytest.raises(ValueError):
        WorkspaceBackingKey("c:/native/path")


@pytest.mark.asyncio
async def test_in_memory_backing_is_immutable_digest_checked_and_close_safe() -> None:
    adapter = InMemoryWorkspaceBackingAdapter()
    key = _key()
    content = b"artifact bytes"
    digest = artifact_content_digest(content)

    await adapter.write(key, content, expected_digest=digest)
    assert await adapter.read(key, expected_digest=digest) == content
    assert await adapter.exists(key) is True

    # Exact idempotent write is allowed.
    await adapter.write(key, content, expected_digest=digest)

    with pytest.raises(AgentStateConflictError):
        await adapter.write(
            key,
            b"different bytes",
            expected_digest=artifact_content_digest(b"different bytes"),
        )

    with pytest.raises(AgentCodecError):
        await adapter.read(
            key,
            expected_digest=artifact_content_digest(b"wrong"),
        )

    await adapter.delete(key)
    assert await adapter.exists(key) is False

    await adapter.close()
    assert adapter.closed is True
    with pytest.raises(AgentServiceUnavailableError):
        await adapter.exists(key)


@pytest.mark.asyncio
async def test_local_backing_requires_absolute_safe_root(tmp_path: Path) -> None:
    relative = Path("relative-workspace-root")
    with pytest.raises(ValueError):
        LocalFilesystemWorkspaceBackingAdapter(relative)

    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    assert adapter.root == root.resolve()
    assert adapter.closed is False
    await adapter.close()


@pytest.mark.asyncio
async def test_local_backing_atomic_roundtrip_never_uses_logical_paths(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    content = b"safe workspace bytes"
    digest = artifact_content_digest(content)

    await adapter.write(key, content, expected_digest=digest)

    target = root.joinpath(*key.segments)
    assert target.is_file()
    assert target.read_bytes() == content
    assert await adapter.read(key, expected_digest=digest) == content
    assert not any(path.suffix == ".tmp" for path in root.rglob("*"))

    await adapter.delete(key)
    assert not target.exists()


@pytest.mark.asyncio
async def test_local_backing_fails_closed_on_digest_substitution(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    content = b"original"
    digest = artifact_content_digest(content)
    await adapter.write(key, content, expected_digest=digest)

    target = root.joinpath(*key.segments)
    target.write_bytes(b"tampered")

    with pytest.raises(AgentCodecError):
        await adapter.read(key, expected_digest=digest)


@pytest.mark.asyncio
async def test_local_backing_publish_race_never_clobbers_existing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    content = b"writer-a"
    competing_content = b"writer-b"
    target = root.joinpath(*key.segments)
    real_link = os.link

    def publish_competitor_then_link(src: Path | str, dst: Path | str) -> None:
        Path(dst).write_bytes(competing_content)
        real_link(src, dst)

    monkeypatch.setattr(os, "link", publish_competitor_then_link)

    with pytest.raises(AgentStateConflictError):
        await adapter.write(
            key,
            content,
            expected_digest=artifact_content_digest(content),
        )

    assert target.read_bytes() == competing_content
    assert not any(path.suffix == ".tmp" for path in root.rglob("*"))


@pytest.mark.asyncio
async def test_local_backing_publish_race_is_idempotent_for_exact_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    content = b"same immutable bytes"
    digest = artifact_content_digest(content)
    target = root.joinpath(*key.segments)
    real_link = os.link

    def publish_same_bytes_then_link(src: Path | str, dst: Path | str) -> None:
        Path(dst).write_bytes(content)
        real_link(src, dst)

    monkeypatch.setattr(os, "link", publish_same_bytes_then_link)

    await adapter.write(key, content, expected_digest=digest)

    assert target.read_bytes() == content
    assert await adapter.read(key, expected_digest=digest) == content
    assert not any(path.suffix == ".tmp" for path in root.rglob("*"))


@pytest.mark.asyncio
async def test_local_backing_rejects_symlink_or_reparse_object_when_available(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")

    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    target = root.joinpath(*key.segments)
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")

    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(AgentCodecError):
        await adapter.exists(key)
    with pytest.raises(AgentCodecError):
        await adapter.read(key, expected_digest=artifact_content_digest(b"outside"))


@pytest.mark.asyncio
async def test_local_backing_rejects_symlink_parent_escape_when_available(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")

    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    first_segment = root / key.segments[0]
    outside = tmp_path / "outside-dir"
    outside.mkdir()

    try:
        first_segment.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation unavailable")

    with pytest.raises(AgentCodecError):
        await adapter.write(
            key,
            b"blocked",
            expected_digest=artifact_content_digest(b"blocked"),
        )


@pytest.mark.asyncio
async def test_local_backing_rejects_hardlinked_object_when_available(tmp_path: Path) -> None:
    if not hasattr(os, "link"):
        pytest.skip("hardlinks unavailable")

    root = tmp_path / "workspace"
    adapter = LocalFilesystemWorkspaceBackingAdapter(root, create=True)
    key = _key()
    content = b"single-link artifact"
    digest = artifact_content_digest(content)
    await adapter.write(key, content, expected_digest=digest)

    target = root.joinpath(*key.segments)
    alias = tmp_path / "hardlink-alias.bin"
    try:
        os.link(target, alias)
    except OSError:
        pytest.skip("hardlink creation unavailable")

    with pytest.raises(AgentCodecError):
        await adapter.exists(key)
    with pytest.raises(AgentCodecError):
        await adapter.read(key, expected_digest=digest)
