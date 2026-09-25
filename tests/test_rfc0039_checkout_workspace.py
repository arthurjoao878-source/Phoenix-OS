from __future__ import annotations

import hashlib
import os
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_LIST_ENTRIES,
    MAX_CHECKOUT_LIST_RESULT_BYTES,
    MAX_CHECKOUT_TEXT_READ_BYTES,
    CheckoutEntryCategory,
    RegisteredDevelopmentCheckoutAdapter,
    checkout_path_resource,
    checkout_prefix_resource,
)
from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.policy import PolicyRequest

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    return root


def _try_directory_symlink(link: Path, target: Path) -> Path | None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        return None
    return link


def _adapter(
    root: Path,
    *,
    patch_prefixes: tuple[str, ...] = (),
    protected_paths: tuple[Path, ...] = (),
    protected_roots: tuple[Path, ...] = (),
) -> RegisteredDevelopmentCheckoutAdapter:
    return RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="project",
        generation=7,
        root=root,
        read_prefixes=("src", "tests"),
        patch_prefixes=patch_prefixes,
        protected_paths=protected_paths,
        protected_roots=protected_roots,
    )


@pytest.mark.asyncio
async def test_registration_is_content_free_and_resources_use_only_logical_identity(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    adapter = _adapter(root)

    registration = adapter.registration
    assert registration.workspace_id == _WORKSPACE_ID
    assert registration.workspace_name == "project"
    assert registration.generation == 7
    assert registration.read_prefixes == ("src", "tests")
    assert registration.patch_prefixes == ()
    assert registration.root_identity.startswith("sha256:")
    assert str(root) not in repr(registration)

    assert checkout_prefix_resource(registration, "src") == (
        f"development-checkout:{_WORKSPACE_ID}/prefix:src"
    )
    assert checkout_path_resource(registration, "src/example.py") == (
        f"development-checkout:{_WORKSPACE_ID}/path:src/example.py"
    )

    await adapter.close()
    assert adapter.closed
    with pytest.raises(AgentServiceUnavailableError):
        await adapter.list("src")


def test_registration_patch_prefixes_are_canonical_and_within_read_prefixes(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)

    registration = _adapter(
        root,
        patch_prefixes=("tests", "src/pkg"),
    ).registration
    assert registration.patch_prefixes == ("src/pkg", "tests")

    with pytest.raises(ValueError, match="patch_prefixes contain duplicates"):
        _adapter(root, patch_prefixes=("src", "src"))

    with pytest.raises(ValueError, match="patch_prefixes must be within read_prefixes"):
        _adapter(root, patch_prefixes=("private",))

    with pytest.raises(ValueError):
        _adapter(root, patch_prefixes=("Src",))


def test_checkout_logical_resource_grammar_is_policy_safe(tmp_path: Path) -> None:
    registration = _adapter(_root(tmp_path)).registration

    prefix_resource = checkout_prefix_resource(registration, "src")
    path_resource = checkout_path_resource(registration, "src/.env")
    assert (
        PolicyRequest(action="workspace.list", resource=prefix_resource).resource == prefix_resource
    )
    assert PolicyRequest(action="workspace.read", resource=path_resource).resource == path_resource

    for invalid in (
        "Src/example.py",
        "src/Ãrvore.py",
        "src/name with space.py",
        "src/con.txt",
        "src/nul.txt",
        "src/file.",
        ".git/config",
    ):
        with pytest.raises(ValueError):
            checkout_path_resource(registration, invalid)


def test_root_admission_rejects_relative_filesystem_root_and_noncanonical_symlink(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError):
        RegisteredDevelopmentCheckoutAdapter(
            workspace_id=_WORKSPACE_ID,
            workspace_name="project",
            generation=1,
            root=Path("relative"),
            read_prefixes=("src",),
        )

    filesystem_root = Path(tmp_path.anchor)
    with pytest.raises(AgentCodecError):
        RegisteredDevelopmentCheckoutAdapter(
            workspace_id=_WORKSPACE_ID,
            workspace_name="project",
            generation=1,
            root=filesystem_root,
            read_prefixes=("src",),
        )

    root = _root(tmp_path)
    link = tmp_path / "checkout-link"
    try:
        link.symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable on this platform")
    with pytest.raises(AgentCodecError):
        RegisteredDevelopmentCheckoutAdapter(
            workspace_id=_WORKSPACE_ID,
            workspace_name="project",
            generation=1,
            root=link,
            read_prefixes=("src",),
        )


@pytest.mark.asyncio
async def test_list_is_one_level_deterministic_bounded_and_hides_unsafe_entries(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    (root / "src" / "b.py").write_text("b", encoding="utf-8")
    (root / "src" / "a.py").write_text("a", encoding="utf-8")
    (root / "src" / "pkg").mkdir()
    (root / "src" / ".git").mkdir()

    unsafe = _try_directory_symlink(root / "src" / "unsafe-link", root / "tests")

    adapter = _adapter(root)
    result = await adapter.list("src")

    assert result.workspace_id == _WORKSPACE_ID
    assert result.registration_generation == 7
    assert result.prefix == "src"
    assert tuple(entry.logical_path for entry in result.entries) == (
        "src/a.py",
        "src/b.py",
        "src/pkg",
    )
    assert tuple(entry.category for entry in result.entries) == (
        CheckoutEntryCategory.FILE,
        CheckoutEntryCategory.FILE,
        CheckoutEntryCategory.DIRECTORY,
    )
    assert result.excluded_count >= 1 + (1 if unsafe is not None else 0)
    assert all(str(root) not in repr(entry) for entry in result.entries)


@pytest.mark.asyncio
async def test_list_caps_entry_count_and_serialized_size(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for index in range(MAX_CHECKOUT_LIST_ENTRIES + 40):
        (root / "src" / f"f-{index:03d}-{'x' * 80}.txt").write_text("x", encoding="utf-8")

    adapter = _adapter(root)
    result = await adapter.list("src")

    assert len(result.entries) <= MAX_CHECKOUT_LIST_ENTRIES
    assert result.excluded_count >= 40

    import json

    payload = {
        "entries": [
            {"logical_path": entry.logical_path, "category": entry.category.value}
            for entry in result.entries
        ],
        "excluded_count": result.excluded_count,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(encoded) <= MAX_CHECKOUT_LIST_RESULT_BYTES


@pytest.mark.asyncio
async def test_read_returns_exact_utf8_and_current_run_snapshot(tmp_path: Path) -> None:
    root = _root(tmp_path)
    payload = "linha 1\nÃ§Ã£Ãµ\n".encode()
    target = root / "src" / "example.py"
    target.write_bytes(payload)

    adapter = _adapter(root)
    result = await adapter.read("src/example.py", run_id=_RUN_ID)

    assert result.text.encode("utf-8") == payload
    assert result.snapshot.run_id == _RUN_ID
    assert result.snapshot.workspace_id == _WORKSPACE_ID
    assert result.snapshot.registration_generation == 7
    assert result.snapshot.logical_path == "src/example.py"
    assert result.snapshot.root_identity == adapter.registration.root_identity
    assert result.snapshot.file_identity.startswith("sha256:")
    assert result.snapshot.content_digest == "sha256:" + hashlib.sha256(payload).hexdigest()
    assert result.snapshot.byte_length == len(payload)
    assert str(root) not in repr(result.snapshot)


@pytest.mark.asyncio
async def test_read_rejects_traversal_outside_prefix_reserved_binary_invalid_utf8_and_oversize(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    (root / "outside.txt").write_text("no", encoding="utf-8")
    (root / "src" / "nul-byte.txt").write_bytes(b"a\x00b")
    (root / "src" / "bad.txt").write_bytes(b"\xff")
    (root / "src" / "huge.txt").write_bytes(b"x" * (MAX_CHECKOUT_TEXT_READ_BYTES + 1))
    (root / "src" / ".git").mkdir()

    adapter = _adapter(root)

    for logical_path in (
        "../outside.txt",
        "src/../outside.txt",
        "/src/file.txt",
        "src\\file.txt",
        "outside.txt",
        "src/.git/config",
    ):
        with pytest.raises((ValueError, AgentCodecError)):
            await adapter.read(logical_path, run_id=_RUN_ID)

    for logical_path in ("src/nul-byte.txt", "src/bad.txt", "src/huge.txt"):
        with pytest.raises(AgentCodecError):
            await adapter.read(logical_path, run_id=_RUN_ID)


@pytest.mark.asyncio
async def test_read_rejects_hardlinked_file(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = root / "src" / "first.txt"
    second = root / "src" / "second.txt"
    first.write_text("same", encoding="utf-8")
    try:
        os.link(first, second)
    except OSError:
        pytest.skip("hardlinks unavailable on this platform")

    adapter = _adapter(root)
    with pytest.raises(AgentCodecError):
        await adapter.read("src/first.txt", run_id=_RUN_ID)


@pytest.mark.asyncio
async def test_native_protected_exact_path_and_root_fail_closed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    exact = root / "src" / "secret.txt"
    exact.write_text("secret", encoding="utf-8")
    protected_dir = root / "src" / "runtime"
    protected_dir.mkdir()
    (protected_dir / "state.txt").write_text("state", encoding="utf-8")

    adapter = _adapter(
        root,
        protected_paths=(exact,),
        protected_roots=(protected_dir,),
    )

    with pytest.raises(AgentCodecError):
        await adapter.read("src/secret.txt", run_id=_RUN_ID)
    with pytest.raises(AgentCodecError):
        await adapter.read("src/runtime/state.txt", run_id=_RUN_ID)
    with pytest.raises(AgentCodecError):
        await adapter.list("src/runtime")


@pytest.mark.asyncio
async def test_root_identity_replacement_is_detected_before_access(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "src" / "file.txt").write_text("before", encoding="utf-8")
    adapter = _adapter(root)

    moved = tmp_path / "checkout-old"
    root.rename(moved)
    root.mkdir()
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src" / "file.txt").write_text("after", encoding="utf-8")

    with pytest.raises(AgentStateConflictError):
        await adapter.read("src/file.txt", run_id=_RUN_ID)


@pytest.mark.asyncio
async def test_read_prefixes_are_independently_enforced_for_list_and_read(tmp_path: Path) -> None:
    root = _root(tmp_path)
    private = root / "private"
    private.mkdir()
    (private / "x.txt").write_text("x", encoding="utf-8")

    adapter = _adapter(root)
    with pytest.raises(AgentCodecError):
        await adapter.list("private")
    with pytest.raises(AgentCodecError):
        await adapter.read("private/x.txt", run_id=_RUN_ID)
