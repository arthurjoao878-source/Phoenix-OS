from __future__ import annotations

import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath

_ROOT = Path(__file__).resolve().parents[1]

_COMPANION_TESTS = (
    "tests/test_rfc_0030.py",
    "tests/test_v030_release.py",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/releases/v0.30.0.md",
    "docs/rfcs/RFC-0030-secure-agent-memory-and-context-retrieval.md",
    "docs/migrations/v0.29.0-to-v0.30.0-agent-memory.md",
    "docs/security/RFC-0030-agent-memory-threat-model-review.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0052-memory-informs-work-never-authority.md",
    "docs/adrs/ADR-0053-phoenix-owned-exact-memory-scopes.md",
    "docs/adrs/ADR-0054-authoritative-memory-records-derived-indexes.md",
    "docs/adrs/ADR-0055-finite-retention-runtime-owned-memory-lifecycle.md",
)

_REQUIRED_INTEGRATION_FILES = (
    "phoenix_os/agent/__init__.py",
    "phoenix_os/configuration/dependencies.py",
    "phoenix_os/policy/__init__.py",
    "phoenix_os/runtime/__init__.py",
)

_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})


def _run(
    command: Sequence[str],
    *,
    cwd: Path = _ROOT,
    env: Mapping[str, str] | None = None,
) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(
        tuple(command),
        cwd=cwd,
        env=None if env is None else dict(env),
        check=True,
    )


def _project_metadata() -> tuple[str, str, str]:
    document = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]
    if not isinstance(project, dict):
        raise RuntimeError("pyproject project metadata is invalid")
    name = project.get("name")
    version = project.get("version")
    requires_python = project.get("requires-python")
    if not isinstance(name, str) or not name:
        raise RuntimeError("pyproject project name is missing")
    if not isinstance(version, str) or not version:
        raise RuntimeError("pyproject project version is missing")
    if not isinstance(requires_python, str) or not requires_python:
        raise RuntimeError("pyproject Python requirement is missing")
    return name, version, requires_python


def _memory_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_agent_memory*.py"))
    )
    if len(discovered) < 11:
        raise RuntimeError("agent-memory regression suite is unexpectedly small")
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required agent-memory release test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _memory_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "agent"
    files = tuple(f"phoenix_os/agent/{path.name}" for path in sorted(source.glob("memory_*.py")))
    if len(files) < 5:
        raise RuntimeError("agent-memory package contains too few memory modules")
    return files


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_memory_source_files(),
            *_REQUIRED_INTEGRATION_FILES,
        }
    )


def _validate_archive_names(names: Sequence[str], *, label: str) -> None:
    if not names:
        raise RuntimeError(f"{label} is empty")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError(f"{label} contains an unsafe path: {name}")
        if any(part in _FORBIDDEN_ARCHIVE_COMPONENTS for part in path.parts):
            raise RuntimeError(f"{label} contains a forbidden component: {name}")
        if path.suffix.lower() in _FORBIDDEN_ARCHIVE_SUFFIXES:
            raise RuntimeError(f"{label} contains a forbidden file type: {name}")


def _validate_wheel(
    wheel: Path,
    *,
    project_name: str,
    version: str,
    requires_python: str,
) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = tuple(archive.namelist())
        _validate_archive_names(names, label=f"wheel {wheel.name}")
        available = frozenset(names)
        missing = sorted(_required_package_files() - available)
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing required agent-memory files: " + ", ".join(missing)
            )

        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_paths) != 1:
            raise RuntimeError(f"wheel {wheel.name} must contain exactly one METADATA file")
        metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_paths[0]))
        if metadata["Name"] != project_name:
            raise RuntimeError("wheel project name does not match pyproject")
        if metadata["Version"] != version:
            raise RuntimeError("wheel version does not match pyproject")
        if metadata["Requires-Python"] != requires_python:
            raise RuntimeError("wheel Python requirement does not match pyproject")
        if any(name.startswith("tests/") for name in names):
            raise RuntimeError("wheel unexpectedly contains the test suite")
        if any(name.startswith("docs/") for name in names):
            raise RuntimeError("wheel unexpectedly contains repository documentation")


def _sdist_relative_names(archive: tarfile.TarFile) -> tuple[str, ...]:
    names = tuple(member.name for member in archive.getmembers())
    _validate_archive_names(names, label="sdist")
    roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
    if len(roots) != 1:
        raise RuntimeError("sdist must contain exactly one top-level directory")
    root = next(iter(roots))
    prefix = f"{root}/"
    return tuple(
        name[len(prefix) :] for name in names if name.startswith(prefix) and name != prefix
    )


def _validate_sdist(sdist: Path) -> None:
    with tarfile.open(sdist, mode="r:gz") as archive:
        relative = frozenset(_sdist_relative_names(archive))
    required = {
        *_REQUIRED_SDIST_DOCUMENTS,
        *{f"src/{name}" for name in _required_package_files()},
    }
    missing = sorted(required - relative)
    if missing:
        raise RuntimeError(
            f"sdist {sdist.name} is missing required agent-memory files: " + ", ".join(missing)
        )


def _extract_sdist(sdist: Path, destination: Path) -> Path:
    with tarfile.open(sdist, mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError(f"sdist contains an unsafe path: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"sdist contains an unexpected link: {member.name}")
        archive.extractall(destination, filter="data")
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("extracted sdist must contain one source directory")
    return roots[0]


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _smoke_install(
    wheel: Path,
    *,
    version: str,
    workspace: Path,
    label: str,
) -> None:
    environment = workspace / f"venv-{label}"
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    python = _venv_python(environment)
    _run(
        (
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--no-index",
            str(wheel),
        ),
        cwd=workspace,
    )

    smoke_directory = workspace / f"smoke-{label}"
    smoke_directory.mkdir()
    program = f"""
import asyncio
from datetime import UTC, datetime
from importlib.metadata import version as distribution_version
from pathlib import Path
import sys
from uuid import UUID

import phoenix_os
from phoenix_os.agent import (
    MEMORY_ADMIN_ACTION,
    MEMORY_DELETE_ACTION,
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
    MEMORY_WRITE_ACTION,
    DeterministicLexicalMemoryRetrievalAdapter,
    InMemoryAgentMemoryStore,
    MemoryDeleteRequest,
    MemoryId,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecordIncarnation,
    MemoryRecordStatus,
    MemoryRecordVersion,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    memory_content_digest,
    memory_record_resource,
    memory_scope_resource,
)


async def main() -> None:
    assert distribution_version("phoenix-os") == {version!r}
    assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

    assert (
        MEMORY_SEARCH_ACTION,
        MEMORY_READ_ACTION,
        MEMORY_WRITE_ACTION,
        MEMORY_DELETE_ACTION,
        MEMORY_ADMIN_ACTION,
    ) == (
        "memory.search",
        "memory.read",
        "memory.write",
        "memory.delete",
        "memory.admin",
    )

    now = datetime.now(UTC)
    scope = MemoryScope(
        namespace=MemoryNamespace("release"),
        kind=MemoryScopeKind.AGENT,
        scope_id=MemoryScopeId("assistant"),
    )
    memory_id = MemoryId(UUID("30000000-0000-0000-0000-000000000030"))
    assert memory_scope_resource(scope) == "agent-memory:release/scope:agent:assistant"
    assert memory_record_resource(scope, memory_id) == (
        "agent-memory:release/scope:agent:assistant/"
        "record:30000000-0000-0000-0000-000000000030"
    )

    content = "remember the blue release folder"
    digest = memory_content_digest(content)
    write = MemoryWriteRequest(
        scope=scope,
        memory_id=memory_id,
        content=content,
        provenance=MemoryProvenance(
            origin=MemoryOriginKind.USER_INPUT,
            content_digest=digest,
            created_at=now,
            attributes={{"source": "release-smoke"}},
        ),
        metadata={{"kind": "release"}},
        created_at=now,
    )
    store = InMemoryAgentMemoryStore()
    record = await store.write(write)
    assert isinstance(record.incarnation, MemoryRecordIncarnation)
    assert record.incarnation.value.version == 4
    assert record.version == MemoryRecordVersion(1)
    assert record.status is MemoryRecordStatus.ACTIVE
    assert record.content_digest == digest

    loaded = await store.read(
        MemoryReadRequest(scope=scope, memory_id=memory_id, created_at=now)
    )
    assert loaded == record

    adapter = DeterministicLexicalMemoryRetrievalAdapter(store)
    candidates = await adapter.search(
        MemorySearchRequest(
            scope=scope,
            query="blue folder",
            max_results=4,
            created_at=now,
        )
    )
    assert len(candidates) == 1
    assert candidates[0].memory_id == memory_id
    assert candidates[0].incarnation == record.incarnation
    assert candidates[0].version == record.version
    assert candidates[0].content_digest == digest

    await store.delete(
        MemoryDeleteRequest(
            scope=scope,
            memory_id=memory_id,
            expected_version=record.version,
            expected_incarnation=record.incarnation,
            created_at=now,
        )
    )
    assert (
        await store.read(
            MemoryReadRequest(scope=scope, memory_id=memory_id, created_at=now)
        )
        is None
    )
    await store.close()
    assert store.closed


asyncio.run(main())
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    _run((str(python), "-I", "-c", program), cwd=smoke_directory, env=env)


def _single_artifact(directory: Path, pattern: str, *, label: str) -> Path:
    matches = tuple(directory.glob(pattern))
    if len(matches) != 1:
        rendered = ", ".join(path.name for path in matches) or "<none>"
        raise RuntimeError(f"expected one {label}; found {len(matches)}: {rendered}")
    return matches[0]


def _validate_filename_version(path: Path, *, version: str) -> None:
    normalized = re.sub(r"[-_.]+", r"[-_.]", version)
    if re.search(rf"[-_]{normalized}(?:[-_.]|$)", path.name) is None:
        raise RuntimeError(f"artifact filename does not contain version {version}: {path.name}")


def main() -> int:
    project_name, version, requires_python = _project_metadata()
    print(
        "Running RFC-0030 agent-memory authorization, store, retrieval, context, "
        "semantic, Runtime, migration, ADR, security-review, and release suites.",
        flush=True,
    )
    _run((sys.executable, "-m", "pytest", "-q", *_memory_test_files()))

    with tempfile.TemporaryDirectory(prefix="phoenix-agent-memory-release-") as temporary:
        workspace = Path(temporary)
        artifacts = workspace / "dist"
        artifacts.mkdir()

        print("Building wheel and sdist without network isolation.", flush=True)
        _run(
            (
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(artifacts),
                str(_ROOT),
            )
        )

        wheel = _single_artifact(artifacts, "*.whl", label="wheel")
        sdist = _single_artifact(artifacts, "*.tar.gz", label="sdist")
        _validate_filename_version(wheel, version=version)
        _validate_filename_version(sdist, version=version)
        _validate_wheel(
            wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )
        _validate_sdist(sdist)

        extracted = workspace / "extracted"
        extracted.mkdir()
        source = _extract_sdist(sdist, extracted)
        rebuilt = workspace / "rebuilt"
        rebuilt.mkdir()

        print("Rebuilding a wheel from the validated sdist.", flush=True)
        _run(
            (
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(rebuilt),
                str(source),
            ),
            cwd=workspace,
        )
        rebuilt_wheel = _single_artifact(rebuilt, "*.whl", label="rebuilt wheel")
        _validate_filename_version(rebuilt_wheel, version=version)
        _validate_wheel(
            rebuilt_wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )

        print("Installing and smoking both wheel forms offline.", flush=True)
        _smoke_install(
            wheel,
            version=version,
            workspace=workspace,
            label="direct",
        )
        _smoke_install(
            rebuilt_wheel,
            version=version,
            workspace=workspace,
            label="rebuilt",
        )

    print("RFC-0030 agent-memory release gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
